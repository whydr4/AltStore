//
//  RemoteAnisetteProvider.swift
//  AltServer
//
//  Anisette v3 client (https://github.com/Dadoum/anisette-v3-server).
//  The ADI state is provisioned through a remote server that emulates an Android device,
//  so requests to Apple must also describe the client as Android, otherwise
//  GrandSlam rejects the login with -80045 ("This action cannot be completed at this time").
//

import Foundation
import CommonCrypto

struct RemoteAnisetteHeaders
{
    var machineID: String
    var oneTimePassword: String
    var routingInfo: UInt64
    var localUserID: String
    var deviceUniqueIdentifier: String
    var deviceDescription: String
    var userAgent: String
}

enum RemoteAnisetteError: LocalizedError
{
    case server(String)
    case provisioning(String)
    case invalidResponse(String)

    var errorDescription: String? {
        switch self
        {
        case .server(let message): return "Anisette server error: \(message)"
        case .provisioning(let message): return "Anisette provisioning failed: \(message)"
        case .invalidResponse(let message): return "Invalid anisette response: \(message)"
        }
    }
}

final class RemoteAnisetteProvider
{
    // Client info matching the Android-based ADI state the anisette server provisions.
    static let androidClientInfo = "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    static let userAgent = "akd/1.0 CFNetwork/808.1.4"

    // GrandSlam returns the wrong URL bag for Android client info, so the lookup claims to be a Mac.
    private static let lookupClientInfo = "<MacBookPro18,3> <macOS;14.6;23G80> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

    static let defaultServerURLs = [
        "https://ani.stikstore.app",
        "https://ani.sidestore.io",
        "https://ani.sidestore.zip",
    ]

    private let storage: UserDefaults
    private let session: URLSession
    private let queue = DispatchQueue(label: "RemoteAnisetteProvider")

    private struct Keys
    {
        static let serverURL = "remoteAnisetteServerURL"
        static let identifier = "remoteAnisetteIdentifier"
        static let adiPb = "remoteAnisetteADIPb"
    }

    init(storage: UserDefaults = .standard, session: URLSession = .shared)
    {
        self.storage = storage
        self.session = session
    }

    var serverURLs: [URL] {
        var urls = RemoteAnisetteProvider.defaultServerURLs
        if let custom = self.storage.string(forKey: Keys.serverURL), !custom.isEmpty
        {
            urls.removeAll { $0 == custom }
            urls.insert(custom, at: 0)
        }
        return urls.compactMap(URL.init(string:))
    }

    /// Identifier is 16 random bytes, persisted so the provisioned ADI state can be reused.
    private var identifier: Data {
        if let string = self.storage.string(forKey: Keys.identifier), let data = Data(base64Encoded: string), data.count == 16
        {
            return data
        }

        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let data = Data(bytes)
        self.storage.set(data.base64EncodedString(), forKey: Keys.identifier)
        return data
    }

    var localUserID: String { self.identifier.sha256().hexEncodedString() }
    var deviceUniqueIdentifier: String { UUID(uuid: self.identifier.withUnsafeBytes { $0.load(as: uuid_t.self) }).uuidString.uppercased() }

    func resetProvisioning()
    {
        self.storage.removeObject(forKey: Keys.adiPb)
    }

    /// Fetches anisette headers. Pass `resyncSIM` (base64 X-Apple-I-MD-DATA from a GrandSlam hsc 434 response) to resync the ADI state.
    func fetchHeaders(resyncSIM: String? = nil, completion: @escaping (Result<RemoteAnisetteHeaders, Error>) -> Void)
    {
        self.fetchHeaders(servers: self.serverURLs, resyncSIM: resyncSIM, lastError: nil, completion: completion)
    }
}

private extension RemoteAnisetteProvider
{
    func fetchHeaders(servers: [URL], resyncSIM: String?, lastError: Error?, completion: @escaping (Result<RemoteAnisetteHeaders, Error>) -> Void)
    {
        guard let server = servers.first else {
            completion(.failure(lastError ?? RemoteAnisetteError.server("No anisette servers available.")))
            return
        }

        self.fetchHeaders(server: server, resyncSIM: resyncSIM, allowReprovision: true) { result in
            switch result
            {
            case .success: completion(result)
            case .failure(let error):
                print("[Anisette] \(server.absoluteString) failed: \(error.localizedDescription)")
                self.fetchHeaders(servers: Array(servers.dropFirst()), resyncSIM: resyncSIM, lastError: error, completion: completion)
            }
        }
    }

    func fetchHeaders(server: URL, resyncSIM: String?, allowReprovision: Bool, completion: @escaping (Result<RemoteAnisetteHeaders, Error>) -> Void)
    {
        guard let adiPb = self.storage.string(forKey: Keys.adiPb) else {
            self.provision(server: server) { result in
                switch result
                {
                case .failure(let error): completion(.failure(error))
                case .success: self.fetchHeaders(server: server, resyncSIM: resyncSIM, allowReprovision: false, completion: completion)
                }
            }
            return
        }

        var body: [String: String] = [
            "identifier": self.identifier.base64EncodedString(),
            "adi_pb": adiPb,
        ]
        if let resyncSIM
        {
            body["sim"] = resyncSIM
            body["device_id"] = self.deviceUniqueIdentifier
            body["md_lu"] = self.localUserID
        }

        var request = URLRequest(url: server.appendingPathComponent("v3").appendingPathComponent("get_headers"))
        request.httpMethod = "POST"
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        self.session.dataTask(with: request) { data, response, error in
            do
            {
                guard let data else { throw error ?? RemoteAnisetteError.server("No data from \(server.host ?? "server").") }
                guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw RemoteAnisetteError.invalidResponse("not JSON") }

                if json["result"] as? String == "GetHeadersError"
                {
                    let message = json["message"] as? String ?? "unknown error"
                    if message.contains("-45061") && allowReprovision
                    {
                        // ADI state is no longer provisioned, start over.
                        self.resetProvisioning()
                        self.fetchHeaders(server: server, resyncSIM: resyncSIM, allowReprovision: false, completion: completion)
                        return
                    }
                    throw RemoteAnisetteError.server(message)
                }

                guard let machineID = json["X-Apple-I-MD-M"] as? String,
                      let otp = json["X-Apple-I-MD"] as? String
                else { throw RemoteAnisetteError.invalidResponse(String(decoding: data, as: UTF8.self)) }

                let rinfoValue = json["X-Apple-I-MD-RINFO"]
                let routingInfo = (rinfoValue as? NSNumber)?.uint64Value ?? UInt64(rinfoValue as? String ?? "") ?? 17106176

                completion(.success(RemoteAnisetteHeaders(machineID: machineID,
                                                          oneTimePassword: otp,
                                                          routingInfo: routingInfo,
                                                          localUserID: self.localUserID,
                                                          deviceUniqueIdentifier: self.deviceUniqueIdentifier,
                                                          deviceDescription: RemoteAnisetteProvider.androidClientInfo,
                                                          userAgent: RemoteAnisetteProvider.userAgent)))
            }
            catch
            {
                completion(.failure(error))
            }
        }.resume()
    }

    // MARK: - Provisioning

    func provision(server: URL, completion: @escaping (Result<Void, Error>) -> Void)
    {
        self.fetchProvisioningURLs { result in
            switch result
            {
            case .failure(let error): completion(.failure(error))
            case .success(let (startURL, endURL)):
                ProvisioningSession(provider: self, server: server, startURL: startURL, endURL: endURL) { result in
                    if case .success(let adiPb) = result
                    {
                        self.storage.set(adiPb, forKey: Keys.adiPb)
                    }
                    completion(result.map { _ in () })
                }.start()
            }
        }
    }

    func fetchProvisioningURLs(completion: @escaping (Result<(URL, URL), Error>) -> Void)
    {
        var request = self.makeAppleRequest(url: URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup")!)
        request.setValue(RemoteAnisetteProvider.lookupClientInfo, forHTTPHeaderField: "X-Mme-Client-Info")

        self.session.dataTask(with: request) { data, _, error in
            guard let data,
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let urls = plist["urls"] as? [String: Any],
                  let start = (urls["midStartProvisioning"] as? String).flatMap(URL.init(string:)),
                  let end = (urls["midFinishProvisioning"] as? String).flatMap(URL.init(string:))
            else {
                completion(.failure(error ?? RemoteAnisetteError.provisioning("Apple did not return provisioning URLs.")))
                return
            }
            completion(.success((start, end)))
        }.resume()
    }

    func makeAppleRequest(url: URL) -> URLRequest
    {
        var request = URLRequest(url: url)
        request.timeoutInterval = 20
        request.setValue(RemoteAnisetteProvider.androidClientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
        request.setValue(RemoteAnisetteProvider.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(self.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")
        request.setValue(self.deviceUniqueIdentifier, forHTTPHeaderField: "X-Mme-Device-Id")

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        request.setValue(formatter.string(from: Date()), forHTTPHeaderField: "X-Apple-I-Client-Time")
        request.setValue(Locale.current.identifier, forHTTPHeaderField: "X-Apple-Locale")
        request.setValue(TimeZone.current.abbreviation() ?? "UTC", forHTTPHeaderField: "X-Apple-I-TimeZone")
        return request
    }
}

/// Websocket conversation with /v3/provisioning_session, relaying Apple's provisioning endpoints.
private final class ProvisioningSession
{
    private let provider: RemoteAnisetteProvider
    private let server: URL
    private let startURL: URL
    private let endURL: URL
    private var completion: ((Result<String, Error>) -> Void)?
    private var task: URLSessionWebSocketTask?
    private var keepAlive: ProvisioningSession?

    init(provider: RemoteAnisetteProvider, server: URL, startURL: URL, endURL: URL, completion: @escaping (Result<String, Error>) -> Void)
    {
        self.provider = provider
        self.server = server
        self.startURL = startURL
        self.endURL = endURL
        self.completion = completion
    }

    func start()
    {
        var components = URLComponents(url: self.server.appendingPathComponent("v3").appendingPathComponent("provisioning_session"), resolvingAgainstBaseURL: false)!
        components.scheme = (components.scheme == "http") ? "ws" : "wss"

        self.keepAlive = self
        self.task = URLSession.shared.webSocketTask(with: components.url!)
        self.task?.resume()
        self.receive()
    }

    private func finish(_ result: Result<String, Error>)
    {
        guard let completion = self.completion else { return }
        self.completion = nil
        self.task?.cancel(with: .normalClosure, reason: nil)
        self.keepAlive = nil
        completion(result)
    }

    private func send(_ json: [String: String])
    {
        guard let data = try? JSONSerialization.data(withJSONObject: json) else { return }
        self.task?.send(.string(String(decoding: data, as: UTF8.self))) { error in
            if let error { self.finish(.failure(error)) }
        }
    }

    private func receive()
    {
        self.task?.receive { result in
            switch result
            {
            case .failure(let error): self.finish(.failure(error))
            case .success(let message):
                let data: Data
                switch message
                {
                case .string(let string): data = Data(string.utf8)
                case .data(let d): data = d
                @unknown default: return
                }

                guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let step = json["result"] as? String else {
                    self.finish(.failure(RemoteAnisetteError.provisioning("Unexpected message from anisette server.")))
                    return
                }
                self.handle(step: step, json: json)
                if self.completion != nil { self.receive() }
            }
        }
    }

    private func handle(step: String, json: [String: Any])
    {
        switch step
        {
        case "GiveIdentifier":
            self.send(["identifier": self.provider.identifierString])

        case "GiveStartProvisioningData":
            self.postToApple(url: self.startURL, request: [:]) { response in
                guard let spim = response["spim"] as? String else { return self.finish(.failure(RemoteAnisetteError.provisioning("Apple did not return spim."))) }
                self.send(["spim": spim])
            }

        case "GiveEndProvisioningData":
            guard let cpim = json["cpim"] as? String else { return self.finish(.failure(RemoteAnisetteError.provisioning("Server did not return cpim."))) }
            self.postToApple(url: self.endURL, request: ["cpim": cpim]) { response in
                guard let ptm = response["ptm"] as? String, let tk = response["tk"] as? String else {
                    return self.finish(.failure(RemoteAnisetteError.provisioning("Apple did not return ptm/tk.")))
                }
                self.send(["ptm": ptm, "tk": tk])
            }

        case "ProvisioningSuccess":
            guard let adiPb = json["adi_pb"] as? String else { return self.finish(.failure(RemoteAnisetteError.provisioning("Server did not return adi_pb."))) }
            self.finish(.success(adiPb))

        default:
            if step.contains("Error") || step.contains("Invalid") || step == "ClosingPerRequest" || step == "Timeout" || step == "TextOnly"
            {
                let message = json["message"] as? String
                self.finish(.failure(RemoteAnisetteError.provisioning([step, message].compactMap { $0 }.joined(separator: ": "))))
            }
        }
    }

    private func postToApple(url: URL, request body: [String: Any], completion: @escaping ([String: Any]) -> Void)
    {
        var request = self.provider.makeAppleRequestForProvisioning(url: url)
        request.httpMethod = "POST"
        request.httpBody = try? PropertyListSerialization.data(fromPropertyList: ["Header": [String: Any](), "Request": body], format: .xml, options: 0)

        URLSession.shared.dataTask(with: request) { data, _, error in
            guard let data,
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let response = plist["Response"] as? [String: Any]
            else {
                self.finish(.failure(error ?? RemoteAnisetteError.provisioning("Invalid response from \(url.absoluteString).")))
                return
            }
            completion(response)
        }.resume()
    }
}

private extension RemoteAnisetteProvider
{
    var identifierString: String { self.identifier.base64EncodedString() }
    func makeAppleRequestForProvisioning(url: URL) -> URLRequest { self.makeAppleRequest(url: url) }
}

private extension Data
{
    func sha256() -> Data
    {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &hash) }
        return Data(hash)
    }

    func hexEncodedString() -> String
    {
        self.map { String(format: "%02hhX", $0) }.joined()
    }
}
