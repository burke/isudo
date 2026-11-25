import Foundation

/// What can go wrong talking to the relay. A fixed vocabulary plus a status
/// number: nothing the relay or the network says is ever passed along as
/// text.
public enum RelayError: Error, Equatable, Sendable {
    case badURL
    case timedOut
    case offline
    case cannotConnect
    case insecure
    case failed
    case status(Int)
    case unreadable

    public var message: String {
        switch self {
        case .badURL: "The relay address is not valid."
        case .timedOut: "The relay did not answer in time."
        case .offline: "This phone is offline."
        case .cannotConnect: "The relay could not be reached."
        case .insecure: "A secure connection to the relay could not be made."
        case .failed: "The request to the relay failed."
        case .status(401), .status(403): "The relay did not accept this phone's credentials."
        case .status(404): "The relay does not know this pairing or request."
        case .status(409): "The relay refused the request (conflict)."
        case .status(429): "The relay refused the request (too many requests)."
        case .status(let code): "The relay answered with HTTP status \(code)."
        case .unreadable: "The relay's answer could not be understood."
        }
    }
}

/// HTTP client for the relay, phone side. HTTPS is required unless the
/// relay is on this very machine.
public struct RelayClient: Sendable {
    let base: URL
    let session: URLSession

    /// True if `http://` is acceptable for this host: loopback only.
    static func isLoopback(_ host: String) -> Bool {
        ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host)
    }

    public init(baseURL: String, session: URLSession = RelayClient.defaultSession) throws(RelayError) {
        var trimmed = baseURL
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        guard let url = URL(string: trimmed), let scheme = url.scheme, let host = url.host(), !host.isEmpty else {
            throw .badURL
        }
        guard scheme == "https" || (scheme == "http" && Self.isLoopback(host)) else { throw .badURL }
        base = url
        self.session = session
    }

    public static let defaultSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        return URLSession(configuration: configuration)
    }()

    private func send(_ method: String, _ path: [String], bearer: String?, body: Data?) async throws(RelayError) -> (Data, Int) {
        var url = base
        for segment in path { url.append(path: segment) }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let bearer { request.setValue("Bearer " + bearer, forHTTPHeaderField: "authorization") }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "content-type")
        }
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw RelayError.failed }
            return (data, http.statusCode)
        } catch let error as RelayError {
            throw error
        } catch let error as URLError {
            switch error.code {
            case .timedOut: throw .timedOut
            case .notConnectedToInternet, .networkConnectionLost, .dataNotAllowed: throw .offline
            case .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed: throw .cannotConnect
            case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
                 .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .appTransportSecurityRequiresSecureConnection:
                throw .insecure
            default: throw .failed
            }
        } catch {
            throw .failed
        }
    }

    private func done(_ method: String, _ path: [String], bearer: String?, body: (some Encodable)?) async throws(RelayError) {
        let encoded: Data?
        do { encoded = try body.map { try JSONEncoder().encode($0) } } catch { throw .failed }
        let (_, status) = try await send(method, path, bearer: bearer, body: encoded)
        guard (200..<300).contains(status) else { throw .status(status) }
    }

    private func json<T: Decodable>(_ path: [String], bearer: String?) async throws(RelayError) -> T {
        let (data, status) = try await send("GET", path, bearer: bearer, body: nil)
        guard status == 200 else { throw .status(status) }
        guard data.count <= 4 * 1024 * 1024, let value = try? JSONDecoder().decode(T.self, from: data) else {
            throw .unreadable
        }
        return value
    }

    /// Answers a pairing this phone scanned. 409 means another phone got
    /// there first.
    public func claim(pairingID: String, _ body: API.Claim) async throws(RelayError) {
        try await done("POST", ["v1", "pairings", pairingID, "claim"], bearer: nil, body: body)
    }

    public func status(pairingID: String, token: String) async throws(RelayError) -> API.PairingStatus {
        try await json(["v1", "pairings", pairingID], bearer: token)
    }

    public func updateDevice(pairingID: String, token: String, _ body: API.DeviceUpdate) async throws(RelayError) {
        try await done("POST", ["v1", "pairings", pairingID, "device"], bearer: token, body: body)
    }

    public func unpair(pairingID: String, token: String) async throws(RelayError) {
        try await done("POST", ["v1", "pairings", pairingID, "unpair"], bearer: token, body: String?.none)
    }

    public func pending(pairingID: String, token: String) async throws(RelayError) -> API.PendingList {
        try await json(["v1", "pairings", pairingID, "requests"], bearer: token)
    }

    public func answer(requestID: String, token: String, _ body: API.Answer) async throws(RelayError) {
        try await done("POST", ["v1", "requests", requestID, "response"], bearer: token, body: body)
    }
}
