import Foundation

/// What a phone and its own watch say to each other.
///
/// These travel over the link Apple provides between an iPhone app and its
/// watch app, as dictionaries of property-list values. That link is between
/// one person's own devices, and nothing here asks either side to trust what
/// arrives beyond that:
///
/// - No private key is ever in a message. Each device makes its own.
/// - The phone signs for a watch's keys only after the person agrees, with
///   Face ID, in the phone app.
/// - An answer the phone carries to the relay for the watch is already
///   signed by the watch. The phone is a courier and cannot alter it.
public enum WatchMessage: Equatable, Sendable {
    /// Phone to watch: make keys for this pairing and tell me the public
    /// halves.
    case offer(pairingID: Data, hostPub: Data, hostName: String, relayURL: String)
    /// Watch to phone, in reply: the keys it made, the token it will present
    /// to the relay, and what it is called.
    case keys(pairingID: Data, signPub: Data, kemPub: Data, token: String, name: String, hardwareBacked: Bool)
    /// Phone to watch: my signature over your keys. You may answer now.
    case delegation(pairingID: Data, signed: Data)
    /// Phone to watch: this pairing is gone, or you are no longer to answer
    /// for it. Forget it and its keys.
    case removed(pairingID: Data)
    /// Watch to phone: carry this signed answer to the relay for me. Used
    /// when the watch cannot reach the relay itself.
    case answer(pairingID: Data, requestID: String, token: String, body: Data)
    /// Phone to watch, in reply to `answer`: the relay's HTTP status, or 0
    /// if the relay could not be reached.
    case delivered(status: Int)
    /// Either way: this request has been answered, here or elsewhere.
    case settled(requestID: String)
    /// In reply to anything: it could not be done, and why, as a code.
    case failed(Failure)

    public enum Failure: String, Sendable {
        /// The watch has no passcode, or could not make a key.
        case noKey
        /// The pairing named is not one this device knows.
        case unknownPairing
        /// The message was not understood.
        case malformed
    }

    private enum Kind: String {
        case offer, keys, delegation, removed, answer, delivered, settled, failed
    }

    /// The property-list form.
    public var dictionary: [String: Any] {
        switch self {
        case .offer(let pairingID, let hostPub, let hostName, let relayURL):
            ["t": Kind.offer.rawValue, "pid": pairingID, "hostPub": hostPub, "hostName": hostName, "relay": relayURL]
        case .keys(let pairingID, let signPub, let kemPub, let token, let name, let hardwareBacked):
            [
                "t": Kind.keys.rawValue, "pid": pairingID, "sign": signPub, "kem": kemPub, "token": token, "name": name,
                "hw": hardwareBacked,
            ]
        case .delegation(let pairingID, let signed):
            ["t": Kind.delegation.rawValue, "pid": pairingID, "signed": signed]
        case .removed(let pairingID):
            ["t": Kind.removed.rawValue, "pid": pairingID]
        case .answer(let pairingID, let requestID, let token, let body):
            ["t": Kind.answer.rawValue, "pid": pairingID, "rid": requestID, "token": token, "body": body]
        case .delivered(let status):
            ["t": Kind.delivered.rawValue, "status": status]
        case .settled(let requestID):
            ["t": Kind.settled.rawValue, "rid": requestID]
        case .failed(let failure):
            ["t": Kind.failed.rawValue, "why": failure.rawValue]
        }
    }

    /// Strict: every field present, of the right type and size, or nil.
    public init?(dictionary: [String: Any]) {
        func data(_ key: String, count: Int? = nil) -> Data? {
            guard let value = dictionary[key] as? Data, count == nil || value.count == count else { return nil }
            return value
        }
        func text(_ key: String, max: Int) -> String? {
            guard let value = dictionary[key] as? String, value.utf8.count <= max else { return nil }
            return value
        }
        guard let kind = (dictionary["t"] as? String).flatMap(Kind.init(rawValue:)) else { return nil }
        let pairingID = data("pid", count: Proto.pairingIDLength)
        switch kind {
        case .offer:
            guard let pairingID, let hostPub = data("hostPub", count: Proto.pubkeyLength),
                  let hostName = text("hostName", max: Proto.maxNameLength), let relayURL = text("relay", max: 2048)
            else { return nil }
            self = .offer(pairingID: pairingID, hostPub: hostPub, hostName: hostName, relayURL: relayURL)
        case .keys:
            guard let pairingID, let signPub = data("sign", count: Proto.pubkeyLength),
                  let kemPub = data("kem", count: Proto.pubkeyLength), let token = text("token", max: 64),
                  let name = text("name", max: 256), let hardwareBacked = dictionary["hw"] as? Bool
            else { return nil }
            self = .keys(
                pairingID: pairingID, signPub: signPub, kemPub: kemPub, token: token, name: name, hardwareBacked: hardwareBacked
            )
        case .delegation:
            guard let pairingID, let signed = data("signed"), signed.count <= SignedDelegation.maxLength else { return nil }
            self = .delegation(pairingID: pairingID, signed: signed)
        case .removed:
            guard let pairingID else { return nil }
            self = .removed(pairingID: pairingID)
        case .answer:
            guard let pairingID, let requestID = text("rid", max: 2 * Proto.requestIDLength),
                  let token = text("token", max: 64), let body = data("body"), body.count <= 4096
            else { return nil }
            self = .answer(pairingID: pairingID, requestID: requestID, token: token, body: body)
        case .delivered:
            guard let status = dictionary["status"] as? Int else { return nil }
            self = .delivered(status: status)
        case .settled:
            guard let requestID = text("rid", max: 2 * Proto.requestIDLength) else { return nil }
            self = .settled(requestID: requestID)
        case .failed:
            guard let failure = (dictionary["why"] as? String).flatMap(Failure.init(rawValue:)) else { return nil }
            self = .failed(failure)
        }
    }
}

extension Delegation {
    /// A name fit to sign for, made from whatever a watch calls itself:
    /// control characters and surrounding space removed, cut to the limit at
    /// a character boundary. Falls back to a plain description.
    public static func usableName(from raw: String) -> String {
        let cleaned = String(raw.unicodeScalars.filter { $0.properties.generalCategory != .control })
            .trimmingCharacters(in: .whitespacesAndNewlines)
        var name = cleaned
        while name.utf8.count > maxNameLength {
            name.removeLast()
        }
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return isValid(name: name) ? name : "Apple Watch"
    }
}
