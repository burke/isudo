import Foundation

/// Everything in the pairing code (a QR code or link). Mirrors
/// `isudo_proto::pairing::Offer`.
public struct PairingOffer: Equatable, Sendable, Codable {
    public var relayURL: String
    public var pairingID: Data
    public var hostPub: Data
    public var secret: Data
    /// The computer's commitment to the nonce it will reveal when it accepts
    /// an answer. See `Crypto.commitment`.
    public var commitment: Data
    public var hostName: String

    public init(relayURL: String, pairingID: Data, hostPub: Data, secret: Data, commitment: Data, hostName: String) {
        self.relayURL = relayURL
        self.pairingID = pairingID
        self.hostPub = hostPub
        self.secret = secret
        self.commitment = commitment
        self.hostName = hostName
    }

    public struct ParseError: Error, Equatable, Sendable {
        public let reason: String
    }

    static let prefix = "isudo://pair?"
    /// The reason given for a link in the previous format.
    public static let outdated = "pairing link is from an older isudo; update isudo on the computer"

    /// Parses `isudo://pair?v=2&r=<relay>&p=<id>&k=<host key>&s=<secret>&c=<commitment>&n=<name>`.
    /// Exactly these fields, each once, with values of the right size.
    public init(link: String) throws(ParseError) {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(Self.prefix) else { throw ParseError(reason: "not an isudo pairing link") }
        var fields: [String: String] = [:]
        for pair in trimmed.dropFirst(Self.prefix.count).split(separator: "&", omittingEmptySubsequences: false) {
            guard let equals = pair.firstIndex(of: "=") else { throw ParseError(reason: "malformed pairing link") }
            let key = String(pair[..<equals])
            guard ["v", "r", "p", "k", "s", "c", "n"].contains(key) else {
                throw ParseError(reason: "unknown field in pairing link")
            }
            guard fields.updateValue(String(pair[pair.index(after: equals)...]), forKey: key) == nil else {
                throw ParseError(reason: "repeated field in pairing link")
            }
        }
        func field(_ key: String) throws(ParseError) -> String {
            guard let value = fields[key] else { throw ParseError(reason: "pairing link is missing a field") }
            return value
        }
        switch try field("v") {
        case "2": break
        // Version 1 had no commitment, which let whoever wrote the link
        // choose the code this phone would show.
        case "1": throw ParseError(reason: Self.outdated)
        default: throw ParseError(reason: "unsupported pairing link version")
        }
        func binary(_ key: String, count: Int) throws(ParseError) -> Data {
            let text = try field(key)
            do { return try Codec.b64Decode(text, count: count) } catch { throw ParseError(reason: error.reason) }
        }
        relayURL = try Self.percentDecode(try field("r"))
        pairingID = try binary("p", count: Proto.pairingIDLength)
        hostPub = try binary("k", count: Proto.pubkeyLength)
        guard hostPub.first == 0x04 else { throw ParseError(reason: "public key is not in uncompressed form") }
        secret = try binary("s", count: Proto.secretLength)
        commitment = try binary("c", count: Proto.commitmentLength)
        hostName = try Self.percentDecode(try field("n"))
        guard hostName.utf8.count <= Proto.maxNameLength else { throw ParseError(reason: "host name is too long") }
    }

    private static func percentDecode(_ text: String) throws(ParseError) -> String {
        var out = [UInt8]()
        var bytes = text.utf8.makeIterator()
        while let byte = bytes.next() {
            guard byte == UInt8(ascii: "%") else {
                out.append(byte)
                continue
            }
            guard let high = bytes.next(), let low = bytes.next() else {
                throw ParseError(reason: "truncated percent escape")
            }
            guard let value = try? Codec.hexDecode(String(decoding: [high, low], as: UTF8.self)).first else {
                throw ParseError(reason: "invalid percent escape")
            }
            out.append(value)
        }
        guard let decoded = String(validatingUTF8: out) else {
            throw ParseError(reason: "pairing link text is not UTF-8")
        }
        return decoded
    }

    private static func percentEncode(_ text: String) -> String {
        var out = ""
        for byte in text.utf8 {
            let scalar = Unicode.Scalar(byte)
            let unreserved = (byte < 0x80 && (Character(scalar).isLetter || Character(scalar).isNumber))
                || "-._~".utf8.contains(byte)
            out += unreserved ? String(Character(scalar)) : "%" + Codec.hexEncode([byte]).uppercased()
        }
        return out
    }

    /// The link form, as `isudo-admin pair` prints it.
    public var link: String {
        Self.prefix + "v=2&r=" + Self.percentEncode(relayURL) + "&p=" + Codec.b64Encode(pairingID)
            + "&k=" + Codec.b64Encode(hostPub) + "&s=" + Codec.b64Encode(secret)
            + "&c=" + Codec.b64Encode(commitment) + "&n=" + Self.percentEncode(hostName)
    }
}

extension String {
    /// A string from bytes, or nil unless they are valid UTF-8.
    init?(validatingUTF8 bytes: [UInt8]) {
        guard let string = String(validating: bytes, as: UTF8.self) else { return nil }
        self = string
    }
}
