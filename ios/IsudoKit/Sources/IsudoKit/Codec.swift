import Foundation

/// Hex and unpadded base64url, both strict: anything the encoder could not
/// have produced is rejected. Mirrors `isudo_proto::codec`.
public enum Codec {
    public struct DecodeError: Error, Equatable, Sendable {
        public let reason: String
    }

    private static let hexDigits = Array("0123456789abcdef".utf8)

    public static func hexEncode(_ bytes: some Sequence<UInt8>) -> String {
        var out = [UInt8]()
        for byte in bytes {
            out.append(hexDigits[Int(byte >> 4)])
            out.append(hexDigits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    private static func hexValue(_ digit: UInt8) -> UInt8? {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): digit - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): digit - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): digit - UInt8(ascii: "A") + 10
        default: nil
        }
    }

    public static func hexDecode(_ text: String) throws(DecodeError) -> Data {
        let digits = Array(text.utf8)
        guard digits.count.isMultiple(of: 2) else { throw DecodeError(reason: "hex string has odd length") }
        var out = Data(capacity: digits.count / 2)
        var index = 0
        while index < digits.count {
            guard let high = hexValue(digits[index]), let low = hexValue(digits[index + 1]) else {
                throw DecodeError(reason: "invalid hex digit")
            }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    public static func hexDecode(_ text: String, count: Int) throws(DecodeError) -> Data {
        let data = try hexDecode(text)
        guard data.count == count else { throw DecodeError(reason: "hex value has the wrong length") }
        return data
    }

    private static func b64Char(_ sextet: UInt8) -> UInt8 {
        switch sextet {
        case 0...25: UInt8(ascii: "A") + sextet
        case 26...51: UInt8(ascii: "a") + sextet - 26
        case 52...61: UInt8(ascii: "0") + sextet - 52
        case 62: UInt8(ascii: "-")
        default: UInt8(ascii: "_")
        }
    }

    private static func b64Value(_ char: UInt8) throws(DecodeError) -> UInt8 {
        switch char {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): char - UInt8(ascii: "A")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): char - UInt8(ascii: "a") + 26
        case UInt8(ascii: "0")...UInt8(ascii: "9"): char - UInt8(ascii: "0") + 52
        case UInt8(ascii: "-"): 62
        case UInt8(ascii: "_"): 63
        default: throw DecodeError(reason: "invalid base64url character")
        }
    }

    /// Unpadded base64url (RFC 4648 section 5).
    public static func b64Encode(_ data: some Sequence<UInt8>) -> String {
        let bytes = Array(data)
        var out = [UInt8]()
        var index = 0
        while index < bytes.count {
            let b0 = bytes[index]
            let b1 = index + 1 < bytes.count ? bytes[index + 1] : 0
            let b2 = index + 2 < bytes.count ? bytes[index + 2] : 0
            let group = [b0 >> 2, (b0 & 0x03) << 4 | b1 >> 4, (b1 & 0x0f) << 2 | b2 >> 6, b2 & 0x3f]
            let sextets = min(bytes.count - index, 3) + 1
            out.append(contentsOf: group.prefix(sextets).map(b64Char))
            index += 3
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Strict unpadded base64url: rejects padding, other alphabets, and
    /// non-canonical trailing bits.
    public static func b64Decode(_ text: String) throws(DecodeError) -> Data {
        let chars = Array(text.utf8)
        let nonCanonical = DecodeError(reason: "non-canonical base64url")
        var out = Data(capacity: chars.count * 3 / 4)
        var index = 0
        while index < chars.count {
            let remaining = chars.count - index
            switch remaining {
            case 4...:
                let (v0, v1) = (try b64Value(chars[index]), try b64Value(chars[index + 1]))
                let (v2, v3) = (try b64Value(chars[index + 2]), try b64Value(chars[index + 3]))
                out.append(contentsOf: [v0 << 2 | v1 >> 4, (v1 & 0x0f) << 4 | v2 >> 2, (v2 & 0x03) << 6 | v3])
            case 3:
                let (v0, v1) = (try b64Value(chars[index]), try b64Value(chars[index + 1]))
                let v2 = try b64Value(chars[index + 2])
                guard v2 & 0x03 == 0 else { throw nonCanonical }
                out.append(contentsOf: [v0 << 2 | v1 >> 4, (v1 & 0x0f) << 4 | v2 >> 2])
            case 2:
                let (v0, v1) = (try b64Value(chars[index]), try b64Value(chars[index + 1]))
                guard v1 & 0x0f == 0 else { throw nonCanonical }
                out.append(v0 << 2 | v1 >> 4)
            default:
                throw DecodeError(reason: "invalid base64url length")
            }
            index += 4
        }
        return out
    }

    public static func b64Decode(_ text: String, count: Int) throws(DecodeError) -> Data {
        let data = try b64Decode(text)
        guard data.count == count else { throw DecodeError(reason: "base64url value has the wrong length") }
        return data
    }
}
