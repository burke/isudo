import CryptoKit
import Foundation

/// The exact byte strings that get signed. Mirrors `isudo_proto::sigs`.
///
/// Every signature is ECDSA P-256 over SHA-256 of one of these messages,
/// encoded as raw `r || s`. Each message starts with a distinct
/// NUL-terminated context string, so a signature made for one purpose can
/// never be presented for another.
public enum Messages {
    static func context(_ name: String) -> Data { Data(name.utf8) + [0] }

    static let request = context("isudo/v1/request")
    static let approve = context("isudo/v1/approve")
    static let deny = context("isudo/v1/deny")
    static let pairAck = context("isudo/v1/pair-ack")
    static let pairConfirm = context("isudo/v1/pair-confirm")
    static let envelope = context("isudo/v1/envelope")
    static let pairClaim = context("isudo/v1/pair-claim")
    static let pairCode = context("isudo/v1/pair-code")

    /// SHA-256 of the encoded request. The phone's approval covers this.
    public static func requestDigest(_ request: Data) -> Data {
        Data(SHA256.hash(data: request))
    }

    /// Public handle for a request: the first half of its digest.
    public static func requestID(_ request: Data) -> Data {
        requestDigest(request).prefix(Proto.requestIDLength)
    }

    /// Signed by the host key over the request it built.
    public static func hostRequest(_ request: Data) -> Data {
        Self.request + request
    }

    /// Signed by the phone key, behind Face ID. This is the approval.
    public static func approve(digest: Data) -> Data {
        approve + digest
    }

    /// Signed by the phone key. The reason is covered, so the relay cannot
    /// put words in the approver's mouth.
    public static func deny(digest: Data, reason: Data) -> Data {
        deny + digest + reason
    }

    /// Signed by the host key as soon as it accepts a phone's answer, before
    /// anyone types a code. It names the phone keys the host accepted, and
    /// carries a random nonce the host chose only after it had those keys.
    /// The phone shows its code only once it holds this signature over its
    /// own keys, and derives the code from the nonce, so the code can be
    /// neither obtained by a phone whose keys were swapped on the way nor
    /// searched for by choosing keys.
    public static func pairAck(pairingID: Data, phoneSignPub: Data, phoneKemPub: Data, nonce: Data) -> Data {
        pairAck + pairingID + phoneSignPub + phoneKemPub + nonce
    }

    /// Signed by the host key once the operator has confirmed the code.
    public static func pairConfirm(pairingID: Data, phoneSignPub: Data, phoneKemPub: Data) -> Data {
        pairConfirm + pairingID + phoneSignPub + phoneKemPub
    }

    /// HPKE `info` for a request sealed to a pairing's phone.
    public static func envelopeInfo(pairingID: Data) -> Data {
        envelope + pairingID
    }
}
