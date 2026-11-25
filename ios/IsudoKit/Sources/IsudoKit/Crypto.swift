import CryptoKit
import Foundation

/// The cryptographic operations the phone performs, apart from signing
/// (see `ApprovalSigner`).
public enum Crypto {
    /// Verifies a raw `r || s` ECDSA P-256 signature over SHA-256 of
    /// `message`, against an uncompressed SEC1 public key. Any malformed
    /// input is simply "not verified".
    public static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard publicKey.count == Proto.pubkeyLength, signature.count == Proto.signatureLength,
              let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// True if the bytes are an uncompressed point on P-256.
    public static func isValidPublicKey(_ publicKey: Data) -> Bool {
        publicKey.count == Proto.pubkeyLength && publicKey.first == 0x04
            && (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil
    }

    public struct EnvelopeError: Error, Equatable, Sendable {}

    /// Opens a request envelope: standard HPKE (RFC 9180) base mode with
    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. The envelope
    /// is the 65-byte encapsulated key followed by the ciphertext of
    /// `host signature || request`. Returns the two parts.
    public static func openEnvelope(
        _ envelope: Data, kemPrivate: P256.KeyAgreement.PrivateKey, pairingID: Data
    ) throws(EnvelopeError) -> (hostSignature: Data, request: Data) {
        guard envelope.count >= Proto.pubkeyLength else { throw EnvelopeError() }
        let encapsulated = envelope.prefix(Proto.pubkeyLength)
        let ciphertext = envelope.dropFirst(Proto.pubkeyLength)
        let plaintext: Data
        do {
            var recipient = try HPKE.Recipient(
                privateKey: kemPrivate,
                ciphersuite: .P256_SHA256_AES_GCM_256,
                info: Messages.envelopeInfo(pairingID: pairingID),
                encapsulatedKey: Data(encapsulated)
            )
            plaintext = try recipient.open(Data(ciphertext))
        } catch {
            throw EnvelopeError()
        }
        guard plaintext.count >= Proto.signatureLength else { throw EnvelopeError() }
        return (Data(plaintext.prefix(Proto.signatureLength)), Data(plaintext.dropFirst(Proto.signatureLength)))
    }

    /// Seals a request the way the host's helper does. Used by tests and
    /// fixtures; the app itself never seals.
    public static func sealEnvelope(
        hostSignature: Data, request: Data, kemPublic: P256.KeyAgreement.PublicKey, pairingID: Data
    ) throws -> Data {
        var sender = try HPKE.Sender(
            recipientKey: kemPublic,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: Messages.envelopeInfo(pairingID: pairingID)
        )
        let ciphertext = try sender.seal(hostSignature + request)
        return sender.encapsulatedKey + ciphertext
    }

    /// The keys that take part in a pairing, in transcript order.
    public struct Parties: Equatable, Sendable {
        public var pairingID: Data
        public var hostPub: Data
        public var phoneSignPub: Data
        public var phoneKemPub: Data

        public init(pairingID: Data, hostPub: Data, phoneSignPub: Data, phoneKemPub: Data) {
            self.pairingID = pairingID
            self.hostPub = hostPub
            self.phoneSignPub = phoneSignPub
            self.phoneKemPub = phoneKemPub
        }

        var transcript: Data { pairingID + hostPub + phoneSignPub + phoneKemPub }
    }

    /// The phone's proof that it read the QR code: HMAC-SHA256 under the
    /// pairing secret over every key in the pairing and the phone's name.
    public static func claimMAC(secret: Data, parties: Parties, phoneName: String) -> Data {
        let message = Messages.pairClaim + parties.transcript + Data(phoneName.utf8)
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
    }

    /// The six-digit code shown on the phone and typed into the host.
    ///
    /// `ackNonce` is the random value in the host's acknowledgement. Because
    /// the host picks it only after receiving the phone's keys, the code
    /// cannot be steered by choosing keys.
    public static func confirmationCode(secret: Data, parties: Parties, ackNonce: Data) -> String {
        let message = Messages.pairCode + parties.transcript + ackNonce
        let tag = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        let number = tag.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) } % 1_000_000
        let digits = String(number)
        return String(repeating: "0", count: 6 - digits.count) + digits
    }
}
