import CryptoKit
import Foundation

/// The phone's authorisation of a second device, a watch. Mirrors
/// `isudo_proto::delegation`.
///
/// The computer pins one key: the phone's. A watch has keys of its own, made
/// on the watch and never moved. The phone signs a `Delegation` naming those
/// keys, and the watch's answers travel with it. The computer checks both
/// signatures, in a chain that starts at the key it already holds.
///
/// A watch is deliberately the lesser approver. It cannot check a face, so
/// "present" means unlocked and still on the wrist that unlocked it. And its
/// screen is small. So it may approve only a request that is simple enough
/// to read there in full with nothing that needs explaining, and only if
/// root on the computer has allowed a watch at all. It may deny anything.
public struct Delegation: Equatable, Sendable {
    public static let context = Messages.context("isudo/v1/delegate")
    /// Longest name a watch may carry, in bytes of UTF-8.
    public static let maxNameLength = 64
    /// Longest a delegation may run: about three months. The computer cannot
    /// see when one was issued, only when it ends, so this limit is the
    /// phone's to keep.
    public static let maxLifetimeSecs: UInt64 = 90 * 24 * 60 * 60

    public var pairingID: Data
    /// The watch's signing key, whose signatures count as answers.
    public var signPub: Data
    /// The watch's decryption key, to which requests are also sealed.
    public var kemPub: Data
    /// Unix time after which the computer no longer honours this.
    public var notAfter: UInt64
    /// What the watch is called, for messages.
    public var name: String

    public init(pairingID: Data, signPub: Data, kemPub: Data, notAfter: UInt64, name: String) {
        self.pairingID = pairingID
        self.signPub = signPub
        self.kemPub = kemPub
        self.notAfter = notAfter
        self.name = name
    }

    /// A name that reads the way it is written: some text, no longer than
    /// the limit, no surrounding space, no control characters.
    public static func isValid(name: String) -> Bool {
        let bytes = name.utf8.count
        return bytes > 0 && bytes <= maxNameLength
            && name.trimmingWhitespace.unicodeScalars.elementsEqual(name.unicodeScalars)
            && !name.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }

    private var isWellFormed: Bool {
        pairingID.count == Proto.pairingIDLength && signPub.count == Proto.pubkeyLength
            && kemPub.count == Proto.pubkeyLength && Self.isValid(name: name)
    }

    /// The one encoding of this delegation, or nil if it is not well formed.
    var body: Data? {
        guard isWellFormed else { return nil }
        var out = pairingID + signPub + kemPub
        withUnsafeBytes(of: notAfter.bigEndian) { out.append(contentsOf: $0) }
        let name = Data(name.utf8)
        withUnsafeBytes(of: UInt32(name.count).bigEndian) { out.append(contentsOf: $0) }
        return out + name
    }

    /// The exact bytes the phone signs: the context, then the encoding.
    public var message: Data? {
        body.map { Self.context + $0 }
    }
}

/// A delegation and the phone's signature over it.
public struct SignedDelegation: Equatable, Sendable {
    public var delegation: Delegation
    public var phoneSignature: Data

    public init(delegation: Delegation, phoneSignature: Data) {
        self.delegation = delegation
        self.phoneSignature = phoneSignature
    }

    public static let maxLength = Proto.pairingIDLength + 2 * Proto.pubkeyLength + 8 + 4
        + Delegation.maxNameLength + Proto.signatureLength

    public func encode() -> Data? {
        guard phoneSignature.count == Proto.signatureLength, let body = delegation.body else { return nil }
        return body + phoneSignature
    }

    /// Strict: anything `encode` could not have produced is an error.
    public static func decode(_ input: Data) throws(WireError) -> SignedDelegation {
        guard input.count <= maxLength else { throw .tooLarge("delegation") }
        var r = Reader(input)
        let pairingID = try r.take(Proto.pairingIDLength, "pairing id")
        let signPub = try r.take(Proto.pubkeyLength, "delegate signing key")
        let kemPub = try r.take(Proto.pubkeyLength, "delegate decryption key")
        let notAfter = try r.u64("delegation expiry")
        let nameBytes = try r.bytes("delegate name")
        guard let name = String(validating: Array(nameBytes), as: UTF8.self), Delegation.isValid(name: name) else {
            throw .invalid("delegate name")
        }
        let signature = try r.take(Proto.signatureLength, "delegation signature")
        try r.finish()
        let delegation = Delegation(pairingID: pairingID, signPub: signPub, kemPub: kemPub, notAfter: notAfter, name: name)
        return SignedDelegation(delegation: delegation, phoneSignature: signature)
    }

    /// Whether `phoneSignPub` signed this delegation.
    public func isSigned(by phoneSignPub: Data) -> Bool {
        guard let message = delegation.message else { return false }
        return Crypto.verify(publicKey: phoneSignPub, message: message, signature: phoneSignature)
    }
}

extension Request {
    /// The computer will accept a watch's approval of this request: root has
    /// allowed a watch there, and the computer found the request simple
    /// enough. Set by the computer, inside the request it signed.
    public static let flagDelegable: UInt8 = 0x02

    public var isMarkedForWatch: Bool { flags & Self.flagDelegable != 0 }

    public static let maxSimpleArgs = 12
    public static let maxSimpleArgBytes = 240
    public static let maxSimplePathLength = 128

    /// Printable ASCII, and at least one byte of it. Nothing that needs
    /// escaping, nothing invisible, nothing laid out right to left, nothing
    /// that looks like another character.
    ///
    /// No backslash either: it is the one printable character that is not
    /// shown as it is (display doubles it, so that an escape can never be
    /// mistaken for text).
    private static func isPlain(_ bytes: Data) -> Bool {
        !bytes.isEmpty && bytes.allSatisfy { (0x20...0x7e).contains($0) && $0 != UInt8(ascii: "\\") }
    }

    /// True if this request can be read in full on a small screen with
    /// nothing that needs explaining. Mirrors
    /// `isudo_proto::delegation::simple_enough`, and is checked against it.
    ///
    /// - Nothing the phone would warn about: the program cannot be replaced
    ///   without root, input is not arriving unseen, and the caller named no
    ///   environment variables.
    /// - Every piece of text is plain printable ASCII.
    /// - It is short.
    public var isSimpleEnough: Bool {
        let quiet = !exeIsWritableByNonRoot && (stdin == .terminal || stdin == .null)
            && env.allSatisfy { $0.origin != .explicit }
        let readable = Self.isPlain(exe) && Self.isPlain(cwd) && Self.isPlain(host)
            && (user.isEmpty || Self.isPlain(user)) && argv.allSatisfy(Self.isPlain)
        let short = !argv.isEmpty && argv.count <= Self.maxSimpleArgs
            && argv.reduce(0) { $0 + $1.count } <= Self.maxSimpleArgBytes
            && exe.count <= Self.maxSimplePathLength && cwd.count <= Self.maxSimplePathLength
        return quiet && readable && short
    }

    /// Whether a watch may offer to approve this. Both must hold: the
    /// computer said it would honour a watch here, and the request is simple
    /// enough by this device's own reading of the same rule.
    public var watchMayApprove: Bool { isMarkedForWatch && isSimpleEnough }
}

extension Pairing {
    /// Signs an authorisation of a watch's keys for this pairing. Like an
    /// approval, this is the phone's key at work, so it is behind Face ID.
    ///
    /// The keys come from the person's own watch over the link between a
    /// phone and its watch. `validFor` is cut to the longest a delegation
    /// may run.
    public func delegate(
        watchSignPub: Data, watchKemPub: Data, name: String, now: UInt64, validFor: UInt64 = Delegation.maxLifetimeSecs,
        signer: some ApprovalSigner, prompt: String
    ) async throws -> SignedDelegation {
        precondition(signer.publicKey == signPub, "signing with a key the host did not pin")
        let lifetime = min(validFor, Delegation.maxLifetimeSecs)
        let (notAfter, overflow) = now.addingReportingOverflow(lifetime)
        let delegation = Delegation(
            pairingID: pairingID, signPub: watchSignPub, kemPub: watchKemPub, notAfter: overflow ? UInt64.max : notAfter,
            name: name
        )
        guard active, Crypto.isValidPublicKey(watchSignPub), Crypto.isValidPublicKey(watchKemPub),
              let message = delegation.message
        else { throw SignerError.keyUnusable }
        return SignedDelegation(delegation: delegation, phoneSignature: try await signer.sign(message, prompt: prompt))
    }
}

/// One pairing, from the watch's point of view: the second, lesser approver.
/// Mirrors `isudo_phone::Delegate`.
///
/// It makes every check the phone makes before showing a request. It can
/// answer only while it holds the phone's current authorisation of its own
/// keys. This value holds no private key material.
public struct WatchPairing: Equatable, Sendable, Codable, Identifiable {
    public let pairingID: Data
    public let hostPub: Data
    public let hostName: String
    public let relayURL: String
    public let signPub: Data
    public let kemPub: Data
    /// The phone's authorisation of these keys, encoded, once received.
    public private(set) var delegation: Data?
    private var seen: Set<Data>

    public var id: Data { pairingID }
    public var idHex: String { Codec.hexEncode(pairingID) }

    public init(pairingID: Data, hostPub: Data, hostName: String, relayURL: String, signPub: Data, kemPub: Data) throws(PairingError) {
        guard Crypto.isValidPublicKey(hostPub), pairingID.count == Proto.pairingIDLength else { throw .badOffer }
        self.pairingID = pairingID
        self.hostPub = hostPub
        self.hostName = hostName
        self.relayURL = relayURL
        self.signPub = signPub
        self.kemPub = kemPub
        delegation = nil
        seen = []
    }

    /// The authorisation, decoded.
    public var signedDelegation: SignedDelegation? {
        delegation.flatMap { try? SignedDelegation.decode($0) }
    }

    /// When the authorisation runs out, in unix seconds.
    public var authorisedUntil: UInt64? { signedDelegation?.delegation.notAfter }

    /// Takes the phone's authorisation, if it is for this watch's own keys
    /// and this pairing. Returns whether it was taken.
    ///
    /// The phone's signature is not checked here. A watch gets this from its
    /// own phone and gains nothing from a forged one: the computer checks
    /// the signature against the key it pinned.
    public mutating func accept(_ signed: SignedDelegation) -> Bool {
        let ours = signed.delegation.pairingID == pairingID && signed.delegation.signPub == signPub
            && signed.delegation.kemPub == kemPub
        guard ours, let encoded = signed.encode() else { return false }
        delegation = encoded
        return true
    }

    /// Checks a delivered request exactly as the phone does and returns the
    /// card to show. Without a current authorisation, nothing is shown.
    public mutating func open(
        _ delivered: API.PendingRequest, now: UInt64, kemPrivate: P256.KeyAgreement.PrivateKey
    ) throws(Refusal) -> Card {
        guard let until = authorisedUntil else { throw .notActive }
        guard now <= until else { throw .authorisationExpired }
        return try RequestOpener(pairingID: pairingID, hostPub: hostPub)
            .open(delivered, now: now, kemPrivate: kemPrivate, seen: &seen)
    }

    /// Signs an approval, if this watch may approve the card.
    public func approve(_ card: Card, signer: some ApprovalSigner, prompt: String) async throws -> API.Answer? {
        guard card.request.watchMayApprove else { return nil }
        precondition(signer.publicKey == signPub, "signing with a key the phone did not authorise")
        let signature = try await signer.sign(Messages.approve(digest: card.digest), prompt: prompt)
        return API.Answer(decision: .approve, sig: Codec.b64Encode(signature), reason: nil)
    }

    /// Signs a denial. A watch may deny anything.
    public func deny(_ card: Card, reason: String, signer: some ApprovalSigner, prompt: String) async throws -> API.Answer {
        precondition(signer.publicKey == signPub, "signing with a key the phone did not authorise")
        let reason = Pairing.clip(reason: reason)
        let signature = try await signer.sign(Messages.deny(digest: card.digest, reason: Data(reason.utf8)), prompt: prompt)
        return API.Answer(decision: .deny, sig: Codec.b64Encode(signature), reason: reason.isEmpty ? nil : reason)
    }
}

/// The checks every approving device makes, in this order, before a request
/// may be shown.
struct RequestOpener {
    let pairingID: Data
    let hostPub: Data

    func open(
        _ delivered: API.PendingRequest, now: UInt64, kemPrivate: P256.KeyAgreement.PrivateKey, seen: inout Set<Data>
    ) throws(Refusal) -> Card {
        guard let sealed = try? Codec.b64Decode(delivered.envelope),
              let (hostSignature, bytes) = try? Crypto.openEnvelope(sealed, kemPrivate: kemPrivate, pairingID: pairingID)
        else { throw .undecryptable }
        guard Crypto.verify(publicKey: hostPub, message: Messages.hostRequest(bytes), signature: hostSignature) else {
            throw .notFromHost
        }
        guard let request = try? Request.decode(bytes) else { throw .malformed }
        let requestID = Messages.requestID(bytes)
        guard request.pairingID == pairingID,
              (try? Codec.hexDecode(delivered.requestID, count: Proto.requestIDLength)) == requestID
        else { throw .malformed }
        let (sum, overflow) = request.issuedAt.addingReportingOverflow(UInt64(request.ttlSecs))
        let expiresAt = overflow ? UInt64.max : sum
        let (limit, limitOverflow) = expiresAt.addingReportingOverflow(Pairing.clockSkewSecs)
        guard now <= (limitOverflow ? UInt64.max : limit) else { throw .expired }
        guard seen.insert(requestID).inserted else { throw .alreadySeen }
        while seen.count > Pairing.maxSeen {
            // Forget the smallest id, as the reference implementation does.
            if let smallest = seen.min(by: { $0.lexicographicallyPrecedes($1) }) {
                seen.remove(smallest)
            }
        }
        return Card(digest: Messages.requestDigest(bytes), requestID: requestID, expiresAt: expiresAt, request: request)
    }
}
