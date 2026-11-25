import CryptoKit
import Foundation

/// Why the phone will not show a request. Mirrors `isudo_phone::Refusal`.
/// None of these become an approval card; at most they are logged.
public enum Refusal: Error, Equatable, Sendable {
    /// The pairing has not been confirmed by its host.
    case notActive
    /// The envelope did not decrypt with this pairing's key.
    case undecryptable
    /// The request is not signed by the paired host.
    case notFromHost
    /// The request does not decode, or is for a different pairing, or does
    /// not match the id it was delivered under.
    case malformed
    /// The request is past its expiry.
    case expired
    /// This request was already shown.
    case alreadySeen
    /// A watch only: the phone's authorisation of it has run out.
    case authorisationExpired
}

public enum PairingError: Error, Equatable, Sendable {
    /// The offer carries a host key that is not a curve point.
    case badOffer
    /// The host accepted an answer, and it was not this phone's: its
    /// acknowledgement is missing or does not cover this phone's keys.
    /// Someone else answered the pairing, or the relay is lying. The person
    /// must not continue on the host.
    case anotherPhoneWasAccepted
    /// The acknowledgement reveals a nonce that the pairing code did not
    /// commit to. Whoever wrote the pairing code is trying to choose the
    /// code this phone shows, which an honest computer never does. The
    /// person must not type anything into any computer.
    case codeWasSteered
    /// The relay says the pairing is active, but the host's signature over
    /// this phone's keys is missing or wrong.
    case notConfirmedByHost
}

/// Where a pairing has got to, from the phone's side. Mirrors
/// `isudo_phone::Progress`.
public enum PairingProgress: Equatable, Sendable {
    /// The host has not yet looked at this phone's answer.
    case waiting
    /// The host accepted this phone's answer. Show the person this code to
    /// type into the host.
    case showCode(String)
    /// The host confirmed the pairing. Requests can now arrive.
    case active
}

/// A request that passed every check and may be shown to the person.
/// Outside of debug fixtures, the only way to obtain one is `Pairing.open`.
public struct Card: Equatable, Sendable, Identifiable {
    public let digest: Data
    public let requestID: Data
    /// When the host stops waiting, by the host's clock, in unix seconds.
    public let expiresAt: UInt64
    public let request: Request

    public var id: Data { requestID }
    public var requestIDHex: String { Codec.hexEncode(requestID) }

    init(digest: Data, requestID: Data, expiresAt: UInt64, request: Request) {
        self.digest = digest
        self.requestID = requestID
        self.expiresAt = expiresAt
        self.request = request
    }

    #if DEBUG
    /// A card for previews and screenshots. It belongs to no pairing, so
    /// nothing can be signed for it.
    public static func fixture(_ request: Request) -> Card {
        let bytes = request.encode()
        return Card(
            digest: Messages.requestDigest(bytes),
            requestID: Messages.requestID(bytes),
            expiresAt: request.issuedAt + UInt64(request.ttlSecs),
            request: request
        )
    }
    #endif
}

/// One pairing, from the phone's point of view. Mirrors
/// `isudo_phone::Pairing`: the same checks, in the same order.
///
/// This value holds no private key material. The signing key is an
/// `ApprovalSigner`, the decryption key and relay token live in a
/// `SecretStore`, and both are passed in where needed.
public struct Pairing: Equatable, Sendable, Codable, Identifiable {
    /// Seconds a request may appear to be past its expiry, to allow for the
    /// host's and phone's clocks disagreeing, before the phone refuses it.
    public static let clockSkewSecs: UInt64 = 30
    /// How many shown request ids are remembered.
    static let maxSeen = 4096

    public let pairingID: Data
    public let hostPub: Data
    public let hostName: String
    public let relayURL: String
    /// The single-use secret from the pairing code. Dropped once the pairing
    /// is active, when nothing needs it any more.
    public private(set) var secret: Data?
    /// The pairing code's commitment to the host's nonce, and the nonce this
    /// phone chose after reading the pairing code. Both are dropped with the
    /// secret.
    public private(set) var commitment: Data?
    public private(set) var phoneNonce: Data?
    public let signPub: Data
    public let kemPub: Data
    /// Whether the signing key is in the Secure Enclave behind biometry.
    public let hardwareBacked: Bool
    /// The host's nonce, once its acknowledgement of this phone's own answer
    /// has been verified. Like the secret, it is dropped when the pairing
    /// becomes active.
    public private(set) var hostNonce: Data?
    public private(set) var active: Bool
    private var seen: Set<Data>

    public var id: Data { pairingID }
    public var idHex: String { Codec.hexEncode(pairingID) }

    enum CodingKeys: String, CodingKey {
        case pairingID, hostPub, hostName, relayURL, secret, commitment, phoneNonce, signPub, kemPub, hardwareBacked
        case hostNonce, active, seen
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        pairingID = try values.decode(Data.self, forKey: .pairingID)
        hostPub = try values.decode(Data.self, forKey: .hostPub)
        hostName = try values.decode(String.self, forKey: .hostName)
        relayURL = try values.decode(String.self, forKey: .relayURL)
        secret = try values.decodeIfPresent(Data.self, forKey: .secret)
        // Absent for an active pairing. Also absent for one left unfinished
        // by a version of the app from before pairing codes carried a
        // commitment; that one can never finish, and `observe` says so.
        commitment = try values.decodeIfPresent(Data.self, forKey: .commitment)
        phoneNonce = try values.decodeIfPresent(Data.self, forKey: .phoneNonce)
        signPub = try values.decode(Data.self, forKey: .signPub)
        kemPub = try values.decode(Data.self, forKey: .kemPub)
        hardwareBacked = try values.decode(Bool.self, forKey: .hardwareBacked)
        active = try values.decode(Bool.self, forKey: .active)
        hostNonce = try values.decodeIfPresent(Data.self, forKey: .hostNonce)
        seen = try values.decode(Set<Data>.self, forKey: .seen)
    }

    /// Starts a pairing from a scanned offer with this pairing's own freshly
    /// generated public keys. Each pairing gets its own keys, so nothing
    /// links a phone's pairings to each other.
    ///
    /// `phoneNonce` must be freshly random, from `Pairing.freshNonce()`. It
    /// has to be chosen now, after the offer was read: the offer's author
    /// has already fixed their own nonce, so this one is what stops them
    /// choosing the code.
    public init(
        offer: PairingOffer, signPub: Data, kemPub: Data, phoneNonce: Data, hardwareBacked: Bool
    ) throws(PairingError) {
        guard Crypto.isValidPublicKey(offer.hostPub), offer.commitment.count == Proto.commitmentLength,
              phoneNonce.count == Proto.phoneNonceLength
        else { throw .badOffer }
        pairingID = offer.pairingID
        hostPub = offer.hostPub
        hostName = offer.hostName
        relayURL = offer.relayURL
        secret = offer.secret
        commitment = offer.commitment
        self.phoneNonce = phoneNonce
        self.signPub = signPub
        self.kemPub = kemPub
        self.hardwareBacked = hardwareBacked
        hostNonce = nil
        active = false
        seen = []
    }

    /// A random nonce for a new pairing.
    public static func freshNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: Proto.phoneNonceLength)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SignerError.keyUnusable
        }
        return Data(bytes)
    }

    private var parties: Crypto.Parties {
        Crypto.Parties(pairingID: pairingID, hostPub: hostPub, phoneSignPub: signPub, phoneKemPub: kemPub)
    }

    /// What to send the relay to answer the pairing, or nil once active.
    public func claim(phoneName: String, token: String, device: API.DeviceUpdate?) -> API.Claim? {
        guard let secret, let phoneNonce else { return nil }
        let mac = Crypto.claimMAC(secret: secret, parties: parties, phoneNonce: phoneNonce, phoneName: phoneName)
        return API.Claim(
            phoneSignPub: Codec.b64Encode(signPub),
            phoneKemPub: Codec.b64Encode(kemPub),
            phoneName: phoneName,
            phoneNonce: Codec.b64Encode(phoneNonce),
            claimMac: Codec.b64Encode(mac),
            phoneToken: token,
            device: device
        )
    }

    /// Whether the host has acknowledged this phone's own keys.
    public var acknowledged: Bool { active || hostNonce != nil }

    /// The six digits to show the person, who types them into the host.
    ///
    /// There is no code until the host has acknowledged, with its signature,
    /// that the answer it accepted is this phone's. That ordering is what
    /// the code's meaning rests on: a phone whose keys were swapped in
    /// transit never gets that signature and so never has a code to show.
    /// The code depends on both nonces: the host's, which the pairing code
    /// committed to before this phone chose its own, and this phone's. So
    /// neither side could have chosen it.
    ///
    /// Also nil once the pairing is active, when the secret and nonces have
    /// been dropped.
    public var code: String? {
        guard let secret, let hostNonce, let phoneNonce else { return nil }
        return Crypto.confirmationCode(secret: secret, parties: parties, hostNonce: hostNonce, phoneNonce: phoneNonce)
    }

    private func hostSigned(_ message: Data, _ encoded: String?) -> Bool {
        guard let encoded, let signature = try? Codec.b64Decode(encoded, count: Proto.signatureLength) else {
            return false
        }
        return Crypto.verify(publicKey: hostPub, message: message, signature: signature)
    }

    /// Advances the pairing from what the relay reports, believing only the
    /// host's signatures.
    ///
    /// - The code is released only on the host's acknowledgement of this
    ///   phone's own keys and nonce, revealing the nonce that the pairing
    ///   code committed to.
    /// - The pairing becomes active only on the host's confirmation of them.
    ///
    /// Throws if the relay reports progress that the host's signatures do
    /// not back up. `anotherPhoneWasAccepted` and `codeWasSteered` in
    /// particular mean the person must not continue on the host.
    public mutating func observe(_ status: API.PairingStatus) throws(PairingError) -> PairingProgress {
        if active { return .active }
        if hostNonce == nil {
            // An unfinished pairing from before pairing codes carried a
            // commitment cannot be finished safely. Start again.
            guard let commitment, let phoneNonce else { throw .badOffer }
            let claimsProgress = status.state == .acknowledged || status.state == .active
            guard let ack = status.ack else {
                if claimsProgress { throw .anotherPhoneWasAccepted }
                return .waiting
            }
            guard let nonce = try? Codec.b64Decode(ack.nonce, count: Proto.hostNonceLength) else {
                throw .anotherPhoneWasAccepted
            }
            let message = Messages.pairAck(
                pairingID: pairingID, phoneSignPub: signPub, phoneKemPub: kemPub, phoneNonce: phoneNonce, hostNonce: nonce
            )
            guard hostSigned(message, ack.hostSig) else { throw .anotherPhoneWasAccepted }
            // The holder of the host key signed for this phone's answer. The
            // nonce must also be the one fixed before this phone answered;
            // otherwise it could have been picked, after seeing this phone's
            // nonce, to make the code come out as wanted.
            guard Crypto.commitment(pairingID: pairingID, hostPub: hostPub, hostNonce: nonce) == commitment else {
                throw .codeWasSteered
            }
            hostNonce = nonce
        }
        if status.state == .active {
            let message = Messages.pairConfirm(pairingID: pairingID, phoneSignPub: signPub, phoneKemPub: kemPub)
            guard hostSigned(message, status.hostSig) else { throw .notConfirmedByHost }
            active = true
            // The single-use secret and nonces have done their job.
            secret = nil
            commitment = nil
            phoneNonce = nil
            hostNonce = nil
            return .active
        }
        guard let code else { throw .anotherPhoneWasAccepted }
        return .showCode(code)
    }

    /// Checks a delivered request and, if everything holds, returns the card
    /// to show. `now` is the phone's clock in unix seconds.
    ///
    /// A card exists only for a request that decrypted under this pairing's
    /// key, is signed by the paired host, decodes strictly, names this
    /// pairing, matches the id it was delivered under, has not expired and
    /// has not been shown before.
    public mutating func open(
        _ delivered: API.PendingRequest, now: UInt64, kemPrivate: P256.KeyAgreement.PrivateKey
    ) throws(Refusal) -> Card {
        guard active else { throw .notActive }
        return try RequestOpener(pairingID: pairingID, hostPub: hostPub)
            .open(delivered, now: now, kemPrivate: kemPrivate, seen: &seen)
    }

    /// Signs an approval of a card. This is the step behind Face ID.
    public func approve(_ card: Card, signer: some ApprovalSigner, prompt: String) async throws -> API.Answer {
        precondition(signer.publicKey == signPub, "signing with a key the host did not pin")
        let signature = try await signer.sign(Messages.approve(digest: card.digest), prompt: prompt)
        return API.Answer(decision: .approve, sig: Codec.b64Encode(signature), reason: nil)
    }

    /// Cuts a reason to the protocol's limit at a character boundary.
    public static func clip(reason: String) -> String {
        var end = reason.utf8.index(reason.utf8.startIndex, offsetBy: Proto.maxReasonLength, limitedBy: reason.utf8.endIndex)
            ?? reason.utf8.endIndex
        // Step back to the start of a scalar, as the reference does.
        while end != reason.utf8.startIndex, end.samePosition(in: reason.unicodeScalars) == nil {
            end = reason.utf8.index(before: end)
        }
        return String(reason[..<end])
    }

    /// Signs a denial of a card, with an optional reason for the caller.
    public func deny(_ card: Card, reason: String, signer: some ApprovalSigner, prompt: String) async throws -> API.Answer {
        precondition(signer.publicKey == signPub, "signing with a key the host did not pin")
        let reason = Self.clip(reason: reason)
        let signature = try await signer.sign(Messages.deny(digest: card.digest, reason: Data(reason.utf8)), prompt: prompt)
        return API.Answer(decision: .deny, sig: Codec.b64Encode(signature), reason: reason.isEmpty ? nil : reason)
    }
}

/// The per-pairing secrets that are not the signing key.
public enum PairingSecrets {
    static func kemAccount(_ idHex: String) -> String { idHex + ".kem" }
    static func tokenAccount(_ idHex: String) -> String { idHex + ".token" }

    /// Generates and stores the decryption key and relay token for a new
    /// pairing. Returns the public decryption key and the token.
    public static func create(pairingIDHex: String, in store: some SecretStore) throws -> (kemPub: Data, token: String) {
        let kem = P256.KeyAgreement.PrivateKey()
        var tokenBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, tokenBytes.count, &tokenBytes) == errSecSuccess else {
            throw SignerError.keyUnusable
        }
        let token = Codec.b64Encode(tokenBytes)
        try store.write(kemAccount(pairingIDHex), kem.rawRepresentation)
        try store.write(tokenAccount(pairingIDHex), Data(token.utf8))
        return (kem.publicKey.x963Representation, token)
    }

    public static func kemPrivate(pairingIDHex: String, from store: some SecretStore) throws -> P256.KeyAgreement.PrivateKey {
        guard let raw = try store.read(kemAccount(pairingIDHex)) else { throw SignerError.keyUnusable }
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
    }

    public static func token(pairingIDHex: String, from store: some SecretStore) throws -> String {
        guard let raw = try store.read(tokenAccount(pairingIDHex)) else { throw SignerError.keyUnusable }
        return String(decoding: raw, as: UTF8.self)
    }

    public static func delete(pairingIDHex: String, from store: some SecretStore) {
        for account in [kemAccount(pairingIDHex), tokenAccount(pairingIDHex), Signers.account(pairingIDHex)] {
            try? store.delete(account)
        }
    }
}
