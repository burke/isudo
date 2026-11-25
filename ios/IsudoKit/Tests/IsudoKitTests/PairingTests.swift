import CryptoKit
import Foundation
import Testing

@testable import IsudoKit

/// The same cases as `crates/phone/src/tests.rs`, against this implementation.
@Suite struct PairingTests {
    let host = P256.Signing.PrivateKey()
    let store = MemorySecretStore()
    let now: UInt64 = 1_795_000_010

    var offer: PairingOffer {
        PairingOffer(
            relayURL: "https://relay.example",
            pairingID: Data(repeating: 0xa1, count: 16),
            hostPub: host.publicKey.x963Representation,
            secret: Data(repeating: 0x3c, count: 32),
            hostName: "burke-mbp"
        )
    }

    struct Phone {
        var pairing: Pairing
        let signer: SoftwareSigner
        let kem: P256.KeyAgreement.PrivateKey
        let token: String
    }

    func begin(_ tag: String = "a") throws -> Phone {
        let offer = offer
        let signer = try SoftwareSigner.create(account: tag + ".sign", in: store, authenticate: false)
        let (kemPub, token) = try PairingSecrets.create(pairingIDHex: tag, in: store)
        let pairing = try Pairing(offer: offer, signPub: signer.publicKey, kemPub: kemPub, hardwareBacked: false)
        return Phone(pairing: pairing, signer: signer, kem: try PairingSecrets.kemPrivate(pairingIDHex: tag, from: store), token: token)
    }

    func sign(_ key: P256.Signing.PrivateKey, _ message: Data) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }

    let ackNonce = Data(repeating: 0x4e, count: Proto.ackNonceLength)

    func ack(by key: P256.Signing.PrivateKey, _ pairing: Pairing, nonce: Data? = nil) throws -> API.Ack {
        let nonce = nonce ?? ackNonce
        let message = Messages.pairAck(
            pairingID: pairing.pairingID, phoneSignPub: pairing.signPub, phoneKemPub: pairing.kemPub, nonce: nonce
        )
        return API.Ack(nonce: Codec.b64Encode(nonce), hostSig: Codec.b64Encode(try sign(key, message)))
    }

    func acknowledged(by key: P256.Signing.PrivateKey, _ pairing: Pairing) throws -> API.PairingStatus {
        API.PairingStatus(state: .acknowledged, ack: try ack(by: key, pairing), hostSig: nil)
    }

    /// Active, with a genuine acknowledgement and a confirmation by `key`.
    func confirmed(by key: P256.Signing.PrivateKey, _ pairing: Pairing) throws -> API.PairingStatus {
        let message = Messages.pairConfirm(pairingID: pairing.pairingID, phoneSignPub: pairing.signPub, phoneKemPub: pairing.kemPub)
        return API.PairingStatus(
            state: .active, ack: try ack(by: host, pairing), hostSig: Codec.b64Encode(try sign(key, message))
        )
    }

    func active(_ tag: String = "a") throws -> Phone {
        var phone = try begin(tag)
        #expect(try phone.pairing.observe(try confirmed(by: host, phone.pairing)) == .active)
        return phone
    }

    func request(_ nonce: UInt8) -> Request {
        Request(
            nonce: Data(repeating: nonce, count: 32), pairingID: offer.pairingID, issuedAt: 1_795_000_000,
            ttlSecs: 120, uid: 501, gid: 20, user: Data("burke".utf8), host: Data("burke-mbp".utf8),
            cwd: Data("/tmp".utf8), exe: Data("/bin/rm".utf8), flags: 0, stdin: .terminal,
            argv: ["rm", "-rf", "/var/tmp/build"].map { Data($0.utf8) },
            env: [.init(origin: .default, name: Data("TERM".utf8), value: Data("xterm".utf8))], ancestry: []
        )
    }

    /// What the helper would deliver for `request`, signed by `signer`.
    func deliver(_ phone: Phone, _ request: Request, signedBy signer: P256.Signing.PrivateKey, sealedFor pairingID: Data? = nil) throws -> API.PendingRequest {
        let bytes = request.encode()
        let hostSig = try sign(signer, Messages.hostRequest(bytes))
        let sealed = try Crypto.sealEnvelope(
            hostSignature: hostSig, request: bytes, kemPublic: phone.kem.publicKey,
            pairingID: pairingID ?? phone.pairing.pairingID
        )
        return API.PendingRequest(
            requestID: Codec.hexEncode(Messages.requestID(bytes)),
            expiresAt: request.issuedAt + UInt64(request.ttlSecs),
            envelope: Codec.b64Encode(sealed)
        )
    }

    func verifies(_ phone: Phone, _ message: Data, _ answer: API.Answer) throws -> Bool {
        Crypto.verify(publicKey: phone.pairing.signPub, message: message, signature: try Codec.b64Decode(answer.sig))
    }

    @Test func theClaimProvesKnowledgeOfTheSecret() throws {
        let phone = try begin()
        let claim = try #require(phone.pairing.claim(phoneName: "Burke's iPhone", token: phone.token, device: nil))
        let parties = Crypto.Parties(
            pairingID: offer.pairingID, hostPub: offer.hostPub, phoneSignPub: phone.pairing.signPub, phoneKemPub: phone.pairing.kemPub
        )
        #expect(try Codec.b64Decode(claim.claimMac) == Crypto.claimMAC(secret: offer.secret, parties: parties, phoneName: "Burke's iPhone"))
        #expect(claim.phoneToken == phone.token)
        #expect(try Codec.b64Decode(claim.phoneToken).count == 32)
    }

    @Test func eachPairingHasItsOwnKeys() throws {
        let (first, second) = (try begin("a"), try begin("b"))
        #expect(first.pairing.signPub != second.pairing.signPub)
        #expect(first.pairing.kemPub != second.pairing.kemPub)
        #expect(first.token != second.token)
    }

    @Test func aBadHostKeyIsRefusedAtTheStart() throws {
        var bad = offer
        bad.hostPub = Data([0x04]) + Data(repeating: 0x11, count: 64)
        #expect(throws: PairingError.badOffer) {
            try Pairing(offer: bad, signPub: Data(count: 65), kemPub: Data(count: 65), hardwareBacked: false)
        }
    }

    @Test func theCodeAppearsOnlyAfterTheHostAcknowledgesTheseKeys() throws {
        var phone = try begin()
        #expect(phone.pairing.code == nil, "no code straight after scanning")

        // Nothing from the host yet.
        #expect(try phone.pairing.observe(API.PairingStatus(state: .pending, ack: nil, hostSig: nil)) == .waiting)
        #expect(try phone.pairing.observe(API.PairingStatus(state: .claimed, ack: nil, hostSig: nil)) == .waiting)
        #expect(phone.pairing.code == nil)

        func refused(_ status: API.PairingStatus, _ what: Comment) {
            #expect(throws: PairingError.anotherPhoneWasAccepted, what) { try phone.pairing.observe(status) }
        }
        let genuine = try ack(by: host, phone.pairing)

        // The relay says the host acknowledged, with nothing to show for it.
        refused(API.PairingStatus(state: .acknowledged, ack: nil, hostSig: nil), "bare acknowledged")
        // ...or says the pairing is already active, likewise.
        refused(API.PairingStatus(state: .active, ack: nil, hostSig: nil), "bare active")
        // ...or with an acknowledgement signed by some other key (a forgery).
        refused(try acknowledged(by: P256.Signing.PrivateKey(), phone.pairing), "forged")
        // ...or with a malformed signature or nonce.
        refused(API.PairingStatus(state: .claimed, ack: API.Ack(nonce: genuine.nonce, hostSig: "AAAA"), hostSig: nil), "bad signature")
        refused(API.PairingStatus(state: .acknowledged, ack: API.Ack(nonce: "not base64!", hostSig: genuine.hostSig), hostSig: nil), "bad nonce")
        let short = Codec.b64Encode(Data(repeating: 0x4e, count: 15))
        refused(API.PairingStatus(state: .acknowledged, ack: API.Ack(nonce: short, hostSig: genuine.hostSig), hostSig: nil), "short nonce")
        // ...or with the host's genuine acknowledgement of a different phone,
        // which is what this phone sees if its keys were swapped on the way.
        refused(try acknowledged(by: host, try begin("stranger").pairing), "other phone's ack")
        // ...or a confirmation presented as an acknowledgement.
        let confirm = Messages.pairConfirm(
            pairingID: phone.pairing.pairingID, phoneSignPub: phone.pairing.signPub, phoneKemPub: phone.pairing.kemPub
        )
        let crossed = API.Ack(nonce: genuine.nonce, hostSig: Codec.b64Encode(try sign(host, confirm)))
        refused(API.PairingStatus(state: .acknowledged, ack: crossed, hostSig: nil), "confirm as ack")
        // ...or the genuine acknowledgement with its nonce changed, which
        // would otherwise let the relay choose the code.
        let renonced = API.Ack(nonce: Codec.b64Encode(Data(repeating: 0x4f, count: 16)), hostSig: genuine.hostSig)
        refused(API.PairingStatus(state: .acknowledged, ack: renonced, hostSig: nil), "changed nonce")
        #expect(phone.pairing.code == nil, "none of that released a code")
        #expect(!phone.pairing.acknowledged)

        // The real thing.
        let parties = Crypto.Parties(
            pairingID: offer.pairingID, hostPub: offer.hostPub, phoneSignPub: phone.pairing.signPub, phoneKemPub: phone.pairing.kemPub
        )
        let expected = Crypto.confirmationCode(secret: offer.secret, parties: parties, ackNonce: ackNonce)
        #expect(try phone.pairing.observe(try acknowledged(by: host, phone.pairing)) == .showCode(expected))
        #expect(phone.pairing.code == expected)
        #expect(phone.pairing.ackNonce == ackNonce)
        #expect(!phone.pairing.active, "acknowledged is not yet paired")
        // The code depends on the nonce: a different one gives a different code.
        let other = Crypto.confirmationCode(secret: offer.secret, parties: parties, ackNonce: Data(repeating: 0x4f, count: 16))
        #expect(other != expected)
        // Once acknowledged, the nonce is fixed: later statuses, with no
        // acknowledgement or a different genuine one, do not change the code.
        #expect(try phone.pairing.observe(API.PairingStatus(state: .acknowledged, ack: nil, hostSig: nil)) == .showCode(expected))
        let second = try ack(by: host, phone.pairing, nonce: Data(repeating: 0x4f, count: 16))
        #expect(try phone.pairing.observe(API.PairingStatus(state: .acknowledged, ack: second, hostSig: nil)) == .showCode(expected))
        // And the acknowledged state survives being stored and loaded.
        let restored = try JSONDecoder().decode(Pairing.self, from: JSONEncoder().encode(phone.pairing))
        #expect(restored.code == expected)
    }

    @Test func onlyTheHostsConfirmationActivatesAPairing() throws {
        var phone = try begin()
        let ack = try ack(by: host, phone.pairing)

        // The relay claims the pairing is active, with no confirmation.
        #expect(throws: PairingError.notConfirmedByHost) {
            try phone.pairing.observe(API.PairingStatus(state: .active, ack: ack, hostSig: nil))
        }
        // ...or with a confirmation by some other key.
        let other = try confirmed(by: P256.Signing.PrivateKey(), phone.pairing)
        #expect(throws: PairingError.notConfirmedByHost) { try phone.pairing.observe(other) }
        // ...or with the acknowledgement replayed as the confirmation.
        #expect(throws: PairingError.notConfirmedByHost) {
            try phone.pairing.observe(API.PairingStatus(state: .active, ack: ack, hostSig: ack.hostSig))
        }
        // ...or with the host's confirmation of someone else's keys.
        var stranger = try confirmed(by: host, try begin("stranger").pairing)
        stranger.ack = ack
        #expect(throws: PairingError.notConfirmedByHost) { try phone.pairing.observe(stranger) }
        #expect(!phone.pairing.active)
        #expect(phone.pairing.code != nil, "still showing the code")

        #expect(try phone.pairing.observe(try confirmed(by: host, phone.pairing)) == .active)
        #expect(phone.pairing.active)
        // The single-use secret and nonce are gone once they have done their job.
        #expect(phone.pairing.secret == nil)
        #expect(phone.pairing.ackNonce == nil)
        #expect(phone.pairing.code == nil)
        #expect(phone.pairing.acknowledged)
        #expect(phone.pairing.claim(phoneName: "x", token: "y", device: nil) == nil)
        let stored = String(decoding: try JSONEncoder().encode(phone.pairing), as: UTF8.self)
        #expect(!stored.contains("ackNonce") && !stored.contains("secret"), "nothing single-use is kept on disk")
        // An active pairing stays active whatever the relay says next.
        #expect(try phone.pairing.observe(API.PairingStatus(state: .pending, ack: nil, hostSig: nil)) == .active)
    }

    @Test func pairingsStoredInOlderFormsStillLoad() throws {
        // An active pairing stored when there was an `acknowledged` flag and no nonce.
        let phone = try active()
        var stored = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(phone.pairing)) as? [String: Any])
        stored["acknowledged"] = true
        let restored = try JSONDecoder().decode(Pairing.self, from: JSONSerialization.data(withJSONObject: stored))
        #expect(restored.active && restored.acknowledged)
        #expect(restored == phone.pairing)
    }

    @Test func aGenuineRequestBecomesACard() throws {
        var phone = try active()
        let delivered = try deliver(phone, request(1), signedBy: host)
        let card = try phone.pairing.open(delivered, now: now, kemPrivate: phone.kem)
        #expect(card.request == request(1))
        #expect(card.requestIDHex == delivered.requestID)
        #expect(card.expiresAt == 1_795_000_120)
        #expect(card.digest == Messages.requestDigest(request(1).encode()))
    }

    @Test func requestsAreRefusedBeforeThePairingIsActive() throws {
        var phone = try begin()
        let delivered = try deliver(phone, request(1), signedBy: host)
        #expect(throws: Refusal.notActive) { try phone.pairing.open(delivered, now: now, kemPrivate: phone.kem) }
    }

    @Test func aRequestNotSignedByTheHostIsNeverShown() throws {
        var phone = try active()
        // Anyone can encrypt to the phone's public key; only the host can sign.
        let delivered = try deliver(phone, request(1), signedBy: P256.Signing.PrivateKey())
        #expect(throws: Refusal.notFromHost) { try phone.pairing.open(delivered, now: now, kemPrivate: phone.kem) }
    }

    @Test func tamperedAndMisdirectedEnvelopesAreRefused() throws {
        var phone = try active()
        let good = try deliver(phone, request(1), signedBy: host)

        var sealed = try Codec.b64Decode(good.envelope)
        sealed[100] ^= 1
        var tampered = good
        tampered.envelope = Codec.b64Encode(sealed)
        #expect(throws: Refusal.undecryptable) { try phone.pairing.open(tampered, now: now, kemPrivate: phone.kem) }

        var garbage = good
        garbage.envelope = "not base64!"
        #expect(throws: Refusal.undecryptable) { try phone.pairing.open(garbage, now: now, kemPrivate: phone.kem) }

        // Sealed for a different pairing of the same phone key.
        let misdirected = try deliver(phone, request(1), signedBy: host, sealedFor: Data(repeating: 0xb2, count: 16))
        #expect(throws: Refusal.undecryptable) { try phone.pairing.open(misdirected, now: now, kemPrivate: phone.kem) }
    }

    @Test func aRequestMustNameThisPairingAndMatchItsID() throws {
        var phone = try active()
        // Signed by the host, but describing another pairing.
        var other = request(1)
        other.pairingID = Data(repeating: 0xb2, count: 16)
        let delivered = try deliver(phone, other, signedBy: host)
        #expect(throws: Refusal.malformed) { try phone.pairing.open(delivered, now: now, kemPrivate: phone.kem) }

        // Delivered by the relay under a different request's id.
        var relabelled = try deliver(phone, request(1), signedBy: host)
        relabelled.requestID = Codec.hexEncode(Data(repeating: 7, count: 16))
        #expect(throws: Refusal.malformed) { try phone.pairing.open(relabelled, now: now, kemPrivate: phone.kem) }
    }

    @Test func expiredRequestsAreRefused() throws {
        var phone = try active()
        let delivered = try deliver(phone, request(1), signedBy: host)
        let expiry: UInt64 = 1_795_000_120
        #expect(throws: Refusal.expired) {
            try phone.pairing.open(delivered, now: expiry + Pairing.clockSkewSecs + 1, kemPrivate: phone.kem)
        }
        // Within the allowance for clock disagreement it is still shown.
        _ = try phone.pairing.open(delivered, now: expiry + Pairing.clockSkewSecs, kemPrivate: phone.kem)
    }

    @Test func aRequestIsShownOnlyOnce() throws {
        var phone = try active()
        let delivered = try deliver(phone, request(1), signedBy: host)
        _ = try phone.pairing.open(delivered, now: now, kemPrivate: phone.kem)
        #expect(throws: Refusal.alreadySeen) { try phone.pairing.open(delivered, now: now, kemPrivate: phone.kem) }
        // A different request from the same host is fine.
        _ = try phone.pairing.open(try deliver(phone, request(2), signedBy: host), now: now, kemPrivate: phone.kem)
        // The seen-set survives being stored and loaded.
        var restored = try JSONDecoder().decode(Pairing.self, from: JSONEncoder().encode(phone.pairing))
        #expect(restored == phone.pairing)
        #expect(throws: Refusal.alreadySeen) { try restored.open(delivered, now: now, kemPrivate: phone.kem) }
    }

    @Test func anApprovalSignsExactlyThisRequest() async throws {
        var phone = try active()
        let card = try phone.pairing.open(try deliver(phone, request(1), signedBy: host), now: now, kemPrivate: phone.kem)
        let answer = try await phone.pairing.approve(card, signer: phone.signer, prompt: "test")
        #expect(answer.decision == .approve)
        #expect(answer.reason == nil)
        #expect(try verifies(phone, Messages.approve(digest: card.digest), answer))
        // It is not an approval of the same command asked again.
        let other = Messages.requestDigest(request(2).encode())
        #expect(try !verifies(phone, Messages.approve(digest: other), answer))
        // And not a denial.
        #expect(try !verifies(phone, Messages.deny(digest: card.digest, reason: Data()), answer))
        // The JSON shape is what the relay expects.
        let json = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(answer)) as? [String: String])
        #expect(json == ["decision": "approve", "sig": answer.sig])
    }

    @Test func aDenialSignsItsReason() async throws {
        var phone = try active()
        let card = try phone.pairing.open(try deliver(phone, request(1), signedBy: host), now: now, kemPrivate: phone.kem)
        let reason = "use the staging database"
        let answer = try await phone.pairing.deny(card, reason: reason, signer: phone.signer, prompt: "test")
        #expect(answer.decision == .deny)
        #expect(answer.reason == reason)
        #expect(try verifies(phone, Messages.deny(digest: card.digest, reason: Data(reason.utf8)), answer))
        #expect(try !verifies(phone, Messages.deny(digest: card.digest, reason: Data("something else".utf8)), answer))
        #expect(try !verifies(phone, Messages.approve(digest: card.digest), answer))

        let silent = try await phone.pairing.deny(card, reason: "", signer: phone.signer, prompt: "test")
        #expect(silent.reason == nil)
        #expect(try verifies(phone, Messages.deny(digest: card.digest, reason: Data()), silent))
    }

    @Test func longReasonsAreCutAtACharacterBoundary() async throws {
        var phone = try active()
        let card = try phone.pairing.open(try deliver(phone, request(1), signedBy: host), now: now, kemPrivate: phone.kem)
        // 'é' is two bytes, so the limit falls in the middle of one.
        let long = String(repeating: "é", count: Proto.maxReasonLength)
        let answer = try await phone.pairing.deny(card, reason: long, signer: phone.signer, prompt: "test")
        let reason = try #require(answer.reason)
        #expect(reason.utf8.count == Proto.maxReasonLength - (Proto.maxReasonLength % 2))
        #expect(try verifies(phone, Messages.deny(digest: card.digest, reason: Data(reason.utf8)), answer))
        // An odd offset: one ASCII byte first.
        #expect(Pairing.clip(reason: "a" + long).utf8.count == Proto.maxReasonLength - 1)
        #expect(Pairing.clip(reason: "short") == "short")
    }
}

@Suite struct DisplayTests {
    func request(_ change: (inout Request) -> Void = { _ in }) -> Request {
        var request = Request(
            nonce: Data(count: 32), pairingID: Data(count: 16), issuedAt: 1000, ttlSecs: 120, uid: 501, gid: 20,
            user: Data("burke".utf8), host: Data("burke-mbp".utf8), cwd: Data("/Users/burke/app".utf8),
            exe: Data("/usr/bin/tee".utf8), flags: 0, stdin: .terminal,
            argv: ["tee", "/etc/hosts"].map { Data($0.utf8) },
            env: [.init(origin: .default, name: Data("TERM".utf8), value: Data("xterm".utf8))], ancestry: []
        )
        change(&request)
        return request
    }

    @Test func aPlainRequestHasNoCallouts() {
        let display = RequestDisplay(request())
        #expect(display.callouts.isEmpty)
        #expect(display.environment.map(\.name.plain) == ["TERM"])
        #expect(!display.hasRisk)
        #expect(display.arguments.map(\.plain) == ["tee", "/etc/hosts"])
        #expect(display.summary == "tee /etc/hosts")
        #expect(display.user?.plain == "burke")
    }

    @Test func everythingThatWeakensTheArgumentListIsCalledOut() {
        let display = RequestDisplay(request {
            $0.flags = Request.flagExeWritable
            $0.stdin = .pipe
            $0.user = Data()
            $0.env.append(.init(origin: .explicit, name: Data("DEBUG".utf8), value: Data("1".utf8)))
            $0.env.append(.init(origin: .explicit, name: Data("LD_PRELOAD".utf8), value: Data("/tmp/x.so".utf8)))
            $0.ancestry = [.init(pid: 2, name: Data("zsh".utf8)), .init(pid: 1, name: Data("claude".utf8))]
        })
        #expect(display.callouts.map(\.kind) == [
            .executableWritable,
            .unseenInput,
            .variable(name: EscapedText("DEBUG"), value: EscapedText("1")),
            .riskyVariable(name: EscapedText("LD_PRELOAD"), value: EscapedText("/tmp/x.so")),
        ])
        #expect(display.callouts.map(\.isRisk) == [true, false, false, true])
        #expect(display.hasRisk)
        #expect(display.user == nil)
        #expect(display.ancestry.map(\.plain) == ["zsh", "claude"])
    }

    /// Variables isudo builds itself are part of the signed request but are
    /// not the caller's doing: no callout and no warning, even for names
    /// that would be flagged had the caller set them.
    @Test func constructedVariablesAreListedButNeverCalledOut() {
        let display = RequestDisplay(request {
            $0.env = [
                .init(origin: .constructed, name: Data("PATH".utf8), value: Data("/usr/bin:/bin".utf8)),
                .init(origin: .constructed, name: Data("HOME".utf8), value: Data("/var/root".utf8)),
                .init(origin: .default, name: Data("TERM".utf8), value: Data("xterm".utf8)),
                .init(origin: .explicit, name: Data("PATH".utf8), value: Data("/tmp/evil".utf8)),
            ]
        })
        #expect(display.callouts.map(\.kind) == [
            .riskyVariable(name: EscapedText("PATH"), value: EscapedText("/tmp/evil")),
        ])
        #expect(display.environment.map(\.name.plain) == ["PATH", "HOME", "TERM", "PATH"])
        #expect(display.environment.map(\.origin) == [.constructed, .constructed, .default, .explicit])
        #expect(display.environment.map(\.isRisk) == [false, false, false, true])
    }

    @Test func environmentOriginsRoundTripAndUnknownOnesAreRefused() throws {
        let sample = request {
            $0.env = [.init(origin: .constructed, name: Data("PATH".utf8), value: Data("/usr/bin".utf8))]
        }
        var bytes = sample.encode()
        #expect(try Request.decode(bytes) == sample)
        // The origin byte follows the env count; find it by re-encoding with
        // each value and checking the decoder's verdict.
        let originAt = try #require(bytes.indices.first { index in
            var probe = bytes
            probe[index] = 2
            return (try? Request.decode(probe))?.env.first?.origin == .explicit
        })
        for (code, ok) in [(UInt8(1), true), (2, true), (3, true), (0, false), (4, false), (255, false)] {
            bytes[originAt] = code
            let accepted = (try? Request.decode(bytes)) != nil
            #expect(accepted == ok, "origin \(code)")
        }
    }

    @Test func nothingCanHideInAnArgument() {
        let display = RequestDisplay(request {
            $0.argv = [Data("sh".utf8), Data("-c".utf8), Data("echo ok\n\u{202e}rm -rf /\u{1b}[2K\r".utf8), Data([0xff]), Data()]
        })
        #expect(display.arguments[2].plain == "echo ok\\n\\u{202e}rm -rf /\\u{1b}[2K\\r")
        #expect(display.arguments[3].plain == "\\xff")
        #expect(display.arguments[4].isEmpty)
        #expect(display.arguments.count == 5)
    }
}

@Suite struct RelayClientTests {
    @Test func httpsIsRequiredExceptForLoopback() {
        for good in ["https://relay.example", "https://relay.example/base/", "http://127.0.0.1:8787",
                     "http://localhost:8787/x", "http://[::1]:8787"] {
            #expect((try? RelayClient(baseURL: good)) != nil, "refused \(good)")
        }
        for bad in ["http://relay.example", "http://127.0.0.1.evil.example", "http://localhost.evil.example:80",
                    "ftp://relay.example", "https://", "relay.example", ""] {
            #expect(throws: RelayError.badURL, "accepted \(bad)") { try RelayClient(baseURL: bad) }
        }
    }

    @Test func errorsNeverCarryRemoteText() {
        #expect(RelayError.status(500).message == "The relay answered with HTTP status 500.")
        #expect(RelayError.status(409).message == "The relay refused the request (conflict).")
    }
}
