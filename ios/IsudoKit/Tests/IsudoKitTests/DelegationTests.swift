import CryptoKit
import Foundation
import Testing

@testable import IsudoKit

/// The watch: its authorisation by the phone, what it may approve, and the
/// checks it makes. Formats and rules are checked against the Rust
/// reference's vectors; behaviour follows `isudo_phone::Delegate`.
@Suite struct DelegationTests {
    let vectors: Vectors
    let host = P256.Signing.PrivateKey()
    let store = MemorySecretStore()
    let now: UInt64 = 1_795_000_010

    init() throws {
        vectors = try Vectors()
    }

    // MARK: Against the reference

    @Test func aDelegationDecodesToTheReferencesFieldsAndBack() throws {
        let encoded = try vectors.hex("delegation", "signed_hex")
        let signed = try SignedDelegation.decode(encoded)
        let delegation = signed.delegation
        #expect(delegation.pairingID == (try vectors.hex("pairing", "pairing_id_hex")))
        #expect(delegation.signPub == (try vectors.b64("delegation", "watch_sign_pub_b64")))
        #expect(delegation.kemPub == (try vectors.b64("delegation", "watch_kem_pub_b64")))
        #expect(delegation.name == (try vectors.string("delegation", "name")))
        let notAfter = try #require(try vectors.section("delegation")["not_after"] as? NSNumber).uint64Value
        #expect(delegation.notAfter == notAfter)
        #expect(signed.phoneSignature == (try vectors.b64("delegation", "phone_sig_b64")))
        // The same bytes back, and the same bytes signed.
        #expect(signed.encode() == encoded)
        #expect(delegation.message == (try vectors.hex("delegation", "message_hex")))
        // Signed by the reference phone, and by nobody else.
        #expect(signed.isSigned(by: try vectors.b64("signatures", "phone_sign_pub_b64")))
        #expect(!signed.isSigned(by: try vectors.b64("signatures", "host_pub_b64")))
    }

    @Test func delegationDecodingIsStrict() throws {
        let encoded = try vectors.hex("delegation", "signed_hex")
        #expect(throws: WireError.self) { try SignedDelegation.decode(encoded + [0]) }
        #expect(throws: WireError.self) { try SignedDelegation.decode(encoded.dropLast()) }
        #expect(throws: WireError.self) { try SignedDelegation.decode(Data()) }
        #expect(throws: WireError.tooLarge("delegation")) {
            try SignedDelegation.decode(Data(count: SignedDelegation.maxLength + 1))
        }
        // A control character in the name.
        let nameAt = Proto.pairingIDLength + 2 * Proto.pubkeyLength + 8 + 4
        var badName = encoded
        badName[nameAt] = 0x0a
        #expect(throws: WireError.invalid("delegate name")) { try SignedDelegation.decode(badName) }
        // A sliced buffer decodes like a fresh one.
        let padded = Data([0xff, 0xff]) + encoded
        #expect(try SignedDelegation.decode(padded.dropFirst(2)).encode() == encoded)
    }

    @Test func namesThatWouldNotReadAsWrittenAreRefused() throws {
        #expect(Delegation.isValid(name: "Burke\u{2019}s Apple Watch"))
        #expect(Delegation.isValid(name: String(repeating: "x", count: Delegation.maxNameLength)))
        for bad in ["", " padded", "padded ", "two\nlines", "tab\there", String(repeating: "x", count: Delegation.maxNameLength + 1)] {
            #expect(!Delegation.isValid(name: bad), "\(bad.debugDescription)")
            let delegation = Delegation(
                pairingID: Data(count: 16), signPub: Data(count: 65), kemPub: Data(count: 65), notAfter: 1, name: bad
            )
            #expect(delegation.message == nil)
            #expect(SignedDelegation(delegation: delegation, phoneSignature: Data(count: 64)).encode() == nil)
        }
        let limits = try #require(try vectors.section("delegation")["limits"] as? [String: NSNumber])
        #expect(limits["max_name_len"]?.intValue == Delegation.maxNameLength)
        #expect(limits["max_delegation_secs"]?.uint64Value == Delegation.maxLifetimeSecs)
        #expect(limits["max_args"]?.intValue == Request.maxSimpleArgs)
        #expect(limits["max_arg_bytes"]?.intValue == Request.maxSimpleArgBytes)
        #expect(limits["max_path_len"]?.intValue == Request.maxSimplePathLength)
    }

    /// The rule for what a watch may approve, case by case, as the reference
    /// decides it. The computer applies the same rule before it marks a
    /// request; the watch must never be more generous.
    @Test func theRuleForWhatAWatchMayApproveMatchesTheReference() throws {
        let cases = try #require(try vectors.section("delegation")["simple_enough"] as? [[String: Any]])
        #expect(cases.count >= 14)
        var (simple, notSimple) = (0, 0)
        for entry in cases {
            let what = try #require(entry["what"] as? String)
            let request = try Request.decode(try Codec.hexDecode(try #require(entry["request_hex"] as? String)))
            let expected = try #require(entry["simple_enough"] as? Bool)
            #expect(request.isSimpleEnough == expected, "\(what)")
            if expected { simple += 1 } else { notSimple += 1 }
        }
        #expect(simple >= 3 && notSimple >= 10)
    }

    @Test func aWatchNeedsBothTheComputersMarkAndItsOwnReading() throws {
        let marked = try Request.decode(try vectors.hex("delegation", "request_hex"))
        #expect(marked.isMarkedForWatch && marked.isSimpleEnough && marked.watchMayApprove)
        // Simple, but the computer did not mark it: root has not allowed a watch.
        let unmarked = try Request.decode(try vectors.hex("delegation", "unmarked_request_hex"))
        #expect(!unmarked.isMarkedForWatch && unmarked.isSimpleEnough && !unmarked.watchMayApprove)
        // Marked, but not simple by this device's own reading: a computer
        // that marked it wrongly does not get an Approve button out of it.
        var wronglyMarked = marked
        wronglyMarked.stdin = .pipe
        #expect(wronglyMarked.isMarkedForWatch && !wronglyMarked.watchMayApprove)
    }

    @Test func theReferenceWatchsSignaturesVerify() throws {
        let watchPub = try vectors.b64("delegation", "watch_sign_pub_b64")
        let digest = Messages.requestDigest(try vectors.hex("delegation", "request_hex"))
        let approve = try vectors.b64("delegation", "watch_approve_sig_b64")
        #expect(Crypto.verify(publicKey: watchPub, message: Messages.approve(digest: digest), signature: approve))
        let reason = Data(try vectors.string("delegation", "watch_deny_reason").utf8)
        let deny = try vectors.b64("delegation", "watch_deny_sig_b64")
        #expect(Crypto.verify(publicKey: watchPub, message: Messages.deny(digest: digest, reason: reason), signature: deny))
        #expect(!Crypto.verify(publicKey: watchPub, message: Messages.approve(digest: digest), signature: deny))
    }

    // MARK: The phone authorising a watch

    struct Phone {
        var pairing: Pairing
        let signer: SoftwareSigner
    }

    struct Watch {
        var pairing: WatchPairing
        let signer: SoftwareSigner
        let kem: P256.KeyAgreement.PrivateKey
    }

    func activePhone() throws -> Phone {
        let hostNonce = Data(repeating: 0x4e, count: Proto.hostNonceLength)
        let phoneNonce = Data(repeating: 0x70, count: Proto.phoneNonceLength)
        let (pairingID, hostPub) = (Data(repeating: 0xa1, count: 16), host.publicKey.x963Representation)
        let offer = PairingOffer(
            relayURL: "https://relay.example", pairingID: pairingID, hostPub: hostPub,
            secret: Data(repeating: 0x3c, count: 32),
            commitment: Crypto.commitment(pairingID: pairingID, hostPub: hostPub, hostNonce: hostNonce), hostName: "burke-mbp"
        )
        let signer = try SoftwareSigner.create(account: "phone.sign", in: store, authenticate: false)
        let (kemPub, _) = try PairingSecrets.create(pairingIDHex: "phone", in: store)
        var pairing = try Pairing(
            offer: offer, signPub: signer.publicKey, kemPub: kemPub, phoneNonce: phoneNonce, hardwareBacked: false
        )
        func signed(_ message: Data) throws -> String { Codec.b64Encode(try host.signature(for: message).rawRepresentation) }
        let ack = API.Ack(
            nonce: Codec.b64Encode(hostNonce),
            hostSig: try signed(Messages.pairAck(
                pairingID: pairingID, phoneSignPub: signer.publicKey, phoneKemPub: kemPub, phoneNonce: phoneNonce, hostNonce: hostNonce
            ))
        )
        let confirm = try signed(Messages.pairConfirm(pairingID: pairingID, phoneSignPub: signer.publicKey, phoneKemPub: kemPub))
        #expect(try pairing.observe(API.PairingStatus(state: .active, ack: ack, hostSig: confirm)) == .active)
        return Phone(pairing: pairing, signer: signer)
    }

    func newWatch(for phone: Phone, tag: String = "watch") throws -> Watch {
        let signer = try SoftwareSigner.create(account: tag + ".sign", in: store, authenticate: false)
        let kem = P256.KeyAgreement.PrivateKey()
        let pairing = try WatchPairing(
            pairingID: phone.pairing.pairingID, hostPub: phone.pairing.hostPub, hostName: phone.pairing.hostName,
            relayURL: phone.pairing.relayURL, signPub: signer.publicKey, kemPub: kem.publicKey.x963Representation
        )
        return Watch(pairing: pairing, signer: signer, kem: kem)
    }

    func authorise(_ watch: inout Watch, by phone: Phone, validFor: UInt64 = 1000) async throws -> SignedDelegation {
        let signed = try await phone.pairing.delegate(
            watchSignPub: watch.pairing.signPub, watchKemPub: watch.pairing.kemPub, name: "Test Watch", now: now,
            validFor: validFor, signer: phone.signer, prompt: "test"
        )
        let taken = watch.pairing.accept(signed)
        #expect(taken)
        return signed
    }

    func request(_ nonce: UInt8, simple: Bool = true, marked: Bool = true) -> Request {
        Request(
            nonce: Data(repeating: nonce, count: 32), pairingID: Data(repeating: 0xa1, count: 16), issuedAt: 1_795_000_000,
            ttlSecs: 120, uid: 501, gid: 20, user: Data("burke".utf8), host: Data("burke-mbp".utf8),
            cwd: Data("/tmp".utf8), exe: Data("/usr/sbin/nginx".utf8), flags: marked ? Request.flagDelegable : 0,
            stdin: simple ? .terminal : .pipe, argv: ["nginx", "-s", "reload"].map { Data($0.utf8) },
            env: [.init(origin: .default, name: Data("TERM".utf8), value: Data("xterm".utf8))], ancestry: []
        )
    }

    func deliver(_ request: Request, to kem: P256.KeyAgreement.PublicKey, signedBy signer: P256.Signing.PrivateKey) throws -> API.PendingRequest {
        let bytes = request.encode()
        let hostSig = try signer.signature(for: Messages.hostRequest(bytes)).rawRepresentation
        let sealed = try Crypto.sealEnvelope(hostSignature: hostSig, request: bytes, kemPublic: kem, pairingID: request.pairingID)
        return API.PendingRequest(
            requestID: Codec.hexEncode(Messages.requestID(bytes)), expiresAt: request.issuedAt + UInt64(request.ttlSecs),
            envelope: Codec.b64Encode(sealed)
        )
    }

    @Test func thePhoneSignsForExactlyTheWatchsKeysAndNoLongerThanAllowed() async throws {
        let phone = try activePhone()
        var watch = try newWatch(for: phone)
        let signed = try await authorise(&watch, by: phone, validFor: 500)
        #expect(signed.isSigned(by: phone.pairing.signPub))
        #expect(signed.delegation.pairingID == phone.pairing.pairingID)
        #expect(signed.delegation.signPub == watch.pairing.signPub && signed.delegation.kemPub == watch.pairing.kemPub)
        #expect(signed.delegation.notAfter == now + 500)
        #expect(watch.pairing.authorisedUntil == now + 500)
        // Asked for a year, the phone signs for the longest allowed.
        let capped = try await phone.pairing.delegate(
            watchSignPub: watch.pairing.signPub, watchKemPub: watch.pairing.kemPub, name: "Test Watch", now: now,
            validFor: 365 * 24 * 60 * 60, signer: phone.signer, prompt: "test"
        )
        #expect(capped.delegation.notAfter == now + Delegation.maxLifetimeSecs)
        // It round-trips through the encoding the computer will read.
        #expect(try SignedDelegation.decode(try #require(signed.encode())) == signed)
    }

    @Test func thePhoneRefusesToSignForNonsense() async throws {
        let phone = try activePhone()
        let watch = try newWatch(for: phone)
        let offCurve = Data([0x04]) + Data(repeating: 0x11, count: 64)
        for (signPub, kemPub, name) in [
            (offCurve, watch.pairing.kemPub, "Test Watch"), (watch.pairing.signPub, offCurve, "Test Watch"),
            (watch.pairing.signPub, watch.pairing.kemPub, "two\nlines"), (watch.pairing.signPub, watch.pairing.kemPub, ""),
        ] {
            await #expect(throws: SignerError.keyUnusable) {
                try await phone.pairing.delegate(
                    watchSignPub: signPub, watchKemPub: kemPub, name: name, now: now, signer: phone.signer, prompt: "test"
                )
            }
        }
    }

    // MARK: The watch

    @Test func aWatchShowsNothingUntilThePhoneHasAuthorisedIt() async throws {
        let phone = try activePhone()
        var watch = try newWatch(for: phone)
        let delivered = try deliver(request(1), to: watch.kem.publicKey, signedBy: host)
        #expect(throws: Refusal.notActive) { try watch.pairing.open(delivered, now: now, kemPrivate: watch.kem) }

        // An authorisation of some other watch's keys, or for another
        // pairing, is not this watch's to use.
        var other = try newWatch(for: phone, tag: "other")
        let forOther = try await authorise(&other, by: phone)
        let tookAnothers = watch.pairing.accept(forOther)
        #expect(!tookAnothers)
        var elsewhere = forOther
        elsewhere.delegation.signPub = watch.pairing.signPub
        elsewhere.delegation.kemPub = watch.pairing.kemPub
        elsewhere.delegation.pairingID = Data(repeating: 0xb2, count: 16)
        let tookAnotherPairings = watch.pairing.accept(elsewhere)
        #expect(!tookAnotherPairings)
        #expect(watch.pairing.delegation == nil)

        _ = try await authorise(&watch, by: phone)
        #expect(try watch.pairing.open(delivered, now: now, kemPrivate: watch.kem).request == request(1))
    }

    @Test func aWatchMakesEveryCheckThePhoneMakes() async throws {
        let phone = try activePhone()
        var watch = try newWatch(for: phone)
        _ = try await authorise(&watch, by: phone)

        // Not signed by the paired computer.
        let forged = try deliver(request(1), to: watch.kem.publicKey, signedBy: P256.Signing.PrivateKey())
        #expect(throws: Refusal.notFromHost) { try watch.pairing.open(forged, now: now, kemPrivate: watch.kem) }
        // Sealed to someone else.
        let misdirected = try deliver(request(2), to: P256.KeyAgreement.PrivateKey().publicKey, signedBy: host)
        #expect(throws: Refusal.undecryptable) { try watch.pairing.open(misdirected, now: now, kemPrivate: watch.kem) }
        // Delivered under another request's id.
        var relabelled = try deliver(request(3), to: watch.kem.publicKey, signedBy: host)
        relabelled.requestID = Codec.hexEncode(Data(repeating: 9, count: 16))
        #expect(throws: Refusal.malformed) { try watch.pairing.open(relabelled, now: now, kemPrivate: watch.kem) }
        // Past its expiry.
        let late = try deliver(request(4), to: watch.kem.publicKey, signedBy: host)
        #expect(throws: Refusal.expired) { try watch.pairing.open(late, now: now + 1000, kemPrivate: watch.kem) }
        // Shown once.
        let genuine = try deliver(request(5), to: watch.kem.publicKey, signedBy: host)
        _ = try watch.pairing.open(genuine, now: now, kemPrivate: watch.kem)
        #expect(throws: Refusal.alreadySeen) { try watch.pairing.open(genuine, now: now, kemPrivate: watch.kem) }
    }

    @Test func aWatchApprovesOnlyWhatItMayAndDeniesAnything() async throws {
        let phone = try activePhone()
        var watch = try newWatch(for: phone)
        _ = try await authorise(&watch, by: phone)

        let simple = try watch.pairing.open(try deliver(request(1), to: watch.kem.publicKey, signedBy: host), now: now, kemPrivate: watch.kem)
        let approval = try #require(try await watch.pairing.approve(simple, signer: watch.signer, prompt: "test"))
        #expect(approval.decision == .approve && approval.delegation == nil)
        #expect(Crypto.verify(
            publicKey: watch.pairing.signPub, message: Messages.approve(digest: simple.digest),
            signature: try Codec.b64Decode(approval.sig)
        ))
        // The phone's key did not sign it: without the delegation it is
        // just a signature by a key the computer never pinned.
        #expect(!Crypto.verify(
            publicKey: phone.pairing.signPub, message: Messages.approve(digest: simple.digest),
            signature: try Codec.b64Decode(approval.sig)
        ))

        // Not simple, or not marked by the computer: no approval is signed.
        for (nonce, isSimple, isMarked) in [(UInt8(2), false, true), (3, true, false), (4, false, false)] {
            let delivered = try deliver(request(nonce, simple: isSimple, marked: isMarked), to: watch.kem.publicKey, signedBy: host)
            let card = try watch.pairing.open(delivered, now: now, kemPrivate: watch.kem)
            #expect(try await watch.pairing.approve(card, signer: watch.signer, prompt: "test") == nil)
            // But it can always be denied, with the reason signed.
            let denial = try await watch.pairing.deny(card, reason: "not now", signer: watch.signer, prompt: "test")
            #expect(denial.decision == .deny && denial.reason == "not now")
            #expect(Crypto.verify(
                publicKey: watch.pairing.signPub, message: Messages.deny(digest: card.digest, reason: Data("not now".utf8)),
                signature: try Codec.b64Decode(denial.sig)
            ))
        }
    }

    @Test func aWatchStopsWhenItsAuthorisationRunsOut() async throws {
        let phone = try activePhone()
        var watch = try newWatch(for: phone)
        _ = try await authorise(&watch, by: phone, validFor: 100)
        let first = try deliver(request(1), to: watch.kem.publicKey, signedBy: host)
        #expect(try watch.pairing.open(first, now: now + 100, kemPrivate: watch.kem).request == request(1))
        var later = request(2)
        later.issuedAt = now + 101
        let second = try deliver(later, to: watch.kem.publicKey, signedBy: host)
        #expect(throws: Refusal.authorisationExpired) { try watch.pairing.open(second, now: now + 101, kemPrivate: watch.kem) }
        // Renewed by the phone, it carries on.
        _ = try await authorise(&watch, by: phone, validFor: 1000)
        #expect(try watch.pairing.open(second, now: now + 101, kemPrivate: watch.kem).request == later)
    }

    @Test func aWatchPairingSurvivesBeingStored() async throws {
        let phone = try activePhone()
        var watch = try newWatch(for: phone)
        let signed = try await authorise(&watch, by: phone)
        let restored = try JSONDecoder().decode(WatchPairing.self, from: JSONEncoder().encode(watch.pairing))
        #expect(restored == watch.pairing)
        #expect(restored.signedDelegation == signed)
    }

    // MARK: Between a phone and its watch

    @Test func messagesBetweenPhoneAndWatchRoundTripAndAreStrict() {
        let (id, key) = (Data(repeating: 0xa1, count: 16), Data([0x04]) + Data(repeating: 0x11, count: 64))
        let all: [WatchMessage] = [
            .offer(pairingID: id, hostPub: key, hostName: "burke-mbp", relayURL: "https://relay.example"),
            .keys(pairingID: id, signPub: key, kemPub: key, token: "tok", name: "Burke\u{2019}s Apple Watch", hardwareBacked: true),
            .delegation(pairingID: id, signed: Data(repeating: 7, count: 200)),
            .removed(pairingID: id),
            .answer(pairingID: id, requestID: String(repeating: "ab", count: 16), token: "tok", body: Data("{}".utf8)),
            .delivered(status: 204),
            .settled(requestID: String(repeating: "cd", count: 16)),
            .failed(.noKey),
        ]
        for message in all {
            #expect(WatchMessage(dictionary: message.dictionary) == message)
            // Every value is a property-list type, as the link requires.
            #expect(PropertyListSerialization.propertyList(message.dictionary, isValidFor: .binary))
        }
        // Wrong sizes, wrong types, missing fields and unknown kinds are all refused.
        var short = all[0].dictionary
        short["pid"] = Data(count: 15)
        #expect(WatchMessage(dictionary: short) == nil)
        var mistyped = all[1].dictionary
        mistyped["hw"] = "yes"
        #expect(WatchMessage(dictionary: mistyped) == nil)
        var missing = all[4].dictionary
        missing["body"] = nil
        #expect(WatchMessage(dictionary: missing) == nil)
        var oversized = all[2].dictionary
        oversized["signed"] = Data(count: SignedDelegation.maxLength + 1)
        #expect(WatchMessage(dictionary: oversized) == nil)
        #expect(WatchMessage(dictionary: ["t": "launch missiles"]) == nil)
        #expect(WatchMessage(dictionary: [:]) == nil)
        #expect(WatchMessage(dictionary: ["t": "failed", "why": "because"]) == nil)
    }

    @Test func aWatchsOwnNameIsMadeFitToSignFor() {
        #expect(Delegation.usableName(from: "Burke\u{2019}s Apple Watch") == "Burke\u{2019}s Apple Watch")
        #expect(Delegation.usableName(from: "  padded\n") == "padded")
        #expect(Delegation.usableName(from: "two\nlines") == "twolines")
        #expect(Delegation.usableName(from: "") == "Apple Watch")
        #expect(Delegation.usableName(from: "\u{1b}\n") == "Apple Watch")
        let long = Delegation.usableName(from: String(repeating: "\u{e9}", count: 100))
        #expect(long.utf8.count <= Delegation.maxNameLength && Delegation.isValid(name: long))
    }
}
