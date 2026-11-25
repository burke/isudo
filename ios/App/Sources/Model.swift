import CryptoKit
import Foundation
import IsudoKit
import Observation
import UIKit
import os

/// A request that passed every check and is waiting for the person.
struct WaitingRequest: Identifiable, Equatable {
    enum Phase: Equatable {
        case waiting
        /// Face ID is up, or the signature is being made.
        case signing
        /// Signed; the answer is on its way to the relay.
        case sending
        /// Finished. The card lingers a moment to show it.
        case finished(ActivityEntry.Outcome)
        /// Signed, but the answer did not reach the relay.
        case undelivered(String)
    }

    let pairingID: Data
    let card: Card
    let display: RequestDisplay
    var phase: Phase = .waiting
    /// A signed answer that still has to be delivered.
    var signedAnswer: API.Answer?

    var id: Data { card.requestID }
}

/// One line of history.
struct ActivityEntry: Identifiable, Codable, Equatable {
    enum Outcome: String, Codable {
        case approved, denied, expired
    }

    var id = UUID()
    var date: Date
    var hostName: String
    var summary: String
    var outcome: Outcome
    var reason: String?
}

/// How a pairing code reached the app.
enum OfferSource: Equatable {
    case scan
    case paste
    /// An `isudo://` link opened from outside the app. Any app or web page
    /// can do that, so this one gets a warning.
    case link
}

/// Where the pairing sheet is in its conversation with the computer.
enum PairingFlow: Equatable {
    case scanning
    /// A pairing code has been read and nothing else has happened: no keys
    /// made, nothing sent. The person decides whether to go on.
    case confirming(PairingOffer, source: OfferSource)
    case contacting(hostName: String)
    /// This phone has answered; the computer has not yet accepted it. There
    /// is no code to show until it does.
    case waitingForComputer(hostName: String, pairingID: Data)
    case code(hostName: String, code: String, pairingID: Data)
    /// Another phone answered this pairing first.
    case alreadyClaimed(hostName: String)
    /// The computer accepted an answer, and it was not this phone's.
    case otherPhoneAccepted(hostName: String)
    /// Whoever wrote the pairing code tried to choose the code this phone
    /// would show.
    case steered(hostName: String)
    case failed(String)
    case paired(hostName: String, hardwareBacked: Bool)
}

/// A watch this phone has authorised to answer for one pairing.
struct WatchGrant: Codable, Equatable {
    var pairingID: Data
    var signPub: Data
    var name: String
    /// When the authorisation runs out, in unix seconds.
    var notAfter: UInt64
}

/// Where authorising a watch has got to, for one pairing.
enum WatchSetup: Equatable {
    case working
    case failed(String)
}

@MainActor
@Observable
final class AppModel {
    private(set) var pairings: [Pairing] = []
    private(set) var waiting: [WaitingRequest] = []
    private(set) var activity: [ActivityEntry] = []
    var pairingFlow: PairingFlow?
    /// A transient problem worth telling the person about.
    var notice: String?
    /// True when showing built-in sample data (debug builds only).
    private(set) var isFixture = false

    /// Watches this phone has authorised, one per pairing at most.
    private(set) var watchGrants: [WatchGrant] = []
    /// Progress or failure of authorising a watch, by pairing.
    private(set) var watchSetup: [Data: WatchSetup] = [:]
    private var watchLink: WatchLink?

    private let secrets: any SecretStore
    private let storage: Storage
    private var deviceToken: String?
    private var pollTask: Task<Void, Never>?
    /// Requests already refused, so each is examined once.
    private var refused: Set<String> = []
    private var reportedKeyProblem = false
    /// Shows in the Xcode console and in Console.app; never contains secrets.
    private let diagnostics = Logger(subsystem: Bundle.main.bundleIdentifier ?? "isudo", category: "requests")

    var phoneName: String { UIDevice.current.name }

    init(secrets: any SecretStore = KeychainSecretStore(service: Bundle.main.bundleIdentifier ?? "isudo"), storage: Storage = Storage()) {
        self.secrets = secrets
        self.storage = storage
        pairings = storage.loadPairings()
        activity = storage.loadActivity()
        watchGrants = storage.loadWatchGrants()
    }

    #if DEBUG
    /// A model showing sample data, for previews and screenshots. It talks to
    /// nobody and signs nothing.
    init(fixture: Fixture) {
        secrets = MemorySecretStore()
        storage = Storage(directory: nil)
        isFixture = true
        pairings = fixture.pairings
        waiting = fixture.waiting
        activity = fixture.activity
        pairingFlow = fixture.pairingFlow
    }
    #endif

    func pairing(_ id: Data) -> Pairing? {
        pairings.first { $0.pairingID == id }
    }

    private func now() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970))
    }

    private func save() {
        guard !isFixture else { return }
        storage.save(pairings: pairings)
        storage.save(activity: activity)
        storage.save(watchGrants: watchGrants)
    }

    private func record(_ outcome: ActivityEntry.Outcome, _ item: WaitingRequest, reason: String? = nil) {
        let host = pairing(item.pairingID)?.hostName ?? item.display.host.plain
        activity.insert(
            ActivityEntry(date: Date(), hostName: host, summary: item.display.summary, outcome: outcome, reason: reason),
            at: 0
        )
        activity = Array(activity.prefix(100))
        save()
    }

    // MARK: Polling

    /// Polls while the app is in front. Push notifications only make this
    /// sooner; the app works without them.
    func startPolling() {
        guard pollTask == nil, !isFixture else { return }
        pollTask = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                guard let self else { return }
                self.retireExpired()
                // Every two seconds; every second while a pairing is under way,
                // so the code appears promptly.
                if tick.isMultiple(of: 2) || self.pairings.contains(where: { !$0.active }) {
                    await self.refresh()
                }
                tick += 1
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    /// Seconds until the host stops waiting for this request.
    func secondsLeft(_ item: WaitingRequest, at date: Date = Date()) -> Int {
        let now = UInt64(max(0, date.timeIntervalSince1970))
        let left = item.card.expiresAt > now ? item.card.expiresAt - now : 0
        // If the clocks disagree, never claim longer than the host waits.
        return Int(min(left, UInt64(item.card.request.ttlSecs)))
    }

    private func retireExpired() {
        guard !isFixture else { return }
        for item in waiting where item.phase == .waiting && secondsLeft(item) == 0 {
            record(.expired, item)
            waiting.removeAll { $0.id == item.id }
        }
    }

    func refresh() async {
        guard !isFixture else { return }
        for pairing in pairings {
            guard let relay = try? RelayClient(baseURL: pairing.relayURL),
                  let token = try? PairingSecrets.token(pairingIDHex: pairing.idHex, from: secrets)
            else { continue }
            if pairing.active {
                await fetchRequests(pairing.pairingID, relay: relay, token: token)
            } else {
                await checkConfirmation(pairing.pairingID, relay: relay, token: token)
            }
        }
    }

    private func update(_ id: Data, _ change: (inout Pairing) throws -> Void) rethrows {
        guard let index = pairings.firstIndex(where: { $0.pairingID == id }) else { return }
        try change(&pairings[index])
    }

    private func fetchRequests(_ id: Data, relay: RelayClient, token: String) async {
        let delivered: [API.PendingRequest]
        do {
            delivered = try await relay.pending(pairingID: Codec.hexEncode(id), token: token).requests
        } catch RelayError.status(404), RelayError.status(401) {
            // The computer unpaired this phone.
            forget(id)
            notice = "A computer removed its pairing with this phone."
            return
        } catch {
            // Usually the network; the next poll tries again. Logged so a
            // persistent failure can be seen in the console.
            diagnostics.error("could not fetch requests: \(String(describing: error), privacy: .public)")
            return
        }
        let kem: P256.KeyAgreement.PrivateKey
        do {
            kem = try PairingSecrets.kemPrivate(pairingIDHex: Codec.hexEncode(id), from: secrets)
        } catch {
            diagnostics.error("decryption key unavailable: \(String(describing: error), privacy: .public)")
            if !delivered.isEmpty, !reportedKeyProblem {
                reportedKeyProblem = true
                notice = "A request arrived, but this phone could not read its key for that computer. Pair the computer again."
            }
            return
        }
        for request in delivered where !refused.contains(request.requestID) {
            guard !waiting.contains(where: { $0.card.requestIDHex == request.requestID }) else { continue }
            var opened: Card?
            var refusal: String?
            update(id) { pairing in
                // A refusal is never shown as a card; the request is skipped.
                do {
                    opened = try pairing.open(request, now: now(), kemPrivate: kem)
                } catch {
                    refusal = String(describing: error)
                }
            }
            guard let card = opened else {
                refused.insert(request.requestID)
                // Not a card, but not silence either: someone is waiting on
                // the computer, and they should be able to find out why.
                diagnostics.error("refused request \(request.requestID, privacy: .public): \(refusal ?? "unknown", privacy: .public)")
                notice = "A request arrived that this phone refused to show (\(refusal ?? "unknown")). Nothing was approved."
                continue
            }
            save()
            waiting.append(WaitingRequest(pairingID: id, card: card, display: RequestDisplay(card.request)))
            UINotificationFeedbackGenerator().notificationOccurred(.warning)
        }
    }

    // MARK: Pairing

    /// A pairing link opened from outside the app.
    func handle(url: URL) {
        guard url.scheme == "isudo" else { return }
        // Anything can open a link. It must never displace a pairing that is
        // under way, or the pairing code the person is being asked about.
        switch pairingFlow {
        case .confirming, .contacting, .waitingForComputer, .code: return
        case nil, .scanning, .alreadyClaimed, .otherPhoneAccepted, .steered, .failed, .paired: break
        }
        review(link: url.absoluteString, source: .link)
    }

    /// Reads a pairing code and asks the person about it. Nothing is
    /// generated or sent until they agree: see `confirmPairing`.
    func review(link: String, source: OfferSource) {
        let offer: PairingOffer
        do throws(PairingOffer.ParseError) {
            offer = try PairingOffer(link: link)
        } catch {
            pairingFlow = .failed(error.reason == PairingOffer.outdated
                ? "That pairing code was made by an older version of isudo. Update isudo on the computer, then run the pairing command again."
                : "That is not an isudo pairing code.")
            return
        }
        guard pairing(offer.pairingID) == nil else {
            pairingFlow = .failed("This phone already answered that pairing code.")
            return
        }
        // The name and relay are about to be shown, and acted on. Refuse
        // anything that would not read the way it is written.
        let readable = [offer.hostName, offer.relayURL].allSatisfy { text in
            !text.isEmpty && !EscapedText(Data(text.utf8)).hasEscapes
        }
        guard readable, (try? RelayClient(baseURL: offer.relayURL)) != nil else {
            pairingFlow = .failed("That pairing code is not one this phone will use: its computer name or relay address is not acceptable.")
            return
        }
        pairingFlow = .confirming(offer, source: source)
    }

    /// The person agreed to pair with the computer in the pairing code.
    func confirmPairing() async {
        guard case .confirming(let offer, _) = pairingFlow else { return }
        guard !isFixture else {
            pairingFlow = .failed("Sample data is showing, so nothing can be paired.")
            return
        }
        await beginPairing(offer)
    }

    private func beginPairing(_ offer: PairingOffer) async {
        pairingFlow = .contacting(hostName: offer.hostName)
        let idHex = Codec.hexEncode(offer.pairingID)
        do {
            let relay = try RelayClient(baseURL: offer.relayURL)
            let signer: any ApprovalSigner
            do {
                signer = try Signers.create(pairingIDHex: idHex, in: secrets)
            } catch {
                pairingFlow = .failed("Face ID or Touch ID must be set up on this phone before it can approve anything.")
                return
            }
            let (kemPub, token) = try PairingSecrets.create(pairingIDHex: idHex, in: secrets)
            // Chosen now, after the pairing code was read: this is what
            // stops whoever wrote that code choosing the six digits.
            let pairing = try Pairing(
                offer: offer, signPub: signer.publicKey, kemPub: kemPub, phoneNonce: try Pairing.freshNonce(),
                hardwareBacked: signer.isHardwareBacked
            )
            guard let claim = pairing.claim(phoneName: phoneName, token: token, device: currentDevice) else {
                throw RelayError.failed
            }
            try await relay.claim(pairingID: idHex, claim)
            pairings.append(pairing)
            save()
            // No code yet: it exists only once the computer has acknowledged
            // this phone's keys.
            pairingFlow = .waitingForComputer(hostName: offer.hostName, pairingID: offer.pairingID)
            startPolling()
        } catch RelayError.status(409) {
            PairingSecrets.delete(pairingIDHex: idHex, from: secrets)
            pairingFlow = .alreadyClaimed(hostName: offer.hostName)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        } catch let error as RelayError {
            PairingSecrets.delete(pairingIDHex: idHex, from: secrets)
            pairingFlow = .failed(error == .status(404)
                ? "That pairing code has expired. Run the pairing command on the computer again."
                : error.message)
        } catch {
            PairingSecrets.delete(pairingIDHex: idHex, from: secrets)
            pairingFlow = .failed("Pairing could not be started.")
        }
    }

    /// The pairing the sheet is currently about, if it is mid-conversation.
    private var flowPairingID: Data? {
        switch pairingFlow {
        case .waitingForComputer(_, let id), .code(_, _, let id): id
        default: nil
        }
    }

    private func checkConfirmation(_ id: Data, relay: RelayClient, token: String) async {
        let name = pairing(id)?.hostName ?? "The computer"
        let inSheet = flowPairingID == id
        let status: API.PairingStatus
        do {
            status = try await relay.status(pairingID: Codec.hexEncode(id), token: token)
        } catch RelayError.status(404) {
            // The computer gave up on, or refused, this pairing.
            forget(id)
            if inSheet {
                pairingFlow = .failed("\(name) did not confirm the pairing. Nothing was paired.")
            }
            return
        } catch {
            return
        }
        var progress: Result<PairingProgress, PairingError>?
        update(id) { pairing in
            do throws(PairingError) {
                progress = .success(try pairing.observe(status))
            } catch {
                progress = .failure(error)
            }
        }
        switch progress {
        case nil:
            return
        case .failure(.anotherPhoneWasAccepted):
            // The computer accepted an answer that was not this phone's.
            forget(id)
            if inSheet { pairingFlow = .otherPhoneAccepted(hostName: name) }
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        case .failure(.codeWasSteered):
            // Whoever wrote the pairing code tried to choose the code.
            forget(id)
            if inSheet { pairingFlow = .steered(hostName: name) }
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        case .failure(.badOffer):
            // Left unfinished by an older version of the app.
            forget(id)
            if inSheet {
                pairingFlow = .failed("That pairing was started by an older version of this app. Run the pairing command on the computer again.")
            }
        case .failure:
            // The relay says "active" without the computer's confirmation of
            // this phone's keys. Do not believe it.
            forget(id)
            if inSheet {
                pairingFlow = .failed("The relay reported a pairing that \(name) never confirmed. Nothing was paired.")
            }
        case .success(.waiting):
            break
        case .success(.showCode(let code)):
            save()
            if inSheet, pairingFlow != .code(hostName: name, code: code, pairingID: id) {
                pairingFlow = .code(hostName: name, code: code, pairingID: id)
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            }
        case .success(.active):
            guard let pairing = pairing(id) else { return }
            save()
            if inSheet {
                pairingFlow = .paired(hostName: pairing.hostName, hardwareBacked: pairing.hardwareBacked)
            }
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            Notifications.requestPermission()
        }
    }

    /// Abandons a pairing that is still waiting for the computer.
    func cancelPairing() {
        if let id = flowPairingID, let pairing = pairing(id), !pairing.active {
            Task { await unpair(id) }
        }
        pairingFlow = nil
    }

    private func forget(_ id: Data) {
        PairingSecrets.delete(pairingIDHex: Codec.hexEncode(id), from: secrets)
        pairings.removeAll { $0.pairingID == id }
        waiting.removeAll { $0.pairingID == id }
        if watchGrants.contains(where: { $0.pairingID == id }) {
            watchGrants.removeAll { $0.pairingID == id }
            watchLink?.tell(.removed(pairingID: id))
        }
        watchSetup[id] = nil
        save()
    }

    // MARK: Apple Watch

    /// Starts listening to this phone's watch. Sample data talks to nobody.
    func startWatchLink() {
        guard !isFixture, watchLink == nil else { return }
        watchLink = WatchLink { [weak self] message in
            await self?.fromWatch(message)
        }
    }

    /// Whether this phone has a watch with the isudo app on it.
    var hasWatchApp: Bool { watchLink?.hasWatchApp ?? false }

    func watchGrant(_ pairingID: Data) -> WatchGrant? {
        watchGrants.first { $0.pairingID == pairingID }
    }

    /// Authorises this phone's watch to answer for a pairing, or renews it.
    ///
    /// The watch makes its own keys and sends only their public halves. The
    /// phone signs for them behind Face ID, like an approval, because that
    /// is what it is: a standing permission for a second device to approve
    /// simple requests. Whether the computer honours it is up to root there.
    func allowWatch(_ pairingID: Data) async {
        guard !isFixture, let pairing = pairing(pairingID), pairing.active, let link = watchLink else { return }
        watchSetup[pairingID] = .working
        func fail(_ why: String) {
            watchSetup[pairingID] = .failed(why)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
        let reply: WatchMessage
        do {
            reply = try await link.ask(.offer(
                pairingID: pairingID, hostPub: pairing.hostPub, hostName: pairing.hostName, relayURL: pairing.relayURL
            ))
        } catch {
            fail("Open isudo on your Apple Watch, keep it nearby, and try again.")
            return
        }
        guard case .keys(pairingID, let signPub, let kemPub, let watchToken, let rawName, _) = reply else {
            fail(reply == .failed(.noKey)
                ? "Your Apple Watch could not make a key. It needs a passcode, with wrist detection on."
                : "Your Apple Watch did not answer as expected. Update isudo on both devices.")
            return
        }
        let name = Delegation.usableName(from: rawName)
        let signed: SignedDelegation
        do {
            let signer = try Signers.load(
                pairingIDHex: pairing.idHex, from: secrets, publicKey: pairing.signPub, hardwareBacked: pairing.hardwareBacked
            )
            signed = try await pairing.delegate(
                watchSignPub: signPub, watchKemPub: kemPub, name: name, now: now(), signer: signer,
                prompt: "Allow \(name) to approve simple requests for \(pairing.hostName)"
            )
        } catch {
            fail("Not allowed: Face ID did not complete.")
            return
        }
        guard let encoded = signed.encode() else {
            fail("The authorisation could not be made.")
            return
        }
        do {
            let relay = try RelayClient(baseURL: pairing.relayURL)
            let token = try PairingSecrets.token(pairingIDHex: pairing.idHex, from: secrets)
            let body = API.AddDelegate(delegation: Codec.b64Encode(encoded), delegateToken: watchToken)
            try await relay.addDelegate(pairingID: pairing.idHex, token: token, body)
        } catch {
            let why = (error as? RelayError)?.message ?? "The relay could not be told."
            fail(why + " Your Apple Watch was not set up.")
            return
        }
        // Sent both ways: at once if the watch is still listening, and in
        // the queue it reads when its app next runs.
        let message = WatchMessage.delegation(pairingID: pairingID, signed: encoded)
        link.tell(message)
        _ = try? await link.ask(message)
        watchGrants.removeAll { $0.pairingID == pairingID }
        watchGrants.append(WatchGrant(pairingID: pairingID, signPub: signPub, name: name, notAfter: signed.delegation.notAfter))
        watchSetup[pairingID] = nil
        save()
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }

    /// Stops the watch answering for a pairing: the relay stops serving it
    /// and the watch forgets its keys.
    ///
    /// The computer would still honour that watch's signature until the
    /// authorisation runs out. If the watch is lost rather than merely
    /// unwanted, turn the watch off on the computer (`sudo isudo-admin watch
    /// off`), which takes effect at once.
    func removeWatch(_ pairingID: Data) async {
        guard let grant = watchGrant(pairingID), let pairing = pairing(pairingID) else { return }
        if let relay = try? RelayClient(baseURL: pairing.relayURL),
           let token = try? PairingSecrets.token(pairingIDHex: pairing.idHex, from: secrets) {
            let body = API.RemoveDelegate(delegate: Codec.b64Encode(grant.signPub))
            try? await relay.removeDelegate(pairingID: pairing.idHex, token: token, body)
        }
        watchLink?.tell(.removed(pairingID: pairingID))
        watchGrants.removeAll { $0.pairingID == pairingID }
        watchSetup[pairingID] = nil
        save()
    }

    /// Something the watch sent. The only thing it can ask of the phone is
    /// to carry an answer, already signed by the watch, to the relay.
    private func fromWatch(_ message: WatchMessage) async -> WatchMessage? {
        switch message {
        case .answer(let pairingID, let requestID, let token, let body):
            guard let pairing = pairing(pairingID) else { return .failed(.unknownPairing) }
            guard let answer = try? JSONDecoder().decode(API.Answer.self, from: body),
                  let relay = try? RelayClient(baseURL: pairing.relayURL)
            else { return .failed(.malformed) }
            do {
                try await relay.answer(requestID: requestID, token: token, answer)
            } catch RelayError.status(let status) {
                return .delivered(status: status)
            } catch {
                return .delivered(status: 0)
            }
            settled(requestID: requestID)
            return .delivered(status: 204)
        case .settled(let requestID):
            settled(requestID: requestID)
            return nil
        case .offer, .keys, .delegation, .removed, .delivered, .failed:
            return .failed(.malformed)
        }
    }

    /// A request was answered, here or on the watch. Its card and its
    /// notification have nothing left to say.
    func settled(requestID: String) {
        waiting.removeAll { item in
            guard item.card.requestIDHex == requestID else { return false }
            // A card this phone is in the middle of answering finishes itself.
            if case .waiting = item.phase { return true }
            return false
        }
        Notifications.clear(requestID: requestID)
    }

    func unpair(_ id: Data) async {
        guard let pairing = pairing(id) else { return }
        if !isFixture, let relay = try? RelayClient(baseURL: pairing.relayURL),
           let token = try? PairingSecrets.token(pairingIDHex: pairing.idHex, from: secrets) {
            // Best effort: forgetting the keys is what ends the pairing here.
            try? await relay.unpair(pairingID: pairing.idHex, token: token)
        }
        forget(id)
    }

    // MARK: Push

    private var currentDevice: API.DeviceUpdate? {
        deviceToken.map { API.DeviceUpdate(apnsToken: $0, apnsEnv: Notifications.environment) }
    }

    func setDeviceToken(_ token: String) {
        deviceToken = token
        Task { await registerDevice() }
    }

    private func registerDevice() async {
        guard let device = currentDevice else { return }
        for pairing in pairings {
            guard let relay = try? RelayClient(baseURL: pairing.relayURL),
                  let token = try? PairingSecrets.token(pairingIDHex: pairing.idHex, from: secrets)
            else { continue }
            try? await relay.updateDevice(pairingID: pairing.idHex, token: token, device)
        }
    }

    // MARK: Answering

    private func setPhase(_ id: Data, _ phase: WaitingRequest.Phase) {
        guard let index = waiting.firstIndex(where: { $0.id == id }) else { return }
        waiting[index].phase = phase
    }

    func approve(_ item: WaitingRequest) async {
        await answer(item, reason: nil)
    }

    func deny(_ item: WaitingRequest, reason: String) async {
        await answer(item, reason: reason)
    }

    /// Signs (behind Face ID) and delivers. `reason` nil means approve.
    private func answer(_ item: WaitingRequest, reason: String?) async {
        let outcome: ActivityEntry.Outcome = reason == nil ? .approved : .denied
        if isFixture {
            await finish(item, outcome, reason: reason)
            return
        }
        guard let pairing = pairing(item.pairingID) else { return }
        setPhase(item.id, .signing)
        let signed: API.Answer
        do {
            let signer = try Signers.load(
                pairingIDHex: pairing.idHex, from: secrets, publicKey: pairing.signPub, hardwareBacked: pairing.hardwareBacked
            )
            if let reason {
                signed = try await pairing.deny(item.card, reason: reason, signer: signer, prompt: "Deny this request")
            } else {
                let prompt = "Approve running \(item.display.summary.prefix(80)) as root"
                signed = try await pairing.approve(item.card, signer: signer, prompt: prompt)
            }
        } catch {
            diagnostics.error("signing failed: \(String(describing: error), privacy: .public)")
            setPhase(item.id, .waiting)
            notice = reason == nil
                ? "Not approved: Face ID did not complete. If Face ID was changed since pairing, pair this computer again."
                : "The denial was not sent because Face ID did not complete. The request will simply expire."
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            return
        }
        if let index = waiting.firstIndex(where: { $0.id == item.id }) {
            waiting[index].signedAnswer = signed
        }
        await deliver(item.id)
    }

    /// Sends an already signed answer. Safe to repeat.
    func deliver(_ id: Data) async {
        guard let item = waiting.first(where: { $0.id == id }), let signed = item.signedAnswer,
              let pairing = pairing(item.pairingID)
        else { return }
        setPhase(id, .sending)
        do {
            let relay = try RelayClient(baseURL: pairing.relayURL)
            let token = try PairingSecrets.token(pairingIDHex: pairing.idHex, from: secrets)
            try await relay.answer(requestID: item.card.requestIDHex, token: token, signed)
        } catch RelayError.status(404), RelayError.status(409) {
            // The computer stopped waiting, or an answer already stands.
            setPhase(id, .waiting)
            record(.expired, item)
            waiting.removeAll { $0.id == id }
            notice = "The computer had already stopped waiting for that request."
            return
        } catch {
            diagnostics.error("could not deliver the answer: \(String(describing: error), privacy: .public)")
            let why = (error as? RelayError)?.message ?? "The answer could not be sent."
            setPhase(id, .undelivered(why))
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            return
        }
        await finish(item, signed.decision == .approve ? .approved : .denied, reason: signed.reason)
    }

    private func finish(_ item: WaitingRequest, _ outcome: ActivityEntry.Outcome, reason: String?) async {
        setPhase(item.id, .finished(outcome))
        // The watch may be showing the same request.
        watchLink?.tell(.settled(requestID: item.card.requestIDHex))
        Notifications.clear(requestID: item.card.requestIDHex)
        UINotificationFeedbackGenerator().notificationOccurred(outcome == .approved ? .success : .warning)
        record(outcome, item, reason: reason)
        try? await Task.sleep(for: .seconds(1.1))
        waiting.removeAll { $0.id == item.id }
    }
}

/// Pairings and history on disk. Neither file holds a secret: keys and
/// tokens are in the Keychain.
struct Storage {
    let directory: URL?

    init() {
        directory = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        )
    }

    init(directory: URL?) {
        self.directory = directory
    }

    private func load<T: Decodable>(_ name: String, default value: T) -> T {
        guard let url = directory?.appending(path: name), let data = try? Data(contentsOf: url) else { return value }
        return (try? JSONDecoder().decode(T.self, from: data)) ?? value
    }

    private func save(_ value: some Encodable, as name: String) {
        guard let url = directory?.appending(path: name), let data = try? JSONEncoder().encode(value) else { return }
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    func loadPairings() -> [Pairing] { load("pairings.json", default: []) }
    func loadActivity() -> [ActivityEntry] { load("activity.json", default: []) }
    func loadWatchGrants() -> [WatchGrant] { load("watch.json", default: []) }
    func save(watchGrants: [WatchGrant]) { save(watchGrants, as: "watch.json") }
    func save(pairings: [Pairing]) { save(pairings, as: "pairings.json") }
    func save(activity: [ActivityEntry]) { save(activity, as: "activity.json") }
}
