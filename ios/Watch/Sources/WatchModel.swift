import CryptoKit
import Foundation
import IsudoKit
import Observation
import UserNotifications
import WatchKit

/// One request on the watch: the card that passed every check, and where
/// answering it has got to.
struct WatchRequest: Identifiable, Equatable {
    enum Phase: Equatable {
        case waiting
        case working
        /// Signed and delivered: approved, or denied.
        case done(approved: Bool)
        /// Signed, but the answer could not be delivered.
        case undelivered
    }

    let pairingID: Data
    let hostName: String
    let card: Card
    let display: RequestDisplay
    var phase: Phase = .waiting

    var id: Data { card.requestID }
    /// Whether this watch may offer to approve it. If not, the watch shows
    /// it, can deny it, and sends the person to their phone.
    var mayApprove: Bool { card.request.watchMayApprove }
}

/// A pairing as the watch keeps it.
struct StoredWatchPairing: Codable, Equatable {
    var pairing: WatchPairing
    /// Whether the signing key is in the watch's Secure Enclave.
    var hardwareBacked: Bool
}

/// The watch app's state. Everything here runs on the main actor.
///
/// The watch is the second, lesser approver. It makes its own keys, answers
/// only while it holds the phone's current authorisation of them, makes
/// every check the phone makes before showing a request, and offers to
/// approve only what the computer marked as simple.
@MainActor
@Observable
final class WatchModel {
    static let shared = WatchModel()

    private(set) var pairings: [StoredWatchPairing] = []
    private(set) var requests: [WatchRequest] = []
    /// A problem worth telling the person about.
    var notice: String?

    private let secrets: any SecretStore
    private let directory: URL?
    private var link: WatchLinkClient?
    private var polling: Task<Void, Never>?

    private init() {
        secrets = KeychainSecretStore(service: Bundle.main.bundleIdentifier ?? "isudo.watch")
        directory = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        )
        if let url = directory?.appending(path: "pairings.json"), let data = try? Data(contentsOf: url) {
            pairings = (try? JSONDecoder().decode([StoredWatchPairing].self, from: data)) ?? []
        }
    }

    #if DEBUG
    /// True when showing built-in sample data.
    private(set) var isFixture = false

    func setFixture(pairings: [StoredWatchPairing], requests: [WatchRequest]) {
        isFixture = true
        self.pairings = pairings
        self.requests = requests
    }
    #else
    private let isFixture = false
    #endif

    private func save() {
        guard !isFixture else { return }
        guard let url = directory?.appending(path: "pairings.json"), let data = try? JSONEncoder().encode(pairings) else {
            return
        }
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    private func now() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970))
    }

    /// Pairings this watch may answer for right now.
    var ready: [StoredWatchPairing] {
        pairings.filter { ($0.pairing.authorisedUntil ?? 0) >= now() }
    }

    // MARK: The phone

    func start() {
        guard link == nil, !isFixture else { return }
        link = WatchLinkClient { [weak self] message in
            await self?.fromPhone(message)
        }
    }

    private func index(of pairingID: Data) -> Int? {
        pairings.firstIndex { $0.pairing.pairingID == pairingID }
    }

    private func fromPhone(_ message: WatchMessage) async -> WatchMessage? {
        switch message {
        case .offer(let pairingID, let hostPub, let hostName, let relayURL):
            return keys(pairingID: pairingID, hostPub: hostPub, hostName: hostName, relayURL: relayURL)
        case .delegation(let pairingID, let signed):
            guard let index = index(of: pairingID) else { return .failed(.unknownPairing) }
            guard let decoded = try? SignedDelegation.decode(signed), pairings[index].pairing.accept(decoded) else {
                return .failed(.malformed)
            }
            save()
            WKInterfaceDevice.current().play(.success)
            // Shared with the phone app's permission; asked here so that the
            // watch can show requests whichever device granted it.
            Task { _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) }
            return .delivered(status: 204)
        case .removed(let pairingID):
            forget(pairingID)
            return nil
        case .settled(let requestID):
            settled(requestID: requestID)
            return nil
        case .keys, .answer, .delivered, .failed:
            return .failed(.malformed)
        }
    }

    /// Makes this watch's keys for a pairing, or finds the ones it already
    /// made, and reports their public halves. Private keys never leave.
    private func keys(pairingID: Data, hostPub: Data, hostName: String, relayURL: String) -> WatchMessage {
        let idHex = Codec.hexEncode(pairingID)
        let name = WKInterfaceDevice.current().name
        if let index = index(of: pairingID), pairings[index].pairing.hostPub == hostPub,
           let token = try? PairingSecrets.token(pairingIDHex: idHex, from: secrets) {
            // A renewal: the same keys, signed for again.
            let known = pairings[index]
            return .keys(
                pairingID: pairingID, signPub: known.pairing.signPub, kemPub: known.pairing.kemPub, token: token, name: name,
                hardwareBacked: known.hardwareBacked
            )
        }
        forget(pairingID)
        do {
            let signer = try Signers.create(pairingIDHex: idHex, in: secrets)
            let (kemPub, token) = try PairingSecrets.create(pairingIDHex: idHex, in: secrets)
            let pairing = try WatchPairing(
                pairingID: pairingID, hostPub: hostPub, hostName: hostName, relayURL: relayURL, signPub: signer.publicKey,
                kemPub: kemPub
            )
            pairings.append(StoredWatchPairing(pairing: pairing, hardwareBacked: signer.isHardwareBacked))
            save()
            return .keys(
                pairingID: pairingID, signPub: signer.publicKey, kemPub: kemPub, token: token, name: name,
                hardwareBacked: signer.isHardwareBacked
            )
        } catch {
            PairingSecrets.delete(pairingIDHex: idHex, from: secrets)
            return .failed(.noKey)
        }
    }

    private func forget(_ pairingID: Data) {
        PairingSecrets.delete(pairingIDHex: Codec.hexEncode(pairingID), from: secrets)
        pairings.removeAll { $0.pairing.pairingID == pairingID }
        requests.removeAll { $0.pairingID == pairingID }
        save()
    }

    // MARK: Requests

    /// Takes a delivered request through every check and, if it passes,
    /// shows it. Returns the request shown, or nil.
    @discardableResult
    private func open(_ delivered: API.PendingRequest, pairingID: Data) -> WatchRequest? {
        if let known = requests.first(where: { $0.card.requestIDHex == delivered.requestID }) {
            return known
        }
        guard let index = index(of: pairingID),
              let kem = try? PairingSecrets.kemPrivate(pairingIDHex: pairings[index].pairing.idHex, from: secrets),
              let card = try? pairings[index].pairing.open(delivered, now: now(), kemPrivate: kem)
        else { return nil }
        save()
        let request = WatchRequest(
            pairingID: pairingID, hostName: pairings[index].pairing.hostName, card: card, display: RequestDisplay(card.request)
        )
        requests.append(request)
        return request
    }

    /// A notification about a request. If the relay sent the request along,
    /// sealed to this watch, it can be shown at once with nothing fetched.
    @discardableResult
    func received(push userInfo: [AnyHashable: Any]) -> WatchRequest? {
        guard let fields = userInfo["isudo"] as? [String: Any], let requestID = fields["r"] as? String,
              let pairingHex = fields["p"] as? String, let pairingID = try? Codec.hexDecode(pairingHex)
        else { return nil }
        if fields["done"] as? Bool == true {
            settled(requestID: requestID)
            return nil
        }
        if let envelope = fields["w"] as? String {
            let expiresAt = (fields["x"] as? NSNumber)?.uint64Value ?? 0
            let delivered = API.PendingRequest(requestID: requestID, expiresAt: expiresAt, envelope: envelope)
            if let shown = open(delivered, pairingID: pairingID) {
                return shown
            }
        }
        Task { await refresh() }
        return requests.first { $0.card.requestIDHex == requestID }
    }

    /// Asks each relay what is waiting. Works when the watch can reach the
    /// relay itself; when it cannot, requests still arrive in notifications.
    func refresh() async {
        guard !isFixture else { return }
        retire()
        for stored in ready {
            guard let relay = try? RelayClient(baseURL: stored.pairing.relayURL),
                  let token = try? PairingSecrets.token(pairingIDHex: stored.pairing.idHex, from: secrets),
                  let waiting = try? await relay.pending(pairingID: stored.pairing.idHex, token: token)
            else { continue }
            for delivered in waiting.requests {
                open(delivered, pairingID: stored.pairing.pairingID)
            }
        }
    }

    func startPolling() {
        guard polling == nil else { return }
        polling = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    func stopPolling() {
        polling?.cancel()
        polling = nil
    }

    func secondsLeft(_ request: WatchRequest, at date: Date = Date()) -> Int {
        max(0, Int(Double(request.card.expiresAt) - date.timeIntervalSince1970))
    }

    /// Drops requests the computer has stopped waiting for.
    func retire() {
        requests.removeAll { request in
            request.phase == .waiting && secondsLeft(request) == 0
        }
    }

    private func settled(requestID: String) {
        requests.removeAll { $0.card.requestIDHex == requestID && $0.phase == .waiting }
        clearNotification(requestID: requestID)
    }

    private func clearNotification(requestID: String) {
        let center = UNUserNotificationCenter.current()
        Task {
            let stale = await center.deliveredNotifications()
                .filter { (($0.request.content.userInfo["isudo"] as? [String: Any])?["r"] as? String) == requestID }
                .map(\.request.identifier)
            if !stale.isEmpty {
                center.removeDeliveredNotifications(withIdentifiers: stale)
            }
        }
    }

    // MARK: Answering

    private func setPhase(_ id: Data, _ phase: WatchRequest.Phase) {
        guard let index = requests.firstIndex(where: { $0.id == id }) else { return }
        requests[index].phase = phase
    }

    func approve(_ request: WatchRequest) async {
        await answer(request, reason: nil)
    }

    func deny(_ request: WatchRequest, reason: String) async {
        await answer(request, reason: reason)
    }

    /// Signs and delivers. `reason` nil means approve.
    ///
    /// The key is in this watch's Secure Enclave and signs only while the
    /// watch is unlocked and has stayed on the wrist. An approval is signed
    /// only for a request this watch may approve.
    private func answer(_ request: WatchRequest, reason: String?) async {
        if isFixture {
            setPhase(request.id, .done(approved: reason == nil))
            return
        }
        guard request.phase == .waiting || request.phase == .undelivered,
              let stored = pairings.first(where: { $0.pairing.pairingID == request.pairingID }),
              secondsLeft(request) > 0
        else { return }
        setPhase(request.id, .working)
        let signed: API.Answer
        do {
            let signer = try Signers.load(
                pairingIDHex: stored.pairing.idHex, from: secrets, publicKey: stored.pairing.signPub,
                hardwareBacked: stored.hardwareBacked
            )
            if let reason {
                signed = try await stored.pairing.deny(request.card, reason: reason, signer: signer, prompt: "Deny this request")
            } else {
                let approval = try await stored.pairing.approve(request.card, signer: signer, prompt: "Approve this request")
                guard let approval else {
                    setPhase(request.id, .waiting)
                    return
                }
                signed = approval
            }
        } catch {
            setPhase(request.id, .waiting)
            notice = "Not signed. Your watch must be unlocked and on your wrist."
            WKInterfaceDevice.current().play(.failure)
            return
        }
        switch await deliver(signed, for: request, stored: stored) {
        case .delivered:
            setPhase(request.id, .done(approved: reason == nil))
            WKInterfaceDevice.current().play(reason == nil ? .success : .directionDown)
            clearNotification(requestID: request.card.requestIDHex)
            link?.tell(.settled(requestID: request.card.requestIDHex))
            try? await Task.sleep(for: .seconds(1.4))
            requests.removeAll { $0.id == request.id }
        case .alreadyAnswered:
            // Another device got there first. This watch does not know what
            // it said, and must not claim its own answer counted.
            requests.removeAll { $0.id == request.id }
            clearNotification(requestID: request.card.requestIDHex)
            notice = "Already answered on your other device."
            WKInterfaceDevice.current().play(.retry)
        case .failed:
            setPhase(request.id, .undelivered)
            WKInterfaceDevice.current().play(.failure)
        }
    }

    private enum Delivery {
        case delivered
        /// The relay already holds an answer to this request.
        case alreadyAnswered
        case failed
    }

    /// Gets a signed answer to the relay: through the phone when it is in
    /// reach, which works even if the relay is on a network only the phone
    /// is part of, and otherwise directly. Whoever carries it cannot change
    /// it, and the relay keeps only the first answer to a request.
    private func deliver(_ answer: API.Answer, for request: WatchRequest, stored: StoredWatchPairing) async -> Delivery {
        let requestID = request.card.requestIDHex
        guard let token = try? PairingSecrets.token(pairingIDHex: stored.pairing.idHex, from: secrets) else { return .failed }
        if let link, link.isReachable, let body = try? JSONEncoder().encode(answer) {
            let carried = await link.ask(.answer(pairingID: stored.pairing.pairingID, requestID: requestID, token: token, body: body))
            switch carried {
            case .delivered(status: 204): return .delivered
            case .delivered(status: 409): return .alreadyAnswered
            default: break
            }
        }
        guard let relay = try? RelayClient(baseURL: stored.pairing.relayURL) else { return .failed }
        do {
            try await relay.answer(requestID: requestID, token: token, answer)
            return .delivered
        } catch RelayError.status(409) {
            return .alreadyAnswered
        } catch {
            return .failed
        }
    }
}
