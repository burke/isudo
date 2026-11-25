import Foundation
import IsudoKit
import WatchConnectivity
import os

/// The watch's end of the link to its own iPhone. See `WatchMessage` for
/// what crosses it. The phone asks this watch to make keys and tells it when
/// it has signed for them; the watch may ask the phone to carry an answer
/// it has already signed.
final class WatchLinkClient: NSObject, WCSessionDelegate, @unchecked Sendable {
    private let handle: @MainActor @Sendable (WatchMessage) async -> WatchMessage?
    private let session: WCSession
    /// Shows in Console.app; never contains keys or requests.
    private let diagnostics = Logger(subsystem: Bundle.main.bundleIdentifier ?? "isudo.watch", category: "phone")

    init(handle: @escaping @MainActor @Sendable (WatchMessage) async -> WatchMessage?) {
        self.handle = handle
        session = WCSession.default
        super.init()
        session.delegate = self
        session.activate()
    }

    /// Whether the phone can be asked something right now.
    var isReachable: Bool { session.activationState == .activated && session.isReachable }

    /// Asks the phone something and waits for its reply, or nil if the
    /// phone could not be reached.
    func ask(_ message: WatchMessage) async -> WatchMessage? {
        guard isReachable else { return nil }
        let dictionary = message.dictionary
        let session = session
        return await withCheckedContinuation { continuation in
            session.sendMessage(dictionary) { reply in
                continuation.resume(returning: WatchMessage(dictionary: reply))
            } errorHandler: { _ in
                continuation.resume(returning: nil)
            }
        }
    }

    /// Tells the phone something it should learn whenever it next can.
    func tell(_ message: WatchMessage) {
        guard session.activationState == .activated else { return }
        _ = session.transferUserInfo(message.dictionary)
    }

    func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: (any Error)?) {
        diagnostics.notice(
            "link to the phone: activated=\(state == .activated) reachable=\(session.isReachable) companionInstalled=\(session.isCompanionAppInstalled)"
        )
    }

    func sessionReachabilityDidChange(_ session: WCSession) {
        diagnostics.notice("link to the phone: reachable=\(session.isReachable)")
    }

    func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        guard let parsed = WatchMessage(dictionary: message) else {
            replyHandler(WatchMessage.failed(.malformed).dictionary)
            return
        }
        let reply = Reply(replyHandler)
        let handle = handle
        Task { @MainActor in
            reply.send(await handle(parsed) ?? .failed(.malformed))
        }
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any] = [:]) {
        guard let parsed = WatchMessage(dictionary: userInfo) else { return }
        let handle = handle
        Task { @MainActor in
            _ = await handle(parsed)
        }
    }

    /// The reply callback, which the system expects back exactly once.
    private final class Reply: @unchecked Sendable {
        private let handler: ([String: Any]) -> Void

        init(_ handler: @escaping ([String: Any]) -> Void) {
            self.handler = handler
        }

        func send(_ message: WatchMessage) {
            handler(message.dictionary)
        }
    }
}
