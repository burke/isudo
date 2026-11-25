import Foundation
import IsudoKit
import WatchConnectivity
import os

/// The phone's end of the link to its own Apple Watch.
///
/// What crosses it is described in `WatchMessage`. No private key does, and
/// nothing arriving over it is acted on without the person: authorising a
/// watch needs Face ID in this app, and an answer the phone carries for the
/// watch is already signed by the watch.
final class WatchLink: NSObject, WCSessionDelegate, @unchecked Sendable {
    /// Called on the main actor for each message from the watch, and returns
    /// the reply.
    private let handle: @MainActor @Sendable (WatchMessage) async -> WatchMessage?
    private let session: WCSession?
    /// Shows in Console.app; never contains keys or requests.
    private let diagnostics = Logger(subsystem: Bundle.main.bundleIdentifier ?? "isudo", category: "watch")

    /// The state of the link, for the log.
    private func describe() -> String {
        guard let session else { return "this device cannot have a watch" }
        return "activated=\(session.activationState == .activated) paired=\(session.isPaired) "
            + "watchAppInstalled=\(session.isWatchAppInstalled) reachable=\(session.isReachable)"
    }

    init(handle: @escaping @MainActor @Sendable (WatchMessage) async -> WatchMessage?) {
        self.handle = handle
        session = WCSession.isSupported() ? WCSession.default : nil
        super.init()
        session?.delegate = self
        session?.activate()
    }

    /// Whether this phone has a watch with the isudo app on it.
    var hasWatchApp: Bool {
        guard let session, session.activationState == .activated else { return false }
        return session.isPaired && session.isWatchAppInstalled
    }

    /// Whether the watch app can be talked to right now: it is open on the
    /// watch, and the watch is in range.
    var isReachable: Bool { hasWatchApp && session?.isReachable == true }

    enum LinkError: Error {
        case unreachable
        case noReply
    }

    /// Asks the watch something and waits for its reply.
    func ask(_ message: WatchMessage) async throws -> WatchMessage {
        guard isReachable, let session else {
            diagnostics.notice("cannot ask the watch: \(self.describe(), privacy: .public)")
            throw LinkError.unreachable
        }
        let dictionary = message.dictionary
        let diagnostics = diagnostics
        return try await withCheckedThrowingContinuation { continuation in
            session.sendMessage(dictionary) { reply in
                if let parsed = WatchMessage(dictionary: reply) {
                    continuation.resume(returning: parsed)
                } else {
                    continuation.resume(throwing: LinkError.noReply)
                }
            } errorHandler: { error in
                diagnostics.notice("the watch did not answer: \(String(describing: error), privacy: .public)")
                continuation.resume(throwing: LinkError.unreachable)
            }
        }
    }

    /// Tells the watch something it should learn even if it is not
    /// listening now. Delivered in order, when the watch app next runs.
    func tell(_ message: WatchMessage) {
        guard hasWatchApp, let session else { return }
        _ = session.transferUserInfo(message.dictionary)
    }

    // MARK: WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: (any Error)?) {
        diagnostics.notice("link to the watch: \(self.describe(), privacy: .public)")
    }

    func sessionReachabilityDidChange(_ session: WCSession) {
        diagnostics.notice("link to the watch: \(self.describe(), privacy: .public)")
    }

    func sessionDidBecomeInactive(_ session: WCSession) {}

    func sessionDidDeactivate(_ session: WCSession) {
        // The person switched watches. Talk to the new one.
        session.activate()
    }

    /// A message that wants a reply: the watch asking the phone to carry an
    /// answer to the relay.
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

    /// The reply callback, which the system hands over on its own queue and
    /// expects back exactly once, from anywhere.
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
