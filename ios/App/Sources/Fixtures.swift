#if DEBUG
import CryptoKit
import Foundation
import IsudoKit

/// Sample data for previews and screenshots, selected with `-fixture NAME`.
/// A fixture model talks to nobody and signs nothing.
struct Fixture {
    var pairings: [Pairing] = []
    var waiting: [WaitingRequest] = []
    var activity: [ActivityEntry] = []
    var pairingFlow: PairingFlow?

    init?(named name: String) {
        let laptop = Self.pairing("burke-mbp", id: 0xa1, hardwareBacked: true)
        let server = Self.pairing("build-server", id: 0xb2, hardwareBacked: true)
        switch name {
        case "empty":
            break
        case "quiet":
            pairings = [laptop, server]
            activity = Self.history
        case "plain":
            pairings = [laptop]
            waiting = [Self.waiting(Self.plain, laptop)]
            activity = Self.history
        case "risky":
            pairings = [laptop]
            waiting = [Self.waiting(Self.risky, laptop)]
        case "long":
            pairings = [laptop]
            waiting = [Self.waiting(Self.long, laptop)]
        case "multi":
            pairings = [laptop, server]
            waiting = [Self.waiting(Self.plain, laptop), Self.waiting(Self.restart, server)]
            activity = Self.history
        case "simulator":
            pairings = [Self.pairing("burke-mbp", id: 0xa1, hardwareBacked: false)]
            activity = Self.history
        case "waiting":
            pairingFlow = .waitingForComputer(hostName: "burke-mbp", pairingID: Data(repeating: 0xa1, count: 16))
        case "confirm", "confirmlink":
            let (pairingID, hostPub) = (Data(repeating: 0xa1, count: 16), P256.Signing.PrivateKey().publicKey.x963Representation)
            let offer = PairingOffer(
                relayURL: "https://relay.example", pairingID: pairingID, hostPub: hostPub,
                secret: Data(repeating: 1, count: 32), commitment: Data(repeating: 2, count: 32), hostName: "burke-mbp"
            )
            pairingFlow = .confirming(offer, source: name == "confirm" ? .scan : .link)
        case "steered":
            pairingFlow = .steered(hostName: "burke-mbp")
        case "otherphone":
            pairingFlow = .otherPhoneAccepted(hostName: "burke-mbp")
        case "code":
            pairingFlow = .code(hostName: "burke-mbp", code: "396666", pairingID: Data(repeating: 0xa1, count: 16))
        case "claimed":
            pairingFlow = .alreadyClaimed(hostName: "burke-mbp")
        case "paired":
            pairings = [laptop]
            pairingFlow = .paired(hostName: "burke-mbp", hardwareBacked: true)
        case "scan":
            pairingFlow = .scanning
        default:
            return nil
        }
    }

    /// A pairing confirmed by a host key made up on the spot.
    private static func pairing(_ name: String, id: UInt8, hardwareBacked: Bool) -> Pairing {
        let host = P256.Signing.PrivateKey()
        let (pairingID, hostPub) = (Data(repeating: id, count: 16), host.publicKey.x963Representation)
        let nonce = Data(repeating: 0x4e, count: Proto.hostNonceLength)
        let phoneNonce = Data(repeating: 0x70, count: Proto.phoneNonceLength)
        let offer = PairingOffer(
            relayURL: "https://relay.example", pairingID: pairingID, hostPub: hostPub,
            secret: Data(repeating: 1, count: 32),
            commitment: Crypto.commitment(pairingID: pairingID, hostPub: hostPub, hostNonce: nonce), hostName: name
        )
        let signPub = P256.Signing.PrivateKey().publicKey.x963Representation
        let kemPub = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        guard var pairing = try? Pairing(
            offer: offer, signPub: signPub, kemPub: kemPub, phoneNonce: phoneNonce, hardwareBacked: hardwareBacked
        ) else {
            fatalError("fixture pairing")
        }
        func signed(_ message: Data) -> String {
            Codec.b64Encode((try? host.signature(for: message).rawRepresentation) ?? Data())
        }
        let ack = API.Ack(
            nonce: Codec.b64Encode(nonce),
            hostSig: signed(Messages.pairAck(
                pairingID: offer.pairingID, phoneSignPub: signPub, phoneKemPub: kemPub, phoneNonce: phoneNonce, hostNonce: nonce
            ))
        )
        let confirm = signed(Messages.pairConfirm(pairingID: offer.pairingID, phoneSignPub: signPub, phoneKemPub: kemPub))
        _ = try? pairing.observe(API.PairingStatus(state: .active, ack: ack, hostSig: confirm))
        return pairing
    }

    private static func waiting(_ request: Request, _ pairing: Pairing) -> WaitingRequest {
        var request = request
        request.pairingID = pairing.pairingID
        request.host = Data(pairing.hostName.utf8)
        // Issued a few seconds ago, so the countdown is mid-flight.
        request.issuedAt = UInt64(Date().timeIntervalSince1970) - 14
        let card = Card.fixture(request)
        return WaitingRequest(pairingID: pairing.pairingID, card: card, display: RequestDisplay(card.request))
    }

    private static func request(
        exe: String, argv: [String], cwd: String = "/Users/burke/src/app", flags: UInt8 = 0,
        stdin: Request.StdinKind = .terminal, env: [Request.EnvVar] = [], ancestry: [String] = ["zsh", "claude"]
    ) -> Request {
        Request(
            nonce: Data(repeating: 7, count: 32), pairingID: Data(count: 16), issuedAt: 0, ttlSecs: 120,
            uid: 501, gid: 20, user: Data("burke".utf8), host: Data(), cwd: Data(cwd.utf8), exe: Data(exe.utf8),
            flags: flags, stdin: stdin, argv: argv.map { Data($0.utf8) },
            env: constructed + [.init(origin: .default, name: Data("TERM".utf8), value: Data("xterm-256color".utf8))] + env,
            ancestry: ancestry.enumerated().map { .init(pid: UInt32(4200 + $0), name: Data($1.utf8)) }
        )
    }

    /// The variables isudo builds for every command.
    private static let constructed: [Request.EnvVar] = [
        ("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"), ("HOME", "/var/root"), ("SHELL", "/bin/sh"),
        ("USER", "root"), ("LOGNAME", "root"), ("SUDO_USER", "burke"), ("SUDO_UID", "501"), ("SUDO_GID", "20"),
    ].map { .init(origin: .constructed, name: Data($0.0.utf8), value: Data($0.1.utf8)) }

    private static func explicit(_ name: String, _ value: String) -> Request.EnvVar {
        .init(origin: .explicit, name: Data(name.utf8), value: Data(value.utf8))
    }

    static let plain = request(exe: "/usr/sbin/nginx", argv: ["nginx", "-s", "reload"], cwd: "/Users/burke/src/site")

    static let restart = request(
        exe: "/usr/bin/systemctl", argv: ["systemctl", "restart", "postgresql@17-main.service"],
        cwd: "/home/deploy", ancestry: ["bash", "sshd"]
    )

    static let risky = request(
        exe: "/opt/homebrew/bin/node",
        argv: ["node", "-e", "require('fs').writeFileSync('/etc/hosts', data)\n\u{202e}// harmless", "--", ""],
        flags: Request.flagExeWritable, stdin: .pipe,
        env: [explicit("DEBUG", "1"), explicit("NODE_OPTIONS", "--require /tmp/hook.js")]
    )

    static let long = request(
        exe: "/bin/bash",
        argv: ["bash", "-c"] + [(1...22).map { "step_\($0) --target /srv/app/releases/2026-11-24 --verbose" }.joined(separator: " && \\\n  ")]
            + ["deploy", "--force"]
    )

    static var history: [ActivityEntry] {
        let now = Date()
        return [
            ActivityEntry(date: now.addingTimeInterval(-240), hostName: "burke-mbp", summary: "launchctl kickstart -k system/com.apple.mDNSResponder", outcome: .approved),
            ActivityEntry(date: now.addingTimeInterval(-3_100), hostName: "burke-mbp", summary: "rm -rf /var/db/postgres", outcome: .denied, reason: "use the staging database"),
            ActivityEntry(date: now.addingTimeInterval(-9_400), hostName: "build-server", summary: "apt-get install -y libssl-dev", outcome: .approved),
            ActivityEntry(date: now.addingTimeInterval(-90_000), hostName: "burke-mbp", summary: "tee /etc/hosts", outcome: .expired),
        ]
    }
}
#endif
