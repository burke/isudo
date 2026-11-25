#if DEBUG
import CryptoKit
import Foundation
import IsudoKit

/// Sample data for screenshots, selected with `-fixture NAME`. A model
/// showing a fixture talks to nobody and signs nothing.
extension WatchModel {
    func loadFixture(named name: String) {
        let host = P256.Signing.PrivateKey()
        let pairingID = Data(repeating: 0xa1, count: 16)
        func request(_ argv: [String], exe: String, marked: Bool, stdin: Request.StdinKind = .terminal) -> Request {
            Request(
                nonce: Data(repeating: UInt8(argv.count), count: 32), pairingID: pairingID,
                issuedAt: UInt64(Date().timeIntervalSince1970), ttlSecs: 120, uid: 501, gid: 20, user: Data("burke".utf8),
                host: Data("burke-mbp".utf8), cwd: Data("/Users/burke".utf8), exe: Data(exe.utf8),
                flags: marked ? Request.flagDelegable : 0, stdin: stdin, argv: argv.map { Data($0.utf8) },
                env: [.init(origin: .default, name: Data("TERM".utf8), value: Data("xterm".utf8))], ancestry: []
            )
        }
        func waiting(_ request: Request, phase: WatchRequest.Phase = .waiting) -> WatchRequest {
            WatchRequest(
                pairingID: pairingID, hostName: "burke-mbp", card: Card.fixture(request), display: RequestDisplay(request),
                phase: phase
            )
        }
        var stored: [StoredWatchPairing] = []
        if name != "empty", var pairing = try? WatchPairing(
            pairingID: pairingID, hostPub: host.publicKey.x963Representation, hostName: "burke-mbp",
            relayURL: "https://relay.example", signPub: P256.Signing.PrivateKey().publicKey.x963Representation,
            kemPub: P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        ) {
            let until = UInt64(Date().timeIntervalSince1970) + 80 * 24 * 60 * 60
            let delegation = Delegation(
                pairingID: pairingID, signPub: pairing.signPub, kemPub: pairing.kemPub, notAfter: until, name: "Apple Watch"
            )
            _ = pairing.accept(SignedDelegation(delegation: delegation, phoneSignature: Data(count: 64)))
            stored = [StoredWatchPairing(pairing: pairing, hardwareBacked: true)]
        }
        let simple = request(["nginx", "-s", "reload"], exe: "/usr/sbin/nginx", marked: true)
        let longer = request(
            ["launchctl", "kickstart", "-k", "system/com.openssh.sshd"], exe: "/bin/launchctl", marked: true
        )
        let script = request(["sh", "-c", "curl -fsSL https://example.com/install.sh | sh"], exe: "/bin/sh", marked: false, stdin: .pipe)
        let requests: [WatchRequest] = switch name {
        case "simple": [waiting(simple)]
        case "longer": [waiting(longer)]
        case "phone-only": [waiting(script)]
        case "approved": [waiting(simple, phase: .done(approved: true))]
        default: []
        }
        setFixture(pairings: stored, requests: requests)
    }
}
#endif
