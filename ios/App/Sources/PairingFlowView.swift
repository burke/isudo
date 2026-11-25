import IsudoKit
import SwiftUI
import VisionKit

/// The pairing sheet: scan, show the code, and say plainly how it ended.
struct PairingFlowView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            Group {
                switch model.pairingFlow {
                case .scanning, nil:
                    ScanStep()
                case .confirming(let offer, let source):
                    ConfirmStep(offer: offer, source: source)
                case .contacting(let hostName):
                    VStack(spacing: 16) {
                        ProgressView().controlSize(.large)
                        Text("Contacting \(hostName)…").foregroundStyle(.secondary)
                    }
                case .waitingForComputer(let hostName, _):
                    WaitingStep(hostName: hostName)
                case .code(let hostName, let code, _):
                    CodeStep(hostName: hostName, code: code)
                case .otherPhoneAccepted(let hostName):
                    ResultStep(
                        symbol: "exclamationmark.octagon.fill", tint: Theme.risk,
                        title: "\(hostName) accepted a different phone",
                        message: "This phone is not paired, and has no code to show.\n\nDo not type any code into the computer. Press Control-C there, then run the pairing command again somewhere the QR code cannot be seen."
                    )
                case .steered(let hostName):
                    ResultStep(
                        symbol: "exclamationmark.octagon.fill", tint: Theme.risk,
                        title: "That pairing code is not genuine",
                        message: "It claimed to be from \(hostName) and tried to choose the code this phone would show, which a real computer never does. This phone is not paired.\n\nDo not type any code into a computer. If you are pairing one now, press Control-C there and start again where its screen and clipboard cannot be interfered with."
                    )
                case .alreadyClaimed(let hostName):
                    ResultStep(
                        symbol: "exclamationmark.octagon.fill", tint: Theme.risk,
                        title: "Another phone scanned this code first",
                        message: "This phone is not paired with \(hostName).\n\nIf that other phone is not yours, do not type any code into the computer. Press Control-C there, then run the pairing command again somewhere the QR code cannot be seen."
                    )
                case .failed(let message):
                    ResultStep(symbol: "xmark.circle.fill", tint: .secondary, title: "Not paired", message: message)
                case .paired(let hostName, let hardwareBacked):
                    ResultStep(
                        symbol: "checkmark.circle.fill", tint: .green,
                        title: "Paired with \(hostName)",
                        message: hardwareBacked
                            ? "Commands run with isudo on that computer now need your approval here, with Face ID."
                            : "Paired using a Simulator key that is not protected by Face ID. Use this for testing only."
                    )
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(24)
            .background(Theme.page)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    switch model.pairingFlow {
                    case .paired, .failed, .alreadyClaimed, .otherPhoneAccepted, .steered:
                        EmptyView()
                    default:
                        Button("Cancel") { model.cancelPairing() }
                    }
                }
            }
            .navigationTitle("Pair a computer")
            .navigationBarTitleDisplayMode(.inline)
            .animation(.snappy, value: model.pairingFlow)
        }
        .interactiveDismissDisabled()
    }
}

private struct ScanStep: View {
    @Environment(AppModel.self) private var model
    @State private var pasting = false
    @State private var link = ""

    private var canScan: Bool { DataScannerViewController.isSupported && DataScannerViewController.isAvailable }

    var body: some View {
        VStack(spacing: 20) {
            if canScan {
                ScannerView { scanned in
                    model.review(link: scanned, source: .scan)
                }
                .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 28, style: .continuous).strokeBorder(.white.opacity(0.25), lineWidth: 1)
                }
            } else {
                Spacer()
                SymbolBadge(symbol: "qrcode.viewfinder", size: 88)
                Text("The camera is not available here.").foregroundStyle(.secondary)
                Spacer()
            }
            VStack(spacing: 6) {
                Text("Scan the code shown by").font(.subheadline).foregroundStyle(.secondary)
                Text("sudo isudo-admin pair").font(.system(.subheadline, design: .monospaced).weight(.medium))
            }
            Button {
                if let pasted = UIPasteboard.general.string, pasted.contains("isudo://pair") {
                    model.review(link: pasted, source: .paste)
                } else {
                    pasting = true
                }
            } label: {
                Label("Paste a pairing link instead", systemImage: "doc.on.clipboard").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            .controlSize(.large)
        }
        .alert("Pairing link", isPresented: $pasting) {
            TextField("isudo://pair?…", text: $link)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Pair") { model.review(link: link, source: .paste) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Paste the link printed under the QR code.")
        }
    }
}

/// A pairing code has been read. Before this phone makes keys or contacts
/// anything, the person sees which computer and relay it names and decides.
///
/// The name is only what the pairing code says, and anyone can write a
/// pairing code. What makes pairing safe is the six-digit code that follows;
/// this step is so that nothing happens behind the person's back, least of
/// all because some link was opened.
private struct ConfirmStep: View {
    @Environment(AppModel.self) private var model
    let offer: PairingOffer
    let source: OfferSource

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            SymbolBadge(symbol: "desktopcomputer", size: 88)
            Text("Pair with this computer?")
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
                .padding(.top, 24)
            VStack(alignment: .leading, spacing: 12) {
                detail("Computer", offer.hostName)
                Divider()
                detail("Relay", offer.relayURL)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .padding(.top, 24)
            if source == .link {
                Label {
                    Text("This pairing code came from a link opened on this phone, not from scanning a screen. Any app or web page can open one.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.risk)
                }
                .font(.subheadline)
                .padding(.top, 18)
            }
            Text("Continue only if you ran the pairing command on that computer yourself, just now. Nothing has been sent yet.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 18)
            Spacer()
            Button {
                Task { await model.confirmPairing() }
            } label: {
                Text("Pair with this computer").fontWeight(.semibold).frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
        }
    }

    private func detail(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            // Shown as text, never as Markdown or a link.
            Text(verbatim: value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }
}

/// After answering, before the computer has accepted this phone. The code
/// does not exist yet, so there is nothing to type.
private struct WaitingStep: View {
    let hostName: String

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ProgressView().controlSize(.extraLarge)
            Text("Waiting for the computer…")
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
                .padding(.top, 28)
            Text("Six digits will appear here once \(hostName) has accepted this phone. If the computer asks for a code before then, do not type one.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 12)
            Spacer()
        }
    }
}

private struct CodeStep: View {
    let hostName: String
    let code: String

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            Text("Type this code into the computer")
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
            HStack(spacing: 8) {
                ForEach(Array(code.enumerated()), id: \.offset) { index, digit in
                    Text(String(digit))
                        .font(.system(size: 40, weight: .semibold, design: .rounded).monospacedDigit())
                        .frame(width: 46, height: 64)
                        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .padding(.trailing, index == 2 ? 10 : 0)
                }
            }
            .padding(.top, 28)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Code \(code.map(String.init).joined(separator: " "))")

            Text("\(hostName) has accepted this phone and is asking for the code in the terminal. Typing it there finishes the pairing.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 24)
            Spacer()
            HStack(spacing: 10) {
                ProgressView()
                Text("Waiting for \(hostName)…").foregroundStyle(.secondary)
            }
            .font(.subheadline)
            .padding(.bottom, 12)
        }
    }
}

private struct ResultStep: View {
    @Environment(AppModel.self) private var model
    let symbol: String
    let tint: Color
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            Image(systemName: symbol)
                .font(.system(size: 68))
                .foregroundStyle(tint)
                .symbolEffect(.bounce, value: title)
            Text(title)
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
                .padding(.top, 20)
            Text(message)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 10)
            Spacer()
            Button {
                model.pairingFlow = nil
            } label: {
                Text("Done").fontWeight(.semibold).frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
        }
    }
}

/// The system's live QR scanner.
struct ScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        scanner.stopScanning()
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onScan: (String) -> Void
        private var done = false

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for case .barcode(let code) in addedItems {
                if let payload = code.payloadStringValue, payload.hasPrefix("isudo://pair") {
                    done = true
                    scanner.stopScanning()
                    onScan(payload)
                    return
                }
            }
        }
    }
}
