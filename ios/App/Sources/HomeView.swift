import IsudoKit
import SwiftUI

struct HomeView: View {
    @Environment(AppModel.self) private var model
    @State private var showingPairing = false

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Group {
                if model.pairings.isEmpty && model.waiting.isEmpty {
                    EmptyStateView { startPairing() }
                } else {
                    content
                }
            }
            .background(Theme.page)
            .navigationTitle("isudo")
            .toolbar {
                if !model.pairings.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Pair a computer", systemImage: "plus") { startPairing() }
                    }
                }
            }
            .navigationDestination(for: Data.self) { id in
                PairingDetailView(pairingID: id)
            }
        }
        .sheet(isPresented: Binding(
            get: { model.pairingFlow != nil },
            set: { if !$0 { model.cancelPairing() } }
        )) {
            PairingFlowView()
        }
        .alert("isudo", isPresented: Binding(get: { model.notice != nil }, set: { if !$0 { model.notice = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.notice ?? "")
        }
    }

    private func startPairing() {
        model.pairingFlow = .scanning
    }

    private var content: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 28) {
                if model.waiting.isEmpty {
                    QuietCard()
                } else {
                    VStack(alignment: .leading, spacing: 14) {
                        SectionTitle(model.waiting.count == 1 ? "Waiting for you" : "\(model.waiting.count) waiting for you")
                        ForEach(model.waiting) { item in
                            RequestCardView(item: item)
                                .transition(.asymmetric(insertion: .scale(scale: 0.96).combined(with: .opacity), removal: .opacity))
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 10) {
                    SectionTitle("Computers")
                    VStack(spacing: 0) {
                        ForEach(model.pairings) { pairing in
                            NavigationLink(value: pairing.pairingID) {
                                PairingRow(pairing: pairing)
                            }
                            .buttonStyle(.plain)
                            if pairing.id != model.pairings.last?.id {
                                Divider().padding(.leading, 68)
                            }
                        }
                    }
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                }

                if !model.activity.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionTitle("Recent")
                        VStack(spacing: 0) {
                            ForEach(model.activity.prefix(20)) { entry in
                                ActivityRow(entry: entry)
                                if entry.id != model.activity.prefix(20).last?.id {
                                    Divider().padding(.leading, 52)
                                }
                            }
                        }
                        .background(Theme.card, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 32)
            .animation(.snappy, value: model.waiting.map(\.id))
        }
    }
}

struct SectionTitle: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.title3.weight(.semibold))
            .padding(.horizontal, 4)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Shown at the top when nothing is waiting.
struct QuietCard: View {
    var body: some View {
        HStack(spacing: 14) {
            SymbolBadge(symbol: "checkmark.shield.fill", tint: .green)
            VStack(alignment: .leading, spacing: 2) {
                Text("Nothing is waiting").font(.headline)
                Text("When a computer asks to run something as root, it appears here.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(18)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }
}

struct PairingRow: View {
    let pairing: Pairing

    var body: some View {
        HStack(spacing: 14) {
            SymbolBadge(symbol: "desktopcomputer", tint: pairing.active ? .accentColor : .orange, size: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text(pairing.hostName).font(.body.weight(.medium))
                if !pairing.active {
                    Text("Waiting for the computer to confirm").font(.footnote).foregroundStyle(.orange)
                } else if !pairing.hardwareBacked {
                    Tag(text: "Simulator key, not protected by Face ID", symbol: "exclamationmark.triangle.fill", tint: .orange)
                } else {
                    Text("Approvals need Face ID").font(.footnote).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .contentShape(.rect)
    }
}

struct ActivityRow: View {
    let entry: ActivityEntry

    private var symbol: (name: String, tint: Color) {
        switch entry.outcome {
        case .approved: ("checkmark.circle.fill", .green)
        case .denied: ("xmark.circle.fill", .secondary)
        case .expired: ("clock.fill", .secondary)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol.name)
                .font(.title3)
                .foregroundStyle(symbol.tint)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(entry.summary)
                    .font(.system(.subheadline, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.tail)
                HStack(spacing: 4) {
                    Text(entry.outcome.rawValue.capitalized)
                    Text("·")
                    Text(entry.hostName)
                    Text("·")
                    Text(entry.date, format: .relative(presentation: .named))
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                if let reason = entry.reason, !reason.isEmpty {
                    Text("“\(reason)”").font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .accessibilityElement(children: .combine)
    }
}

struct EmptyStateView: View {
    let pair: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ZStack {
                Circle().fill(Color.accentColor.opacity(0.10)).frame(width: 148, height: 148)
                Circle().fill(Color.accentColor.opacity(0.12)).frame(width: 104, height: 104)
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 50, weight: .medium))
                    .foregroundStyle(Color.accentColor)
            }
            .accessibilityHidden(true)
            .padding(.bottom, 28)

            Text("Root, with your say-so")
                .font(.largeTitle.weight(.bold))
                .multilineTextAlignment(.center)
            Text("When something on your computer wants to run a command as root, you see exactly what it is here, and approve it with Face ID.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 10)
                .padding(.horizontal, 12)

            Spacer()

            VStack(spacing: 14) {
                HStack(spacing: 8) {
                    Text("On the computer, run")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text("sudo isudo-admin pair")
                        .font(.system(.footnote, design: .monospaced).weight(.medium))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                }
                Button(action: pair) {
                    Label("Pair a computer", systemImage: "qrcode.viewfinder")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
            }
            .padding(.bottom, 24)
        }
        .padding(.horizontal, 28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct PairingDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let pairingID: Data
    @State private var confirmingUnpair = false

    var body: some View {
        if let pairing = model.pairing(pairingID) {
            List {
                Section {
                    LabeledContent("Computer", value: pairing.hostName)
                    LabeledContent("Status", value: pairing.active ? "Paired" : "Waiting for confirmation")
                    LabeledContent("Relay") {
                        Text(pairing.relayURL).font(.system(.footnote, design: .monospaced)).multilineTextAlignment(.trailing)
                    }
                    LabeledContent("Pairing") {
                        Text(pairing.idHex.prefix(12) + "…").font(.system(.footnote, design: .monospaced))
                    }
                }
                Section {
                    if pairing.hardwareBacked {
                        Label {
                            Text("This pairing’s key lives in the Secure Enclave. Each approval needs Face ID, and changing the enrolled face ends the pairing.")
                        } icon: {
                            Image(systemName: "faceid").foregroundStyle(Color.accentColor)
                        }
                    } else {
                        Label {
                            Text("This pairing uses a software key because it was made in the Simulator. It is not protected by Face ID and must not guard a real machine.")
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                    }
                }
                .font(.footnote)
                Section {
                    Button("Unpair this computer", role: .destructive) { confirmingUnpair = true }
                } footer: {
                    Text("The computer will no longer be able to get anything approved by this phone. To pair again, run sudo isudo-admin unpair and then pair on the computer.")
                }
            }
            .navigationTitle(pairing.hostName)
            .navigationBarTitleDisplayMode(.inline)
            .confirmationDialog("Unpair \(pairing.hostName)?", isPresented: $confirmingUnpair, titleVisibility: .visible) {
                Button("Unpair", role: .destructive) {
                    Task {
                        await model.unpair(pairingID)
                        dismiss()
                    }
                }
            }
        } else {
            ContentUnavailableView("No longer paired", systemImage: "desktopcomputer.trianglebadge.exclamationmark")
        }
    }
}
