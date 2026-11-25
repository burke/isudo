import IsudoKit
import SwiftUI
import WatchKit

enum WatchTheme {
    /// Escaped characters: something in the command was not shown as is.
    static let escape = Color.orange
    static let risk = Color.red
}

extension EscapedText {
    /// The text with its escapes tinted, so nothing hides in it.
    var tinted: AttributedString {
        var out = AttributedString()
        for run in runs {
            var part = AttributedString(run.text)
            if run.isEscape {
                part.foregroundColor = WatchTheme.escape
            }
            out.append(part)
        }
        return out
    }
}

/// What the app shows when opened: the request that is waiting, or which
/// computers this watch may answer for.
struct WatchHomeView: View {
    @Environment(WatchModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            if let request = model.requests.first {
                // The computer's name takes the title's place beside the
                // clock, leaving the screen to the command.
                RequestView(request: request, showsHost: false)
                    .navigationTitle(Text(verbatim: request.display.host.plain))
                    .navigationBarTitleDisplayMode(.inline)
            } else {
                StatusView().navigationTitle("isudo")
            }
        }
        .alert("isudo", isPresented: Binding(get: { model.notice != nil }, set: { if !$0 { model.notice = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.notice ?? "")
        }
    }
}

/// Nothing is waiting. Says which computers this watch may answer for, and
/// what to do if there are none.
struct StatusView: View {
    @Environment(WatchModel.self) private var model

    var body: some View {
        List {
            if model.pairings.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Image(systemName: "iphone.and.arrow.forward").font(.title2).foregroundStyle(.tint)
                    Text("Not set up").font(.headline)
                    Text("Keep this open. On your iPhone, open isudo, choose a computer, and tap Allow Apple Watch.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 6)
            } else {
                Section {
                    ForEach(model.pairings, id: \.pairing.pairingID) { stored in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: stored.pairing.hostName).font(.headline)
                            Text(state(of: stored)).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                } footer: {
                    Text("Requests appear here and as notifications. This watch can approve simple ones and deny any; the rest need your iPhone.")
                }
            }
        }
    }

    private func state(of stored: StoredWatchPairing) -> String {
        guard let until = stored.pairing.authorisedUntil else { return "Waiting for your iPhone to allow this watch" }
        let date = Date(timeIntervalSince1970: Double(until))
        if date < Date() {
            return "Ran out \(date.formatted(date: .abbreviated, time: .omitted)). Renew on your iPhone."
        }
        return "Ready until \(date.formatted(date: .abbreviated, time: .omitted))"
    }
}

/// One request, in full. Everything the computer would run is on screen
/// before the controls are: they come after the last line of it.
struct RequestView: View {
    @Environment(WatchModel.self) private var model
    let request: WatchRequest
    /// False where the computer's name is already shown as the title.
    var showsHost = true
    @State private var denying = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { timeline in
            let seconds = model.secondsLeft(request, at: timeline.date)
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    header
                    CommandBlock(display: request.display)
                    Label {
                        Text(request.display.workingDirectory.tinted)
                    } icon: {
                        Image(systemName: "folder")
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    controls(seconds: seconds)
                }
                .padding(.horizontal, 2)
            }
        }
        .sheet(isPresented: $denying) {
            DenyView { reason in
                denying = false
                Task { await model.deny(request, reason: reason) }
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 1) {
            if showsHost {
                Text(request.display.host.tinted).font(.headline)
            }
            Text("wants to run as root").font(.caption2).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func controls(seconds: Int) -> some View {
        switch request.phase {
        case .working:
            HStack(spacing: 8) {
                ProgressView()
                Text("Sending…").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
        case .done(let approved):
            Label(approved ? "Approved" : "Denied", systemImage: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.headline)
                .foregroundStyle(approved ? .green : .secondary)
                .frame(maxWidth: .infinity)
        case .waiting, .undelivered:
            if seconds == 0 {
                Text("Expired. The computer has stopped waiting.").font(.footnote).foregroundStyle(.secondary)
            } else {
                if request.phase == .undelivered {
                    Text("Could not be sent. Try again.").font(.footnote).foregroundStyle(WatchTheme.risk)
                }
                if request.mayApprove {
                    HoldToApprove(secondsLeft: seconds) {
                        Task { await model.approve(request) }
                    }
                } else {
                    Label("Review on iPhone", systemImage: "iphone")
                        .font(.footnote.weight(.medium))
                        .frame(maxWidth: .infinity)
                    Text("This one needs your iPhone to approve. You can deny it here.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Button("Deny", role: .destructive) { denying = true }
            }
        }
    }
}

/// The program and every argument, each on its own line, nothing cut short.
struct CommandBlock: View {
    let display: RequestDisplay

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(display.executable.tinted)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            ForEach(Array(display.arguments.enumerated()), id: \.offset) { _, argument in
                Group {
                    if argument.isEmpty {
                        Text("(empty)").italic().foregroundStyle(.secondary)
                    } else {
                        Text(argument.tinted)
                    }
                }
                .font(.system(.body, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        // Not on the dimmed always-on face, where anyone could read it.
        .privacySensitive()
        .accessibilityElement(children: .combine)
    }
}

/// Approving takes a deliberate second of pressure, not a tap: a sleeve, a
/// stray touch or a habit must not be able to run something as root. Lifting
/// early cancels. It is never bound to Double Tap.
struct HoldToApprove: View {
    let secondsLeft: Int
    let action: () -> Void
    @State private var progress = 0.0
    @State private var fired = false

    private static let holdSeconds = 1.0

    var body: some View {
        ZStack {
            Capsule().fill(Color.accentColor.opacity(0.25))
            GeometryReader { proxy in
                Capsule().fill(Color.accentColor).frame(width: proxy.size.width * progress)
            }
            HStack(spacing: 6) {
                Text("Hold to approve").fontWeight(.semibold)
                Text("\(secondsLeft)s").monospacedDigit().foregroundStyle(.secondary)
            }
            .font(.footnote)
        }
        .frame(height: 44)
        .clipShape(Capsule())
        .contentShape(Capsule())
        .onLongPressGesture(minimumDuration: Self.holdSeconds, maximumDistance: 30) {
            guard !fired else { return }
            fired = true
            action()
        } onPressingChanged: { pressing in
            if pressing {
                WKInterfaceDevice.current().play(.start)
                withAnimation(.linear(duration: Self.holdSeconds)) { progress = 1 }
            } else if !fired {
                withAnimation(.easeOut(duration: 0.15)) { progress = 0 }
            }
        }
        .accessibilityElement()
        .accessibilityLabel("Approve")
        .accessibilityHint("Press and hold for one second")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { action() }
    }
}

/// A denial can carry a reason, which the program that asked reads as an
/// instruction from you. A few ready ones, or say your own.
struct DenyView: View {
    let deny: (String) -> Void
    @State private var custom = ""

    private static let reasons = ["Not now", "Ask me on my phone", "That is the wrong command"]

    var body: some View {
        List {
            Button("Deny", role: .destructive) { deny("") }
            Section("With a reason") {
                ForEach(Self.reasons, id: \.self) { reason in
                    Button(reason) { deny(reason) }
                }
                TextField("Say or write one", text: $custom)
                    .onSubmit {
                        let reason = custom.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !reason.isEmpty {
                            deny(reason)
                        }
                    }
            }
        }
        .navigationTitle("Deny")
    }
}
