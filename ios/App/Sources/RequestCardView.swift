import IsudoKit
import SwiftUI

/// The approval card: who is asking, exactly what would run, anything that
/// weakens what the argument list tells you, and the two answers.
struct RequestCardView: View {
    @Environment(AppModel.self) private var model
    let item: WaitingRequest

    /// Whether the whole command has been on screen.
    @State private var readToEnd = false
    @State private var denying = false

    private var display: RequestDisplay { item.display }
    private var riskCount: Int { display.callouts.count(where: \.isRisk) }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            CommandPanel(arguments: display.arguments, readToEnd: $readToEnd)
            details
            if !display.callouts.isEmpty {
                VStack(spacing: 8) {
                    ForEach(display.callouts) { CalloutRow(callout: $0) }
                }
            }
            if !display.environment.isEmpty {
                EnvironmentDisclosure(entries: display.environment)
            }
            footer
        }
        .padding(20)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
        .overlay {
            if case .finished(let outcome) = item.phase {
                OutcomeOverlay(outcome: outcome)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
        .overlay {
            if riskCount > 0 {
                RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous)
                    .strokeBorder(Theme.risk.opacity(0.45), lineWidth: 1.5)
            }
        }
        .shadow(color: .black.opacity(0.08), radius: 18, y: 8)
        .sheet(isPresented: $denying) {
            DenySheet { reason in
                Task { await model.deny(item, reason: reason) }
            }
        }
        .animation(.snappy, value: item.phase)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            SymbolBadge(symbol: "desktopcomputer")
            VStack(alignment: .leading, spacing: 2) {
                Text(display.host.attributed())
                    .font(.headline)
                Text(asker)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                if riskCount > 0 {
                    Tag(
                        text: riskCount == 1 ? "1 warning below" : "\(riskCount) warnings below",
                        symbol: "exclamationmark.triangle.fill", tint: Theme.risk
                    )
                    .padding(.top, 3)
                }
            }
            Spacer(minLength: 8)
            Countdown(item: item)
        }
        .accessibilityElement(children: .combine)
    }

    /// "burke wants to run this as root", with the two names emphasized.
    private var asker: AttributedString {
        var who = display.user?.attributed() ?? AttributedString("User \(display.uid)")
        who.font = .subheadline.weight(.semibold)
        var root = AttributedString("root")
        root.font = .subheadline.weight(.semibold)
        return who + AttributedString(" wants to run as ") + root
    }

    private var details: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 8) {
            GridRow {
                Text("Program").detailLabel()
                Text(display.executable.attributed()).detailValue()
            }
            GridRow {
                Text("Folder").detailLabel()
                Text(display.workingDirectory.attributed()).detailValue()
            }
            if !display.ancestry.isEmpty {
                GridRow {
                    Text("Asked by").detailLabel()
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ancestry).detailValue()
                        Text("Process names are not verified").font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
        }
        .padding(.horizontal, 4)
    }

    private var ancestry: AttributedString {
        var out = AttributedString()
        for (index, name) in display.ancestry.enumerated() {
            if index > 0 {
                var arrow = AttributedString("  ‹  ")
                arrow.foregroundColor = .secondary
                out.append(arrow)
            }
            out.append(name.attributed())
        }
        return out
    }

    @ViewBuilder private var footer: some View {
        switch item.phase {
        case .undelivered(let why):
            VStack(alignment: .leading, spacing: 10) {
                Label(why, systemImage: "wifi.exclamationmark")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button {
                    Task { await model.deliver(item.id) }
                } label: {
                    Text("Send again").frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
            }
        default:
            VStack(spacing: 10) {
                if !readToEnd {
                    Label("Scroll through the whole command to approve", systemImage: "arrow.down")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 12) {
                    Button {
                        denying = true
                    } label: {
                        Text("Deny").fontWeight(.medium).frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)

                    Button {
                        Task { await model.approve(item) }
                    } label: {
                        Group {
                            if item.phase == .signing || item.phase == .sending {
                                ProgressView()
                            } else {
                                Label("Approve", systemImage: "faceid").fontWeight(.semibold)
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent)
                    .disabled(!readToEnd)
                }
                .controlSize(.large)
                .disabled(item.phase != .waiting)
            }
        }
    }
}

private extension Text {
    func detailLabel() -> some View {
        font(.caption.weight(.medium)).foregroundStyle(.secondary).gridColumnAlignment(.leading)
    }

    func detailValue() -> some View {
        font(.system(.footnote, design: .monospaced))
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The command, one argument per line, on a dark panel. Nothing is cut: a
/// long command scrolls, and `readToEnd` becomes true only once its last
/// line has been on screen.
struct CommandPanel: View {
    let arguments: [EscapedText]
    @Binding var readToEnd: Bool

    /// Tallest the panel grows before it scrolls.
    private let maxHeight: CGFloat = 340
    @State private var contentHeight: CGFloat = 0

    private var scrolls: Bool { contentHeight > maxHeight }

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(arguments.enumerated()), id: \.offset) { index, argument in
                    row(index: index, argument: argument)
                    if index < arguments.count - 1 {
                        Rectangle().fill(Theme.terminalRule).frame(height: 1).padding(.leading, 38)
                    }
                }
            }
            .padding(.vertical, 8)
            .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { height in
                contentHeight = height
                if height > 0, height <= maxHeight { readToEnd = true }
            }
        }
        .frame(height: contentHeight == 0 ? nil : min(contentHeight, maxHeight))
        .scrollBounceBehavior(.basedOnSize)
        .scrollIndicatorsFlash(onAppear: true)
        .onScrollGeometryChange(for: Bool.self) { geometry in
            geometry.contentOffset.y + geometry.containerSize.height >= geometry.contentSize.height - 12
        } action: { _, atEnd in
            if atEnd, contentHeight > 0 { readToEnd = true }
        }
        .background(Theme.terminal, in: RoundedRectangle(cornerRadius: Theme.panelRadius, style: .continuous))
        .overlay(alignment: .bottom) {
            if scrolls && !readToEnd {
                LinearGradient(colors: [.clear, Theme.terminal], startPoint: .top, endPoint: .bottom)
                    .frame(height: 44)
                    .clipShape(.rect(bottomLeadingRadius: Theme.panelRadius, bottomTrailingRadius: Theme.panelRadius))
                    .allowsHitTesting(false)
            }
        }
        .overlay {
            RoundedRectangle(cornerRadius: Theme.panelRadius, style: .continuous)
                .strokeBorder(.white.opacity(0.08), lineWidth: 1)
        }
        .environment(\.colorScheme, .dark)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Command, \(arguments.count) parts")
    }

    private func row(index: Int, argument: EscapedText) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(index == 0 ? "$" : "\(index)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(Theme.terminalDim)
                .frame(width: 20, alignment: .trailing)
                .accessibilityHidden(true)
            Group {
                if argument.isEmpty {
                    Text("empty").italic().foregroundStyle(Theme.escape)
                } else {
                    Text(argument.attributed(breakingLines: true)).foregroundStyle(Theme.terminalText)
                }
            }
            .font(.system(.callout, design: .monospaced).weight(index == 0 ? .bold : .regular))
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }
}

/// One thing that weakens what the argument list tells you.
struct CalloutRow: View {
    let callout: Callout

    private var tint: Color { callout.isRisk ? Theme.risk : .secondary }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(tint)
                .frame(width: 22)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.subheadline.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
                if let value {
                    // On its own lines and never shortened: this is part of
                    // what would run.
                    Text(value.attributed())
                        .font(.system(.footnote, design: .monospaced))
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                if let detail {
                    Text(detail).font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            callout.isRisk ? AnyShapeStyle(Theme.risk.opacity(0.10)) : AnyShapeStyle(.quaternary.opacity(0.5)),
            in: RoundedRectangle(cornerRadius: 14, style: .continuous)
        )
        .accessibilityElement(children: .combine)
    }

    private var symbol: String {
        switch callout.kind {
        case .executableWritable: "exclamationmark.triangle.fill"
        case .riskyVariable: "exclamationmark.triangle.fill"
        case .unseenInput: "arrow.down.doc"
        case .variable: "equal.circle"
        }
    }

    private var title: AttributedString {
        switch callout.kind {
        case .executableWritable:
            return AttributedString("This program can be changed without root")
        case .unseenInput:
            return AttributedString("Reads input that isn’t shown here")
        case .riskyVariable(let name, _), .variable(let name, _):
            var variable = name.attributed()
            variable.font = .system(.subheadline, design: .monospaced).weight(.semibold)
            return AttributedString("Sets ") + variable + AttributedString(" to")
        }
    }

    private var value: EscapedText? {
        switch callout.kind {
        case .riskyVariable(_, let value), .variable(_, let value): value
        case .executableWritable, .unseenInput: nil
        }
    }

    private var detail: String? {
        switch callout.kind {
        case .executableWritable: "What runs may not be what its name suggests."
        case .unseenInput: "It is fed from a pipe or file, and will act on whatever arrives."
        case .riskyVariable: "This variable can make the program run other code."
        case .variable: nil
        }
    }
}

/// The command's whole environment, folded away. Everything worth a
/// warning is already a callout above; this is for the curious.
struct EnvironmentDisclosure: View {
    let entries: [EnvironmentEntry]
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.snappy) { expanded.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Text("Environment").fontWeight(.medium)
                    Text(entries.count == 1 ? "1 variable" : "\(entries.count) variables").foregroundStyle(.tertiary)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.bold))
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Environment, \(entries.count) variables")
            .accessibilityHint(expanded ? "Hides the list" : "Shows every variable the command will receive")

            if expanded {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(entries) { entry in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(line(entry))
                                .font(.system(.caption, design: .monospaced))
                                .fixedSize(horizontal: false, vertical: true)
                                .textSelection(.enabled)
                            Text(source(entry)).font(.caption2).foregroundStyle(.tertiary)
                        }
                    }
                }
                .transition(.opacity)
            }
        }
        .padding(.horizontal, 4)
    }

    private func line(_ entry: EnvironmentEntry) -> AttributedString {
        var name = entry.name.attributed()
        name.foregroundColor = entry.isRisk ? Theme.risk : .secondary
        return name + AttributedString("=") + entry.value.attributed()
    }

    private func source(_ entry: EnvironmentEntry) -> String {
        switch entry.origin {
        case .constructed: "set by isudo"
        case .default: "passed from the caller by default"
        case .explicit: "requested by the caller"
        }
    }
}

/// Time left before the computer stops waiting.
struct Countdown: View {
    @Environment(AppModel.self) private var model
    let item: WaitingRequest

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = model.secondsLeft(item, at: context.date)
            let total = max(1, Int(item.card.request.ttlSecs))
            let urgent = left <= 15
            ZStack {
                Circle().stroke(.quaternary, lineWidth: 3)
                Circle()
                    .trim(from: 0, to: CGFloat(left) / CGFloat(total))
                    .stroke(urgent ? Color.orange : Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .animation(.linear(duration: 1), value: left)
                Text(left >= 60 ? "\(left / 60):\(String(format: "%02d", left % 60))" : "\(left)")
                    .font(.system(size: 12, weight: .semibold, design: .rounded).monospacedDigit())
                    .foregroundStyle(urgent ? Color.orange : .secondary)
                    .contentTransition(.numericText(countsDown: true))
            }
            .frame(width: 42, height: 42)
            .accessibilityLabel("\(left) seconds left")
        }
    }
}

/// Shown over a card for a moment once it has been answered.
struct OutcomeOverlay: View {
    let outcome: ActivityEntry.Outcome

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: outcome == .approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.system(size: 54))
                .symbolEffect(.bounce, value: outcome)
                .foregroundStyle(outcome == .approved ? Color.green : .secondary)
            Text(outcome == .approved ? "Approved" : "Denied")
                .font(.title3.weight(.semibold))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial)
        .transition(.opacity)
    }
}

/// Asks for an optional reason, which the caller on the computer will see.
struct DenySheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var reason = ""
    @FocusState private var focused: Bool
    let onDeny: (String) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Reason (optional)", text: $reason, axis: .vertical)
                        .lineLimit(2...5)
                        .focused($focused)
                } footer: {
                    Text("Whoever asked sees this on the computer. If an AI agent asked, it can act on it, for example “use the staging database instead”.")
                }
            }
            .navigationTitle("Deny request")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Deny") {
                        dismiss()
                        onDeny(reason.trimmingCharacters(in: .whitespacesAndNewlines))
                    }
                    .fontWeight(.semibold)
                }
            }
            .onAppear { focused = true }
        }
        .presentationDetents([.medium])
    }
}
