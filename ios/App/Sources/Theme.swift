import IsudoKit
import SwiftUI

/// Colours and shapes used across the app. Red means risk and nothing else.
enum Theme {
    /// The panel a command is shown on: dark in both appearances, like the
    /// terminal the command came from, so it is unmistakably the subject.
    static let terminal = Color(red: 0.055, green: 0.06, blue: 0.075)
    static let terminalText = Color(white: 0.94)
    static let terminalDim = Color(white: 0.52)
    static let terminalRule = Color(white: 1, opacity: 0.08)
    /// Stand-ins for characters that were not shown as they are.
    static let escape = Color(red: 1.0, green: 0.70, blue: 0.28)
    static let risk = Color.red
    static let cardRadius: CGFloat = 30
    static let panelRadius: CGFloat = 18

    static var card: Color { Color(uiColor: .secondarySystemGroupedBackground) }
    static var page: Color { Color(uiColor: .systemGroupedBackground) }
}

extension EscapedText {
    /// The text with its escapes tinted, for display on any background.
    ///
    /// With `breakingLines`, a real line break follows each escaped newline.
    /// The escape itself is still shown, so nothing is hidden; a script
    /// simply reads as the lines it is.
    func attributed(escape: Color = Theme.escape, breakingLines: Bool = false) -> AttributedString {
        var out = AttributedString()
        for run in runs {
            var part = AttributedString(run.text)
            if run.isEscape {
                part.foregroundColor = escape
                part.backgroundColor = escape.opacity(0.16)
            }
            out.append(part)
            if breakingLines, run.isEscape, run.text == "\\n" {
                out.append(AttributedString("\n"))
            }
        }
        return out
    }
}

/// A rounded square holding a symbol, used as a leading badge.
struct SymbolBadge: View {
    let symbol: String
    var tint: Color = .accentColor
    var size: CGFloat = 44

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.44, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: size * 0.3, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// A small capsule label.
struct Tag: View {
    let text: String
    var symbol: String?
    var tint: Color = .secondary

    var body: some View {
        HStack(spacing: 4) {
            if let symbol { Image(systemName: symbol) }
            Text(text)
        }
        .font(.caption2.weight(.semibold))
        .foregroundStyle(tint)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(tint.opacity(0.13), in: Capsule())
    }
}
