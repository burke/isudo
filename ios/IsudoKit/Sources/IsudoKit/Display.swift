import Foundation

/// Text chosen by someone else, rendered so that nothing is hidden: control
/// characters, invisible characters and bytes that are not valid UTF-8 are
/// replaced by visible escapes. Mirrors `isudo_proto::text::escape`, and
/// additionally remembers which parts are escapes so the UI can tint them.
public struct EscapedText: Equatable, Sendable {
    public struct Run: Equatable, Sendable {
        public var text: String
        /// True if this run stands in for something that was not shown as is.
        public var isEscape: Bool
    }

    public private(set) var runs: [Run] = []

    /// The whole text, escapes included.
    public var plain: String { runs.map(\.text).joined() }
    public var hasEscapes: Bool { runs.contains(where: \.isEscape) }
    public var isEmpty: Bool { runs.isEmpty }

    private mutating func append(_ text: String, escape: Bool) {
        if let last = runs.indices.last, runs[last].isEscape == escape, !escape {
            runs[last].text += text
        } else {
            runs.append(Run(text: text, isEscape: escape))
        }
    }

    public init(_ bytes: Data) {
        let bytes = Array(bytes)
        var index = 0
        while index < bytes.count {
            guard let (scalar, length) = Self.decodeScalar(bytes, at: index) else {
                let byte = bytes[index]
                append("\\x" + Codec.hexEncode([byte]), escape: true)
                index += 1
                continue
            }
            index += length
            switch scalar {
            case "\\": append("\\\\", escape: true)
            case "\n": append("\\n", escape: true)
            case "\r": append("\\r", escape: true)
            case "\t": append("\\t", escape: true)
            default:
                if Self.isControl(scalar) || Self.isInvisible(scalar) {
                    append("\\u{" + String(scalar.value, radix: 16) + "}", escape: true)
                } else {
                    append(String(Character(scalar)), escape: false)
                }
            }
        }
    }

    public init(_ text: String) {
        self.init(Data(text.utf8))
    }

    /// Decodes one well-formed UTF-8 scalar at `index`, or nil if the bytes
    /// there are not one (overlong forms, surrogates and values past
    /// U+10FFFF are all ill-formed).
    static func decodeScalar(_ bytes: [UInt8], at index: Int) -> (Unicode.Scalar, Int)? {
        let first = bytes[index]
        func continuation(_ offset: Int, _ range: ClosedRange<UInt8> = 0x80...0xBF) -> UInt32? {
            guard index + offset < bytes.count, range.contains(bytes[index + offset]) else { return nil }
            return UInt32(bytes[index + offset] & 0x3F)
        }
        switch first {
        case 0x00...0x7F:
            return (Unicode.Scalar(first), 1)
        case 0xC2...0xDF:
            guard let c1 = continuation(1) else { return nil }
            return Unicode.Scalar(UInt32(first & 0x1F) << 6 | c1).map { ($0, 2) }
        case 0xE0...0xEF:
            let secondRange: ClosedRange<UInt8> = first == 0xE0 ? 0xA0...0xBF : first == 0xED ? 0x80...0x9F : 0x80...0xBF
            guard let c1 = continuation(1, secondRange), let c2 = continuation(2) else { return nil }
            return Unicode.Scalar(UInt32(first & 0x0F) << 12 | c1 << 6 | c2).map { ($0, 3) }
        case 0xF0...0xF4:
            let secondRange: ClosedRange<UInt8> = first == 0xF0 ? 0x90...0xBF : first == 0xF4 ? 0x80...0x8F : 0x80...0xBF
            guard let c1 = continuation(1, secondRange), let c2 = continuation(2), let c3 = continuation(3) else {
                return nil
            }
            return Unicode.Scalar(UInt32(first & 0x07) << 18 | c1 << 12 | c2 << 6 | c3).map { ($0, 4) }
        default:
            return nil
        }
    }

    /// Unicode general category Cc, as Rust's `char::is_control`.
    static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value <= 0x1F || (0x7F...0x9F).contains(scalar.value)
    }

    /// Characters that change how surrounding text is displayed without
    /// being visible themselves: bidirectional controls, zero-width
    /// characters, and other invisible format characters.
    static func isInvisible(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x00AD,            // soft hyphen
             0x034F,            // combining grapheme joiner
             0x061C,            // Arabic letter mark
             0x115F, 0x1160,    // Hangul fillers
             0x17B4, 0x17B5,    // Khmer inherent vowels
             0x180B...0x180F,   // Mongolian variation selectors
             0x200B...0x200F,   // zero-width space and joiners, LRM, RLM
             0x2028, 0x2029,    // line and paragraph separators
             0x202A...0x202E,   // bidi embeddings and overrides
             0x2060...0x206F,   // word joiner, invisible operators, bidi isolates
             0x3164,            // Hangul filler
             0xFE00...0xFE0F,   // variation selectors
             0xFEFF,            // byte-order mark
             0xFFA0,            // halfwidth Hangul filler
             0xFFF9...0xFFFB,   // interlinear annotation
             0x1D173...0x1D17A, // musical format controls
             0xE0000...0xE0FFF: // tags and variation selectors supplement
            true
        default:
            false
        }
    }
}

/// Environment variables that can make a program run code of the caller's
/// choosing. Mirrors `isudo_proto::envrisk`; keep the two lists identical.
public enum EnvRisk {
    static let exact: Set<String> = [
        // sudo: shells
        "IFS", "CDPATH", "ENV", "BASH_ENV", "PS4", "GLOBIGNORE", "BASHOPTS", "SHELLOPTS",
        "FPATH", "NULLCMD", "READNULLCMD", "ZDOTDIR", "TMPPREFIX",
        // sudo: resolver, locale, terminal databases
        "LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES", "NLSPATH", "PATH_LOCALE",
        "TERMINFO", "TERMINFO_DIRS", "TERMPATH", "TERMCAP",
        // sudo: language runtimes
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
        "PERLIO_DEBUG", "PERLLIB", "PERL5LIB", "PERL5OPT", "PERL5DB",
        "PYTHONHOME", "PYTHONPATH", "PYTHONINSPECT", "PYTHONUSERBASE", "PYTHONSTARTUP",
        "RUBYLIB", "RUBYOPT", "NODE_OPTIONS", "NODE_PATH",
        "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_EXTERNAL_DIFF",
        "GCONV_PATH",
        // glibc secure-execution list (entries not already covered by LD_*)
        "GETCONF_DIR", "GLIBC_TUNABLES", "LOCPATH", "MALLOC_TRACE", "NIS_PATH",
        "RESOLV_HOST_CONF", "TMPDIR", "TZDIR",
        // commonly honoured by root-run tools
        "PATH", "HOME", "SHELL", "EDITOR", "VISUAL", "SUDO_EDITOR", "PAGER", "MANPAGER",
        "LESSOPEN", "LESSCLOSE", "SSH_ASKPASS", "SUDO_ASKPASS", "MAIL_CONFIG",
        "LUA_PATH", "LUA_CPATH", "LUA_INIT", "PYTHONBREAKPOINT", "PYTHONWARNINGS",
        "RUSTC_WRAPPER", "CARGO_HOME", "GOFLAGS", "DOCKER_HOST", "KUBECONFIG",
        "CURL_HOME", "WGETRC", "OPENSSL_CONF", "SSL_CERT_FILE", "SSL_CERT_DIR",
        "NIX_PATH", "NIX_CONF_DIR", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
    ]

    static let prefixes = [
        "LD_", "DYLD_", "_RLD", "LDR_", "KRB5_CONFIG", "GIT_CONFIG", "BASH_FUNC_",
        "MALLOC_", "NPM_CONFIG_", "PIP_", "BUNDLE_", "GEM_", "RUBY", "PERL5", "NODE_",
        "PYTHON",
    ]

    private static let exactBytes = Set(exact.map { Array($0.utf8) })
    private static let prefixBytes = prefixes.map { Array($0.utf8) }

    /// True if handing this variable to a root process deserves a warning.
    /// A name that is not valid UTF-8 always does.
    ///
    /// Compared as bytes, as the reference does and as the program that
    /// receives the variable will. Compared as Swift strings, `LD_` followed
    /// by a combining mark would not begin with `LD_`, and a Kelvin sign
    /// would pass for a K.
    public static func isRisky(_ name: Data) -> Bool {
        let bytes = Array(name)
        guard String(validatingUTF8: bytes) != nil else { return true }
        return exactBytes.contains(bytes) || prefixBytes.contains { bytes.starts(with: $0) }
    }
}

/// Something about a request that weakens what its argument list tells you.
public struct Callout: Equatable, Sendable, Identifiable {
    public enum Kind: Equatable, Sendable {
        /// The executable or its directory can be changed without root.
        case executableWritable
        /// Standard input is a pipe, file or socket whose content is not shown.
        case unseenInput
        /// A variable the caller asked to pass that can inject code.
        case riskyVariable(name: EscapedText, value: EscapedText)
        /// A variable the caller asked to pass.
        case variable(name: EscapedText, value: EscapedText)
    }

    public var kind: Kind
    public var id: Int

    /// Whether this deserves the colour reserved for risk.
    public var isRisk: Bool {
        switch kind {
        case .executableWritable, .riskyVariable: true
        case .unseenInput, .variable: false
        }
    }
}

/// One variable of the command's environment, for the full listing.
public struct EnvironmentEntry: Equatable, Sendable, Identifiable {
    public var id: Int
    public var name: EscapedText
    public var value: EscapedText
    public var origin: Request.EnvOrigin
    /// True if the caller asked for it and it can inject code.
    public var isRisk: Bool
}

/// A request prepared for display. Nothing is dropped or shortened.
public struct RequestDisplay: Equatable, Sendable {
    public var host: EscapedText
    /// The account name, or nil if the host could not determine one.
    public var user: EscapedText?
    public var uid: UInt32
    public var executable: EscapedText
    /// One entry per argument, the command name first.
    public var arguments: [EscapedText]
    public var workingDirectory: EscapedText
    public var callouts: [Callout]
    /// Names of the processes above the caller, nearest first. Chosen by
    /// those processes: context, not identity.
    public var ancestry: [EscapedText]
    /// Every variable the command will receive, in the request's order.
    /// Only the ones the caller asked for become callouts; the rest (built
    /// by isudo, or passed by default after checks) are here for the curious.
    public var environment: [EnvironmentEntry]

    public init(_ request: Request) {
        host = EscapedText(request.host)
        user = request.user.isEmpty ? nil : EscapedText(request.user)
        uid = request.uid
        executable = EscapedText(request.exe)
        arguments = request.argv.map { EscapedText($0) }
        workingDirectory = EscapedText(request.cwd)
        ancestry = request.ancestry.map { EscapedText($0.name) }
        environment = request.env.enumerated().map { index, variable in
            EnvironmentEntry(
                id: index, name: EscapedText(variable.name), value: EscapedText(variable.value), origin: variable.origin,
                isRisk: variable.origin == .explicit && EnvRisk.isRisky(variable.name)
            )
        }

        var kinds: [Callout.Kind] = []
        if request.exeIsWritableByNonRoot {
            kinds.append(.executableWritable)
        }
        switch request.stdin {
        case .terminal, .null: break
        case .pipe, .file, .socket, .other: kinds.append(.unseenInput)
        }
        for variable in request.env where variable.origin == .explicit {
            let (name, value) = (EscapedText(variable.name), EscapedText(variable.value))
            kinds.append(EnvRisk.isRisky(variable.name) ? .riskyVariable(name: name, value: value)
                : .variable(name: name, value: value))
        }
        callouts = kinds.enumerated().map { Callout(kind: $1, id: $0) }
    }

    public var hasRisk: Bool { callouts.contains(where: \.isRisk) }

    /// The command on one line, for history lists where truncation is fine.
    public var summary: String {
        arguments.map(\.plain).joined(separator: " ")
    }
}
