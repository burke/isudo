import Foundation

/// Sizes fixed by the protocol. Mirrors the constants in `isudo_proto`.
public enum Proto {
    public static let pubkeyLength = 65
    public static let signatureLength = 64
    public static let pairingIDLength = 16
    public static let requestIDLength = 16
    public static let nonceLength = 32
    /// Length of the nonce in the host's pairing acknowledgement.
    /// The host's pairing nonce: committed to in the pairing code, revealed
    /// in the acknowledgement.
    public static let hostNonceLength = 16
    /// The phone's pairing nonce, sent with its answer.
    public static let phoneNonceLength = 16
    public static let commitmentLength = 32
    public static let secretLength = 32
    public static let maxRequestLength = 64 * 1024
    public static let maxReasonLength = 512
    public static let maxNameLength = 64
    public static let maxArgs = 4096
    public static let maxEnv = 1024
    public static let maxAncestry = 16
}

public enum WireError: Error, Equatable, Sendable {
    case truncated(String)
    case trailingBytes(Int)
    case invalid(String)
    case tooLarge(String)
}

/// A bounds-checked big-endian reader. Nothing here can trap.
struct Reader {
    private var rest: Data.SubSequence

    init(_ input: Data) {
        rest = input[...]
    }

    mutating func take(_ count: Int, _ what: String) throws(WireError) -> Data {
        guard count >= 0, rest.count >= count else { throw .truncated(what) }
        let head = rest.prefix(count)
        rest = rest.dropFirst(count)
        return Data(head)
    }

    mutating func u8(_ what: String) throws(WireError) -> UInt8 {
        try take(1, what)[0]
    }

    mutating func u32(_ what: String) throws(WireError) -> UInt32 {
        try take(4, what).reduce(0) { $0 << 8 | UInt32($1) }
    }

    mutating func u64(_ what: String) throws(WireError) -> UInt64 {
        try take(8, what).reduce(0) { $0 << 8 | UInt64($1) }
    }

    /// Length-prefixed bytes. The length is checked against the remaining
    /// input before anything is copied.
    mutating func bytes(_ what: String) throws(WireError) -> Data {
        let length = try u32(what)
        guard let count = Int(exactly: length) else { throw .tooLarge(what) }
        return try take(count, what)
    }

    mutating func count(max: Int, _ what: String) throws(WireError) -> Int {
        let value = try u32(what)
        guard let count = Int(exactly: value), count <= max else { throw .tooLarge(what) }
        return count
    }

    func finish() throws(WireError) {
        guard rest.isEmpty else { throw .trailingBytes(rest.count) }
    }
}

/// The approval request: everything the approver needs to see, and exactly
/// what the host will execute if it is approved. Mirrors
/// `isudo_proto::request::Request`; see that file for the layout.
public struct Request: Equatable, Sendable {
    public enum StdinKind: UInt8, Sendable, Equatable {
        case terminal = 0, null = 1, pipe = 2, file = 3, socket = 4, other = 5
    }

    public enum EnvOrigin: UInt8, Sendable, Equatable {
        /// On the short list passed through by default (TERM, LANG, ...).
        case `default` = 1
        /// The caller asked for it with `NAME=value` or `--preserve-env`.
        case explicit = 2
        /// Built by isudo itself (`PATH`, `HOME`, `USER`, ...), not taken
        /// from the caller. Carried so that the signed request describes the
        /// whole environment the command receives.
        case constructed = 3
    }

    public struct EnvVar: Equatable, Sendable {
        public var origin: EnvOrigin
        public var name: Data
        public var value: Data

        public init(origin: EnvOrigin, name: Data, value: Data) {
            self.origin = origin
            self.name = name
            self.value = value
        }
    }

    /// One process in the caller's ancestry. Names are chosen by the
    /// processes themselves: context, not identity.
    public struct Ancestor: Equatable, Sendable {
        public var pid: UInt32
        public var name: Data

        public init(pid: UInt32, name: Data) {
            self.pid = pid
            self.name = name
        }
    }

    public static let magic = Data("ISUDORQ".utf8) + [1]
    /// The executable, or its directory, can be modified without root.
    public static let flagExeWritable: UInt8 = 0x01
    private static let knownFlags: UInt8 = flagExeWritable | flagDelegable

    public var nonce: Data
    public var pairingID: Data
    public var issuedAt: UInt64
    public var ttlSecs: UInt32
    public var uid: UInt32
    public var gid: UInt32
    public var user: Data
    public var host: Data
    public var cwd: Data
    public var exe: Data
    public var flags: UInt8
    public var stdin: StdinKind
    public var argv: [Data]
    public var env: [EnvVar]
    public var ancestry: [Ancestor]

    public init(
        nonce: Data, pairingID: Data, issuedAt: UInt64, ttlSecs: UInt32, uid: UInt32, gid: UInt32,
        user: Data, host: Data, cwd: Data, exe: Data, flags: UInt8, stdin: StdinKind,
        argv: [Data], env: [EnvVar], ancestry: [Ancestor]
    ) {
        self.nonce = nonce
        self.pairingID = pairingID
        self.issuedAt = issuedAt
        self.ttlSecs = ttlSecs
        self.uid = uid
        self.gid = gid
        self.user = user
        self.host = host
        self.cwd = cwd
        self.exe = exe
        self.flags = flags
        self.stdin = stdin
        self.argv = argv
        self.env = env
        self.ancestry = ancestry
    }

    public var exeIsWritableByNonRoot: Bool { flags & Self.flagExeWritable != 0 }

    /// Strict decoding: unknown enum values, reserved flag bits and trailing
    /// bytes are all errors, so a decoder that accepts a request has seen
    /// all of it.
    public static func decode(_ input: Data) throws(WireError) -> Request {
        guard input.count <= Proto.maxRequestLength else { throw .tooLarge("request") }
        var r = Reader(input)
        guard try r.take(8, "magic") == magic else { throw .invalid("magic or version") }
        let nonce = try r.take(Proto.nonceLength, "nonce")
        let pairingID = try r.take(Proto.pairingIDLength, "pairing id")
        let issuedAt = try r.u64("issued_at")
        let ttlSecs = try r.u32("ttl")
        let uid = try r.u32("uid")
        let gid = try r.u32("gid")
        let user = try r.bytes("user")
        let host = try r.bytes("host")
        let cwd = try r.bytes("cwd")
        let exe = try r.bytes("exe")
        let flags = try r.u8("flags")
        guard flags & ~knownFlags == 0 else { throw .invalid("flags") }
        guard let stdin = StdinKind(rawValue: try r.u8("stdin kind")) else { throw .invalid("stdin kind") }

        var argv: [Data] = []
        for _ in 0..<(try r.count(max: Proto.maxArgs, "argument count")) {
            argv.append(try r.bytes("argument"))
        }
        var env: [EnvVar] = []
        for _ in 0..<(try r.count(max: Proto.maxEnv, "environment count")) {
            guard let origin = EnvOrigin(rawValue: try r.u8("env origin")) else { throw .invalid("env origin") }
            let name = try r.bytes("env name")
            let value = try r.bytes("env value")
            env.append(EnvVar(origin: origin, name: name, value: value))
        }
        var ancestry: [Ancestor] = []
        for _ in 0..<(try r.count(max: Proto.maxAncestry, "ancestry count")) {
            let pid = try r.u32("ancestor pid")
            ancestry.append(Ancestor(pid: pid, name: try r.bytes("ancestor name")))
        }
        try r.finish()
        return Request(
            nonce: nonce, pairingID: pairingID, issuedAt: issuedAt, ttlSecs: ttlSecs, uid: uid, gid: gid,
            user: user, host: host, cwd: cwd, exe: exe, flags: flags, stdin: stdin,
            argv: argv, env: env, ancestry: ancestry
        )
    }

    /// Encoding exists for tests and fixtures; in production only the host
    /// ever encodes a request.
    public func encode() -> Data {
        var out = Data()
        func u32(_ value: UInt32) { withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) } }
        func bytes(_ value: Data) {
            u32(UInt32(value.count))
            out.append(value)
        }
        out.append(Self.magic)
        out.append(nonce)
        out.append(pairingID)
        withUnsafeBytes(of: issuedAt.bigEndian) { out.append(contentsOf: $0) }
        u32(ttlSecs)
        u32(uid)
        u32(gid)
        bytes(user)
        bytes(host)
        bytes(cwd)
        bytes(exe)
        out.append(flags)
        out.append(stdin.rawValue)
        u32(UInt32(argv.count))
        argv.forEach(bytes)
        u32(UInt32(env.count))
        for variable in env {
            out.append(variable.origin.rawValue)
            bytes(variable.name)
            bytes(variable.value)
        }
        u32(UInt32(ancestry.count))
        for ancestor in ancestry {
            u32(ancestor.pid)
            bytes(ancestor.name)
        }
        return out
    }
}
