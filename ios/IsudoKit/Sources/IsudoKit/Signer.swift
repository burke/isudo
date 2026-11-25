import CryptoKit
import Foundation
import LocalAuthentication

/// Where small secrets are kept: the Keychain in the app, memory in tests.
public protocol SecretStore: Sendable {
    func read(_ account: String) throws -> Data?
    func write(_ account: String, _ value: Data) throws
    func delete(_ account: String) throws
}

/// A `SecretStore` that forgets everything when the process ends.
public final class MemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    public init() {}

    public func read(_ account: String) -> Data? {
        lock.withLock { items[account] }
    }

    public func write(_ account: String, _ value: Data) {
        lock.withLock { items[account] = value }
    }

    public func delete(_ account: String) {
        lock.withLock { _ = items.removeValue(forKey: account) }
    }
}

/// Generic-password items in the Keychain, readable only on this device and
/// only while it is unlocked.
public struct KeychainSecretStore: SecretStore {
    public struct KeychainError: Error, Equatable, Sendable {
        public let status: OSStatus
    }

    let service: String

    public init(service: String) {
        self.service = service
    }

    private func query(_ account: String) -> [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account]
    }

    public func read(_ account: String) throws -> Data? {
        var query = query(account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        return item as? Data
    }

    public func write(_ account: String, _ value: Data) throws {
        try delete(account)
        var attributes = query(account)
        attributes[kSecValueData] = value
        attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    public func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status: status) }
    }
}

/// The key whose signature is an approval.
public protocol ApprovalSigner: Sendable {
    /// Uncompressed SEC1 public key (65 bytes): what the host pins.
    var publicKey: Data { get }
    /// True if the private key lives in the Secure Enclave behind biometry.
    var isHardwareBacked: Bool { get }
    /// Signs `message`, asking the person to authenticate first. Returns a
    /// raw `r || s` signature. `prompt` is shown by the system.
    func sign(_ message: Data, prompt: String) async throws -> Data
}

public enum SignerError: Error, Equatable, Sendable {
    /// Face ID or Touch ID is not set up, so a protected key cannot be made.
    case biometryUnavailable
    /// The key no longer exists or no longer works. After a change to the
    /// enrolled faces or fingers this is expected: the pairing must be redone.
    case keyUnusable
    /// The person cancelled or failed authentication.
    case notAuthenticated
}

#if os(watchOS)
/// A P-256 key generated inside the watch's Secure Enclave. It cannot be
/// exported or used on any other device.
///
/// A watch cannot check a face. What it can say is that it was unlocked with
/// its passcode and has not left the wrist since, and that is all this key
/// asks for:
///
/// - The key exists only while the watch has a passcode. Without one a
///   watch never locks, so there would be nothing to be present for.
/// - It can be used only while the watch is unlocked.
/// - Before each signature the system is asked whether the watch has been
///   on the wrist continuously since it was unlocked.
///
/// This is weaker than the phone's key, which needs a currently enrolled
/// face or finger for every signature. That is why a watch may approve only
/// what the computer marks as simple, and only if root has allowed a watch.
public struct SecureEnclaveSigner: ApprovalSigner {
    public let publicKey: Data
    public let isHardwareBacked = true
    let blob: Data

    public static func create(account: String, in store: some SecretStore) throws -> SecureEnclaveSigner {
        // Refused now, when the watch is being set up, if it could never
        // sign: no passcode, or wrist detection off. Better said here than
        // discovered at the first request.
        guard SecureEnclave.isAvailable,
              LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithWristDetection, error: nil)
        else { throw SignerError.biometryUnavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage], &error
        ) else { throw SignerError.biometryUnavailable }
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch {
            throw SignerError.biometryUnavailable
        }
        try store.write(account, key.dataRepresentation)
        return SecureEnclaveSigner(publicKey: key.publicKey.x963Representation, blob: key.dataRepresentation)
    }

    public static func load(account: String, from store: some SecretStore, publicKey: Data) throws -> SecureEnclaveSigner {
        guard let blob = try store.read(account) else { throw SignerError.keyUnusable }
        return SecureEnclaveSigner(publicKey: publicKey, blob: blob)
    }

    public func sign(_ message: Data, prompt: String) async throws -> Data {
        let context = LAContext()
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithWristDetection, localizedReason: prompt)
            else { throw SignerError.notAuthenticated }
        } catch {
            throw SignerError.notAuthenticated
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
            guard key.publicKey.x963Representation == publicKey else { throw SignerError.keyUnusable }
            return try key.signature(for: message).rawRepresentation
        } catch let error as SignerError {
            throw error
        } catch {
            throw SignerError.notAuthenticated
        }
    }
}
#else
/// A P-256 key generated inside the Secure Enclave. It cannot be exported,
/// and every signature needs Face ID or Touch ID by a currently enrolled
/// face or finger: enrolling a new one invalidates the key.
public struct SecureEnclaveSigner: ApprovalSigner {
    public let publicKey: Data
    public let isHardwareBacked = true
    /// The Secure Enclave's encrypted handle for the key. Useless on any
    /// other device and without biometry.
    let blob: Data

    /// Creates a new key and stores its handle.
    public static func create(account: String, in store: some SecretStore) throws -> SecureEnclaveSigner {
        guard SecureEnclave.isAvailable else { throw SignerError.biometryUnavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error
        ) else { throw SignerError.biometryUnavailable }
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch {
            throw SignerError.biometryUnavailable
        }
        try store.write(account, key.dataRepresentation)
        return SecureEnclaveSigner(publicKey: key.publicKey.x963Representation, blob: key.dataRepresentation)
    }

    /// Loads a key created earlier, checking it is the one expected.
    public static func load(account: String, from store: some SecretStore, publicKey: Data) throws -> SecureEnclaveSigner {
        guard let blob = try store.read(account) else { throw SignerError.keyUnusable }
        return SecureEnclaveSigner(publicKey: publicKey, blob: blob)
    }

    public func sign(_ message: Data, prompt: String) async throws -> Data {
        let blob = blob
        let expected = publicKey
        // Signing blocks on the biometric prompt, so it runs off the caller's
        // executor.
        return try await Task.detached(priority: .userInitiated) {
            // A fresh context each time: an authenticated one would let the
            // next signature through without asking.
            let context = LAContext()
            context.localizedReason = prompt
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: blob, authenticationContext: context
                )
                guard key.publicKey.x963Representation == expected else { throw SignerError.keyUnusable }
                return try key.signature(for: message).rawRepresentation
            } catch let error as SignerError {
                throw error
            } catch let error as LAError where [.userCancel, .appCancel, .systemCancel, .authenticationFailed]
                .contains(error.code) {
                throw SignerError.notAuthenticated
            } catch {
                // CryptoKit reports a cancelled prompt as a generic failure
                // too; a key that is truly gone fails the same way. The
                // caller tells them apart by whether a retry ever works.
                throw SignerError.notAuthenticated
            }
        }.value
    }
}

#endif

#if targetEnvironment(simulator) || os(macOS)
/// A software key, for the Simulator (which cannot make biometry-bound
/// Secure Enclave keys) and for tests. NOT a substitute for the real thing:
/// the key sits in the Keychain, and authentication is a check the app
/// performs, not a property of the key. It is not compiled into device builds.
public struct SoftwareSigner: ApprovalSigner {
    public let publicKey: Data
    public let isHardwareBacked = false
    let key: P256.Signing.PrivateKey
    /// Whether to ask the system to authenticate the person before signing.
    let authenticate: Bool

    public static func create(account: String, in store: some SecretStore, authenticate: Bool = true) throws -> SoftwareSigner {
        let key = P256.Signing.PrivateKey()
        try store.write(account, key.rawRepresentation)
        return SoftwareSigner(publicKey: key.publicKey.x963Representation, key: key, authenticate: authenticate)
    }

    public static func load(account: String, from store: some SecretStore, authenticate: Bool = true) throws -> SoftwareSigner {
        guard let raw = try store.read(account), let key = try? P256.Signing.PrivateKey(rawRepresentation: raw) else {
            throw SignerError.keyUnusable
        }
        return SoftwareSigner(publicKey: key.publicKey.x963Representation, key: key, authenticate: authenticate)
    }

    public func sign(_ message: Data, prompt: String) async throws -> Data {
        if authenticate {
            let context = LAContext()
            // Face ID or Touch ID if enrolled, else the passcode. With
            // neither set up (a fresh Simulator) there is nothing to ask
            // for; the UI already labels this key as unprotected.
            #if os(watchOS)
            let candidates: [LAPolicy] = [.deviceOwnerAuthenticationWithWristDetection]
            #else
            let candidates: [LAPolicy] = [.deviceOwnerAuthenticationWithBiometrics, .deviceOwnerAuthentication]
            #endif
            let policy: LAPolicy? = candidates.first { context.canEvaluatePolicy($0, error: nil) }
            if let policy {
                do {
                    guard try await context.evaluatePolicy(policy, localizedReason: prompt) else {
                        throw SignerError.notAuthenticated
                    }
                } catch {
                    throw SignerError.notAuthenticated
                }
            }
        }
        return try key.signature(for: message).rawRepresentation
    }
}
#endif

/// Makes and loads the signing key for a pairing.
public enum Signers {
    static func account(_ pairingIDHex: String) -> String { pairingIDHex + ".sign" }

    /// A new key for a new pairing. On a device this is always a Secure
    /// Enclave key or an error; only the Simulator falls back to software.
    public static func create(pairingIDHex: String, in store: some SecretStore) throws -> any ApprovalSigner {
        #if targetEnvironment(simulator)
        if let signer = try? SecureEnclaveSigner.create(account: account(pairingIDHex), in: store) {
            return signer
        }
        return try SoftwareSigner.create(account: account(pairingIDHex), in: store)
        #else
        return try SecureEnclaveSigner.create(account: account(pairingIDHex), in: store)
        #endif
    }

    public static func load(
        pairingIDHex: String, from store: some SecretStore, publicKey: Data, hardwareBacked: Bool
    ) throws -> any ApprovalSigner {
        #if targetEnvironment(simulator) || os(macOS)
        if !hardwareBacked {
            let signer = try SoftwareSigner.load(account: account(pairingIDHex), from: store)
            guard signer.publicKey == publicKey else { throw SignerError.keyUnusable }
            return signer
        }
        #else
        guard hardwareBacked else { throw SignerError.keyUnusable }
        #endif
        return try SecureEnclaveSigner.load(account: account(pairingIDHex), from: store, publicKey: publicKey)
    }
}
