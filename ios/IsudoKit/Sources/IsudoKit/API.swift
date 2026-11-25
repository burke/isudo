import Foundation

/// JSON bodies of the relay HTTP API. Mirrors `isudo_proto::api`.
/// Identifiers are lowercase hex; keys, signatures, MACs, tokens and
/// envelopes are unpadded base64url.
public enum API {
    public struct DeviceUpdate: Codable, Equatable, Sendable {
        public var apnsToken: String
        public var apnsEnv: String

        public init(apnsToken: String, apnsEnv: String) {
            self.apnsToken = apnsToken
            self.apnsEnv = apnsEnv
        }

        enum CodingKeys: String, CodingKey {
            case apnsToken = "apns_token"
            case apnsEnv = "apns_env"
        }
    }

    public struct Claim: Codable, Equatable, Sendable {
        public var phoneSignPub: String
        public var phoneKemPub: String
        public var phoneName: String
        /// Random value this phone chose after reading the pairing code.
        public var phoneNonce: String
        public var claimMac: String
        public var phoneToken: String
        public var device: DeviceUpdate?

        enum CodingKeys: String, CodingKey {
            case phoneSignPub = "phone_sign_pub"
            case phoneKemPub = "phone_kem_pub"
            case phoneName = "phone_name"
            case phoneNonce = "phone_nonce"
            case claimMac = "claim_mac"
            case phoneToken = "phone_token"
            case device
        }
    }

    public enum PairingState: String, Codable, Equatable, Sendable {
        /// Created by the host; no phone has answered.
        case pending
        /// A phone has answered; the host has not yet looked.
        case claimed
        /// The host has accepted the phone's answer and is waiting for the code.
        case acknowledged
        /// Confirmed by the host. Requests are accepted.
        case active
    }

    /// The host's acknowledgement of a phone's answer.
    public struct Ack: Codable, Equatable, Sendable {
        /// Random value chosen by the host after it accepted the phone's answer.
        public var nonce: String
        /// Host signature over `Messages.pairAck`.
        public var hostSig: String

        public init(nonce: String, hostSig: String) {
            self.nonce = nonce
            self.hostSig = hostSig
        }

        enum CodingKeys: String, CodingKey {
            case nonce
            case hostSig = "host_sig"
        }
    }

    public struct PairingStatus: Codable, Equatable, Sendable {
        public var state: PairingState
        /// Present once the host has accepted this phone's answer.
        public var ack: Ack?
        /// Present once active, so the phone can check the host really confirmed.
        public var hostSig: String?

        public init(state: PairingState, ack: Ack?, hostSig: String?) {
            self.state = state
            self.ack = ack
            self.hostSig = hostSig
        }

        enum CodingKeys: String, CodingKey {
            case state
            case ack
            case hostSig = "host_sig"
        }
    }

    public struct PendingRequest: Codable, Equatable, Sendable {
        public var requestID: String
        public var expiresAt: UInt64
        public var envelope: String

        public init(requestID: String, expiresAt: UInt64, envelope: String) {
            self.requestID = requestID
            self.expiresAt = expiresAt
            self.envelope = envelope
        }

        enum CodingKeys: String, CodingKey {
            case requestID = "request_id"
            case expiresAt = "expires_at"
            case envelope
        }
    }

    public struct PendingList: Codable, Equatable, Sendable {
        public var requests: [PendingRequest]
    }

    public enum Decision: String, Codable, Equatable, Sendable {
        case approve, deny
    }

    public struct Answer: Codable, Equatable, Sendable {
        public var decision: Decision
        public var sig: String
        public var reason: String?
        /// Present when a watch answered: its encoded delegation. The relay
        /// fills this in, and the computer checks it; a device sending an
        /// answer leaves it out.
        public var delegation: String? = nil
    }

    /// Phone: registers a watch it has authorised.
    public struct AddDelegate: Codable, Equatable, Sendable {
        /// An encoded `SignedDelegation`, base64url.
        public var delegation: String
        /// Bearer token the watch will use.
        public var delegateToken: String

        public init(delegation: String, delegateToken: String) {
            self.delegation = delegation
            self.delegateToken = delegateToken
        }

        enum CodingKeys: String, CodingKey {
            case delegation
            case delegateToken = "delegate_token"
        }
    }

    public struct RemoveDelegate: Codable, Equatable, Sendable {
        /// The watch's signing key, base64url.
        public var delegate: String

        public init(delegate: String) {
            self.delegate = delegate
        }
    }
}
