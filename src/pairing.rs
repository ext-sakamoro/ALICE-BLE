//! Pairing / SMP (`PairingMethod` / `IoCapability` / `SmpCode` / `AuthReq` / `PairingParams` / `PairingFailedReason`).

// Pairing / SMP
// ---------------------------------------------------------------------------

/// SMP pairing method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingMethod {
    JustWorks,
    PasskeyEntry,
    NumericComparison,
    OutOfBand,
}

/// IO Capability for SMP pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoCapability {
    DisplayOnly = 0x00,
    DisplayYesNo = 0x01,
    KeyboardOnly = 0x02,
    NoInputNoOutput = 0x03,
    KeyboardDisplay = 0x04,
}

impl IoCapability {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::DisplayOnly),
            0x01 => Some(Self::DisplayYesNo),
            0x02 => Some(Self::KeyboardOnly),
            0x03 => Some(Self::NoInputNoOutput),
            0x04 => Some(Self::KeyboardDisplay),
            _ => None,
        }
    }

    /// Determine the pairing method given initiator and responder IO capabilities.
    #[must_use]
    pub const fn pairing_method(initiator: Self, responder: Self) -> PairingMethod {
        use IoCapability::{
            DisplayOnly, DisplayYesNo, KeyboardDisplay, KeyboardOnly, NoInputNoOutput,
        };
        match (initiator, responder) {
            (NoInputNoOutput, _)
            | (_, NoInputNoOutput)
            | (DisplayOnly | DisplayYesNo, DisplayOnly)
            | (DisplayOnly, DisplayYesNo) => PairingMethod::JustWorks,
            (DisplayYesNo | KeyboardDisplay, DisplayYesNo | KeyboardDisplay) => {
                PairingMethod::NumericComparison
            }
            (KeyboardOnly, _) | (_, KeyboardOnly) => PairingMethod::PasskeyEntry,
            (DisplayOnly, KeyboardDisplay) | (KeyboardDisplay, DisplayOnly) => {
                PairingMethod::PasskeyEntry
            }
        }
    }
}

/// SMP command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SmpCode {
    PairingRequest = 0x01,
    PairingResponse = 0x02,
    PairingConfirm = 0x03,
    PairingRandom = 0x04,
    PairingFailed = 0x05,
    EncryptionInformation = 0x06,
    CentralIdentification = 0x07,
    IdentityInformation = 0x08,
    IdentityAddressInformation = 0x09,
    SigningInformation = 0x0A,
    SecurityRequest = 0x0B,
    PairingPublicKey = 0x0C,
    PairingDhKeyCheck = 0x0D,
}

impl SmpCode {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::PairingRequest),
            0x02 => Some(Self::PairingResponse),
            0x03 => Some(Self::PairingConfirm),
            0x04 => Some(Self::PairingRandom),
            0x05 => Some(Self::PairingFailed),
            0x06 => Some(Self::EncryptionInformation),
            0x07 => Some(Self::CentralIdentification),
            0x08 => Some(Self::IdentityInformation),
            0x09 => Some(Self::IdentityAddressInformation),
            0x0A => Some(Self::SigningInformation),
            0x0B => Some(Self::SecurityRequest),
            0x0C => Some(Self::PairingPublicKey),
            0x0D => Some(Self::PairingDhKeyCheck),
            _ => None,
        }
    }
}

/// Authentication requirements flags for SMP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthReq(u8);

impl AuthReq {
    pub const BONDING: Self = Self(0x01);
    pub const MITM: Self = Self(0x04);
    pub const SC: Self = Self(0x08);
    pub const KEYPRESS: Self = Self(0x10);
    pub const CT2: Self = Self(0x20);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn requires_mitm(self) -> bool {
        self.contains(Self::MITM)
    }

    #[must_use]
    pub const fn requires_bonding(self) -> bool {
        self.contains(Self::BONDING)
    }

    #[must_use]
    pub const fn requires_secure_connections(self) -> bool {
        self.contains(Self::SC)
    }
}

/// SMP Pairing Request / Response parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingParams {
    pub io_capability: IoCapability,
    pub oob_data_flag: bool,
    pub auth_req: AuthReq,
    pub max_encryption_key_size: u8,
    pub initiator_key_distribution: u8,
    pub responder_key_distribution: u8,
}

impl PairingParams {
    /// Serialize to 6 bytes (fields after the SMP command code).
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 6] {
        [
            self.io_capability as u8,
            if self.oob_data_flag { 1 } else { 0 },
            self.auth_req.bits(),
            self.max_encryption_key_size,
            self.initiator_key_distribution,
            self.responder_key_distribution,
        ]
    }

    /// Parse from 6 bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8; 6]) -> Option<Self> {
        let io = IoCapability::from_byte(data[0])?;
        Some(Self {
            io_capability: io,
            oob_data_flag: data[1] != 0,
            auth_req: AuthReq::from_bits(data[2]),
            max_encryption_key_size: data[3],
            initiator_key_distribution: data[4],
            responder_key_distribution: data[5],
        })
    }

    /// Build a Pairing Request PDU.
    #[must_use]
    pub fn to_request_pdu(self) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(7);
        pdu.push(SmpCode::PairingRequest as u8);
        pdu.extend_from_slice(&self.to_bytes());
        pdu
    }

    /// Build a Pairing Response PDU.
    #[must_use]
    pub fn to_response_pdu(self) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(7);
        pdu.push(SmpCode::PairingResponse as u8);
        pdu.extend_from_slice(&self.to_bytes());
        pdu
    }
}

/// SMP Pairing Failed reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingFailedReason {
    PasskeyEntryFailed = 0x01,
    OobNotAvailable = 0x02,
    AuthenticationRequirements = 0x03,
    ConfirmValueFailed = 0x04,
    PairingNotSupported = 0x05,
    EncryptionKeySize = 0x06,
    CommandNotSupported = 0x07,
    UnspecifiedReason = 0x08,
    RepeatedAttempts = 0x09,
    InvalidParameters = 0x0A,
    DhKeyCheckFailed = 0x0B,
    NumericComparisonFailed = 0x0C,
    KeyRejected = 0x0F,
}

impl PairingFailedReason {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::PasskeyEntryFailed),
            0x02 => Some(Self::OobNotAvailable),
            0x03 => Some(Self::AuthenticationRequirements),
            0x04 => Some(Self::ConfirmValueFailed),
            0x05 => Some(Self::PairingNotSupported),
            0x06 => Some(Self::EncryptionKeySize),
            0x07 => Some(Self::CommandNotSupported),
            0x08 => Some(Self::UnspecifiedReason),
            0x09 => Some(Self::RepeatedAttempts),
            0x0A => Some(Self::InvalidParameters),
            0x0B => Some(Self::DhKeyCheckFailed),
            0x0C => Some(Self::NumericComparisonFailed),
            0x0F => Some(Self::KeyRejected),
            _ => None,
        }
    }

    /// Build a Pairing Failed PDU.
    #[must_use]
    pub fn to_pdu(self) -> Vec<u8> {
        vec![SmpCode::PairingFailed as u8, self as u8]
    }
}
