//! ATT — Attribute Protocol (`AttOpcode` / `AttError` / `AttPdu`).

// ATT — Attribute Protocol
// ---------------------------------------------------------------------------

/// ATT opcodes (Bluetooth Core Spec Vol 3 Part F).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttOpcode {
    ErrorResponse = 0x01,
    ExchangeMtuRequest = 0x02,
    ExchangeMtuResponse = 0x03,
    FindInformationRequest = 0x04,
    FindInformationResponse = 0x05,
    FindByTypeValueRequest = 0x06,
    FindByTypeValueResponse = 0x07,
    ReadByTypeRequest = 0x08,
    ReadByTypeResponse = 0x09,
    ReadRequest = 0x0A,
    ReadResponse = 0x0B,
    ReadBlobRequest = 0x0C,
    ReadBlobResponse = 0x0D,
    ReadMultipleRequest = 0x0E,
    ReadMultipleResponse = 0x0F,
    ReadByGroupTypeRequest = 0x10,
    ReadByGroupTypeResponse = 0x11,
    WriteRequest = 0x12,
    WriteResponse = 0x13,
    WriteCommand = 0x52,
    SignedWriteCommand = 0xD2,
    PrepareWriteRequest = 0x16,
    PrepareWriteResponse = 0x17,
    ExecuteWriteRequest = 0x18,
    ExecuteWriteResponse = 0x19,
    HandleValueNotification = 0x1B,
    HandleValueIndication = 0x1D,
    HandleValueConfirmation = 0x1E,
}

impl AttOpcode {
    /// Parse from raw byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ErrorResponse),
            0x02 => Some(Self::ExchangeMtuRequest),
            0x03 => Some(Self::ExchangeMtuResponse),
            0x04 => Some(Self::FindInformationRequest),
            0x05 => Some(Self::FindInformationResponse),
            0x06 => Some(Self::FindByTypeValueRequest),
            0x07 => Some(Self::FindByTypeValueResponse),
            0x08 => Some(Self::ReadByTypeRequest),
            0x09 => Some(Self::ReadByTypeResponse),
            0x0A => Some(Self::ReadRequest),
            0x0B => Some(Self::ReadResponse),
            0x0C => Some(Self::ReadBlobRequest),
            0x0D => Some(Self::ReadBlobResponse),
            0x0E => Some(Self::ReadMultipleRequest),
            0x0F => Some(Self::ReadMultipleResponse),
            0x10 => Some(Self::ReadByGroupTypeRequest),
            0x11 => Some(Self::ReadByGroupTypeResponse),
            0x12 => Some(Self::WriteRequest),
            0x13 => Some(Self::WriteResponse),
            0x52 => Some(Self::WriteCommand),
            0xD2 => Some(Self::SignedWriteCommand),
            0x16 => Some(Self::PrepareWriteRequest),
            0x17 => Some(Self::PrepareWriteResponse),
            0x18 => Some(Self::ExecuteWriteRequest),
            0x19 => Some(Self::ExecuteWriteResponse),
            0x1B => Some(Self::HandleValueNotification),
            0x1D => Some(Self::HandleValueIndication),
            0x1E => Some(Self::HandleValueConfirmation),
            _ => None,
        }
    }

    /// Whether this opcode is a command (no response expected).
    #[must_use]
    pub const fn is_command(self) -> bool {
        matches!(self, Self::WriteCommand | Self::SignedWriteCommand)
    }
}

/// ATT error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttError {
    InvalidHandle = 0x01,
    ReadNotPermitted = 0x02,
    WriteNotPermitted = 0x03,
    InvalidPdu = 0x04,
    InsufficientAuthentication = 0x05,
    RequestNotSupported = 0x06,
    InvalidOffset = 0x07,
    InsufficientAuthorization = 0x08,
    PrepareQueueFull = 0x09,
    AttributeNotFound = 0x0A,
    AttributeNotLong = 0x0B,
    InsufficientEncryptionKeySize = 0x0C,
    InvalidAttributeValueLength = 0x0D,
    UnlikelyError = 0x0E,
    InsufficientEncryption = 0x0F,
    UnsupportedGroupType = 0x10,
    InsufficientResources = 0x11,
}

impl AttError {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::InvalidHandle),
            0x02 => Some(Self::ReadNotPermitted),
            0x03 => Some(Self::WriteNotPermitted),
            0x04 => Some(Self::InvalidPdu),
            0x05 => Some(Self::InsufficientAuthentication),
            0x06 => Some(Self::RequestNotSupported),
            0x07 => Some(Self::InvalidOffset),
            0x08 => Some(Self::InsufficientAuthorization),
            0x09 => Some(Self::PrepareQueueFull),
            0x0A => Some(Self::AttributeNotFound),
            0x0B => Some(Self::AttributeNotLong),
            0x0C => Some(Self::InsufficientEncryptionKeySize),
            0x0D => Some(Self::InvalidAttributeValueLength),
            0x0E => Some(Self::UnlikelyError),
            0x0F => Some(Self::InsufficientEncryption),
            0x10 => Some(Self::UnsupportedGroupType),
            0x11 => Some(Self::InsufficientResources),
            _ => None,
        }
    }
}

/// ATT PDU — a parsed Attribute Protocol data unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttPdu {
    pub opcode: AttOpcode,
    pub params: Vec<u8>,
}

impl AttPdu {
    /// Create a new ATT PDU.
    #[must_use]
    pub const fn new(opcode: AttOpcode, params: Vec<u8>) -> Self {
        Self { opcode, params }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.params.len());
        out.push(self.opcode as u8);
        out.extend_from_slice(&self.params);
        out
    }

    /// Parse from bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let opcode = AttOpcode::from_byte(data[0])?;
        Some(Self {
            opcode,
            params: data[1..].to_vec(),
        })
    }

    /// Build an ATT Error Response PDU.
    #[must_use]
    pub fn error_response(request_opcode: AttOpcode, handle: u16, error: AttError) -> Self {
        let h = handle.to_le_bytes();
        Self {
            opcode: AttOpcode::ErrorResponse,
            params: vec![request_opcode as u8, h[0], h[1], error as u8],
        }
    }

    /// Build an Exchange MTU Request.
    #[must_use]
    pub fn exchange_mtu_request(client_mtu: u16) -> Self {
        Self {
            opcode: AttOpcode::ExchangeMtuRequest,
            params: client_mtu.to_le_bytes().to_vec(),
        }
    }

    /// Build an Exchange MTU Response.
    #[must_use]
    pub fn exchange_mtu_response(server_mtu: u16) -> Self {
        Self {
            opcode: AttOpcode::ExchangeMtuResponse,
            params: server_mtu.to_le_bytes().to_vec(),
        }
    }

    /// Build a Handle Value Notification.
    #[must_use]
    pub fn notification(handle: u16, value: &[u8]) -> Self {
        let mut params = handle.to_le_bytes().to_vec();
        params.extend_from_slice(value);
        Self {
            opcode: AttOpcode::HandleValueNotification,
            params,
        }
    }

    /// Build a Handle Value Indication.
    #[must_use]
    pub fn indication(handle: u16, value: &[u8]) -> Self {
        let mut params = handle.to_le_bytes().to_vec();
        params.extend_from_slice(value);
        Self {
            opcode: AttOpcode::HandleValueIndication,
            params,
        }
    }

    /// Build a Handle Value Confirmation.
    #[must_use]
    pub const fn confirmation() -> Self {
        Self {
            opcode: AttOpcode::HandleValueConfirmation,
            params: vec![],
        }
    }

    /// Build a Read Request.
    #[must_use]
    pub fn read_request(handle: u16) -> Self {
        Self {
            opcode: AttOpcode::ReadRequest,
            params: handle.to_le_bytes().to_vec(),
        }
    }

    /// Build a Read Response.
    #[must_use]
    pub fn read_response(value: &[u8]) -> Self {
        Self {
            opcode: AttOpcode::ReadResponse,
            params: value.to_vec(),
        }
    }

    /// Build a Write Request.
    #[must_use]
    pub fn write_request(handle: u16, value: &[u8]) -> Self {
        let mut params = handle.to_le_bytes().to_vec();
        params.extend_from_slice(value);
        Self {
            opcode: AttOpcode::WriteRequest,
            params,
        }
    }

    /// Build a Write Response.
    #[must_use]
    pub const fn write_response() -> Self {
        Self {
            opcode: AttOpcode::WriteResponse,
            params: vec![],
        }
    }
}
