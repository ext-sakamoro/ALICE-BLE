//! L2CAP (`L2capCid` / `L2capSignalCode` / `L2capPdu`).

use crate::att::AttPdu;

// L2CAP
// ---------------------------------------------------------------------------

/// Well-known L2CAP Channel IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum L2capCid {
    /// Null (invalid).
    Null = 0x0000,
    /// L2CAP Signaling channel (ACL-U).
    Signaling = 0x0001,
    /// Connectionless channel.
    Connectionless = 0x0002,
    /// AMP Manager Protocol.
    AmpManager = 0x0003,
    /// ATT bearer (BLE).
    Att = 0x0004,
    /// LE L2CAP Signaling.
    LeSignaling = 0x0005,
    /// Security Manager Protocol.
    Smp = 0x0006,
    /// BR/EDR Security Manager.
    BrEdrSmp = 0x0007,
}

impl L2capCid {
    /// Parse from raw u16.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(Self::Null),
            0x0001 => Some(Self::Signaling),
            0x0002 => Some(Self::Connectionless),
            0x0003 => Some(Self::AmpManager),
            0x0004 => Some(Self::Att),
            0x0005 => Some(Self::LeSignaling),
            0x0006 => Some(Self::Smp),
            0x0007 => Some(Self::BrEdrSmp),
            _ => None,
        }
    }

    /// Whether this is a fixed LE channel.
    #[must_use]
    pub const fn is_le_fixed(self) -> bool {
        matches!(self, Self::Att | Self::LeSignaling | Self::Smp)
    }
}

/// L2CAP signaling command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L2capSignalCode {
    CommandReject = 0x01,
    ConnectionRequest = 0x02,
    ConnectionResponse = 0x03,
    ConfigurationRequest = 0x04,
    ConfigurationResponse = 0x05,
    DisconnectionRequest = 0x06,
    DisconnectionResponse = 0x07,
    InformationRequest = 0x0A,
    InformationResponse = 0x0B,
    ConnectionParameterUpdateRequest = 0x12,
    ConnectionParameterUpdateResponse = 0x13,
    LeCreditBasedConnectionRequest = 0x14,
    LeCreditBasedConnectionResponse = 0x15,
    FlowControlCreditIndication = 0x16,
}

impl L2capSignalCode {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::CommandReject),
            0x02 => Some(Self::ConnectionRequest),
            0x03 => Some(Self::ConnectionResponse),
            0x04 => Some(Self::ConfigurationRequest),
            0x05 => Some(Self::ConfigurationResponse),
            0x06 => Some(Self::DisconnectionRequest),
            0x07 => Some(Self::DisconnectionResponse),
            0x0A => Some(Self::InformationRequest),
            0x0B => Some(Self::InformationResponse),
            0x12 => Some(Self::ConnectionParameterUpdateRequest),
            0x13 => Some(Self::ConnectionParameterUpdateResponse),
            0x14 => Some(Self::LeCreditBasedConnectionRequest),
            0x15 => Some(Self::LeCreditBasedConnectionResponse),
            0x16 => Some(Self::FlowControlCreditIndication),
            _ => None,
        }
    }
}

/// An L2CAP PDU (basic information frame for LE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2capPdu {
    pub channel_id: u16,
    pub payload: Vec<u8>,
}

impl L2capPdu {
    /// Create a new L2CAP PDU.
    #[must_use]
    pub const fn new(channel_id: u16, payload: Vec<u8>) -> Self {
        Self {
            channel_id,
            payload,
        }
    }

    /// Serialize the PDU (length + CID + payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)]
        let len = self.payload.len() as u16;
        let mut out = Vec::with_capacity(4 + self.payload.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.channel_id.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse from raw bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let cid = u16::from_le_bytes([data[2], data[3]]);
        if data.len() < 4 + len {
            return None;
        }
        Some(Self {
            channel_id: cid,
            payload: data[4..4 + len].to_vec(),
        })
    }

    /// Wrap an ATT PDU in an L2CAP frame on CID 0x0004.
    #[must_use]
    pub fn att_frame(att_pdu: &AttPdu) -> Self {
        Self {
            channel_id: L2capCid::Att as u16,
            payload: att_pdu.to_bytes(),
        }
    }
}
