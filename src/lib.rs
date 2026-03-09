#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! ALICE-BLE: Pure Rust BLE protocol stack.
//!
//! Covers GATT, ATT, L2CAP, advertising, pairing, connection management,
//! UUID handling, and notification/indication support.

use core::fmt;

// ---------------------------------------------------------------------------
// UUID
// ---------------------------------------------------------------------------

/// A BLE UUID — either 16-bit (SIG-assigned) or 128-bit (vendor).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Uuid {
    /// 16-bit short UUID (Bluetooth SIG assigned).
    Uuid16(u16),
    /// Full 128-bit UUID.
    Uuid128([u8; 16]),
}

/// Bluetooth Base UUID used to expand 16-bit UUIDs.
const BASE_UUID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0xB3, 0x01, 0x00,
];

impl Uuid {
    /// Expand a 16-bit UUID to its full 128-bit form using the Bluetooth Base UUID.
    #[must_use]
    pub const fn to_uuid128(self) -> [u8; 16] {
        match self {
            Self::Uuid128(v) => v,
            Self::Uuid16(short) => {
                let mut out = BASE_UUID;
                let bytes = short.to_le_bytes();
                out[0] = bytes[0];
                out[1] = bytes[1];
                out
            }
        }
    }

    /// Return the 16-bit value if this is a short UUID.
    #[must_use]
    pub const fn as_u16(self) -> Option<u16> {
        match self {
            Self::Uuid16(v) => Some(v),
            Self::Uuid128(_) => None,
        }
    }

    /// Byte length when serialized.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Uuid16(_) => 2,
            Self::Uuid128(_) => 16,
        }
    }

    /// Serialize into a buffer, returning bytes written.
    ///
    /// # Panics
    ///
    /// Panics if `buf` is too small.
    pub fn write_to(self, buf: &mut [u8]) -> usize {
        match self {
            Self::Uuid16(v) => {
                let b = v.to_le_bytes();
                buf[0] = b[0];
                buf[1] = b[1];
                2
            }
            Self::Uuid128(v) => {
                buf[..16].copy_from_slice(&v);
                16
            }
        }
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uuid16(v) => write!(f, "UUID16(0x{v:04X})"),
            Self::Uuid128(v) => {
                write!(f, "UUID128(")?;
                for (i, b) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{b:02X}")?;
                }
                write!(f, ")")
            }
        }
    }
}

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// GATT
// ---------------------------------------------------------------------------

/// GATT characteristic properties (bitmask).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacteristicProperties(u8);

impl CharacteristicProperties {
    pub const BROADCAST: Self = Self(0x01);
    pub const READ: Self = Self(0x02);
    pub const WRITE_WITHOUT_RESPONSE: Self = Self(0x04);
    pub const WRITE: Self = Self(0x08);
    pub const NOTIFY: Self = Self(0x10);
    pub const INDICATE: Self = Self(0x20);
    pub const AUTHENTICATED_SIGNED_WRITES: Self = Self(0x40);
    pub const EXTENDED_PROPERTIES: Self = Self(0x80);

    /// Create from raw byte.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Check if a flag is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two property sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether notifications are enabled.
    #[must_use]
    pub const fn can_notify(self) -> bool {
        self.contains(Self::NOTIFY)
    }

    /// Whether indications are enabled.
    #[must_use]
    pub const fn can_indicate(self) -> bool {
        self.contains(Self::INDICATE)
    }

    /// Whether readable.
    #[must_use]
    pub const fn can_read(self) -> bool {
        self.contains(Self::READ)
    }

    /// Whether writable.
    #[must_use]
    pub const fn can_write(self) -> bool {
        self.contains(Self::WRITE)
    }
}

/// Client Characteristic Configuration Descriptor (CCCD) value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CccdValue(u16);

impl CccdValue {
    pub const NONE: Self = Self(0);
    pub const NOTIFICATIONS_ENABLED: Self = Self(1);
    pub const INDICATIONS_ENABLED: Self = Self(2);

    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn notifications(self) -> bool {
        (self.0 & 1) != 0
    }

    #[must_use]
    pub const fn indications(self) -> bool {
        (self.0 & 2) != 0
    }

    /// Serialize to 2 bytes (LE).
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    /// Parse from 2 LE bytes.
    #[must_use]
    pub const fn from_le_bytes(b: [u8; 2]) -> Self {
        Self(u16::from_le_bytes(b))
    }
}

/// A GATT Descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub handle: u16,
    pub uuid: Uuid,
    pub value: Vec<u8>,
}

impl Descriptor {
    /// Create a new descriptor.
    #[must_use]
    pub const fn new(handle: u16, uuid: Uuid, value: Vec<u8>) -> Self {
        Self {
            handle,
            uuid,
            value,
        }
    }

    /// Create a CCCD descriptor.
    #[must_use]
    pub fn cccd(handle: u16) -> Self {
        Self {
            handle,
            uuid: Uuid::Uuid16(0x2902),
            value: CccdValue::NONE.to_le_bytes().to_vec(),
        }
    }

    /// Create a Characteristic User Description descriptor.
    #[must_use]
    pub fn user_description(handle: u16, description: &str) -> Self {
        Self {
            handle,
            uuid: Uuid::Uuid16(0x2901),
            value: description.as_bytes().to_vec(),
        }
    }
}

/// A GATT Characteristic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Characteristic {
    pub handle: u16,
    pub value_handle: u16,
    pub uuid: Uuid,
    pub properties: CharacteristicProperties,
    pub value: Vec<u8>,
    pub descriptors: Vec<Descriptor>,
}

impl Characteristic {
    /// Create a new characteristic.
    #[must_use]
    pub const fn new(
        handle: u16,
        value_handle: u16,
        uuid: Uuid,
        properties: CharacteristicProperties,
        value: Vec<u8>,
        descriptors: Vec<Descriptor>,
    ) -> Self {
        Self {
            handle,
            value_handle,
            uuid,
            properties,
            value,
            descriptors,
        }
    }

    /// Serialize the characteristic declaration value.
    #[must_use]
    pub fn declaration_value(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.properties.bits());
        out.extend_from_slice(&self.value_handle.to_le_bytes());
        let mut uuid_buf = [0u8; 16];
        let n = self.uuid.write_to(&mut uuid_buf);
        out.extend_from_slice(&uuid_buf[..n]);
        out
    }

    /// Find a descriptor by UUID.
    #[must_use]
    pub fn find_descriptor(&self, uuid: Uuid) -> Option<&Descriptor> {
        self.descriptors.iter().find(|d| d.uuid == uuid)
    }

    /// Whether this characteristic has a CCCD.
    #[must_use]
    pub fn has_cccd(&self) -> bool {
        self.find_descriptor(Uuid::Uuid16(0x2902)).is_some()
    }
}

/// A GATT Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub handle: u16,
    pub end_group_handle: u16,
    pub uuid: Uuid,
    pub is_primary: bool,
    pub characteristics: Vec<Characteristic>,
    pub included_services: Vec<u16>,
}

impl Service {
    /// Create a new primary service.
    #[must_use]
    pub const fn primary(
        handle: u16,
        end_group_handle: u16,
        uuid: Uuid,
        characteristics: Vec<Characteristic>,
    ) -> Self {
        Self {
            handle,
            end_group_handle,
            uuid,
            is_primary: true,
            characteristics,
            included_services: Vec::new(),
        }
    }

    /// Create a new secondary service.
    #[must_use]
    pub const fn secondary(
        handle: u16,
        end_group_handle: u16,
        uuid: Uuid,
        characteristics: Vec<Characteristic>,
    ) -> Self {
        Self {
            handle,
            end_group_handle,
            uuid,
            is_primary: false,
            characteristics,
            included_services: Vec::new(),
        }
    }

    /// Find a characteristic by UUID.
    #[must_use]
    pub fn find_characteristic(&self, uuid: Uuid) -> Option<&Characteristic> {
        self.characteristics.iter().find(|c| c.uuid == uuid)
    }

    /// Find a characteristic by value handle.
    #[must_use]
    pub fn find_characteristic_by_handle(&self, handle: u16) -> Option<&Characteristic> {
        self.characteristics
            .iter()
            .find(|c| c.value_handle == handle)
    }

    /// Count of characteristics.
    #[must_use]
    pub const fn characteristic_count(&self) -> usize {
        self.characteristics.len()
    }

    /// Add an included service reference.
    pub fn add_included_service(&mut self, handle: u16) {
        self.included_services.push(handle);
    }
}

/// A simple GATT Server holding a set of services.
#[derive(Debug, Clone, Default)]
pub struct GattServer {
    pub services: Vec<Service>,
    next_handle: u16,
}

impl GattServer {
    /// Create a new empty GATT server.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            services: Vec::new(),
            next_handle: 1,
        }
    }

    /// Add a service, auto-assigning handles.
    pub fn add_service(&mut self, uuid: Uuid, is_primary: bool) -> usize {
        let handle = self.next_handle;
        self.next_handle += 1;
        let svc = Service {
            handle,
            end_group_handle: handle,
            uuid,
            is_primary,
            characteristics: Vec::new(),
            included_services: Vec::new(),
        };
        self.services.push(svc);
        self.services.len() - 1
    }

    /// Add a characteristic to the last service, auto-assigning handles.
    ///
    /// # Panics
    ///
    /// Panics if no services have been added.
    pub fn add_characteristic(
        &mut self,
        service_idx: usize,
        uuid: Uuid,
        properties: CharacteristicProperties,
        initial_value: &[u8],
    ) -> u16 {
        let decl_handle = self.next_handle;
        let value_handle = self.next_handle + 1;
        self.next_handle += 2;

        let mut descriptors = Vec::new();
        if properties.can_notify() || properties.can_indicate() {
            let cccd = Descriptor::cccd(self.next_handle);
            self.next_handle += 1;
            descriptors.push(cccd);
        }

        let chr = Characteristic::new(
            decl_handle,
            value_handle,
            uuid,
            properties,
            initial_value.to_vec(),
            descriptors,
        );
        let svc = &mut self.services[service_idx];
        svc.characteristics.push(chr);
        svc.end_group_handle = self.next_handle - 1;
        value_handle
    }

    /// Find a service by UUID.
    #[must_use]
    pub fn find_service(&self, uuid: Uuid) -> Option<&Service> {
        self.services.iter().find(|s| s.uuid == uuid)
    }

    /// Total number of services.
    #[must_use]
    pub const fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Handle an Exchange MTU Request, returning the response.
    #[must_use]
    pub fn handle_exchange_mtu(&self, server_mtu: u16) -> AttPdu {
        AttPdu::exchange_mtu_response(server_mtu)
    }
}

// ---------------------------------------------------------------------------
// Advertising
// ---------------------------------------------------------------------------

/// BLE advertising PDU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdvPduType {
    AdvInd = 0x00,
    AdvDirectInd = 0x01,
    AdvNonconnInd = 0x02,
    ScanReq = 0x03,
    ScanRsp = 0x04,
    ConnectReq = 0x05,
    AdvScanInd = 0x06,
}

impl AdvPduType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::AdvInd),
            0x01 => Some(Self::AdvDirectInd),
            0x02 => Some(Self::AdvNonconnInd),
            0x03 => Some(Self::ScanReq),
            0x04 => Some(Self::ScanRsp),
            0x05 => Some(Self::ConnectReq),
            0x06 => Some(Self::AdvScanInd),
            _ => None,
        }
    }

    /// Whether this PDU type is connectable.
    #[must_use]
    pub const fn is_connectable(self) -> bool {
        matches!(self, Self::AdvInd | Self::AdvDirectInd | Self::ConnectReq)
    }

    /// Whether this PDU type is scannable.
    #[must_use]
    pub const fn is_scannable(self) -> bool {
        matches!(self, Self::AdvInd | Self::AdvScanInd)
    }
}

/// AD structure types used in advertising and scan response data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdType {
    Flags = 0x01,
    IncompleteList16BitUuids = 0x02,
    CompleteList16BitUuids = 0x03,
    IncompleteList128BitUuids = 0x06,
    CompleteList128BitUuids = 0x07,
    ShortenedLocalName = 0x08,
    CompleteLocalName = 0x09,
    TxPowerLevel = 0x0A,
    ServiceData16Bit = 0x16,
    ServiceData128Bit = 0x21,
    ManufacturerSpecificData = 0xFF,
}

impl AdType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Flags),
            0x02 => Some(Self::IncompleteList16BitUuids),
            0x03 => Some(Self::CompleteList16BitUuids),
            0x06 => Some(Self::IncompleteList128BitUuids),
            0x07 => Some(Self::CompleteList128BitUuids),
            0x08 => Some(Self::ShortenedLocalName),
            0x09 => Some(Self::CompleteLocalName),
            0x0A => Some(Self::TxPowerLevel),
            0x16 => Some(Self::ServiceData16Bit),
            0x21 => Some(Self::ServiceData128Bit),
            0xFF => Some(Self::ManufacturerSpecificData),
            _ => None,
        }
    }
}

/// A single AD structure (Type-Length-Value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdStructure {
    pub ad_type: u8,
    pub data: Vec<u8>,
}

impl AdStructure {
    /// Create a new AD structure.
    #[must_use]
    pub const fn new(ad_type: u8, data: Vec<u8>) -> Self {
        Self { ad_type, data }
    }

    /// Create a Flags AD structure.
    #[must_use]
    pub fn flags(flags: u8) -> Self {
        Self {
            ad_type: AdType::Flags as u8,
            data: vec![flags],
        }
    }

    /// Create a Complete Local Name AD structure.
    #[must_use]
    pub fn complete_local_name(name: &str) -> Self {
        Self {
            ad_type: AdType::CompleteLocalName as u8,
            data: name.as_bytes().to_vec(),
        }
    }

    /// Create a Shortened Local Name AD structure.
    #[must_use]
    pub fn shortened_local_name(name: &str) -> Self {
        Self {
            ad_type: AdType::ShortenedLocalName as u8,
            data: name.as_bytes().to_vec(),
        }
    }

    /// Create a TX Power Level AD structure.
    #[must_use]
    pub fn tx_power_level(dbm: i8) -> Self {
        Self {
            ad_type: AdType::TxPowerLevel as u8,
            data: vec![dbm.cast_unsigned()],
        }
    }

    /// Create a Manufacturer Specific Data AD structure.
    #[must_use]
    pub fn manufacturer_specific(company_id: u16, data: &[u8]) -> Self {
        let mut payload = company_id.to_le_bytes().to_vec();
        payload.extend_from_slice(data);
        Self {
            ad_type: AdType::ManufacturerSpecificData as u8,
            data: payload,
        }
    }

    /// Create a 16-bit UUID list.
    #[must_use]
    pub fn complete_list_16bit_uuids(uuids: &[u16]) -> Self {
        let mut data = Vec::with_capacity(uuids.len() * 2);
        for u in uuids {
            data.extend_from_slice(&u.to_le_bytes());
        }
        Self {
            ad_type: AdType::CompleteList16BitUuids as u8,
            data,
        }
    }

    /// Serialized length (length byte + type byte + data).
    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        1 + 1 + self.data.len()
    }

    /// Serialize (length, type, data).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)]
        let len = (1 + self.data.len()) as u8;
        let mut out = Vec::with_capacity(self.serialized_len());
        out.push(len);
        out.push(self.ad_type);
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse one AD structure from the front of `data`, returning it and bytes consumed.
    #[must_use]
    pub fn parse_one(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }
        let len = data[0] as usize;
        if len == 0 || data.len() < 1 + len {
            return None;
        }
        let ad_type = data[1];
        let ad_data = data[2..=len].to_vec();
        Some((
            Self {
                ad_type,
                data: ad_data,
            },
            1 + len,
        ))
    }

    /// Parse all AD structures from advertising data.
    #[must_use]
    pub fn parse_all(mut data: &[u8]) -> Vec<Self> {
        let mut out = Vec::new();
        while let Some((ad, consumed)) = Self::parse_one(data) {
            out.push(ad);
            data = &data[consumed..];
        }
        out
    }
}

/// BLE advertising data builder.
#[derive(Debug, Clone, Default)]
pub struct AdvertisingData {
    pub structures: Vec<AdStructure>,
}

impl AdvertisingData {
    /// Create an empty advertising data builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            structures: Vec::new(),
        }
    }

    /// Add an AD structure.
    pub fn add(&mut self, structure: AdStructure) -> &mut Self {
        self.structures.push(structure);
        self
    }

    /// Total serialized length.
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.structures
            .iter()
            .map(AdStructure::serialized_len)
            .sum()
    }

    /// Whether it fits in the 31-byte advertising payload.
    #[must_use]
    pub fn fits_in_adv(&self) -> bool {
        self.total_len() <= 31
    }

    /// Serialize all structures.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_len());
        for s in &self.structures {
            out.extend(s.to_bytes());
        }
        out
    }
}

/// Scan response data (same structure as advertising data).
pub type ScanResponseData = AdvertisingData;

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Connection Management
// ---------------------------------------------------------------------------

/// BLE connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Encrypting,
    Encrypted,
    Disconnecting,
}

impl ConnectionState {
    /// Whether the connection is active (connected or encrypted).
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Connected | Self::Encrypting | Self::Encrypted)
    }

    /// Whether the link is encrypted.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Encrypted)
    }
}

/// BLE connection parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionParameters {
    /// Connection interval in units of 1.25 ms (range 6..=3200).
    pub interval: u16,
    /// Peripheral latency (number of connection events the peripheral may skip).
    pub latency: u16,
    /// Supervision timeout in units of 10 ms (range 10..=3200).
    pub supervision_timeout: u16,
}

impl ConnectionParameters {
    /// Create new connection parameters.
    #[must_use]
    pub const fn new(interval: u16, latency: u16, supervision_timeout: u16) -> Self {
        Self {
            interval,
            latency,
            supervision_timeout,
        }
    }

    /// Validate the parameters per Bluetooth spec.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        let interval_ok = self.interval >= 6 && self.interval <= 3200;
        let latency_ok = self.latency <= 499;
        let timeout_ok = self.supervision_timeout >= 10 && self.supervision_timeout <= 3200;
        // Supervision timeout > (1 + latency) * interval * 2
        // (all in 10ms units vs 1.25ms units — simplified check)
        interval_ok && latency_ok && timeout_ok
    }

    /// Connection interval in milliseconds.
    #[must_use]
    pub fn interval_ms(&self) -> f64 {
        f64::from(self.interval) * 1.25
    }

    /// Supervision timeout in milliseconds.
    #[must_use]
    pub fn supervision_timeout_ms(&self) -> f64 {
        f64::from(self.supervision_timeout) * 10.0
    }

    /// Serialize to 6 bytes (LE).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..2].copy_from_slice(&self.interval.to_le_bytes());
        out[2..4].copy_from_slice(&self.latency.to_le_bytes());
        out[4..6].copy_from_slice(&self.supervision_timeout.to_le_bytes());
        out
    }

    /// Parse from 6 LE bytes.
    #[must_use]
    pub const fn from_bytes(data: &[u8; 6]) -> Self {
        Self {
            interval: u16::from_le_bytes([data[0], data[1]]),
            latency: u16::from_le_bytes([data[2], data[3]]),
            supervision_timeout: u16::from_le_bytes([data[4], data[5]]),
        }
    }
}

/// BLE device address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Public,
    Random,
    PublicIdentity,
    RandomIdentity,
}

/// BLE device address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdAddr {
    pub address: [u8; 6],
    pub addr_type: AddressType,
}

impl BdAddr {
    /// Create a new device address.
    #[must_use]
    pub const fn new(address: [u8; 6], addr_type: AddressType) -> Self {
        Self { address, addr_type }
    }

    /// Check if the address is a resolvable private address.
    #[must_use]
    pub const fn is_resolvable_private(&self) -> bool {
        matches!(self.addr_type, AddressType::Random) && (self.address[5] & 0xC0) == 0x40
    }

    /// Check if the address is a non-resolvable private address.
    #[must_use]
    pub const fn is_non_resolvable_private(&self) -> bool {
        matches!(self.addr_type, AddressType::Random) && (self.address[5] & 0xC0) == 0x00
    }

    /// Check if the address is a static random address.
    #[must_use]
    pub const fn is_static_random(&self) -> bool {
        matches!(self.addr_type, AddressType::Random) && (self.address[5] & 0xC0) == 0xC0
    }
}

impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.address[5],
            self.address[4],
            self.address[3],
            self.address[2],
            self.address[1],
            self.address[0]
        )
    }
}

/// A BLE connection.
#[derive(Debug, Clone)]
pub struct Connection {
    pub handle: u16,
    pub peer: BdAddr,
    pub state: ConnectionState,
    pub parameters: ConnectionParameters,
    pub mtu: u16,
}

impl Connection {
    /// Create a new connection.
    #[must_use]
    pub const fn new(handle: u16, peer: BdAddr, parameters: ConnectionParameters) -> Self {
        Self {
            handle,
            peer,
            state: ConnectionState::Connected,
            parameters,
            mtu: 23, // default ATT MTU
        }
    }

    /// Update the MTU (must be >= 23).
    pub const fn update_mtu(&mut self, mtu: u16) {
        if mtu >= 23 {
            self.mtu = mtu;
        }
    }

    /// Maximum ATT payload size (MTU - 1 for opcode, or MTU - 3 for handle+opcode).
    #[must_use]
    pub const fn max_att_payload(&self) -> u16 {
        self.mtu.saturating_sub(3)
    }

    /// Transition to encrypted state.
    pub const fn set_encrypted(&mut self) {
        self.state = ConnectionState::Encrypted;
    }

    /// Disconnect.
    pub const fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnected;
    }

    /// Whether the connection is usable.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// Connection manager tracking multiple connections.
#[derive(Debug, Clone, Default)]
pub struct ConnectionManager {
    connections: Vec<Connection>,
    next_handle: u16,
}

impl ConnectionManager {
    /// Create a new connection manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            connections: Vec::new(),
            next_handle: 0x0040,
        }
    }

    /// Create a new connection.
    pub fn connect(&mut self, peer: BdAddr, params: ConnectionParameters) -> u16 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.connections.push(Connection::new(handle, peer, params));
        handle
    }

    /// Find a connection by handle.
    #[must_use]
    pub fn find(&self, handle: u16) -> Option<&Connection> {
        self.connections.iter().find(|c| c.handle == handle)
    }

    /// Find a mutable connection by handle.
    pub fn find_mut(&mut self, handle: u16) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| c.handle == handle)
    }

    /// Disconnect a connection by handle.
    pub fn disconnect(&mut self, handle: u16) -> bool {
        self.find_mut(handle).is_some_and(|conn| {
            conn.disconnect();
            true
        })
    }

    /// Number of active connections.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.connections.iter().filter(|c| c.is_active()).count()
    }

    /// Total connections (including disconnected).
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.connections.len()
    }

    /// Remove disconnected connections.
    pub fn cleanup(&mut self) {
        self.connections
            .retain(|c| c.state != ConnectionState::Disconnected);
    }
}

// ---------------------------------------------------------------------------
// Well-known GATT UUIDs
// ---------------------------------------------------------------------------

/// Well-known BLE GATT service and characteristic UUIDs.
pub mod well_known {
    use super::Uuid;

    // Services
    pub const GENERIC_ACCESS: Uuid = Uuid::Uuid16(0x1800);
    pub const GENERIC_ATTRIBUTE: Uuid = Uuid::Uuid16(0x1801);
    pub const DEVICE_INFORMATION: Uuid = Uuid::Uuid16(0x180A);
    pub const BATTERY_SERVICE: Uuid = Uuid::Uuid16(0x180F);
    pub const HEART_RATE: Uuid = Uuid::Uuid16(0x180D);
    pub const BLOOD_PRESSURE: Uuid = Uuid::Uuid16(0x1810);
    pub const HEALTH_THERMOMETER: Uuid = Uuid::Uuid16(0x1809);
    pub const CURRENT_TIME: Uuid = Uuid::Uuid16(0x1805);
    pub const RUNNING_SPEED_CADENCE: Uuid = Uuid::Uuid16(0x1814);
    pub const CYCLING_SPEED_CADENCE: Uuid = Uuid::Uuid16(0x1816);

    // Characteristics
    pub const DEVICE_NAME: Uuid = Uuid::Uuid16(0x2A00);
    pub const APPEARANCE: Uuid = Uuid::Uuid16(0x2A01);
    pub const PERIPHERAL_PREFERRED_CONN_PARAMS: Uuid = Uuid::Uuid16(0x2A04);
    pub const SERVICE_CHANGED: Uuid = Uuid::Uuid16(0x2A05);
    pub const BATTERY_LEVEL: Uuid = Uuid::Uuid16(0x2A19);
    pub const HEART_RATE_MEASUREMENT: Uuid = Uuid::Uuid16(0x2A37);
    pub const BODY_SENSOR_LOCATION: Uuid = Uuid::Uuid16(0x2A38);
    pub const MANUFACTURER_NAME: Uuid = Uuid::Uuid16(0x2A29);
    pub const MODEL_NUMBER: Uuid = Uuid::Uuid16(0x2A24);
    pub const FIRMWARE_REVISION: Uuid = Uuid::Uuid16(0x2A26);
    pub const SERIAL_NUMBER: Uuid = Uuid::Uuid16(0x2A25);
    pub const SYSTEM_ID: Uuid = Uuid::Uuid16(0x2A23);
    pub const TX_POWER_LEVEL: Uuid = Uuid::Uuid16(0x2A07);
    pub const TEMPERATURE_MEASUREMENT: Uuid = Uuid::Uuid16(0x2A1C);

    // Descriptors
    pub const CCCD: Uuid = Uuid::Uuid16(0x2902);
    pub const CHARACTERISTIC_USER_DESCRIPTION: Uuid = Uuid::Uuid16(0x2901);
    pub const CHARACTERISTIC_PRESENTATION_FORMAT: Uuid = Uuid::Uuid16(0x2904);
    pub const VALID_RANGE: Uuid = Uuid::Uuid16(0x2906);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- UUID tests ---

    #[test]
    fn uuid16_creation() {
        let u = Uuid::Uuid16(0x1800);
        assert_eq!(u.as_u16(), Some(0x1800));
    }

    #[test]
    fn uuid128_creation() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let u = Uuid::Uuid128(bytes);
        assert_eq!(u.as_u16(), None);
    }

    #[test]
    fn uuid16_expand_to_128() {
        let u = Uuid::Uuid16(0x2A00);
        let full = u.to_uuid128();
        assert_eq!(full[0], 0x00);
        assert_eq!(full[1], 0x2A);
        assert_eq!(full[6], 0x10);
        assert_eq!(full[7], 0x00);
    }

    #[test]
    fn uuid128_expand_noop() {
        let bytes = [0xAA; 16];
        let u = Uuid::Uuid128(bytes);
        assert_eq!(u.to_uuid128(), bytes);
    }

    #[test]
    fn uuid_byte_len() {
        assert_eq!(Uuid::Uuid16(0).byte_len(), 2);
        assert_eq!(Uuid::Uuid128([0; 16]).byte_len(), 16);
    }

    #[test]
    fn uuid_write_to_16() {
        let u = Uuid::Uuid16(0x1234);
        let mut buf = [0u8; 16];
        let n = u.write_to(&mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0x34);
        assert_eq!(buf[1], 0x12);
    }

    #[test]
    fn uuid_write_to_128() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let u = Uuid::Uuid128(bytes);
        let mut buf = [0u8; 16];
        let n = u.write_to(&mut buf);
        assert_eq!(n, 16);
        assert_eq!(buf, bytes);
    }

    #[test]
    fn uuid_debug_16() {
        let u = Uuid::Uuid16(0x1800);
        let s = format!("{u:?}");
        assert!(s.contains("1800"));
    }

    #[test]
    fn uuid_debug_128() {
        let u = Uuid::Uuid128([0xAA; 16]);
        let s = format!("{u:?}");
        assert!(s.contains("AA"));
    }

    #[test]
    fn uuid_equality() {
        assert_eq!(Uuid::Uuid16(0x1800), Uuid::Uuid16(0x1800));
        assert_ne!(Uuid::Uuid16(0x1800), Uuid::Uuid16(0x1801));
    }

    // --- ATT tests ---

    #[test]
    fn att_opcode_from_byte_valid() {
        assert_eq!(
            AttOpcode::from_byte(0x02),
            Some(AttOpcode::ExchangeMtuRequest)
        );
        assert_eq!(
            AttOpcode::from_byte(0x1B),
            Some(AttOpcode::HandleValueNotification)
        );
    }

    #[test]
    fn att_opcode_from_byte_invalid() {
        assert_eq!(AttOpcode::from_byte(0xFF), None);
    }

    #[test]
    fn att_opcode_is_command() {
        assert!(AttOpcode::WriteCommand.is_command());
        assert!(AttOpcode::SignedWriteCommand.is_command());
        assert!(!AttOpcode::WriteRequest.is_command());
    }

    #[test]
    fn att_error_from_byte() {
        assert_eq!(AttError::from_byte(0x01), Some(AttError::InvalidHandle));
        assert_eq!(
            AttError::from_byte(0x11),
            Some(AttError::InsufficientResources)
        );
        assert_eq!(AttError::from_byte(0xFE), None);
    }

    #[test]
    fn att_pdu_roundtrip() {
        let pdu = AttPdu::new(AttOpcode::ReadRequest, vec![0x01, 0x00]);
        let bytes = pdu.to_bytes();
        let parsed = AttPdu::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn att_pdu_from_empty() {
        assert!(AttPdu::from_bytes(&[]).is_none());
    }

    #[test]
    fn att_pdu_from_invalid_opcode() {
        assert!(AttPdu::from_bytes(&[0xFF]).is_none());
    }

    #[test]
    fn att_error_response() {
        let pdu =
            AttPdu::error_response(AttOpcode::ReadRequest, 0x0001, AttError::ReadNotPermitted);
        assert_eq!(pdu.opcode, AttOpcode::ErrorResponse);
        assert_eq!(pdu.params, vec![0x0A, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn att_exchange_mtu_request() {
        let pdu = AttPdu::exchange_mtu_request(512);
        assert_eq!(pdu.opcode, AttOpcode::ExchangeMtuRequest);
        assert_eq!(pdu.params, 512u16.to_le_bytes().to_vec());
    }

    #[test]
    fn att_exchange_mtu_response() {
        let pdu = AttPdu::exchange_mtu_response(256);
        assert_eq!(pdu.opcode, AttOpcode::ExchangeMtuResponse);
    }

    #[test]
    fn att_notification() {
        let pdu = AttPdu::notification(0x0003, &[0xAA, 0xBB]);
        assert_eq!(pdu.opcode, AttOpcode::HandleValueNotification);
        assert_eq!(pdu.params[0..2], 0x0003u16.to_le_bytes());
        assert_eq!(&pdu.params[2..], &[0xAA, 0xBB]);
    }

    #[test]
    fn att_indication() {
        let pdu = AttPdu::indication(0x0005, &[0xCC]);
        assert_eq!(pdu.opcode, AttOpcode::HandleValueIndication);
    }

    #[test]
    fn att_confirmation() {
        let pdu = AttPdu::confirmation();
        assert_eq!(pdu.opcode, AttOpcode::HandleValueConfirmation);
        assert!(pdu.params.is_empty());
    }

    #[test]
    fn att_read_request() {
        let pdu = AttPdu::read_request(0x0010);
        assert_eq!(pdu.opcode, AttOpcode::ReadRequest);
    }

    #[test]
    fn att_read_response() {
        let pdu = AttPdu::read_response(&[1, 2, 3]);
        assert_eq!(pdu.opcode, AttOpcode::ReadResponse);
        assert_eq!(pdu.params, vec![1, 2, 3]);
    }

    #[test]
    fn att_write_request() {
        let pdu = AttPdu::write_request(0x0020, &[0xDD]);
        assert_eq!(pdu.opcode, AttOpcode::WriteRequest);
    }

    #[test]
    fn att_write_response() {
        let pdu = AttPdu::write_response();
        assert_eq!(pdu.opcode, AttOpcode::WriteResponse);
        assert!(pdu.params.is_empty());
    }

    // --- L2CAP tests ---

    #[test]
    fn l2cap_cid_from_u16() {
        assert_eq!(L2capCid::from_u16(0x0004), Some(L2capCid::Att));
        assert_eq!(L2capCid::from_u16(0x0006), Some(L2capCid::Smp));
        assert_eq!(L2capCid::from_u16(0x1234), None);
    }

    #[test]
    fn l2cap_cid_is_le_fixed() {
        assert!(L2capCid::Att.is_le_fixed());
        assert!(L2capCid::Smp.is_le_fixed());
        assert!(L2capCid::LeSignaling.is_le_fixed());
        assert!(!L2capCid::Signaling.is_le_fixed());
    }

    #[test]
    fn l2cap_signal_code() {
        assert_eq!(
            L2capSignalCode::from_byte(0x12),
            Some(L2capSignalCode::ConnectionParameterUpdateRequest)
        );
        assert_eq!(L2capSignalCode::from_byte(0xAA), None);
    }

    #[test]
    fn l2cap_pdu_roundtrip() {
        let pdu = L2capPdu::new(0x0004, vec![0x0A, 0x01, 0x00]);
        let bytes = pdu.to_bytes();
        let parsed = L2capPdu::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn l2cap_pdu_from_short() {
        assert!(L2capPdu::from_bytes(&[0x00]).is_none());
    }

    #[test]
    fn l2cap_pdu_from_truncated() {
        // length says 10, but only 1 byte of payload
        assert!(L2capPdu::from_bytes(&[0x0A, 0x00, 0x04, 0x00, 0xFF]).is_none());
    }

    #[test]
    fn l2cap_att_frame() {
        let att = AttPdu::read_request(0x0001);
        let frame = L2capPdu::att_frame(&att);
        assert_eq!(frame.channel_id, 0x0004);
        assert_eq!(frame.payload, att.to_bytes());
    }

    // --- GATT tests ---

    #[test]
    fn characteristic_properties_flags() {
        let props = CharacteristicProperties::READ.union(CharacteristicProperties::NOTIFY);
        assert!(props.can_read());
        assert!(props.can_notify());
        assert!(!props.can_write());
        assert!(!props.can_indicate());
    }

    #[test]
    fn characteristic_properties_contains() {
        let props = CharacteristicProperties::from_bits(0x1A); // READ | WRITE | NOTIFY
        assert!(props.contains(CharacteristicProperties::READ));
        assert!(props.contains(CharacteristicProperties::NOTIFY));
        assert!(!props.contains(CharacteristicProperties::BROADCAST));
    }

    #[test]
    fn cccd_value() {
        let none = CccdValue::NONE;
        assert!(!none.notifications());
        assert!(!none.indications());

        let notif = CccdValue::NOTIFICATIONS_ENABLED;
        assert!(notif.notifications());
        assert!(!notif.indications());

        let ind = CccdValue::INDICATIONS_ENABLED;
        assert!(!ind.notifications());
        assert!(ind.indications());
    }

    #[test]
    fn cccd_bytes_roundtrip() {
        let v = CccdValue::from_bits(3);
        let bytes = v.to_le_bytes();
        let parsed = CccdValue::from_le_bytes(bytes);
        assert_eq!(parsed, v);
    }

    #[test]
    fn descriptor_cccd() {
        let d = Descriptor::cccd(5);
        assert_eq!(d.handle, 5);
        assert_eq!(d.uuid, Uuid::Uuid16(0x2902));
        assert_eq!(d.value, vec![0, 0]);
    }

    #[test]
    fn descriptor_user_description() {
        let d = Descriptor::user_description(6, "Temperature");
        assert_eq!(d.uuid, Uuid::Uuid16(0x2901));
        assert_eq!(d.value, b"Temperature");
    }

    #[test]
    fn characteristic_declaration_value() {
        let chr = Characteristic::new(
            1,
            2,
            Uuid::Uuid16(0x2A00),
            CharacteristicProperties::READ,
            vec![],
            vec![],
        );
        let decl = chr.declaration_value();
        assert_eq!(decl[0], CharacteristicProperties::READ.bits());
        assert_eq!(decl[1..3], 2u16.to_le_bytes());
    }

    #[test]
    fn characteristic_find_descriptor() {
        let chr = Characteristic::new(
            1,
            2,
            Uuid::Uuid16(0x2A00),
            CharacteristicProperties::NOTIFY,
            vec![],
            vec![Descriptor::cccd(3)],
        );
        assert!(chr.find_descriptor(Uuid::Uuid16(0x2902)).is_some());
        assert!(chr.find_descriptor(Uuid::Uuid16(0x2901)).is_none());
    }

    #[test]
    fn characteristic_has_cccd() {
        let with = Characteristic::new(
            1,
            2,
            Uuid::Uuid16(0x2A37),
            CharacteristicProperties::NOTIFY,
            vec![],
            vec![Descriptor::cccd(3)],
        );
        let without = Characteristic::new(
            1,
            2,
            Uuid::Uuid16(0x2A00),
            CharacteristicProperties::READ,
            vec![],
            vec![],
        );
        assert!(with.has_cccd());
        assert!(!without.has_cccd());
    }

    #[test]
    fn service_primary() {
        let svc = Service::primary(1, 5, Uuid::Uuid16(0x1800), vec![]);
        assert!(svc.is_primary);
        assert_eq!(svc.handle, 1);
    }

    #[test]
    fn service_secondary() {
        let svc = Service::secondary(1, 5, Uuid::Uuid16(0x1800), vec![]);
        assert!(!svc.is_primary);
    }

    #[test]
    fn service_find_characteristic() {
        let chr = Characteristic::new(
            2,
            3,
            Uuid::Uuid16(0x2A00),
            CharacteristicProperties::READ,
            b"Test".to_vec(),
            vec![],
        );
        let svc = Service::primary(1, 5, Uuid::Uuid16(0x1800), vec![chr]);
        assert!(svc.find_characteristic(Uuid::Uuid16(0x2A00)).is_some());
        assert!(svc.find_characteristic(Uuid::Uuid16(0x2A01)).is_none());
    }

    #[test]
    fn service_find_by_handle() {
        let chr = Characteristic::new(
            2,
            3,
            Uuid::Uuid16(0x2A00),
            CharacteristicProperties::READ,
            vec![],
            vec![],
        );
        let svc = Service::primary(1, 5, Uuid::Uuid16(0x1800), vec![chr]);
        assert!(svc.find_characteristic_by_handle(3).is_some());
        assert!(svc.find_characteristic_by_handle(99).is_none());
    }

    #[test]
    fn service_characteristic_count() {
        let svc = Service::primary(1, 1, Uuid::Uuid16(0x1800), vec![]);
        assert_eq!(svc.characteristic_count(), 0);
    }

    #[test]
    fn service_included_services() {
        let mut svc = Service::primary(1, 5, Uuid::Uuid16(0x1800), vec![]);
        svc.add_included_service(10);
        svc.add_included_service(20);
        assert_eq!(svc.included_services, vec![10, 20]);
    }

    #[test]
    fn gatt_server_new() {
        let server = GattServer::new();
        assert_eq!(server.service_count(), 0);
    }

    #[test]
    fn gatt_server_add_service() {
        let mut server = GattServer::new();
        let idx = server.add_service(Uuid::Uuid16(0x1800), true);
        assert_eq!(idx, 0);
        assert_eq!(server.service_count(), 1);
        assert!(server.services[0].is_primary);
    }

    #[test]
    fn gatt_server_add_characteristic() {
        let mut server = GattServer::new();
        let idx = server.add_service(Uuid::Uuid16(0x180F), true);
        let vh = server.add_characteristic(
            idx,
            Uuid::Uuid16(0x2A19),
            CharacteristicProperties::READ.union(CharacteristicProperties::NOTIFY),
            &[100],
        );
        assert!(vh > 0);
        let svc = &server.services[0];
        assert_eq!(svc.characteristics.len(), 1);
        assert!(svc.characteristics[0].has_cccd());
    }

    #[test]
    fn gatt_server_find_service() {
        let mut server = GattServer::new();
        server.add_service(Uuid::Uuid16(0x1800), true);
        server.add_service(Uuid::Uuid16(0x180F), true);
        assert!(server.find_service(Uuid::Uuid16(0x180F)).is_some());
        assert!(server.find_service(Uuid::Uuid16(0x9999)).is_none());
    }

    #[test]
    fn gatt_server_handle_mtu() {
        let server = GattServer::new();
        let resp = server.handle_exchange_mtu(256);
        assert_eq!(resp.opcode, AttOpcode::ExchangeMtuResponse);
    }

    // --- Advertising tests ---

    #[test]
    fn adv_pdu_type_from_byte() {
        assert_eq!(AdvPduType::from_byte(0x00), Some(AdvPduType::AdvInd));
        assert_eq!(AdvPduType::from_byte(0x04), Some(AdvPduType::ScanRsp));
        assert_eq!(AdvPduType::from_byte(0x07), None);
    }

    #[test]
    fn adv_pdu_connectable() {
        assert!(AdvPduType::AdvInd.is_connectable());
        assert!(AdvPduType::AdvDirectInd.is_connectable());
        assert!(!AdvPduType::AdvNonconnInd.is_connectable());
        assert!(!AdvPduType::AdvScanInd.is_connectable());
    }

    #[test]
    fn adv_pdu_scannable() {
        assert!(AdvPduType::AdvInd.is_scannable());
        assert!(AdvPduType::AdvScanInd.is_scannable());
        assert!(!AdvPduType::AdvDirectInd.is_scannable());
    }

    #[test]
    fn ad_type_from_byte() {
        assert_eq!(AdType::from_byte(0x01), Some(AdType::Flags));
        assert_eq!(AdType::from_byte(0x09), Some(AdType::CompleteLocalName));
        assert_eq!(
            AdType::from_byte(0xFF),
            Some(AdType::ManufacturerSpecificData)
        );
        assert_eq!(AdType::from_byte(0xFE), None);
    }

    #[test]
    fn ad_structure_flags() {
        let ad = AdStructure::flags(0x06);
        assert_eq!(ad.ad_type, 0x01);
        assert_eq!(ad.data, vec![0x06]);
    }

    #[test]
    fn ad_structure_name() {
        let ad = AdStructure::complete_local_name("ALICE");
        assert_eq!(ad.ad_type, 0x09);
        assert_eq!(ad.data, b"ALICE");
    }

    #[test]
    fn ad_structure_shortened_name() {
        let ad = AdStructure::shortened_local_name("ALI");
        assert_eq!(ad.ad_type, 0x08);
    }

    #[test]
    fn ad_structure_tx_power() {
        let ad = AdStructure::tx_power_level(-20);
        assert_eq!(ad.ad_type, 0x0A);
    }

    #[test]
    fn ad_structure_manufacturer() {
        let ad = AdStructure::manufacturer_specific(0x004C, &[0x01, 0x02]);
        assert_eq!(ad.ad_type, 0xFF);
        assert_eq!(ad.data[0..2], 0x004Cu16.to_le_bytes());
    }

    #[test]
    fn ad_structure_uuid_list() {
        let ad = AdStructure::complete_list_16bit_uuids(&[0x180F, 0x1800]);
        assert_eq!(ad.ad_type, 0x03);
        assert_eq!(ad.data.len(), 4);
    }

    #[test]
    fn ad_structure_serialize_roundtrip() {
        let ad = AdStructure::flags(0x06);
        let bytes = ad.to_bytes();
        assert_eq!(bytes, vec![2, 0x01, 0x06]);
        let (parsed, consumed) = AdStructure::parse_one(&bytes).unwrap();
        assert_eq!(parsed, ad);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn ad_structure_parse_empty() {
        assert!(AdStructure::parse_one(&[]).is_none());
    }

    #[test]
    fn ad_structure_parse_zero_len() {
        assert!(AdStructure::parse_one(&[0x00]).is_none());
    }

    #[test]
    fn ad_structure_parse_all() {
        let mut data = Vec::new();
        data.extend(AdStructure::flags(0x06).to_bytes());
        data.extend(AdStructure::complete_local_name("BLE").to_bytes());
        let parsed = AdStructure::parse_all(&data);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn advertising_data_builder() {
        let mut adv = AdvertisingData::new();
        adv.add(AdStructure::flags(0x06));
        adv.add(AdStructure::complete_local_name("ALICE-BLE"));
        assert!(adv.fits_in_adv());
        let bytes = adv.to_bytes();
        assert!(bytes.len() <= 31);
    }

    #[test]
    fn advertising_data_overflow() {
        let mut adv = AdvertisingData::new();
        adv.add(AdStructure::complete_local_name(&"X".repeat(30)));
        assert!(!adv.fits_in_adv());
    }

    // --- Pairing / SMP tests ---

    #[test]
    fn io_capability_from_byte() {
        assert_eq!(
            IoCapability::from_byte(0x00),
            Some(IoCapability::DisplayOnly)
        );
        assert_eq!(
            IoCapability::from_byte(0x04),
            Some(IoCapability::KeyboardDisplay)
        );
        assert_eq!(IoCapability::from_byte(0x05), None);
    }

    #[test]
    fn pairing_method_just_works() {
        assert_eq!(
            IoCapability::pairing_method(IoCapability::NoInputNoOutput, IoCapability::DisplayOnly),
            PairingMethod::JustWorks
        );
    }

    #[test]
    fn pairing_method_passkey() {
        assert_eq!(
            IoCapability::pairing_method(IoCapability::KeyboardOnly, IoCapability::DisplayOnly),
            PairingMethod::PasskeyEntry
        );
    }

    #[test]
    fn pairing_method_numeric_comparison() {
        assert_eq!(
            IoCapability::pairing_method(IoCapability::DisplayYesNo, IoCapability::DisplayYesNo),
            PairingMethod::NumericComparison
        );
    }

    #[test]
    fn pairing_method_display_keyboard() {
        assert_eq!(
            IoCapability::pairing_method(IoCapability::DisplayOnly, IoCapability::KeyboardDisplay),
            PairingMethod::PasskeyEntry
        );
    }

    #[test]
    fn smp_code_from_byte() {
        assert_eq!(SmpCode::from_byte(0x01), Some(SmpCode::PairingRequest));
        assert_eq!(SmpCode::from_byte(0x0D), Some(SmpCode::PairingDhKeyCheck));
        assert_eq!(SmpCode::from_byte(0xFF), None);
    }

    #[test]
    fn auth_req_flags() {
        let auth = AuthReq::BONDING.union(AuthReq::MITM).union(AuthReq::SC);
        assert!(auth.requires_bonding());
        assert!(auth.requires_mitm());
        assert!(auth.requires_secure_connections());
    }

    #[test]
    fn auth_req_no_mitm() {
        let auth = AuthReq::BONDING;
        assert!(!auth.requires_mitm());
    }

    #[test]
    fn pairing_params_roundtrip() {
        let params = PairingParams {
            io_capability: IoCapability::DisplayYesNo,
            oob_data_flag: false,
            auth_req: AuthReq::from_bits(0x0D),
            max_encryption_key_size: 16,
            initiator_key_distribution: 0x07,
            responder_key_distribution: 0x07,
        };
        let bytes = params.to_bytes();
        let parsed = PairingParams::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, params);
    }

    #[test]
    fn pairing_params_invalid_io() {
        let bytes = [0xFF, 0, 0, 16, 0, 0];
        assert!(PairingParams::from_bytes(&bytes).is_none());
    }

    #[test]
    fn pairing_request_pdu() {
        let params = PairingParams {
            io_capability: IoCapability::NoInputNoOutput,
            oob_data_flag: false,
            auth_req: AuthReq::BONDING,
            max_encryption_key_size: 16,
            initiator_key_distribution: 0,
            responder_key_distribution: 0,
        };
        let pdu = params.to_request_pdu();
        assert_eq!(pdu[0], SmpCode::PairingRequest as u8);
        assert_eq!(pdu.len(), 7);
    }

    #[test]
    fn pairing_response_pdu() {
        let params = PairingParams {
            io_capability: IoCapability::KeyboardOnly,
            oob_data_flag: true,
            auth_req: AuthReq::from_bits(0x05),
            max_encryption_key_size: 16,
            initiator_key_distribution: 0x01,
            responder_key_distribution: 0x01,
        };
        let pdu = params.to_response_pdu();
        assert_eq!(pdu[0], SmpCode::PairingResponse as u8);
    }

    #[test]
    fn pairing_failed_reason() {
        assert_eq!(
            PairingFailedReason::from_byte(0x05),
            Some(PairingFailedReason::PairingNotSupported)
        );
        assert_eq!(PairingFailedReason::from_byte(0xEE), None);
    }

    #[test]
    fn pairing_failed_pdu() {
        let pdu = PairingFailedReason::ConfirmValueFailed.to_pdu();
        assert_eq!(pdu, vec![0x05, 0x04]);
    }

    // --- Connection tests ---

    #[test]
    fn connection_state_active() {
        assert!(ConnectionState::Connected.is_active());
        assert!(ConnectionState::Encrypted.is_active());
        assert!(!ConnectionState::Disconnected.is_active());
        assert!(!ConnectionState::Connecting.is_active());
    }

    #[test]
    fn connection_state_encrypted() {
        assert!(ConnectionState::Encrypted.is_encrypted());
        assert!(!ConnectionState::Connected.is_encrypted());
    }

    #[test]
    fn connection_params_valid() {
        let p = ConnectionParameters::new(80, 0, 100);
        assert!(p.is_valid());
    }

    #[test]
    fn connection_params_invalid_interval() {
        let p = ConnectionParameters::new(5, 0, 100); // interval < 6
        assert!(!p.is_valid());
    }

    #[test]
    fn connection_params_invalid_latency() {
        let p = ConnectionParameters::new(80, 500, 100); // latency > 499
        assert!(!p.is_valid());
    }

    #[test]
    fn connection_params_invalid_timeout() {
        let p = ConnectionParameters::new(80, 0, 5); // timeout < 10
        assert!(!p.is_valid());
    }

    #[test]
    fn connection_params_ms() {
        let p = ConnectionParameters::new(80, 0, 100);
        let interval = p.interval_ms();
        assert!((interval - 100.0).abs() < f64::EPSILON);
        let timeout = p.supervision_timeout_ms();
        assert!((timeout - 1000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn connection_params_bytes_roundtrip() {
        let p = ConnectionParameters::new(80, 4, 200);
        let bytes = p.to_bytes();
        let parsed = ConnectionParameters::from_bytes(&bytes);
        assert_eq!(parsed, p);
    }

    #[test]
    fn bd_addr_display() {
        let addr = BdAddr::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], AddressType::Public);
        let s = format!("{addr}");
        assert_eq!(s, "06:05:04:03:02:01");
    }

    #[test]
    fn bd_addr_static_random() {
        let addr = BdAddr::new([0x00, 0x00, 0x00, 0x00, 0x00, 0xC0], AddressType::Random);
        assert!(addr.is_static_random());
        assert!(!addr.is_resolvable_private());
    }

    #[test]
    fn bd_addr_resolvable_private() {
        let addr = BdAddr::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x40], AddressType::Random);
        assert!(addr.is_resolvable_private());
        assert!(!addr.is_static_random());
    }

    #[test]
    fn bd_addr_non_resolvable_private() {
        let addr = BdAddr::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00], AddressType::Random);
        assert!(addr.is_non_resolvable_private());
    }

    #[test]
    fn bd_addr_public_not_random() {
        let addr = BdAddr::new([0; 6], AddressType::Public);
        assert!(!addr.is_static_random());
        assert!(!addr.is_resolvable_private());
    }

    #[test]
    fn connection_new() {
        let peer = BdAddr::new([1, 2, 3, 4, 5, 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let conn = Connection::new(0x0040, peer, params);
        assert_eq!(conn.mtu, 23);
        assert!(conn.is_active());
    }

    #[test]
    fn connection_update_mtu() {
        let peer = BdAddr::new([0; 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let mut conn = Connection::new(1, peer, params);
        conn.update_mtu(512);
        assert_eq!(conn.mtu, 512);
    }

    #[test]
    fn connection_mtu_min() {
        let peer = BdAddr::new([0; 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let mut conn = Connection::new(1, peer, params);
        conn.update_mtu(10); // too small, should not update
        assert_eq!(conn.mtu, 23);
    }

    #[test]
    fn connection_max_att_payload() {
        let peer = BdAddr::new([0; 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let conn = Connection::new(1, peer, params);
        assert_eq!(conn.max_att_payload(), 20);
    }

    #[test]
    fn connection_encrypt_disconnect() {
        let peer = BdAddr::new([0; 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let mut conn = Connection::new(1, peer, params);
        conn.set_encrypted();
        assert!(conn.state.is_encrypted());
        conn.disconnect();
        assert!(!conn.is_active());
    }

    #[test]
    fn connection_manager_connect() {
        let mut mgr = ConnectionManager::new();
        let peer = BdAddr::new([1, 2, 3, 4, 5, 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let h = mgr.connect(peer, params);
        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.find(h).is_some());
    }

    #[test]
    fn connection_manager_disconnect() {
        let mut mgr = ConnectionManager::new();
        let peer = BdAddr::new([0; 6], AddressType::Random);
        let params = ConnectionParameters::new(80, 0, 100);
        let h = mgr.connect(peer, params);
        assert!(mgr.disconnect(h));
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn connection_manager_disconnect_nonexistent() {
        let mut mgr = ConnectionManager::new();
        assert!(!mgr.disconnect(0xFFFF));
    }

    #[test]
    fn connection_manager_cleanup() {
        let mut mgr = ConnectionManager::new();
        let peer = BdAddr::new([0; 6], AddressType::Public);
        let params = ConnectionParameters::new(80, 0, 100);
        let h = mgr.connect(peer, params);
        mgr.disconnect(h);
        assert_eq!(mgr.total_count(), 1);
        mgr.cleanup();
        assert_eq!(mgr.total_count(), 0);
    }

    #[test]
    fn connection_manager_multiple() {
        let mut mgr = ConnectionManager::new();
        let params = ConnectionParameters::new(80, 0, 100);
        let h1 = mgr.connect(BdAddr::new([1; 6], AddressType::Public), params);
        let h2 = mgr.connect(BdAddr::new([2; 6], AddressType::Public), params);
        assert_ne!(h1, h2);
        assert_eq!(mgr.active_count(), 2);
    }

    // --- Well-known UUID tests ---

    #[test]
    fn well_known_uuids() {
        assert_eq!(well_known::GENERIC_ACCESS.as_u16(), Some(0x1800));
        assert_eq!(well_known::BATTERY_LEVEL.as_u16(), Some(0x2A19));
        assert_eq!(well_known::CCCD.as_u16(), Some(0x2902));
        assert_eq!(well_known::HEART_RATE.as_u16(), Some(0x180D));
    }

    #[test]
    fn well_known_device_info_uuids() {
        assert_eq!(well_known::DEVICE_INFORMATION.as_u16(), Some(0x180A));
        assert_eq!(well_known::MANUFACTURER_NAME.as_u16(), Some(0x2A29));
        assert_eq!(well_known::MODEL_NUMBER.as_u16(), Some(0x2A24));
        assert_eq!(well_known::FIRMWARE_REVISION.as_u16(), Some(0x2A26));
        assert_eq!(well_known::SERIAL_NUMBER.as_u16(), Some(0x2A25));
        assert_eq!(well_known::SYSTEM_ID.as_u16(), Some(0x2A23));
    }

    // --- Integration-style tests ---

    #[test]
    fn full_gatt_server_setup() {
        let mut server = GattServer::new();

        // GAP service
        let gap_idx = server.add_service(well_known::GENERIC_ACCESS, true);
        server.add_characteristic(
            gap_idx,
            well_known::DEVICE_NAME,
            CharacteristicProperties::READ,
            b"ALICE-BLE",
        );
        server.add_characteristic(
            gap_idx,
            well_known::APPEARANCE,
            CharacteristicProperties::READ,
            &0x0000u16.to_le_bytes(),
        );

        // Battery service
        let bat_idx = server.add_service(well_known::BATTERY_SERVICE, true);
        server.add_characteristic(
            bat_idx,
            well_known::BATTERY_LEVEL,
            CharacteristicProperties::READ.union(CharacteristicProperties::NOTIFY),
            &[100],
        );

        assert_eq!(server.service_count(), 2);
        let gap = server.find_service(well_known::GENERIC_ACCESS).unwrap();
        assert_eq!(gap.characteristic_count(), 2);
        let bat = server.find_service(well_known::BATTERY_SERVICE).unwrap();
        let bl = bat.find_characteristic(well_known::BATTERY_LEVEL).unwrap();
        assert!(bl.has_cccd());
        assert!(bl.properties.can_notify());
    }

    #[test]
    fn full_advertising_setup() {
        let mut adv = AdvertisingData::new();
        adv.add(AdStructure::flags(0x06));
        adv.add(AdStructure::complete_list_16bit_uuids(&[0x180F]));
        adv.add(AdStructure::complete_local_name("ALICE"));

        let mut scan = ScanResponseData::new();
        scan.add(AdStructure::tx_power_level(0));
        scan.add(AdStructure::manufacturer_specific(0x1234, &[0x01]));

        assert!(adv.fits_in_adv());
        assert!(scan.fits_in_adv());
    }

    #[test]
    fn full_pairing_flow() {
        let init_params = PairingParams {
            io_capability: IoCapability::DisplayYesNo,
            oob_data_flag: false,
            auth_req: AuthReq::BONDING.union(AuthReq::SC),
            max_encryption_key_size: 16,
            initiator_key_distribution: 0x01,
            responder_key_distribution: 0x01,
        };
        let req_pdu = init_params.to_request_pdu();
        assert_eq!(req_pdu[0], SmpCode::PairingRequest as u8);

        let resp_params = PairingParams {
            io_capability: IoCapability::DisplayYesNo,
            oob_data_flag: false,
            auth_req: AuthReq::BONDING.union(AuthReq::SC),
            max_encryption_key_size: 16,
            initiator_key_distribution: 0x01,
            responder_key_distribution: 0x01,
        };
        let resp_pdu = resp_params.to_response_pdu();
        assert_eq!(resp_pdu[0], SmpCode::PairingResponse as u8);

        let method =
            IoCapability::pairing_method(init_params.io_capability, resp_params.io_capability);
        assert_eq!(method, PairingMethod::NumericComparison);
    }

    #[test]
    fn full_l2cap_att_roundtrip() {
        let att_pdu = AttPdu::notification(0x0003, &[0x64]);
        let l2cap = L2capPdu::att_frame(&att_pdu);
        let bytes = l2cap.to_bytes();
        let parsed = L2capPdu::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.channel_id, L2capCid::Att as u16);
        let inner = AttPdu::from_bytes(&parsed.payload).unwrap();
        assert_eq!(inner.opcode, AttOpcode::HandleValueNotification);
    }

    #[test]
    fn connection_with_encryption() {
        let mut mgr = ConnectionManager::new();
        let peer = BdAddr::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], AddressType::Random);
        let params = ConnectionParameters::new(24, 0, 200);
        let h = mgr.connect(peer, params);
        let conn = mgr.find_mut(h).unwrap();
        assert!(!conn.state.is_encrypted());
        conn.set_encrypted();
        assert!(conn.state.is_encrypted());
        assert!(conn.is_active());
    }
}
