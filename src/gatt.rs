//! GATT (`CharacteristicProperties` / `CccdValue` / `Descriptor` / `Characteristic` / `Service` / `GattServer`).

use crate::att::AttPdu;
use crate::uuid::Uuid;

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
