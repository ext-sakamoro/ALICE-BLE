//! Advertising (`AdvPduType` / `AdType` / `AdStructure` / `AdvertisingData` / `ScanResponseData`).

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
