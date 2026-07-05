//! UUID (`Uuid` — 16/32/128 bit).

use core::fmt;

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
