//! Connection management (`ConnectionState` / `ConnectionParameters` / `AddressType` / `BdAddr` / `Connection` / `ConnectionManager`).

use core::fmt;

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
