//! Convenience re-export (= `use alice_ble::prelude::*;`).

pub use crate::advertising::{AdStructure, AdType, AdvPduType, AdvertisingData, ScanResponseData};
pub use crate::att::{AttError, AttOpcode, AttPdu};
pub use crate::connection::{
    AddressType, BdAddr, Connection, ConnectionManager, ConnectionParameters, ConnectionState,
};
pub use crate::gatt::{
    CccdValue, Characteristic, CharacteristicProperties, Descriptor, GattServer, Service,
};
pub use crate::l2cap::{L2capCid, L2capPdu, L2capSignalCode};
pub use crate::pairing::{
    AuthReq, IoCapability, PairingFailedReason, PairingMethod, PairingParams, SmpCode,
};
pub use crate::uuid::Uuid;
