//! Well-known GATT UUIDs.

use crate::uuid::Uuid;

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
