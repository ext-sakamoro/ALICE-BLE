//! Integration tests spanning multiple modules.

#![allow(
    clippy::float_cmp,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::bool_to_int_with_if,
    clippy::approx_constant,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::format_collect,
    clippy::similar_names,
    clippy::needless_collect,
    clippy::iter_cloned_collect,
    clippy::suboptimal_flops,
    clippy::should_panic_without_expect,
    clippy::manual_range_contains,
    clippy::bool_assert_comparison
)]

use crate::advertising::*;
use crate::att::*;
use crate::connection::*;
use crate::gatt::*;
use crate::l2cap::*;
use crate::pairing::*;
use crate::uuid::*;
use crate::well_known_uuids::*;

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
    let pdu = AttPdu::error_response(AttOpcode::ReadRequest, 0x0001, AttError::ReadNotPermitted);
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

    let method = IoCapability::pairing_method(init_params.io_capability, resp_params.io_capability);
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
