**English** | [日本語](README_JP.md)

# ALICE-BLE

Pure Rust BLE protocol stack for [Project A.L.I.C.E.](https://github.com/anthropics/alice)

## Overview

`alice-ble` implements the Bluetooth Low Energy protocol stack in pure Rust with no external dependencies — covering GATT, ATT, L2CAP, advertising, pairing, and connection management.

## Features

- **UUID Handling** — 16-bit (SIG-assigned) and 128-bit (vendor) UUID support with base UUID expansion
- **GATT** — service/characteristic/descriptor discovery and access
- **ATT Protocol** — Attribute Protocol request/response handling
- **L2CAP** — Logical Link Control and Adaptation Protocol
- **Advertising** — configurable advertisement data construction
- **Pairing** — secure pairing with key exchange
- **Connection Management** — connection parameter negotiation
- **Notification/Indication** — server-initiated value updates

## Quick Start

```rust
use alice_ble::Uuid;

let heart_rate = Uuid::Uuid16(0x180D);
let full = heart_rate.to_uuid128();

let custom = Uuid::Uuid128([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                             0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
```

## Architecture

```
alice-ble
├── Uuid              — 16-bit / 128-bit UUID handling
├── gatt              — GATT services & characteristics
├── att               — Attribute Protocol layer
├── l2cap             — L2CAP signaling & channels
├── advertising       — advertisement data builder
├── pairing           — secure pairing & key exchange
├── connection        — connection parameter management
└── notification      — notification/indication support
```

## License

MIT OR Apache-2.0
