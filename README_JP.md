[English](README.md) | **日本語**

# ALICE-BLE

[Project A.L.I.C.E.](https://github.com/anthropics/alice) の純Rust BLEプロトコルスタック

## 概要

`alice-ble` は外部依存なしの純RustによるBluetooth Low Energyプロトコルスタックです。GATT、ATT、L2CAP、アドバタイジング、ペアリング、接続管理をカバーします。

## 機能

- **UUID処理** — 16ビット（SIG割当）と128ビット（ベンダー）UUIDのサポート、ベースUUID展開
- **GATT** — サービス/キャラクタリスティック/ディスクリプタの検出とアクセス
- **ATTプロトコル** — アトリビュートプロトコルのリクエスト/レスポンス処理
- **L2CAP** — 論理リンク制御適応プロトコル
- **アドバタイジング** — 設定可能なアドバタイズメントデータ構築
- **ペアリング** — 鍵交換によるセキュアペアリング
- **接続管理** — 接続パラメータネゴシエーション
- **通知/インディケーション** — サーバー主導の値更新

## クイックスタート

```rust
use alice_ble::Uuid;

let heart_rate = Uuid::Uuid16(0x180D);
let full = heart_rate.to_uuid128();

let custom = Uuid::Uuid128([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                             0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
```

## アーキテクチャ

```
alice-ble
├── Uuid              — 16ビット/128ビットUUID処理
├── gatt              — GATTサービスとキャラクタリスティック
├── att               — アトリビュートプロトコル層
├── l2cap             — L2CAPシグナリングとチャンネル
├── advertising       — アドバタイズメントデータビルダー
├── pairing           — セキュアペアリングと鍵交換
├── connection        — 接続パラメータ管理
└── notification      — 通知/インディケーションサポート
```

## ライセンス

MIT OR Apache-2.0
