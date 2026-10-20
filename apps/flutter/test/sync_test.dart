import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/core/ffi/vault_ffi_bindings.dart';
import 'package:pwdvault_flutter/models/vault_models.dart';
import 'package:pwdvault_flutter/views/settings/sync_sheet.dart';

void main() {
  group('Phase 6 Encrypted Synchronization Tests', () {
    const testSyncKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    test('Create and apply .syncpack roundtrip with CRDT conflict preservation', () {
      final ffi = RustVaultFfi.instance;
      expect(ffi.isAvailable, isTrue);

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      // 1. Initial local item
      final localItem = VaultItem(
        id: 'sync-item-42',
        title: 'GitHub Work Account',
        category: ItemCategory.login,
        username: 'dev@github.com',
        password: 'local-password-v1',
        createdAt: now - 3600,
        updatedAt: now - 1800,
      );

      final localPayload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'Laptop Vault',
        createdAt: now - 86400,
        updatedAt: now - 1800,
        items: [localItem],
      );

      final localClock = VectorClock(clocks: {'dev-laptop': 1});

      // 2. Remote item modified concurrently with later timestamp
      final remoteItem = VaultItem(
        id: 'sync-item-42',
        title: 'GitHub Work Account',
        category: ItemCategory.login,
        username: 'dev@github.com',
        password: 'remote-phone-password-v2',
        createdAt: now - 3600,
        updatedAt: now - 60, // Later timestamp
      );

      final remotePayload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'Phone Vault',
        createdAt: now - 86400,
        updatedAt: now - 60,
        items: [remoteItem],
      );

      final remoteClock = VectorClock(clocks: {'dev-phone': 2});

      // 3. Export .syncpack from remote device
      final packBytes = ffi.createSyncPack(
        payload: remotePayload,
        syncKeyHex: testSyncKeyHex,
        deviceId: 'dev-phone',
        deviceName: 'iPhone Client',
        clock: remoteClock,
      );

      expect(packBytes, isA<Uint8List>());
      expect(packBytes.length, greaterThan(100)); // Header is 100 bytes + encrypted payload

      // 4. Ingest .syncpack on local device
      final result = ffi.applySyncPack(
        localPayload: localPayload,
        packBytes: packBytes,
        syncKeyHex: testSyncKeyHex,
        localClock: localClock,
      );

      // Verify CRDT report
      expect(result.report.updated, equals(1));
      expect(result.report.conflictsPreserved, equals(1));

      // Verify merged payload
      final mergedItem = result.mergedPayload.items.firstWhere((i) => i.id == 'sync-item-42');
      expect(mergedItem.password, equals('remote-phone-password-v2'));

      // Invariant: Zero Data Loss -> old local password preserved in history!
      expect(mergedItem.revisionHistory.length, equals(1));
      expect(mergedItem.revisionHistory.first.password, equals('local-password-v1'));

      // Verify merged vector clock contains both devices
      expect(result.mergedClock.clocks['dev-laptop'], equals(1));
      expect(result.mergedClock.clocks['dev-phone'], equals(2));
    });

    test('Device Pairing QR URI generation and verification', () {
      final ffi = RustVaultFfi.instance;

      // 1. Generate pairing URI
      final uri = ffi.generatePairingQrUri(
        syncKeyHex: testSyncKeyHex,
        deviceId: 'dev-desktop-win',
        deviceName: 'Workstation Studio',
        addresses: ['192.168.1.50:45824', '10.0.0.12:45824'],
      );

      expect(uri.startsWith('pwdvault://pair?data='), isTrue);

      // 2. Verify with matching sync key
      final verified = ffi.verifyPairingQrUri(qrUri: uri, syncKeyHex: testSyncKeyHex);
      expect(verified.deviceId, equals('dev-desktop-win'));
      expect(verified.deviceName, equals('Workstation Studio'));
      expect(verified.addresses.contains('192.168.1.50:45824'), isTrue);
      expect(verified.expiresAt, greaterThan(verified.createdAt));

      // 3. Verify with mismatched sync key fails
      const wrongKeyHex = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      expect(
        () => ffi.verifyPairingQrUri(qrUri: uri, syncKeyHex: wrongKeyHex),
        throwsA(isA<Exception>()),
      );
    });

    test('Direct CRDT mergePayloads', () {
      final ffi = RustVaultFfi.instance;
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      final localPayload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'V1',
        createdAt: now,
        updatedAt: now,
        items: [
          VaultItem(
            id: 'item-a',
            title: 'Local Item A',
            category: ItemCategory.login,
            createdAt: now,
            updatedAt: now,
          ),
        ],
      );

      final remotePayload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'V2',
        createdAt: now,
        updatedAt: now + 10,
        items: [
          VaultItem(
            id: 'item-b',
            title: 'Remote Item B',
            category: ItemCategory.secureNote,
            createdAt: now,
            updatedAt: now + 10,
          ),
        ],
      );

      final mergeRes = ffi.mergePayloads(
        localPayload: localPayload,
        remotePayload: remotePayload,
      );

      expect(mergeRes.report.added, equals(1));
      expect(mergeRes.mergedPayload.items.length, equals(2));
      expect(mergeRes.mergedPayload.items.any((i) => i.id == 'item-a'), isTrue);
      expect(mergeRes.mergedPayload.items.any((i) => i.id == 'item-b'), isTrue);
    });

    testWidgets('SyncSheet renders 3 tabs and toggles between them', (tester) async {
      tester.view.physicalSize = const Size(1200, 1000);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SyncSheet(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Check header and tabs
      expect(find.text('Encrypted Synchronization & Pairing'), findsOneWidget);
      expect(find.text('Sync Package'), findsOneWidget);
      expect(find.text('Pair & LAN Sync'), findsOneWidget);
      expect(find.text('Vector Clocks'), findsOneWidget);

      // Verify Tab 1 contents
      expect(find.text('Zero Data Loss CRDT Synchronization'), findsOneWidget);
      expect(find.text('Pre-Shared 256-Bit Sync Key'), findsOneWidget);
      expect(find.text('Export .syncpack Archive'), findsOneWidget);

      // Tap Tab 2
      await tester.tap(find.text('Pair & LAN Sync'));
      await tester.pumpAndSettle();

      expect(find.text('Out-of-Band Device Pairing'), findsOneWidget);
      expect(find.text('Pair with Remote Peer Device'), findsOneWidget);
      expect(find.text('Direct Local Area Network (LAN) Sync'), findsOneWidget);

      // Tap Tab 3
      await tester.tap(find.text('Vector Clocks'));
      await tester.pumpAndSettle();

      expect(find.text('Lamport Logical Causality Tracker'), findsOneWidget);
      expect(find.text('Cluster Device Vector Clocks'), findsOneWidget);
    });
  });
}
