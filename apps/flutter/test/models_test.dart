import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/models/vault_models.dart';

void main() {
  group('Vault Models Roundtrip & Logic', () {
    test('ItemCategory serialization and display names', () {
      for (final cat in ItemCategory.values) {
        final json = cat.toJson();
        final deserialized = ItemCategory.fromJson(json);
        expect(deserialized, equals(cat));
        expect(cat.displayName.isNotEmpty, isTrue);
      }
      expect(ItemCategory.fromJson('unknown'), equals(ItemCategory.login));
    });

    test('FieldType serialization', () {
      for (final ft in FieldType.values) {
        final json = ft.toJson();
        final deserialized = FieldType.fromJson(json);
        expect(deserialized, equals(ft));
      }
      expect(FieldType.fromJson('unknown'), equals(FieldType.text));
    });

    test('CustomField JSON roundtrip', () {
      final field = CustomField(
        name: 'PIN',
        value: '9876',
        fieldType: FieldType.concealed,
      );

      final jsonMap = field.toJson();
      final fromJson = CustomField.fromJson(jsonMap);
      expect(fromJson.name, equals('PIN'));
      expect(fromJson.value, equals('9876'));
      expect(fromJson.fieldType, equals(FieldType.concealed));
    });

    test('ItemRevision JSON roundtrip', () {
      final rev = ItemRevision(
        timestamp: 1600000000,
        title: 'Work Email',
        username: 'worker@company.com',
        password: 'old-password-123',
        urls: ['https://company.com/login'],
        notes: 'Backup note',
        customFields: [
          CustomField(name: 'EmpID', value: 'E4401', fieldType: FieldType.text),
        ],
      );

      final jsonMap = rev.toJson();
      final fromJson = ItemRevision.fromJson(jsonMap);
      expect(fromJson.timestamp, equals(1600000000));
      expect(fromJson.title, equals('Work Email'));
      expect(fromJson.username, equals('worker@company.com'));
      expect(fromJson.password, equals('old-password-123'));
      expect(fromJson.urls, contains('https://company.com/login'));
      expect(fromJson.customFields.length, equals(1));
      expect(fromJson.customFields.first.name, equals('EmpID'));
    });

    test('VaultItem serialization, fields, and trash lifecycle', () {
      final nowSec = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final item = VaultItem(
        id: 'item-uuid-1234',
        title: 'Work Email',
        category: ItemCategory.login,
        username: 'worker@company.com',
        password: 'secure-password-456',
        urls: ['https://mail.company.com'],
        notes: 'Primary business email',
        totpSeed: 'JBSWY3DPEHPK3PXP',
        tags: ['work', 'email'],
        favorite: true,
        trashedAt: null,
        createdAt: nowSec,
        updatedAt: nowSec,
        customFields: [
          CustomField(name: 'PinCode', value: '1234', fieldType: FieldType.concealed),
        ],
        revisionHistory: [
          ItemRevision(
            timestamp: nowSec - 3600,
            title: 'Work Email',
            password: 'old-password-000',
          ),
        ],
      );

      expect(item.isTrashed, isFalse);

      // JSON roundtrip
      final jsonStr = jsonEncode(item.toJson());
      final decoded = jsonDecode(jsonStr) as Map<String, dynamic>;
      final fromJson = VaultItem.fromJson(decoded);

      expect(fromJson.id, equals('item-uuid-1234'));
      expect(fromJson.title, equals('Work Email'));
      expect(fromJson.category, equals(ItemCategory.login));
      expect(fromJson.username, equals('worker@company.com'));
      expect(fromJson.password, equals('secure-password-456'));
      expect(fromJson.urls, contains('https://mail.company.com'));
      expect(fromJson.totpSeed, equals('JBSWY3DPEHPK3PXP'));
      expect(fromJson.tags, contains('work'));
      expect(fromJson.favorite, isTrue);
      expect(fromJson.customFields.length, equals(1));
      expect(fromJson.customFields.first.value, equals('1234'));
      expect(fromJson.revisionHistory.length, equals(1));
      expect(fromJson.revisionHistory.first.password, equals('old-password-000'));
      expect(fromJson.isTrashed, isFalse);

      // Trash lifecycle
      item.trashedAt = nowSec;
      expect(item.isTrashed, isTrue);
    });

    test('VaultPayload root serialization and deserialization', () {
      final nowSec = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final payload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'Personal Production Vault',
        createdAt: nowSec,
        updatedAt: nowSec,
        items: [
          VaultItem(
            id: 'item-1',
            title: 'GitHub',
            category: ItemCategory.login,
            username: 'dev@rust.lang',
            password: 'super-secret-password-1',
            createdAt: nowSec,
            updatedAt: nowSec,
          ),
          VaultItem(
            id: 'item-2',
            title: 'Bank Note',
            category: ItemCategory.secureNote,
            notes: 'Safe combination: 12-34-56',
            createdAt: nowSec,
            updatedAt: nowSec,
          ),
        ],
      );

      final serialized = payload.serialize();
      expect(serialized.isNotEmpty, isTrue);

      final fromJson = VaultPayload.fromJson(jsonDecode(serialized) as Map<String, dynamic>);
      expect(fromJson.schemaVersion, equals(1));
      expect(fromJson.vaultName, equals('Personal Production Vault'));
      expect(fromJson.items.length, equals(2));
      expect(fromJson.items.first.title, equals('GitHub'));
      expect(fromJson.items.last.category, equals(ItemCategory.secureNote));
    });

    test('CrackTimeEstimate parsing from JSON', () {
      final jsonMap = {
        'entropy_bits': 88,
        'rating': 'Strong',
        'online_time': '100 centuries',
        'offline_gpu_time': '34 years',
        'cluster_time': '1.2 months',
      };

      final est = CrackTimeEstimate.fromJson(jsonMap);
      expect(est.entropyBits, equals(88));
      expect(est.rating, equals('Strong'));
      expect(est.onlineTime, equals('100 centuries'));
      expect(est.offlineGpuTime, equals('34 years'));
      expect(est.clusterTime, equals('1.2 months'));
    });
  });
}
