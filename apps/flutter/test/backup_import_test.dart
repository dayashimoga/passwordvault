import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/core/ffi/vault_ffi_bindings.dart';
import 'package:pwdvault_flutter/models/vault_models.dart';

void main() {
  group('Rust Core Backup, Recovery & Import FFI Integration Tests', () {
    final ffi = RustVaultFfi.instance;

    setUpAll(() {
      expect(ffi.isAvailable, isTrue, reason: 'FFI DLL must be loaded');
    });

    VaultPayload createSamplePayload() {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      return VaultPayload(
        schemaVersion: 1,
        vaultName: 'Production Test Vault',
        createdAt: now,
        updatedAt: now,
        items: [
          VaultItem(
            id: 'item-1',
            title: 'GitHub Enterprise',
            category: ItemCategory.login,
            username: 'alice@company.com',
            password: 'github-ultra-secret-token',
            urls: ['https://github.com/login'],
            notes: 'Primary dev access',
            createdAt: now,
            updatedAt: now,
          ),
          VaultItem(
            id: 'item-2',
            title: 'Server Root SSH',
            category: ItemCategory.secureNote,
            notes: 'SSH Ed25519 Private Key',
            createdAt: now,
            updatedAt: now,
          ),
        ],
      );
    }

    test('Backup creation, rehearsal, and restore with passphrase roundtrip', () {
      final payload = createSamplePayload();
      const backupPassphrase = 'Backup-Secret-Passphrase-2026!';

      // 1. Create backup
      final backupBytes = ffi.createBackup(payload, passphrase: backupPassphrase);
      expect(backupBytes.length, greaterThan(120));

      // 2. Rehearse restore (dry-run)
      final report = ffi.rehearseRestore(backupBytes, passphrase: backupPassphrase);
      expect(report.isValid, isTrue);
      expect(report.vaultName, equals('Production Test Vault'));
      expect(report.itemCount, equals(2));
      expect(report.trashedCount, equals(0));
      expect(report.categoryCounts['Login'], equals(1));
      expect(report.categoryCounts['SecureNote'], equals(1));
      expect(report.errorMessage, isNull);

      // 3. Full restore
      final restored = ffi.restoreBackup(backupBytes, passphrase: backupPassphrase);
      expect(restored.vaultName, equals('Production Test Vault'));
      expect(restored.items.length, equals(2));
      expect(restored.items[0].title, equals('GitHub Enterprise'));
      expect(restored.items[0].password, equals('github-ultra-secret-token'));
    });

    test('Backup creation, rehearsal, and restore with 256-bit Recovery Key', () {
      final payload = createSamplePayload();
      final recoveryKey = ffi.generateRecoveryKey();
      expect(recoveryKey.startsWith('PV-'), isTrue);

      // 1. Create backup using recovery key
      final backupBytes = ffi.createBackup(payload, recoveryKey: recoveryKey);
      expect(backupBytes.length, greaterThan(120));

      // 2. Rehearse restore using recovery key
      final report = ffi.rehearseRestore(backupBytes, recoveryKey: recoveryKey);
      expect(report.isValid, isTrue);
      expect(report.itemCount, equals(2));

      // 3. Full restore using recovery key
      final restored = ffi.restoreBackup(backupBytes, recoveryKey: recoveryKey);
      expect(restored.items.length, equals(2));
      expect(restored.items[1].title, equals('Server Root SSH'));
    });

    test('Backup rehearsal and restore fail cleanly on invalid credentials', () {
      final payload = createSamplePayload();
      final backupBytes = ffi.createBackup(payload, passphrase: 'CorrectPassphrase123');

      final report = ffi.rehearseRestore(backupBytes, passphrase: 'WrongPassphrase456');
      expect(report.isValid, isFalse);
      expect(report.errorMessage, isNotNull);

      expect(
        () => ffi.restoreBackup(backupBytes, passphrase: 'WrongPassphrase456'),
        throwsA(isA<FormatException>()),
      );
    });

    test('Backup rejects tampered data and bit-flips', () {
      final payload = createSamplePayload();
      final backupBytes = ffi.createBackup(payload, passphrase: 'SecurePassphrase99');
      final tampered = Uint8List.fromList(backupBytes);
      tampered[100] ^= 0xFF; // Flip bit in payload

      final report = ffi.rehearseRestore(tampered, passphrase: 'SecurePassphrase99');
      expect(report.isValid, isFalse);
      expect(report.errorMessage!.contains('integrity commitment failed'), isTrue);
    });

    test('Recovery Kit Document generation and Markdown rendering', () {
      final key = ffi.generateRecoveryKey();
      final doc = ffi.generateRecoveryKitDoc('Personal Vault', key);

      expect(doc.vaultName, equals('Personal Vault'));
      expect(doc.formattedKey, equals(key));
      expect(doc.storageInstructions.contains('fireproof safe'), isTrue);

      final md = doc.renderMarkdown();
      expect(md.contains('PWDVAULT EMERGENCY RECOVERY KIT'), isTrue);
      expect(md.contains(key), isTrue);
    });

    test('Parse Bitwarden JSON export format', () {
      final bwJson = jsonEncode({
        'folders': [],
        'items': [
          {
            'id': 'bw-1',
            'type': 1, // Login
            'name': 'Twitter / X',
            'login': {
              'username': 'bob_dev',
              'password': 'x-password-123',
              'uris': [{'uri': 'https://twitter.com'}]
            }
          },
          {
            'id': 'bw-2',
            'type': 2, // Secure Note
            'name': 'Wi-Fi Password',
            'notes': 'WPA3: HomeNetwork-Pass'
          }
        ]
      });

      final parsed = ffi.parseImport(bwJson);
      expect(parsed.length, equals(2));
      expect(parsed[0].title, equals('Twitter / X'));
      expect(parsed[0].username, equals('bob_dev'));
      expect(parsed[0].password, equals('x-password-123'));
      expect(parsed[1].title, equals('Wi-Fi Password'));
      expect(parsed[1].category, equals(ItemCategory.secureNote));
    });

    test('Parse CSV export format', () {
      const csvData = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n'
          ',0,login,Slack,Team workspace,,0,https://slack.com,slackuser@corp.com,slackpass123,\n';

      final parsed = ffi.parseImport(csvData);
      expect(parsed.length, equals(1));
      expect(parsed[0].title, equals('Slack'));
      expect(parsed[0].username, equals('slackuser@corp.com'));
      expect(parsed[0].password, equals('slackpass123'));
    });

    test('Deduplication analysis and conflict resolution preview', () {
      final current = [
        VaultItem(
          id: 'cur-1',
          title: 'GitHub',
          category: ItemCategory.login,
          username: 'alice',
          password: 'old-password',
          urls: ['https://github.com'],
          createdAt: 1000,
          updatedAt: 1000,
        ),
        VaultItem(
          id: 'cur-2',
          title: 'Google',
          category: ItemCategory.login,
          username: 'alice@gmail.com',
          password: 'google-password',
          urls: ['https://google.com'],
          createdAt: 1000,
          updatedAt: 1000,
        ),
      ];

      final incoming = [
        // Exact duplicate of Google
        VaultItem(
          id: 'inc-1',
          title: 'Google',
          category: ItemCategory.login,
          username: 'alice@gmail.com',
          password: 'google-password',
          urls: ['https://google.com'],
          createdAt: 2000,
          updatedAt: 2000,
        ),
        // Conflict on GitHub (different password)
        VaultItem(
          id: 'inc-2',
          title: 'GitHub',
          category: ItemCategory.login,
          username: 'alice',
          password: 'new-updated-github-pass',
          urls: ['https://github.com'],
          createdAt: 2000,
          updatedAt: 2000,
        ),
        // Completely new item
        VaultItem(
          id: 'inc-3',
          title: 'AWS Console',
          category: ItemCategory.login,
          username: 'alice-aws',
          password: 'aws-secret-access',
          urls: ['https://aws.amazon.com'],
          createdAt: 2000,
          updatedAt: 2000,
        ),
      ];

      final preview = ffi.analyzeDedup(current, incoming);
      expect(preview.totalIncoming, equals(3));
      expect(preview.duplicateCount, equals(1));
      expect(preview.conflictCount, equals(1));
      expect(preview.newCount, equals(1));

      // Verify conflict candidate has diff
      final conflict = preview.candidates.firstWhere((c) => c.status == CandidateStatus.conflict);
      expect(conflict.diff, isNotNull);
      expect(conflict.diff!.currentPassword, equals('old-password'));
      expect(conflict.diff!.incomingPassword, equals('new-updated-github-pass'));

      // Apply with resolution strategies:
      // Overwrite the GitHub conflict
      // Skip the Google duplicate
      // KeepBoth for AWS
      for (final c in preview.candidates) {
        if (c.status == CandidateStatus.conflict) {
          c.selectedStrategy = ResolutionStrategy.overwrite;
        } else if (c.status == CandidateStatus.exactDuplicate) {
          c.selectedStrategy = ResolutionStrategy.skip;
        } else {
          c.selectedStrategy = ResolutionStrategy.keepBoth;
        }
      }

      final updatedItems = ffi.applyImport(current, preview.candidates);
      expect(updatedItems.length, equals(3)); // GitHub (overwritten) + Google + AWS (new)

      final github = updatedItems.firstWhere((i) => i.title == 'GitHub');
      expect(github.password, equals('new-updated-github-pass'));
      // Check revision history contains old password
      expect(github.revisionHistory.length, equals(1));
      expect(github.revisionHistory.first.password, equals('old-password'));
    });

    test('Export items to RFC 4180 CSV', () {
      final items = [
        VaultItem(
          id: '1',
          title: 'Example Service, Inc.',
          category: ItemCategory.login,
          username: 'user@example.com',
          password: 'secret"password',
          urls: ['https://example.com'],
          notes: 'Line 1\nLine 2',
          createdAt: 1000,
          updatedAt: 1000,
        ),
      ];

      final csv = ffi.exportCsv(items);
      expect(csv.contains('Title,Username,Password,URL'), isTrue);
      // Quoting checks for commas, quotes, and newlines
      expect(csv.contains('"Example Service, Inc."'), isTrue);
      expect(csv.contains('"secret""password"'), isTrue);
    });
  });
}
