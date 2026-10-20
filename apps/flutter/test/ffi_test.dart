import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/core/ffi/vault_ffi_bindings.dart';
import 'package:pwdvault_flutter/models/vault_models.dart';

void main() {
  group('Rust Core C-ABI FFI Integration Tests', () {
    test('Verify Rust Security Core FFI library is loaded and operational', () {
      expect(RustVaultFfi.instance.isAvailable, isTrue);
    });
    test('Generate password via Rust core FFI', () {
      final ffi = RustVaultFfi.instance;
      final pwd = ffi.generatePassword(
        length: 24,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true,
        excludeAmbiguous: true,
      );

      expect(pwd.length, equals(24));
      // Ambiguous characters: 1, l, I, |, 0, O, Q, 8, B
      expect(pwd.contains('1'), isFalse);
      expect(pwd.contains('l'), isFalse);
      expect(pwd.contains('I'), isFalse);
      expect(pwd.contains('|'), isFalse);
      expect(pwd.contains('0'), isFalse);
      expect(pwd.contains('O'), isFalse);
    });

    test('Generate passphrase via Rust core FFI', () {
      final ffi = RustVaultFfi.instance;
      final phrase = ffi.generatePassphrase(
        wordCount: 6,
        separator: '-',
        capitalization: 'TitleCase',
        insertNumber: true,
      );

      final parts = phrase.split('-');
      expect(parts.length, equals(7)); // 6 words + 1 number token
      expect(parts.any((p) => RegExp(r'^\d+$').hasMatch(p)), isTrue);
    });

    test('Estimate crack time via Rust core FFI', () {
      final ffi = RustVaultFfi.instance;
      final est = ffi.estimateCrackTime('Correct-Horse-Battery-Staple-99');

      expect(est.entropyBits, greaterThan(60));
      expect(est.rating.isNotEmpty, isTrue);
      expect(est.clusterTime.isNotEmpty, isTrue);
    });

    test('Create and unlock vault roundtrip via Rust core FFI', () {
      final ffi = RustVaultFfi.instance;
      const passphrase = 'Ultra-Secure-Master-Passphrase-2026!';
      const vaultName = 'Integration Test Vault';

      // 1. Create vault
      final encryptedBytes = ffi.createVault(passphrase, vaultName);
      expect(encryptedBytes.length, greaterThan(64));

      // 2. Unlock vault
      final payload = ffi.unlockVault(encryptedBytes, passphrase);
      expect(payload.vaultName, equals(vaultName));
      expect(payload.items.isEmpty, isTrue);

      // 3. Add item and re-save
      final nowSec = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final updatedPayload = VaultPayload(
        schemaVersion: 1,
        vaultName: vaultName,
        createdAt: nowSec,
        updatedAt: nowSec,
        items: [
          VaultItem(
            id: 'item-101',
            title: 'ProtonMail',
            category: ItemCategory.login,
            username: 'user@proton.me',
            password: 'super-proton-secret',
            urls: ['https://mail.proton.me'],
            createdAt: nowSec,
            updatedAt: nowSec,
          ),
        ],
      );

      final savedBytes = ffi.saveVault(passphrase, updatedPayload);
      expect(savedBytes.length, greaterThan(64));

      // 4. Unlock updated vault
      final reloadedPayload = ffi.unlockVault(savedBytes, passphrase);
      expect(reloadedPayload.items.length, equals(1));
      expect(reloadedPayload.items.first.title, equals('ProtonMail'));
      expect(reloadedPayload.items.first.username, equals('user@proton.me'));
      expect(reloadedPayload.items.first.password, equals('super-proton-secret'));

      // 5. Rust search via FFI
      final searchResults = ffi.search(reloadedPayload, 'proton');
      expect(searchResults.length, equals(1));
      expect(searchResults.first.title, equals('ProtonMail'));
    });
  });
}
