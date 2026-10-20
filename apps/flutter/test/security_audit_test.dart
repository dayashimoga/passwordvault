import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/core/ffi/vault_ffi_bindings.dart';
import 'package:pwdvault_flutter/models/vault_models.dart';
import 'package:pwdvault_flutter/services/vault_state.dart';
import 'package:pwdvault_flutter/views/settings/security_audit_sheet.dart';

void main() {
  group('Phase 7 Advanced Personal Security Tests', () {
    test('TOTP RFC 6238 standard vector code generation and remaining time', () {
      final ffi = RustVaultFfi.instance;
      expect(ffi.isAvailable, isTrue);

      // Base32 for ASCII "12345678901234567890"
      const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

      // RFC 6238 Appendix B test vector: t=59, 8 digits, period 30, SHA1 -> "94287082"
      final totp = ffi.generateTotp(
        secretBase32: secret,
        timestampSecs: 59,
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
      );

      expect(totp.code, equals('94287082'));
      expect(totp.remainingSeconds, equals(1)); // 59 % 30 = 29 -> 30 - 29 = 1

      // t=1234567890, 8 digits, period 30, SHA1 -> "89005924"
      final totp2 = ffi.generateTotp(
        secretBase32: secret,
        timestampSecs: 1234567890,
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
      );
      expect(totp2.code, equals('89005924'));
    });

    test('TOTP drift verification within tolerance window', () {
      final ffi = RustVaultFfi.instance;
      const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

      // Current code at t=59
      final totp = ffi.generateTotp(
        secretBase32: secret,
        timestampSecs: 59,
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
      );

      // Exact match
      final validExact = ffi.verifyTotp(
        secretBase32: secret,
        code: totp.code,
        timestampSecs: 59,
        toleranceSteps: 1,
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
      );
      expect(validExact, isTrue);

      // Drift +20s (within 1 step tolerance)
      final validDrift = ffi.verifyTotp(
        secretBase32: secret,
        code: totp.code,
        timestampSecs: 79,
        toleranceSteps: 1,
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
      );
      expect(validDrift, isTrue);

      // Drift +120s (outside tolerance window)
      final invalidDrift = ffi.verifyTotp(
        secretBase32: secret,
        code: totp.code,
        timestampSecs: 200,
        toleranceSteps: 1,
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
      );
      expect(invalidDrift, isFalse);
    });

    test('Parse otpauth://totp/ URI into typed config model', () {
      final ffi = RustVaultFfi.instance;
      const uri = 'otpauth://totp/GitHub:developer?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30';

      final config = ffi.parseTotpUri(uri);
      expect(config.issuer, equals('GitHub'));
      expect(config.accountName, equals('developer'));
      expect(config.digits, equals(6));
      expect(config.periodSeconds, equals(30));
    });

    test('WebAuthn / FIDO2 Passkey credential generation and assertion signing', () {
      final ffi = RustVaultFfi.instance;

      // 1. Generate passkey
      final passkey = ffi.generatePasskey(
        rpId: 'github.com',
        userName: 'lead_dev@antigravity.io',
        algorithm: -7, // ES256
      );

      expect(passkey.rpId, equals('github.com'));
      expect(passkey.userName, equals('lead_dev@antigravity.io'));
      expect(passkey.signCount, equals(0));
      expect(passkey.credentialId.length, greaterThanOrEqualTo(16));
      expect(passkey.publicKey.length, greaterThanOrEqualTo(32));

      // 2. Sign authentication assertion challenge
      const clientData = '{"type":"webauthn.get","challenge":"dGVzdC1jaGFsbGVuZ2U=","origin":"https://github.com"}';
      final result = ffi.signPasskeyAssertion(
        passkey: passkey,
        rpId: 'github.com',
        clientDataJson: clientData,
        userPresent: true,
        userVerified: true,
      );

      // Authenticator data: 32 bytes rpIdHash + 1 byte flags + 4 bytes signCount = 37 bytes
      expect(result.assertion.authenticatorData.length, equals(37));
      expect(result.assertion.signature.length, greaterThan(0));
      // Anti-replay: sign counter increments monotonically
      expect(result.updatedPasskey.signCount, equals(1));
    });

    test('Local vault health audit detects duplicate passwords, weak items, and missing 2FA', () {
      final ffi = RustVaultFfi.instance;
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      // Create a test payload with deliberate security hygiene defects
      final item1 = VaultItem(
        id: 'item-reuse-1',
        title: 'Primary Email',
        category: ItemCategory.login,
        username: 'user@email.com',
        password: 'shared-insecure-password', // Reused
        createdAt: now - 1000,
        updatedAt: now - 1000,
      );

      final item2 = VaultItem(
        id: 'item-reuse-2',
        title: 'Online Banking',
        category: ItemCategory.login,
        username: 'user@email.com',
        password: 'shared-insecure-password', // Reused
        createdAt: now - 1000,
        updatedAt: now - 1000,
      );

      final item3 = VaultItem(
        id: 'item-weak-1',
        title: 'Legacy Forum',
        category: ItemCategory.login,
        username: 'forumuser',
        password: '123', // Very weak (< 12 chars & low entropy)
        createdAt: now - 1000,
        updatedAt: now - 1000,
      );

      final payload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'Audit Test Vault',
        createdAt: now - 10000,
        updatedAt: now,
        items: [item1, item2, item3],
      );

      final report = ffi.auditVault(payload);
      expect(report.totalActiveItems, equals(3));
      expect(report.healthScore, lessThan(80)); // Score deducted
      expect(report.reusedGroups.length, equals(1));
      expect(report.reusedGroups.first.count, equals(2));
      expect(report.weakItems.length, greaterThanOrEqualTo(1));
      expect(report.missing2FaItems.length, equals(3));
      expect(report.recommendations.length, greaterThan(0));
    });

    test('k-Anonymity breach query preparation and range response parsing', () {
      final ffi = RustVaultFfi.instance;

      // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
      final query = ffi.prepareBreachQuery('password');
      expect(query.prefix.length, equals(5));
      expect(query.suffix.length, equals(35));
      expect(query.prefix, equals('5BAA6'));

      // Simulate range response body returned from HIBP API
      final mockBody = '${query.suffix}:3861493\r\nFEEDBEEF000000000000000000000000000:1\r\n';
      final count = ffi.checkBreachResponse(suffix: query.suffix, responseBody: mockBody);
      expect(count, equals(3861493));

      // Suffix not present in range response
      final countMissing = ffi.checkBreachResponse(suffix: '00000000000000000000000000000000000', responseBody: mockBody);
      expect(countMissing, equals(0));
    });

    testWidgets('SecurityAuditSheet renders health audit and switches tabs cleanly', (tester) async {
      await tester.binding.setSurfaceSize(const Size(1024, 900));

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final payload = VaultPayload(
        schemaVersion: 1,
        vaultName: 'Widget Test Vault',
        createdAt: now - 10000,
        updatedAt: now,
        items: [],
      );
      await VaultState.instance.replacePayload(payload);

      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SecurityAuditSheet(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Check header and tabs
      expect(find.text('Personal Security & Hygiene Audit'), findsOneWidget);
      expect(find.text('Health Audit'), findsOneWidget);
      expect(find.text('Breach Watch'), findsOneWidget);
      expect(find.text('Passkeys (FIDO2)'), findsOneWidget);

      // Switch to Breach Watch tab
      await tester.tap(find.text('Breach Watch'));
      await tester.pumpAndSettle();
      expect(find.text('Zero-Knowledge k-Anonymity Guarantee'), findsOneWidget);
      expect(find.text('Check Single Password'), findsOneWidget);

      // Switch to Passkeys tab
      await tester.tap(find.text('Passkeys (FIDO2)'));
      await tester.pumpAndSettle();
      expect(find.text('FIDO2 / WebAuthn Hardware-Grade Passkeys'), findsOneWidget);
      expect(find.text('Generate WebAuthn Passkey'), findsOneWidget);
    });
  });
}
