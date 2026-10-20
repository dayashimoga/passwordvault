import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/services/biometric_service.dart';

void main() {
  group('Phase 5 Cross-Platform & Desktop Integration Tests', () {
    test('BiometricService detects platform availability and types', () async {
      final bio = BiometricService.instance;

      final available = await bio.isBiometricAvailable();
      expect(available, isTrue);

      final bioType = await bio.getBiometricType();
      expect(bioType, isNot(BiometricType.none));

      final name = bio.biometricName;
      expect(name, isNotEmpty);
      expect(
        name.contains('Hello') ||
            name.contains('Touch') ||
            name.contains('Face') ||
            name.contains('Fingerprint') ||
            name.contains('Keyring') ||
            name.contains('Biometric'),
        isTrue,
      );
    });

    test('BiometricService toggles preference and authenticates', () async {
      final bio = BiometricService.instance;

      expect(bio.isBiometricsEnabled, isTrue);
      bio.setBiometricsEnabled(false);
      expect(bio.isBiometricsEnabled, isFalse);
      bio.setBiometricsEnabled(true);
      expect(bio.isBiometricsEnabled, isTrue);

      final authSuccess = await bio.authenticate(localizedReason: 'Test unlock');
      expect(authSuccess, isTrue);
    });
  });
}
