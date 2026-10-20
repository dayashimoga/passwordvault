import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pwdvault_flutter/main.dart';
import 'package:pwdvault_flutter/views/settings/backup_restore_sheet.dart';
import 'package:pwdvault_flutter/views/settings/import_export_sheet.dart';
import 'package:pwdvault_flutter/views/settings/recovery_kit_sheet.dart';

void main() {
  testWidgets('PwdVault starts in locked state with master passphrase prompt', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const PwdVaultApp());

    // Verify brand title and security motto are rendered
    expect(find.text('PWDVAULT'), findsOneWidget);
    expect(find.text('Zero-Knowledge Personal Cryptographic Vault'), findsOneWidget);

    // Verify Unlock mode controls
    expect(find.text('Unlock Vault'), findsNWidgets(2)); // Segment button and submit button
    expect(find.text('Master Passphrase'), findsOneWidget);

    // Verify strictly offline security footer
    expect(find.byIcon(Icons.offline_bolt_outlined), findsOneWidget);
  });

  testWidgets('BackupRestoreSheet renders backup and rehearsal tabs', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: BackupRestoreSheet(),
        ),
      ),
    );

    expect(find.text('Encrypted Backup & Recovery'), findsOneWidget);
    expect(find.text('Create Backup (.vaultbak)'), findsOneWidget);
    expect(find.text('Rehearse & Restore'), findsOneWidget);
    expect(find.text('Create Authenticated Backup'), findsOneWidget);
  });

  testWidgets('RecoveryKitSheet renders 256-bit emergency recovery key controls', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: RecoveryKitSheet(),
        ),
      ),
    );

    expect(find.text('Emergency Recovery Kit'), findsOneWidget);
    expect(find.text('256-Bit Emergency Recovery Key'), findsOneWidget);
    expect(find.text('Copy Key'), findsOneWidget);
    expect(find.text('Offline Storage Guidelines'), findsOneWidget);
  });

  testWidgets('ImportExportSheet renders import and guarded export tabs', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: ImportExportSheet(),
        ),
      ),
    );

    expect(find.text('Portability & Migration'), findsOneWidget);
    expect(find.text('Import Credentials'), findsOneWidget);
    expect(find.text('Guarded CSV Export'), findsOneWidget);
    expect(find.text('Parse & Preview Import'), findsOneWidget);
  });
}

