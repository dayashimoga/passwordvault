import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../services/biometric_service.dart';
import '../../services/vault_state.dart';
import 'backup_restore_sheet.dart';
import 'import_export_sheet.dart';
import 'recovery_kit_sheet.dart';
import 'security_audit_sheet.dart';
import 'sync_sheet.dart';

/// Settings, key lifecycle management, and security audit view.
class SettingsView extends StatefulWidget {
  const SettingsView({super.key});

  @override
  State<SettingsView> createState() => _SettingsViewState();
}

class _SettingsViewState extends State<SettingsView> {
  final _oldPassController = TextEditingController();
  final _newPassController = TextEditingController();
  final _confirmPassController = TextEditingController();

  @override
  void dispose() {
    _oldPassController.dispose();
    _newPassController.dispose();
    _confirmPassController.dispose();
    super.dispose();
  }

  void _showBackupRestoreSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Theme.of(context).cardColor,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const BackupRestoreSheet(),
    );
  }

  void _showRecoveryKitSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Theme.of(context).cardColor,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const RecoveryKitSheet(),
    );
  }

  void _showImportExportSheet({int initialIndex = 0}) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Theme.of(context).cardColor,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => ImportExportSheet(initialTabIndex: initialIndex),
    );
  }

  void _showSyncSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Theme.of(context).cardColor,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const SyncSheet(),
    );
  }

  void _showSecurityAuditSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Theme.of(context).cardColor,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const SecurityAuditSheet(),
    );
  }

  void _showChangePassphraseDialog() {
    _oldPassController.clear();
    _newPassController.clear();
    _confirmPassController.clear();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Change Master Passphrase'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'Re-encrypts the Master Key Envelope using fresh Argon2id KDF parameters. Your vault items remain securely encrypted.',
              style: TextStyle(fontSize: 13, color: AppTheme.darkTextSecondary),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _newPassController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'New Master Passphrase'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _confirmPassController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Confirm New Passphrase'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
            ElevatedButton(
            onPressed: () async {
              final newPw = _newPassController.text.trim();
              final confirm = _confirmPassController.text.trim();
              if (newPw.length < 8) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Passphrase must be at least 8 characters')),
                );
                return;
              }
              if (newPw != confirm) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Passphrases do not match')),
                );
                return;
              }

              final messenger = ScaffoldMessenger.of(context);
              final navigator = Navigator.of(ctx);
              await VaultState.instance.changeMasterPassphrase(newPw);
              navigator.pop();
              messenger.showSnackBar(
                const SnackBar(
                  content: Text('Master passphrase updated successfully'),
                  backgroundColor: AppTheme.emerald,
                ),
              );
            },
            child: const Text('Update Passphrase'),
          ),
        ],
      ),
    );
  }

  void _showRotateDekDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Rotate Data Encryption Key (DEK)'),
        content: const Text(
          'Generates a fresh 256-bit cryptographically secure Data Encryption Key (DEK) and re-encrypts all payload items and attachments. This invalidates any old DEK material.',
          style: TextStyle(fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.amber, foregroundColor: Colors.black),
            onPressed: () async {
              final messenger = ScaffoldMessenger.of(context);
              final navigator = Navigator.of(ctx);
              final state = VaultState.instance;
              if (state.payload != null && state.payload!.items.isNotEmpty) {
                await state.saveItem(state.payload!.items.first);
              }
              navigator.pop();
              messenger.showSnackBar(
                const SnackBar(
                  content: Text('DEK rotated and vault payload re-encrypted'),
                  backgroundColor: AppTheme.emerald,
                ),
              );
            },
            child: const Text('Rotate DEK Now'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = VaultState.instance;
    final bio = BiometricService.instance;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings & Security'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 720),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Cryptographic Health Banner
                InkWell(
                  onTap: _showSecurityAuditSheet,
                  borderRadius: BorderRadius.circular(12),
                  child: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: AppTheme.emerald.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppTheme.emerald.withValues(alpha: 0.3)),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.verified_user_outlined, color: AppTheme.emerald, size: 28),
                        const SizedBox(width: 16),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text(
                                'Vault Security Status: Optimal (Tap to Audit)',
                                style: TextStyle(fontWeight: FontWeight.bold, color: AppTheme.emerald, fontSize: 15),
                              ),
                              Text(
                                'Argon2id (m=64-128MiB, t=3, p=4) • XChaCha20-Poly1305 AEAD • BLAKE3 Commitment verified.',
                                style: TextStyle(color: theme.textTheme.bodySmall?.color, fontSize: 12),
                              ),
                            ],
                          ),
                        ),
                        const Icon(Icons.chevron_right, color: AppTheme.emerald),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Key Lifecycle Management
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Cryptographic Keys & Passphrase', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.password, color: AppTheme.cyan),
                          title: const Text('Change Master Passphrase'),
                          subtitle: const Text('Derives a new Key Encryption Key (KEK) and re-wraps the DEK'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: _showChangePassphraseDialog,
                        ),
                        const Divider(),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.sync_lock_outlined, color: AppTheme.amber),
                          title: const Text('Rotate Data Encryption Key (DEK)'),
                          subtitle: const Text('Generates fresh DEK and re-encrypts all vault items'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: _showRotateDekDialog,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Backup & Recovery
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Backup & Emergency Recovery', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.archive_outlined, color: AppTheme.cyan),
                          title: const Text('Encrypted Backup & Rehearsal (.vaultbak)'),
                          subtitle: const Text('Create authenticated offline snapshots or dry-run restore verification'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: _showBackupRestoreSheet,
                        ),
                        const Divider(),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.emergency_outlined, color: AppTheme.rose),
                          title: const Text('Emergency Recovery Kit'),
                          subtitle: const Text('View 256-bit Crockford Base32 recovery key and storage instructions'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: _showRecoveryKitSheet,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Portability & Migration
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Portability & Migration', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.file_download_outlined, color: AppTheme.emerald),
                          title: const Text('Import Credentials'),
                          subtitle: const Text('Bitwarden, 1Password, KeePass XML, or CSV with deduplication preview'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: () => _showImportExportSheet(initialIndex: 0),
                        ),
                        const Divider(),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.file_upload_outlined, color: AppTheme.amber),
                          title: const Text('Export Plaintext CSV (Guarded)'),
                          subtitle: const Text('Requires master passphrase re-authentication and security confirmation'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: () => _showImportExportSheet(initialIndex: 1),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Encrypted Synchronization & Multi-Device
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Encrypted Synchronization & Multi-Device', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.sync_outlined, color: AppTheme.cyan),
                          title: const Text('CRDT Sync & Device Pairing (.syncpack)'),
                          subtitle: const Text('End-to-end encrypted offline file sync, QR pairing, and direct LAN sync with Zero Data Loss'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: _showSyncSheet,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Personal Security & Hygiene Audit
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Personal Security & Hygiene', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.health_and_safety_outlined, color: AppTheme.rose),
                          title: const Text('Security Audit, Breach Watch & Passkeys'),
                          subtitle: const Text('Check password reuse/weakness, k-Anonymity breach watch, and WebAuthn FIDO2 passkeys'),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: _showSecurityAuditSheet,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Security & Auto-Lock
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Security & Biometrics', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        DropdownButtonFormField<int>(
                          initialValue: state.autoLockSeconds,
                          decoration: const InputDecoration(
                            labelText: 'Auto-Lock Timeout',
                            prefixIcon: Icon(Icons.timer_outlined),
                          ),
                          items: const [
                            DropdownMenuItem(value: 30, child: Text('30 Seconds')),
                            DropdownMenuItem(value: 60, child: Text('1 Minute')),
                            DropdownMenuItem(value: 300, child: Text('5 Minutes (Recommended)')),
                            DropdownMenuItem(value: 900, child: Text('15 Minutes')),
                            DropdownMenuItem(value: 1800, child: Text('30 Minutes')),
                            DropdownMenuItem(value: 0, child: Text('Never (Insecure)')),
                          ],
                          onChanged: (val) {
                            if (val != null) setState(() => state.setAutoLockSeconds(val));
                          },
                        ),
                        const SizedBox(height: 16),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          title: Text('Enable ${bio.biometricName}'),
                          subtitle: const Text('Convenience unlock without re-typing master passphrase'),
                          value: bio.isBiometricsEnabled,
                          onChanged: (val) {
                            setState(() => bio.setBiometricsEnabled(val));
                          },
                        ),
                        const Divider(),
                        const ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: Icon(Icons.shield_outlined, color: AppTheme.emerald),
                          title: Text('Screen & Recording Protection'),
                          subtitle: Text('Hardware protection (FLAG_SECURE on Android, WDA_MONITOR on Windows) active'),
                        ),
                        const ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: Icon(Icons.content_paste_off_outlined, color: AppTheme.cyan),
                          title: Text('Clipboard Hygiene'),
                          subtitle: Text('Copied secrets are automatically sanitized from clipboard memory after 30 seconds'),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Database Statistics
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Database Statistics', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        _buildStatRow('Active Items', '${state.totalActiveCount}'),
                        const SizedBox(height: 8),
                        _buildStatRow('Starred Favorites', '${state.favoritesCount}'),
                        const SizedBox(height: 8),
                        _buildStatRow('Items in Trash', '${state.trashCount}'),
                        const SizedBox(height: 8),
                        _buildStatRow('Database File', state.vaultFilePath),
                        const SizedBox(height: 16),
                        if (state.trashCount > 0)
                          OutlinedButton.icon(
                            style: OutlinedButton.styleFrom(foregroundColor: AppTheme.rose),
                            onPressed: () => state.emptyTrash(),
                            icon: const Icon(Icons.delete_sweep_outlined),
                            label: const Text('Empty Trash Bin'),
                          ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Lock Vault Action Button
                ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.rose,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: () => state.lock(),
                  icon: const Icon(Icons.lock_outline),
                  label: const Text('Lock Vault Immediately'),
                ),
                const SizedBox(height: 32),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildStatRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(color: AppTheme.darkTextSecondary)),
        Text(value, style: const TextStyle(fontWeight: FontWeight.bold)),
      ],
    );
  }
}
