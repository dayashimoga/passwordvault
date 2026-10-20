import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../../core/ffi/vault_ffi_bindings.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';

/// Modal sheet for creating encrypted `.vaultbak` backups and dry-run restoration rehearsals.
class BackupRestoreSheet extends StatefulWidget {
  const BackupRestoreSheet({super.key});

  @override
  State<BackupRestoreSheet> createState() => _BackupRestoreSheetState();
}

class _BackupRestoreSheetState extends State<BackupRestoreSheet> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Create Backup state
  final _createPassController = TextEditingController();
  final _createRecoveryKeyController = TextEditingController();
  bool _useRecoveryKeyForBackup = false;
  bool _isCreatingBackup = false;
  String? _backupSuccessMessage;

  // Restore Backup state
  final _restorePathController = TextEditingController();
  final _restorePassController = TextEditingController();
  final _restoreRecoveryKeyController = TextEditingController();
  bool _useRecoveryKeyForRestore = false;
  bool _isRehearsing = false;
  bool _isRestoring = false;
  BackupRehearsalReport? _rehearsalReport;
  Uint8List? _loadedBackupBytes;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _createPassController.dispose();
    _createRecoveryKeyController.dispose();
    _restorePathController.dispose();
    _restorePassController.dispose();
    _restoreRecoveryKeyController.dispose();
    super.dispose();
  }

  Future<void> _handleCreateBackup() async {
    final state = VaultState.instance;
    final payload = state.payload;
    if (payload == null) return;

    final pass = _createPassController.text.trim();
    final recKey = _createRecoveryKeyController.text.trim();

    if (!_useRecoveryKeyForBackup && pass.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter a backup passphrase')),
      );
      return;
    }
    if (_useRecoveryKeyForBackup && recKey.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please generate or enter a 256-bit recovery key')),
      );
      return;
    }

    setState(() {
      _isCreatingBackup = true;
      _backupSuccessMessage = null;
    });

    try {
      final ffi = RustVaultFfi.instance;
      final bytes = ffi.createBackup(
        payload,
        passphrase: !_useRecoveryKeyForBackup ? pass : null,
        recoveryKey: _useRecoveryKeyForBackup ? recKey : null,
      );

      final now = DateTime.now();
      final filename = 'pwdvault-backup-${now.year}${now.month.toString().padLeft(2, '0')}${now.day.toString().padLeft(2, '0')}-${now.hour.toString().padLeft(2, '0')}${now.minute.toString().padLeft(2, '0')}.vaultbak';
      
      // Save locally alongside vault
      final targetDir = Directory.current.path;
      final backupFile = File('$targetDir/$filename');
      await backupFile.writeAsBytes(bytes);

      setState(() {
        _backupSuccessMessage = 'Encrypted archive created: $filename (${(bytes.length / 1024).toStringAsFixed(1)} KB)';
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Backup creation failed: $e'), backgroundColor: AppTheme.rose),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isCreatingBackup = false);
      }
    }
  }

  Future<void> _handleRehearseRestore() async {
    final path = _restorePathController.text.trim();
    if (path.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter path to .vaultbak archive')),
      );
      return;
    }

    final file = File(path);
    if (!await file.exists()) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('File does not exist at specified path'), backgroundColor: AppTheme.rose),
        );
      }
      return;
    }

    final pass = _restorePassController.text.trim();
    final recKey = _restoreRecoveryKeyController.text.trim();

    setState(() {
      _isRehearsing = true;
      _rehearsalReport = null;
    });

    try {
      final bytes = await file.readAsBytes();
      _loadedBackupBytes = bytes;

      final ffi = RustVaultFfi.instance;
      final report = ffi.rehearseRestore(
        bytes,
        passphrase: !_useRecoveryKeyForRestore ? pass : null,
        recoveryKey: _useRecoveryKeyForRestore ? recKey : null,
      );

      setState(() {
        _rehearsalReport = report;
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Rehearsal failed: $e'), backgroundColor: AppTheme.rose),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isRehearsing = false);
      }
    }
  }

  Future<void> _handleExecuteRestore() async {
    if (_loadedBackupBytes == null || _rehearsalReport == null || !_rehearsalReport!.isValid) {
      return;
    }

    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Confirm Vault Restoration'),
        content: Text(
          'Restoring this backup will replace your current vault with ${_rehearsalReport!.itemCount} items from "${_rehearsalReport!.vaultName}". All existing credentials will be overwritten.',
          style: const TextStyle(fontSize: 13),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.rose, foregroundColor: Colors.white),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Overwrite & Restore'),
          ),
        ],
      ),
    );

    if (confirm != true || !mounted) return;

    setState(() => _isRestoring = true);
    final messenger = ScaffoldMessenger.of(context);
    final navigator = Navigator.of(context);

    try {
      final ffi = RustVaultFfi.instance;
      final pass = _restorePassController.text.trim();
      final recKey = _restoreRecoveryKeyController.text.trim();

      final restoredPayload = ffi.restoreBackup(
        _loadedBackupBytes!,
        passphrase: !_useRecoveryKeyForRestore ? pass : null,
        recoveryKey: _useRecoveryKeyForRestore ? recKey : null,
      );

      // Save into active vault
      final state = VaultState.instance;
      await state.replacePayload(restoredPayload);

      navigator.pop();
      messenger.showSnackBar(
        SnackBar(
          content: Text('Vault restored successfully with ${restoredPayload.items.length} items'),
          backgroundColor: AppTheme.emerald,
        ),
      );
    } catch (e) {
      messenger.showSnackBar(
        SnackBar(content: Text('Restore failed: $e'), backgroundColor: AppTheme.rose),
      );
    } finally {
      if (mounted) setState(() => _isRestoring = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      height: MediaQuery.of(context).size.height * 0.85,
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      child: Column(
        children: [
          Row(
            children: [
              const Icon(Icons.archive_outlined, color: AppTheme.cyan, size: 28),
              const SizedBox(width: 12),
              Text('Encrypted Backup & Recovery', style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold)),
              const Spacer(),
              IconButton(onPressed: () => Navigator.of(context).pop(), icon: const Icon(Icons.close)),
            ],
          ),
          const SizedBox(height: 12),
          TabBar(
            controller: _tabController,
            tabs: const [
              Tab(icon: Icon(Icons.cloud_upload_outlined), text: 'Create Backup (.vaultbak)'),
              Tab(icon: Icon(Icons.settings_backup_restore_outlined), text: 'Rehearse & Restore'),
            ],
          ),
          const SizedBox(height: 16),
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildCreateBackupTab(theme),
                _buildRestoreBackupTab(theme),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCreateBackupTab(ThemeData theme) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.cyan.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.3)),
            ),
            child: const Text(
              'Backups are authenticated .vaultbak archives protected by XChaCha20-Poly1305 and Argon2id. They contain full encrypted snapshots with zero cloud dependency.',
              style: TextStyle(fontSize: 12, color: AppTheme.cyan),
            ),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              ChoiceChip(
                label: const Text('Passphrase Protection'),
                selected: !_useRecoveryKeyForBackup,
                onSelected: (val) => setState(() => _useRecoveryKeyForBackup = !val),
              ),
              const SizedBox(width: 8),
              ChoiceChip(
                label: const Text('256-bit Recovery Key'),
                selected: _useRecoveryKeyForBackup,
                onSelected: (val) => setState(() => _useRecoveryKeyForBackup = val),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (!_useRecoveryKeyForBackup)
            TextField(
              controller: _createPassController,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Backup Passphrase',
                prefixIcon: Icon(Icons.lock_outline),
                helperText: 'A dedicated passphrase used exclusively for this backup snapshot.',
              ),
            )
          else ...[
            TextField(
              controller: _createRecoveryKeyController,
              decoration: InputDecoration(
                labelText: 'Emergency Recovery Key',
                prefixIcon: const Icon(Icons.vpn_key_outlined),
                suffixIcon: IconButton(
                  icon: const Icon(Icons.refresh),
                  tooltip: 'Generate Fresh Key',
                  onPressed: () {
                    final key = RustVaultFfi.instance.generateRecoveryKey();
                    _createRecoveryKeyController.text = key;
                  },
                ),
                helperText: 'Crockford Base32 format (PV-XXXX-XXXX-...)',
              ),
            ),
          ],
          const SizedBox(height: 24),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.cyan,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: _isCreatingBackup ? null : _handleCreateBackup,
            icon: _isCreatingBackup
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.save_alt_outlined),
            label: Text(_isCreatingBackup ? 'Encrypting Archive...' : 'Create Authenticated Backup'),
          ),
          if (_backupSuccessMessage != null) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppTheme.emerald.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppTheme.emerald),
              ),
              child: Row(
                children: [
                  const Icon(Icons.check_circle_outline, color: AppTheme.emerald),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(_backupSuccessMessage!, style: const TextStyle(color: AppTheme.emerald, fontSize: 13)),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildRestoreBackupTab(ThemeData theme) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.amber.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppTheme.amber.withValues(alpha: 0.3)),
            ),
            child: const Text(
              'Restoration Rehearsal dry-runs decryption and cryptographic verification without modifying your current vault. Always rehearse before committing to a restore.',
              style: TextStyle(fontSize: 12, color: AppTheme.amber),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _restorePathController,
            decoration: const InputDecoration(
              labelText: 'Path to .vaultbak file',
              prefixIcon: Icon(Icons.folder_open_outlined),
              hintText: 'e.g. C:/backups/pwdvault-backup.vaultbak',
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              ChoiceChip(
                label: const Text('Passphrase'),
                selected: !_useRecoveryKeyForRestore,
                onSelected: (val) => setState(() => _useRecoveryKeyForRestore = !val),
              ),
              const SizedBox(width: 8),
              ChoiceChip(
                label: const Text('Recovery Key'),
                selected: _useRecoveryKeyForRestore,
                onSelected: (val) => setState(() => _useRecoveryKeyForRestore = val),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (!_useRecoveryKeyForRestore)
            TextField(
              controller: _restorePassController,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Backup Passphrase',
                prefixIcon: Icon(Icons.password_outlined),
              ),
            )
          else
            TextField(
              controller: _restoreRecoveryKeyController,
              decoration: const InputDecoration(
                labelText: '256-bit Emergency Recovery Key',
                prefixIcon: Icon(Icons.vpn_key_outlined),
                hintText: 'PV-XXXX-XXXX-...',
              ),
            ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.violet,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 14),
            ),
            onPressed: _isRehearsing ? null : _handleRehearseRestore,
            icon: _isRehearsing
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                : const Icon(Icons.play_circle_outline),
            label: Text(_isRehearsing ? 'Validating...' : 'Dry-Run Restoration Rehearsal'),
          ),
          if (_rehearsalReport != null) ...[
            const SizedBox(height: 16),
            Card(
              color: _rehearsalReport!.isValid
                  ? AppTheme.emerald.withValues(alpha: 0.1)
                  : AppTheme.rose.withValues(alpha: 0.1),
              shape: RoundedRectangleBorder(
                side: BorderSide(
                  color: _rehearsalReport!.isValid ? AppTheme.emerald : AppTheme.rose,
                ),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          _rehearsalReport!.isValid ? Icons.verified_outlined : Icons.error_outline,
                          color: _rehearsalReport!.isValid ? AppTheme.emerald : AppTheme.rose,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          _rehearsalReport!.isValid ? 'Rehearsal Passed: Verified Authenticated' : 'Rehearsal Failed',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            color: _rehearsalReport!.isValid ? AppTheme.emerald : AppTheme.rose,
                          ),
                        ),
                      ],
                    ),
                    if (_rehearsalReport!.isValid) ...[
                      const SizedBox(height: 12),
                      Text('Vault Name: ${_rehearsalReport!.vaultName}', style: const TextStyle(fontWeight: FontWeight.bold)),
                      Text('Active Items: ${_rehearsalReport!.itemCount}'),
                      Text('Trashed Items: ${_rehearsalReport!.trashedCount}'),
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 8,
                        children: _rehearsalReport!.categoryCounts.entries
                            .map((e) => Chip(label: Text('${e.key}: ${e.value}'), visualDensity: VisualDensity.compact))
                            .toList(),
                      ),
                      const SizedBox(height: 16),
                      ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.emerald,
                          foregroundColor: Colors.black,
                        ),
                        onPressed: _isRestoring ? null : _handleExecuteRestore,
                        icon: const Icon(Icons.restore_page_outlined),
                        label: Text(_isRestoring ? 'Restoring...' : 'Restore Verified Backup to Vault'),
                      ),
                    ] else ...[
                      const SizedBox(height: 8),
                      Text(
                        _rehearsalReport!.errorMessage ?? 'Decryption failed or invalid signature.',
                        style: const TextStyle(color: AppTheme.rose, fontSize: 13),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
