import 'dart:io';
import 'package:flutter/material.dart';
import '../../core/ffi/vault_ffi_bindings.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';

/// Modal sheet for viewing, generating, and printing an Emergency Recovery Kit.
class RecoveryKitSheet extends StatefulWidget {
  const RecoveryKitSheet({super.key});

  @override
  State<RecoveryKitSheet> createState() => _RecoveryKitSheetState();
}

class _RecoveryKitSheetState extends State<RecoveryKitSheet> {
  late String _recoveryKey;
  RecoveryKitDocument? _document;
  bool _isExporting = false;
  String? _exportSuccessMessage;

  @override
  void initState() {
    super.initState();
    _generateKey();
  }

  void _generateKey() {
    final state = VaultState.instance;
    final vaultName = state.payload?.vaultName ?? 'Personal Vault';
    final key = RustVaultFfi.instance.generateRecoveryKey();
    final doc = RustVaultFfi.instance.generateRecoveryKitDoc(vaultName, key);
    setState(() {
      _recoveryKey = key;
      _document = doc;
      _exportSuccessMessage = null;
    });
  }

  Future<void> _handleExportMarkdown() async {
    if (_document == null) return;

    setState(() => _isExporting = true);
    try {
      final md = _document!.renderMarkdown();
      final targetPath = '${Directory.current.path}/pwdvault-recovery-kit.md';
      final file = File(targetPath);
      await file.writeAsString(md);

      setState(() {
        _exportSuccessMessage = 'Recovery Kit saved to $targetPath';
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to save kit: $e'), backgroundColor: AppTheme.rose),
        );
      }
    } finally {
      if (mounted) setState(() => _isExporting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = VaultState.instance;

    return Container(
      height: MediaQuery.of(context).size.height * 0.85,
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.emergency_outlined, color: AppTheme.rose, size: 28),
              const SizedBox(width: 12),
              Text('Emergency Recovery Kit', style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold)),
              const Spacer(),
              IconButton(onPressed: () => Navigator.of(context).pop(), icon: const Icon(Icons.close)),
            ],
          ),
          const SizedBox(height: 12),
          // Security Alert
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.rose.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppTheme.rose.withValues(alpha: 0.3)),
            ),
            child: Row(
              children: [
                const Icon(Icons.warning_amber_rounded, color: AppTheme.rose, size: 24),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'CRITICAL NOTICE: Anyone with this key and your encrypted vault can decrypt all credentials without knowing your master passphrase. Keep it strictly offline.',
                    style: TextStyle(fontSize: 12, color: AppTheme.rose.withValues(alpha: 0.9)),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          Expanded(
            child: SingleChildScrollView(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('256-Bit Emergency Recovery Key', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  const Text(
                    'Encoded in Crockford Base32 with built-in case insensitivity and visual ambiguity tolerance (0/O, 1/I/L).',
                    style: TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                  ),
                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: AppTheme.darkSurfaceVariant,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.3)),
                    ),
                    child: SelectableText(
                      _recoveryKey,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                        letterSpacing: 1.2,
                        color: AppTheme.cyan,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: () {
                            state.copyToClipboard(_recoveryKey);
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('Recovery key copied to clipboard (will auto-clear in 30s)'),
                                duration: Duration(seconds: 4),
                              ),
                            );
                          },
                          icon: const Icon(Icons.copy_outlined),
                          label: const Text('Copy Key'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: _generateKey,
                          icon: const Icon(Icons.refresh_outlined),
                          label: const Text('Generate Fresh Key'),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 24),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Offline Storage Guidelines', style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
                          const SizedBox(height: 8),
                          const Text('• Print this document and store in a fireproof safe or safety deposit box.', style: TextStyle(fontSize: 12)),
                          const Text('• NEVER save this key in cloud drives (Google Drive, iCloud, OneDrive).', style: TextStyle(fontSize: 12)),
                          const Text('• NEVER email, text, or store this key in unencrypted note applications.', style: TextStyle(fontSize: 12)),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 20),
                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.emerald,
                      foregroundColor: Colors.black,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                    ),
                    onPressed: _isExporting ? null : _handleExportMarkdown,
                    icon: _isExporting
                        ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.print_outlined),
                    label: Text(_isExporting ? 'Saving Kit...' : 'Export Printable Kit (.md)'),
                  ),
                  if (_exportSuccessMessage != null) ...[
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
                            child: Text(_exportSuccessMessage!, style: const TextStyle(color: AppTheme.emerald, fontSize: 13)),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
