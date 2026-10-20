import 'dart:io';
import 'package:flutter/material.dart';
import '../../core/ffi/vault_ffi_bindings.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';

/// Modal sheet for multi-format credential import with interactive deduplication and guarded CSV export.
class ImportExportSheet extends StatefulWidget {
  final int initialTabIndex;
  const ImportExportSheet({super.key, this.initialTabIndex = 0});

  @override
  State<ImportExportSheet> createState() => _ImportExportSheetState();
}

class _ImportExportSheetState extends State<ImportExportSheet> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Import state
  final _importContentController = TextEditingController();
  final _importFilePathController = TextEditingController();
  bool _isAnalyzing = false;
  bool _isImporting = false;
  ImportPreview? _preview;
  String? _importSuccessMessage;

  // Export state
  final _exportPassController = TextEditingController();
  bool _isExporting = false;
  bool _confirmedRisk = false;
  String? _exportSuccessMessage;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this, initialIndex: widget.initialTabIndex);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _importContentController.dispose();
    _importFilePathController.dispose();
    _exportPassController.dispose();
    super.dispose();
  }

  Future<void> _handleAnalyzeImport() async {
    String content = _importContentController.text.trim();

    // If text empty, check file path
    if (content.isEmpty && _importFilePathController.text.trim().isNotEmpty) {
      final file = File(_importFilePathController.text.trim());
      if (await file.exists()) {
        content = await file.readAsString();
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('File not found at specified path'), backgroundColor: AppTheme.rose),
          );
        }
        return;
      }
    }

    if (!mounted) return;

    if (content.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please paste export data or enter a file path')),
      );
      return;
    }

    setState(() {
      _isAnalyzing = true;
      _preview = null;
      _importSuccessMessage = null;
    });

    try {
      final ffi = RustVaultFfi.instance;
      final incomingItems = ffi.parseImport(content);
      if (incomingItems.isEmpty) {
        throw Exception('No credentials found in the provided content.');
      }

      final state = VaultState.instance;
      final currentItems = state.payload?.items ?? [];
      final preview = ffi.analyzeDedup(currentItems, incomingItems);

      setState(() {
        _preview = preview;
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Import analysis failed: $e'), backgroundColor: AppTheme.rose),
        );
      }
    } finally {
      if (mounted) setState(() => _isAnalyzing = false);
    }
  }

  void _applyBulkStrategy(CandidateStatus status, ResolutionStrategy strategy) {
    if (_preview == null) return;
    setState(() {
      for (final cand in _preview!.candidates) {
        if (cand.status == status) {
          cand.selectedStrategy = strategy;
        }
      }
    });
  }

  Future<void> _handleCommitImport() async {
    if (_preview == null) return;

    setState(() => _isImporting = true);
    final messenger = ScaffoldMessenger.of(context);
    final state = VaultState.instance;

    try {
      final ffi = RustVaultFfi.instance;
      final current = state.payload?.items ?? [];
      final updatedItems = ffi.applyImport(current, _preview!.candidates);

      if (state.payload != null) {
        final cur = state.payload!;
        final updatedPayload = VaultPayload(
          schemaVersion: cur.schemaVersion,
          vaultName: cur.vaultName,
          items: updatedItems,
          createdAt: cur.createdAt,
          updatedAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        );
        await state.replacePayload(updatedPayload);
      }

      final added = updatedItems.length - current.length;
      setState(() {
        _importSuccessMessage = 'Import committed: ${updatedItems.length} total items in vault ($added added/modified).';
        _preview = null;
        _importContentController.clear();
      });

      messenger.showSnackBar(
        SnackBar(content: Text(_importSuccessMessage!), backgroundColor: AppTheme.emerald),
      );
    } catch (e) {
      messenger.showSnackBar(
        SnackBar(content: Text('Failed to commit import: $e'), backgroundColor: AppTheme.rose),
      );
    } finally {
      if (mounted) setState(() => _isImporting = false);
    }
  }

  Future<void> _handleGuardedExport() async {
    final pass = _exportPassController.text.trim();
    if (pass.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter your master passphrase to re-authenticate')),
      );
      return;
    }
    if (!_confirmedRisk) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('You must confirm the unencrypted plaintext risk checkbox')),
      );
      return;
    }

    final state = VaultState.instance;
    final payload = state.payload;
    if (payload == null) return;

    setState(() {
      _isExporting = true;
      _exportSuccessMessage = null;
    });

    try {
      // Re-authenticate by validating master passphrase against current container
      final ffi = RustVaultFfi.instance;
      // We verify passphrase by calling saveVault test
      ffi.saveVault(pass, payload);

      final csvData = ffi.exportCsv(payload.items);
      final now = DateTime.now();
      final filename = 'pwdvault-export-${now.year}${now.month.toString().padLeft(2, '0')}${now.day.toString().padLeft(2, '0')}.csv';
      final path = '${Directory.current.path}/$filename';
      final file = File(path);
      await file.writeAsString(csvData);

      setState(() {
        _exportSuccessMessage = 'Exported ${payload.items.length} items to unencrypted CSV at $path. Delete or shred this file after use!';
        _exportPassController.clear();
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Authentication failed: incorrect master passphrase'), backgroundColor: AppTheme.rose),
        );
      }
    } finally {
      if (mounted) setState(() => _isExporting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      height: MediaQuery.of(context).size.height * 0.9,
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      child: Column(
        children: [
          Row(
            children: [
              const Icon(Icons.import_export, color: AppTheme.cyan, size: 28),
              const SizedBox(width: 12),
              Text('Portability & Migration', style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold)),
              const Spacer(),
              IconButton(onPressed: () => Navigator.of(context).pop(), icon: const Icon(Icons.close)),
            ],
          ),
          const SizedBox(height: 12),
          TabBar(
            controller: _tabController,
            tabs: const [
              Tab(icon: Icon(Icons.file_download_outlined), text: 'Import Credentials'),
              Tab(icon: Icon(Icons.file_upload_outlined), text: 'Guarded CSV Export'),
            ],
          ),
          const SizedBox(height: 16),
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildImportTab(theme),
                _buildExportTab(theme),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildImportTab(ThemeData theme) {
    if (_preview != null) {
      return _buildDeduplicationPreview(theme);
    }

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
              'Supports Bitwarden JSON, 1Password 1PUX/CSV, KeePass 2.x XML, and RFC 4180 CSV exports. The engine will auto-detect format and analyze conflicts before importing.',
              style: TextStyle(fontSize: 12, color: AppTheme.cyan),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _importFilePathController,
            decoration: const InputDecoration(
              labelText: 'Path to Export File (Optional)',
              prefixIcon: Icon(Icons.folder_open_outlined),
              hintText: 'e.g. C:/exports/bitwarden_export.json',
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _importContentController,
            maxLines: 8,
            decoration: const InputDecoration(
              labelText: 'Or Paste Export File Contents Here',
              hintText: 'Paste raw JSON, XML, or CSV content...',
              alignLabelWithHint: true,
            ),
          ),
          const SizedBox(height: 20),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.cyan,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(vertical: 14),
            ),
            onPressed: _isAnalyzing ? null : _handleAnalyzeImport,
            icon: _isAnalyzing
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.search_outlined),
            label: Text(_isAnalyzing ? 'Analyzing Format & Duplicates...' : 'Parse & Preview Import'),
          ),
          if (_importSuccessMessage != null) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppTheme.emerald.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppTheme.emerald),
              ),
              child: Text(_importSuccessMessage!, style: const TextStyle(color: AppTheme.emerald)),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildDeduplicationPreview(ThemeData theme) {
    final preview = _preview!;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Summary Cards
        Row(
          children: [
            _buildStatCard('Total', '${preview.totalIncoming}', AppTheme.cyan),
            const SizedBox(width: 8),
            _buildStatCard('New', '${preview.newCount}', AppTheme.emerald),
            const SizedBox(width: 8),
            _buildStatCard('Duplicates', '${preview.duplicateCount}', AppTheme.amber),
            const SizedBox(width: 8),
            _buildStatCard('Conflicts', '${preview.conflictCount}', AppTheme.rose),
          ],
        ),
        const SizedBox(height: 12),
        // Bulk Actions
        Wrap(
          spacing: 8,
          runSpacing: 4,
          children: [
            OutlinedButton(
              onPressed: () => _applyBulkStrategy(CandidateStatus.exactDuplicate, ResolutionStrategy.skip),
              child: const Text('Skip All Duplicates'),
            ),
            OutlinedButton(
              onPressed: () => _applyBulkStrategy(CandidateStatus.conflict, ResolutionStrategy.overwrite),
              child: const Text('Overwrite All Conflicts'),
            ),
            OutlinedButton(
              onPressed: () => _applyBulkStrategy(CandidateStatus.conflict, ResolutionStrategy.keepBoth),
              child: const Text('Keep Both All'),
            ),
          ],
        ),
        const SizedBox(height: 8),
        const Divider(),
        // Candidates list
        Expanded(
          child: ListView.builder(
            itemCount: preview.candidates.length,
            itemBuilder: (ctx, idx) {
              final cand = preview.candidates[idx];
              Color statusColor;
              String statusLabel;
              switch (cand.status) {
                case CandidateStatus.newCandidate:
                  statusColor = AppTheme.emerald;
                  statusLabel = 'NEW';
                  break;
                case CandidateStatus.exactDuplicate:
                  statusColor = AppTheme.amber;
                  statusLabel = 'EXACT DUPLICATE';
                  break;
                case CandidateStatus.conflict:
                  statusColor = AppTheme.rose;
                  statusLabel = 'CONFLICT';
                  break;
              }

              return Card(
                margin: const EdgeInsets.symmetric(vertical: 4),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                            decoration: BoxDecoration(
                              color: statusColor.withValues(alpha: 0.2),
                              borderRadius: BorderRadius.circular(4),
                              border: Border.all(color: statusColor),
                            ),
                            child: Text(
                              statusLabel,
                              style: TextStyle(color: statusColor, fontSize: 10, fontWeight: FontWeight.bold),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              cand.item.title,
                              style: const TextStyle(fontWeight: FontWeight.bold),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          DropdownButton<ResolutionStrategy>(
                            value: cand.selectedStrategy,
                            isDense: true,
                            underline: const SizedBox(),
                            items: const [
                              DropdownMenuItem(value: ResolutionStrategy.keepBoth, child: Text('Keep Both')),
                              DropdownMenuItem(value: ResolutionStrategy.overwrite, child: Text('Overwrite')),
                              DropdownMenuItem(value: ResolutionStrategy.skip, child: Text('Skip')),
                            ],
                            onChanged: (val) {
                              if (val != null) setState(() => cand.selectedStrategy = val);
                            },
                          ),
                        ],
                      ),
                      if (cand.item.username != null)
                        Text('Username: ${cand.item.username}', style: const TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary)),
                      if (cand.diff != null) ...[
                        const SizedBox(height: 8),
                        Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: AppTheme.darkSurfaceVariant,
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('• Current Password: ${cand.diff!.currentPassword ?? "none"}', style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary)),
                              Text('• Imported Password: ${cand.diff!.incomingPassword ?? "none"}', style: const TextStyle(fontSize: 11, color: AppTheme.cyan)),
                            ],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              );
            },
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            OutlinedButton(
              onPressed: () => setState(() => _preview = null),
              child: const Text('Back'),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.emerald,
                  foregroundColor: Colors.black,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                ),
                onPressed: _isImporting ? null : _handleCommitImport,
                icon: const Icon(Icons.check_circle_outline),
                label: Text(_isImporting ? 'Importing...' : 'Commit ${preview.totalIncoming} Items to Vault'),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStatCard(String label, String value, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.3)),
        ),
        child: Column(
          children: [
            Text(value, style: TextStyle(color: color, fontSize: 18, fontWeight: FontWeight.bold)),
            Text(label, style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary)),
          ],
        ),
      ),
    );
  }

  Widget _buildExportTab(ThemeData theme) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.rose.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppTheme.rose),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.gpp_bad_outlined, color: AppTheme.rose, size: 28),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'HIGH SECURITY RISK: Plaintext Export',
                        style: TextStyle(color: AppTheme.rose, fontWeight: FontWeight.bold, fontSize: 14),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Exporting to RFC 4180 CSV completely strips encryption. Any person or malicious program with file system access will be able to read your passwords. For secure backups, use the encrypted .vaultbak format instead.',
                        style: TextStyle(color: AppTheme.rose.withValues(alpha: 0.9), fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('I understand my credentials will be saved in unencrypted plaintext on disk.'),
            value: _confirmedRisk,
            onChanged: (val) => setState(() => _confirmedRisk = val ?? false),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _exportPassController,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Re-authenticate Master Passphrase',
              prefixIcon: Icon(Icons.lock_reset_outlined),
              helperText: 'Verification required to authorize plaintext credential extraction.',
            ),
          ),
          const SizedBox(height: 24),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.rose,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 14),
            ),
            onPressed: (!_confirmedRisk || _isExporting) ? null : _handleGuardedExport,
            icon: _isExporting
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                : const Icon(Icons.file_download_outlined),
            label: Text(_isExporting ? 'Exporting...' : 'Authorize & Export Plaintext CSV'),
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
              child: Text(_exportSuccessMessage!, style: const TextStyle(color: AppTheme.emerald, fontSize: 12)),
            ),
          ],
        ],
      ),
    );
  }
}
