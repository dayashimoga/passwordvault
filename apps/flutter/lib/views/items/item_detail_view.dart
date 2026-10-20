import 'dart:async';
import 'package:flutter/material.dart';
import '../../core/ffi/vault_ffi_bindings.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';
import 'item_editor_view.dart';

/// Detailed inspection pane for a selected vault item.
class ItemDetailView extends StatefulWidget {
  final VaultItem item;

  const ItemDetailView({super.key, required this.item});

  @override
  State<ItemDetailView> createState() => _ItemDetailViewState();
}

class _ItemDetailViewState extends State<ItemDetailView> {
  bool _obscurePassword = true;
  CrackTimeEstimate? _estimate;
  Timer? _totpTimer;
  TotpGeneratedCode? _totpCode;

  @override
  void initState() {
    super.initState();
    _loadEstimate();
    _startTotpTimer();
  }

  @override
  void didUpdateWidget(covariant ItemDetailView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.item.password != widget.item.password) {
      _loadEstimate();
    }
    if (oldWidget.item.totpSeed != widget.item.totpSeed) {
      _startTotpTimer();
    }
  }

  @override
  void dispose() {
    _totpTimer?.cancel();
    super.dispose();
  }

  void _startTotpTimer() {
    _totpTimer?.cancel();
    _updateTotp();
    _totpTimer = Timer.periodic(const Duration(seconds: 1), (_) => _updateTotp());
  }

  void _updateTotp() {
    final seed = widget.item.totpSeed?.trim();
    if (seed == null || seed.isEmpty) {
      if (_totpCode != null) setState(() => _totpCode = null);
      return;
    }

    String secret = seed;
    int digits = 6;
    int period = 30;
    String alg = 'SHA1';

    if (seed.toLowerCase().startsWith('otpauth://')) {
      final config = VaultState.instance.parseTotpUri(seed);
      if (config != null) {
        digits = config.digits;
        period = config.periodSeconds;
        alg = config.algorithm;
        // Base32 secret bytes converted or parsed
      }
    }

    final gen = VaultState.instance.generateTotpCode(
      secret,
      digits: digits,
      period: period,
      algorithm: alg,
    );

    if (mounted) {
      setState(() => _totpCode = gen);
    }
  }

  String _formattedTotp(String code) {
    if (code.length == 6) {
      return '${code.substring(0, 3)} ${code.substring(3)}';
    } else if (code.length == 8) {
      return '${code.substring(0, 4)} ${code.substring(4)}';
    }
    return code;
  }

  void _loadEstimate() {
    if (widget.item.password != null && widget.item.password!.isNotEmpty) {
      final est = RustVaultFfi.instance.estimateCrackTime(widget.item.password!);
      setState(() => _estimate = est);
    } else {
      setState(() => _estimate = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final item = widget.item;

    return Scaffold(
      appBar: AppBar(
        title: Text(item.title),
        actions: [
          IconButton(
            tooltip: item.favorite ? 'Unstar' : 'Star Favorite',
            icon: Icon(
              item.favorite ? Icons.star : Icons.star_border,
              color: item.favorite ? AppTheme.amber : null,
            ),
            onPressed: () => VaultState.instance.toggleFavorite(item.id),
          ),
          IconButton(
            tooltip: 'Edit Item',
            icon: const Icon(Icons.edit_outlined),
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (ctx) => ItemEditorView(item: item),
                ),
              );
            },
          ),
          IconButton(
            tooltip: item.isTrashed ? 'Delete Permanently' : 'Move to Trash',
            icon: Icon(
              item.isTrashed ? Icons.delete_forever_outlined : Icons.delete_outline,
              color: AppTheme.rose,
            ),
            onPressed: () {
              if (item.isTrashed) {
                VaultState.instance.deletePermanently(item.id);
              } else {
                VaultState.instance.trashItem(item.id);
              }
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 720),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Top Category & Title Badge
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppTheme.cyan.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.3)),
                      ),
                      child: Icon(_categoryIcon(item.category), color: AppTheme.cyan, size: 28),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            item.title,
                            style: theme.textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.bold),
                          ),
                          Text(
                            item.category.displayName,
                            style: const TextStyle(color: AppTheme.darkTextSecondary, fontSize: 13),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 24),

                // Credentials Box
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Credentials', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),

                        // Username Field
                        if (item.username != null && item.username!.isNotEmpty) ...[
                          _buildDetailRow(
                            context,
                            icon: Icons.person_outline,
                            label: 'Username',
                            value: item.username!,
                            onCopy: () => VaultState.instance.copySecret(context, item.username!, 'Username'),
                          ),
                          const Divider(height: 24),
                        ],

                        // Password Field
                        if (item.password != null && item.password!.isNotEmpty) ...[
                          Row(
                            crossAxisAlignment: CrossAxisAlignment.center,
                            children: [
                              const Icon(Icons.lock_outline, size: 20, color: AppTheme.darkTextSecondary),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Text('Password', style: TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary)),
                                    const SizedBox(height: 2),
                                    Text(
                                      _obscurePassword ? '••••••••••••••••' : item.password!,
                                      style: TextStyle(
                                        fontFamily: _obscurePassword ? null : 'monospace',
                                        fontSize: 15,
                                        fontWeight: FontWeight.w600,
                                        color: _obscurePassword ? null : AppTheme.cyan,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              IconButton(
                                tooltip: _obscurePassword ? 'Reveal' : 'Conceal',
                                icon: Icon(_obscurePassword ? Icons.visibility_outlined : Icons.visibility_off_outlined),
                                onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
                              ),
                              IconButton(
                                tooltip: 'Copy Password',
                                icon: const Icon(Icons.copy_outlined, color: AppTheme.emerald),
                                onPressed: () => VaultState.instance.copySecret(context, item.password!, 'Password'),
                              ),
                            ],
                          ),
                          if (_estimate != null) ...[
                            const SizedBox(height: 8),
                            Padding(
                              padding: const EdgeInsets.only(left: 32),
                              child: Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: _ratingColor(_estimate!.rating).withValues(alpha: 0.15),
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: Text(
                                      '${_estimate!.rating} (${_estimate!.entropyBits} bits)',
                                      style: TextStyle(fontSize: 11, color: _ratingColor(_estimate!.rating), fontWeight: FontWeight.bold),
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  Text(
                                    'GPU crack: ${_estimate!.offlineGpuTime}',
                                    style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary),
                                  ),
                                ],
                              ),
                            ),
                          ],
                          const Divider(height: 24),
                        ],

                        // URLs
                        if (item.urls.isNotEmpty) ...[
                          for (final url in item.urls) ...[
                            _buildDetailRow(
                              context,
                              icon: Icons.link_outlined,
                              label: 'URL',
                              value: url,
                              onCopy: () => VaultState.instance.copySecret(context, url, 'URL'),
                            ),
                            if (url != item.urls.last) const SizedBox(height: 12),
                          ],
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Two-Factor Authenticator (TOTP) Card
                if (item.totpSeed != null && item.totpSeed!.isNotEmpty) ...[
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(
                                'Two-Factor Authenticator (2FA)',
                                style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold),
                              ),
                              if (_totpCode != null)
                                Row(
                                  children: [
                                    SizedBox(
                                      width: 18,
                                      height: 18,
                                      child: CircularProgressIndicator(
                                        value: _totpCode!.remainingSeconds / 30.0,
                                        strokeWidth: 3,
                                        backgroundColor: Colors.white12,
                                        valueColor: AlwaysStoppedAnimation(
                                          _totpCode!.remainingSeconds <= 5 ? AppTheme.rose : AppTheme.cyan,
                                        ),
                                      ),
                                    ),
                                    const SizedBox(width: 8),
                                    Text(
                                      '${_totpCode!.remainingSeconds}s',
                                      style: TextStyle(
                                        fontSize: 12,
                                        fontWeight: FontWeight.bold,
                                        color: _totpCode!.remainingSeconds <= 5 ? AppTheme.rose : AppTheme.cyan,
                                      ),
                                    ),
                                  ],
                                ),
                            ],
                          ),
                          const SizedBox(height: 16),
                          if (_totpCode != null) ...[
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                              decoration: BoxDecoration(
                                color: AppTheme.cyan.withValues(alpha: 0.08),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.25)),
                              ),
                              child: Row(
                                children: [
                                  const Icon(Icons.timer_outlined, color: AppTheme.cyan, size: 28),
                                  const SizedBox(width: 16),
                                  Expanded(
                                    child: Text(
                                      _formattedTotp(_totpCode!.code),
                                      style: const TextStyle(
                                        fontFamily: 'monospace',
                                        fontSize: 26,
                                        fontWeight: FontWeight.bold,
                                        letterSpacing: 4,
                                        color: AppTheme.cyan,
                                      ),
                                    ),
                                  ),
                                  IconButton(
                                    tooltip: 'Copy 2FA Code',
                                    icon: const Icon(Icons.copy_outlined, color: AppTheme.cyan),
                                    onPressed: () => VaultState.instance.copySecret(context, _totpCode!.code, '2FA Code'),
                                  ),
                                ],
                              ),
                            ),
                          ] else ...[
                            const Text('Initializing 2FA authenticator key...', style: TextStyle(color: AppTheme.darkTextSecondary)),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],

                // Notes Card
                if (item.notes != null && item.notes!.isNotEmpty) ...[
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Secure Notes', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                          const SizedBox(height: 12),
                          SelectableText(
                            item.notes!,
                            style: const TextStyle(fontSize: 14, height: 1.5),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],

                // Custom Fields Card
                if (item.customFields.isNotEmpty) ...[
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Custom Fields', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
                          const SizedBox(height: 12),
                          for (final field in item.customFields) ...[
                            _buildDetailRow(
                              context,
                              icon: Icons.extension_outlined,
                              label: field.name,
                              value: field.value,
                              onCopy: () => VaultState.instance.copySecret(context, field.value, field.name),
                            ),
                            if (field != item.customFields.last) const Divider(height: 20),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],

                // Revision History Expander
                if (item.revisionHistory.isNotEmpty) ...[
                  Card(
                    child: ExpansionTile(
                      leading: const Icon(Icons.history_outlined, color: AppTheme.cyan),
                      title: Text('Password History (${item.revisionHistory.length} revisions)'),
                      children: [
                        for (final rev in item.revisionHistory.reversed) ...[
                          ListTile(
                            dense: true,
                            title: Text(rev.password ?? 'No password recorded'),
                            subtitle: Text('Changed on ${DateTime.fromMillisecondsSinceEpoch(rev.timestamp * 1000).toLocal()}'),
                            trailing: IconButton(
                              icon: const Icon(Icons.copy_outlined, size: 16),
                              onPressed: rev.password == null
                                  ? null
                                  : () => VaultState.instance.copySecret(context, rev.password!, 'Historical password'),
                            ),
                          ),
                          const Divider(height: 1),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                ],

                // Item Timestamps
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'Created: ${DateTime.fromMillisecondsSinceEpoch(item.createdAt * 1000).toLocal()}',
                        style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary),
                      ),
                      Text(
                        'Updated: ${DateTime.fromMillisecondsSinceEpoch(item.updatedAt * 1000).toLocal()}',
                        style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDetailRow(
    BuildContext context, {
    required IconData icon,
    required String label,
    required String value,
    required VoidCallback onCopy,
  }) {
    return Row(
      children: [
        Icon(icon, size: 20, color: AppTheme.darkTextSecondary),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label, style: const TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary)),
              const SizedBox(height: 2),
              SelectableText(
                value,
                style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
              ),
            ],
          ),
        ),
        IconButton(
          tooltip: 'Copy $label',
          icon: const Icon(Icons.copy_outlined, size: 18),
          onPressed: onCopy,
        ),
      ],
    );
  }

  IconData _categoryIcon(ItemCategory cat) {
    switch (cat) {
      case ItemCategory.login:
        return Icons.login_outlined;
      case ItemCategory.secureNote:
        return Icons.note_outlined;
      case ItemCategory.paymentCard:
        return Icons.credit_card_outlined;
      case ItemCategory.identity:
        return Icons.badge_outlined;
      case ItemCategory.recoveryCode:
        return Icons.key_outlined;
    }
  }

  Color _ratingColor(String rating) {
    switch (rating.toLowerCase()) {
      case 'veryweak':
      case 'weak':
        return AppTheme.rose;
      case 'fair':
        return AppTheme.amber;
      case 'strong':
      case 'verystrong':
        return AppTheme.emerald;
      default:
        return AppTheme.cyan;
    }
  }
}
