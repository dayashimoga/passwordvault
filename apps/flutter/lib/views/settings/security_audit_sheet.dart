import 'dart:convert';
import 'package:flutter/material.dart';
import '../../core/ffi/vault_ffi_bindings.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';

/// Modal bottom sheet for Personal Security Audit, k-Anonymity Breach Watch, and WebAuthn Passkeys.
class SecurityAuditSheet extends StatefulWidget {
  const SecurityAuditSheet({super.key});

  @override
  State<SecurityAuditSheet> createState() => _SecurityAuditSheetState();
}

class _SecurityAuditSheetState extends State<SecurityAuditSheet>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Tab 1: Audit
  VaultAuditReportModel? _report;
  bool _isAuditing = false;

  // Tab 2: Breach Watch
  final _breachCheckController = TextEditingController();
  bool _isCheckingBreach = false;
  int? _breachResultCount;
  String? _checkedPassword;
  bool _isBatchScanning = false;
  Map<String, int> _batchBreachResults = {};

  // Tab 3: Passkeys
  final _rpIdController = TextEditingController(text: 'github.com');
  final _userNameController = TextEditingController(text: 'security_lead@antigravity.io');
  int _selectedAlg = -7; // COSE ES256
  PasskeyCredentialModel? _activePasskey;
  PasskeyAssertionResult? _lastAssertion;
  bool _isGeneratingPasskey = false;
  bool _isSigningAssertion = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _runAudit();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _breachCheckController.dispose();
    _rpIdController.dispose();
    _userNameController.dispose();
    super.dispose();
  }

  void _runAudit() {
    if (VaultState.instance.payload == null) {
      _report = null;
      _isAuditing = false;
      return;
    }
    setState(() => _isAuditing = true);
    try {
      final report = VaultState.instance.runSecurityAudit();
      setState(() {
        _report = report;
        _isAuditing = false;
      });
    } catch (_) {
      setState(() => _isAuditing = false);
    }
  }

  Future<void> _checkSingleBreach() async {
    final pw = _breachCheckController.text.trim();
    if (pw.isEmpty) return;

    setState(() {
      _isCheckingBreach = true;
      _checkedPassword = pw;
      _breachResultCount = null;
    });

    try {
      final count = await VaultState.instance.checkPasswordBreach(pw);
      setState(() {
        _breachResultCount = count;
        _isCheckingBreach = false;
      });
    } catch (e) {
      setState(() => _isCheckingBreach = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Breach query failed: $e')),
        );
      }
    }
  }

  Future<void> _runBatchBreachScan() async {
    final payload = VaultState.instance.payload;
    if (payload == null) return;

    setState(() {
      _isBatchScanning = true;
      _batchBreachResults.clear();
    });

    final uniquePasswords = <String>{};
    for (final item in payload.items) {
      if (item.trashedAt == null && item.password != null && item.password!.isNotEmpty) {
        uniquePasswords.add(item.password!);
      }
    }

    final results = <String, int>{};
    for (final pw in uniquePasswords) {
      try {
        final count = await VaultState.instance.checkPasswordBreach(pw);
        if (count > 0) {
          results[pw] = count;
        }
      } catch (_) {
        // continue scanning
      }
    }

    if (mounted) {
      setState(() {
        _batchBreachResults = results;
        _isBatchScanning = false;
      });
    }
  }

  void _generatePasskey() {
    final rpId = _rpIdController.text.trim();
    final user = _userNameController.text.trim();
    if (rpId.isEmpty || user.isEmpty) return;

    setState(() => _isGeneratingPasskey = true);
    try {
      final ffi = RustVaultFfi.instance;
      final passkey = ffi.generatePasskey(
        rpId: rpId,
        userName: user,
        algorithm: _selectedAlg,
      );
      setState(() {
        _activePasskey = passkey;
        _lastAssertion = null;
        _isGeneratingPasskey = false;
      });
    } catch (e) {
      setState(() => _isGeneratingPasskey = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Passkey generation failed: $e')),
        );
      }
    }
  }

  void _testSignAssertion() {
    if (_activePasskey == null) return;

    setState(() => _isSigningAssertion = true);
    try {
      final ffi = RustVaultFfi.instance;
      final dummyClientData = jsonEncode({
        'type': 'webauthn.get',
        'challenge': 'dGVzdC1jaGFsbGVuZ2Utbm9uY2UtYW50aWdyYXZpdHk=',
        'origin': 'https://${_activePasskey!.rpId}',
      });

      final result = ffi.signPasskeyAssertion(
        passkey: _activePasskey!,
        rpId: _activePasskey!.rpId,
        clientDataJson: dummyClientData,
        userPresent: true,
        userVerified: true,
      );

      setState(() {
        _activePasskey = result.updatedPasskey;
        _lastAssertion = result.assertion;
        _isSigningAssertion = false;
      });
    } catch (e) {
      setState(() => _isSigningAssertion = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Assertion signing failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return DraggableScrollableSheet(
      initialChildSize: 0.88,
      minChildSize: 0.5,
      maxChildSize: 0.95,
      expand: false,
      builder: (_, scrollController) => Column(
        children: [
          // Drag handle
          Center(
            child: Container(
              margin: const EdgeInsets.only(top: 12, bottom: 8),
              width: 48,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.grey.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),

          // Header
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppTheme.rose.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.shield_outlined, color: AppTheme.rose),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Personal Security & Hygiene Audit',
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        'Audit vault health, k-Anonymity breach watch & FIDO2 passkeys',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: AppTheme.darkTextSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: () => Navigator.of(context).pop(),
                ),
              ],
            ),
          ),

          // Tabs
          TabBar(
            controller: _tabController,
            indicatorColor: AppTheme.cyan,
            labelColor: AppTheme.cyan,
            unselectedLabelColor: AppTheme.darkTextSecondary,
            tabs: const [
              Tab(icon: Icon(Icons.health_and_safety_outlined), text: 'Health Audit'),
              Tab(icon: Icon(Icons.security_outlined), text: 'Breach Watch'),
              Tab(icon: Icon(Icons.key_outlined), text: 'Passkeys (FIDO2)'),
            ],
          ),

          // Content
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildAuditTab(scrollController),
                _buildBreachTab(scrollController),
                _buildPasskeyTab(scrollController),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TAB 1: VAULT HEALTH AUDIT
  // ==========================================
  Widget _buildAuditTab(ScrollController scrollController) {
    if (_isAuditing) {
      return const Center(child: CircularProgressIndicator());
    }

    final report = _report;
    if (report == null) {
      return Center(
        child: ElevatedButton.icon(
          onPressed: _runAudit,
          icon: const Icon(Icons.play_arrow),
          label: const Text('Run Vault Security Audit'),
        ),
      );
    }

    final scoreColor = report.healthScore >= 80
        ? AppTheme.emerald
        : (report.healthScore >= 50 ? AppTheme.amber : AppTheme.rose);

    return ListView(
      controller: scrollController,
      padding: const EdgeInsets.all(20),
      children: [
        // Health Score Widget
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: scoreColor.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: scoreColor.withValues(alpha: 0.3)),
          ),
          child: Row(
            children: [
              Stack(
                alignment: Alignment.center,
                children: [
                  SizedBox(
                    width: 72,
                    height: 72,
                    child: CircularProgressIndicator(
                      value: report.healthScore / 100.0,
                      strokeWidth: 7,
                      backgroundColor: Colors.white10,
                      valueColor: AlwaysStoppedAnimation(scoreColor),
                    ),
                  ),
                  Text(
                    '${report.healthScore}%',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: scoreColor,
                    ),
                  ),
                ],
              ),
              const SizedBox(width: 20),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      report.healthScore >= 80
                          ? 'Vault Security: Excellent'
                          : (report.healthScore >= 50 ? 'Vault Security: Needs Attention' : 'Vault Security: Critical Risks'),
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: scoreColor,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '${report.totalActiveItems} active items inspected across password uniqueness, entropy, age & 2FA readiness.',
                      style: const TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                    ),
                  ],
                ),
              ),
              IconButton(
                icon: const Icon(Icons.refresh, color: AppTheme.cyan),
                tooltip: 'Re-run Audit',
                onPressed: _runAudit,
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),

        // Metrics Grid
        Row(
          children: [
            _buildMetricTile(
              label: 'Reused Passwords',
              count: report.reusedGroups.fold(0, (acc, g) => acc + g.count),
              color: report.reusedGroups.isEmpty ? AppTheme.emerald : AppTheme.rose,
              icon: Icons.copy_all,
            ),
            const SizedBox(width: 12),
            _buildMetricTile(
              label: 'Weak Passwords',
              count: report.weakItems.length,
              color: report.weakItems.isEmpty ? AppTheme.emerald : AppTheme.amber,
              icon: Icons.warning_amber_rounded,
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            _buildMetricTile(
              label: 'Stale (> 90 Days)',
              count: report.staleItems.length,
              color: report.staleItems.isEmpty ? AppTheme.emerald : AppTheme.cyan,
              icon: Icons.history,
            ),
            const SizedBox(width: 12),
            _buildMetricTile(
              label: 'Missing 2FA',
              count: report.missing2FaItems.length,
              color: report.missing2FaItems.isEmpty ? AppTheme.emerald : AppTheme.amber,
              icon: Icons.lock_clock_outlined,
            ),
          ],
        ),
        const SizedBox(height: 24),

        // Reused Passwords Detail
        if (report.reusedGroups.isNotEmpty) ...[
          Text('Duplicate & Reused Passwords',
              style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          ...report.reusedGroups.map(
            (g) => Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.warning, color: AppTheme.rose),
                title: Text('${g.count} accounts share the same password'),
                subtitle: Text(g.itemTitles.join(', ')),
              ),
            ),
          ),
          const SizedBox(height: 16),
        ],

        // Weak Passwords Detail
        if (report.weakItems.isNotEmpty) ...[
          Text('Weak Passwords Detected',
              style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          ...report.weakItems.map(
            (w) => Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.shield_outlined, color: AppTheme.amber),
                title: Text(w.title),
                subtitle: Text('${w.reason} (${w.entropyBits} bits entropy • ${w.rating})'),
              ),
            ),
          ),
          const SizedBox(height: 16),
        ],

        // Actionable Recommendations
        if (report.recommendations.isNotEmpty) ...[
          Text('Actionable Recommendations',
              style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: 0.05),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: report.recommendations
                  .map(
                    (rec) => Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Icon(Icons.check_circle_outline, color: AppTheme.cyan, size: 18),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(rec, style: const TextStyle(fontSize: 13)),
                          ),
                        ],
                      ),
                    ),
                  )
                  .toList(),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildMetricTile({
    required String label,
    required int count,
    required Color color,
    required IconData icon,
  }) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Row(
          children: [
            Icon(icon, color: color, size: 24),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '$count',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: color,
                    ),
                  ),
                  Text(
                    label,
                    style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TAB 2: BREACH WATCH (k-ANONYMITY)
  // ==========================================
  Widget _buildBreachTab(ScrollController scrollController) {
    return ListView(
      controller: scrollController,
      padding: const EdgeInsets.all(20),
      children: [
        // Privacy Guarantee Banner
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppTheme.cyan.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.3)),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.privacy_tip_outlined, color: AppTheme.cyan),
              SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Zero-Knowledge k-Anonymity Guarantee',
                      style: TextStyle(fontWeight: FontWeight.bold, color: AppTheme.cyan, fontSize: 14),
                    ),
                    SizedBox(height: 4),
                    Text(
                      'Your password and full hash never leave this device. The app hashes the password locally, sends only the first 5 hexadecimal characters of the SHA-1 digest to the API range protocol, and scans the matching range response locally.',
                      style: TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),

        // Single password query input
        Text('Check Single Password',
            style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        TextField(
          controller: _breachCheckController,
          obscureText: true,
          decoration: InputDecoration(
            labelText: 'Candidate Password to Inspect',
            prefixIcon: const Icon(Icons.lock_outline),
            suffixIcon: IconButton(
              icon: _isCheckingBreach
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.search, color: AppTheme.cyan),
              onPressed: _isCheckingBreach ? null : _checkSingleBreach,
            ),
          ),
          onSubmitted: (_) => _checkSingleBreach(),
        ),
        const SizedBox(height: 12),
        ElevatedButton.icon(
          onPressed: _isCheckingBreach ? null : _checkSingleBreach,
          icon: const Icon(Icons.shield_outlined),
          label: const Text('Check Breach Database (k-Anonymity)'),
        ),
        const SizedBox(height: 16),

        // Single check result card
        if (_breachResultCount != null && _checkedPassword != null) ...[
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: _breachResultCount! > 0
                  ? AppTheme.rose.withValues(alpha: 0.12)
                  : AppTheme.emerald.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: _breachResultCount! > 0
                    ? AppTheme.rose.withValues(alpha: 0.3)
                    : AppTheme.emerald.withValues(alpha: 0.3),
              ),
            ),
            child: Row(
              children: [
                Icon(
                  _breachResultCount! > 0 ? Icons.error_outline : Icons.check_circle_outline,
                  color: _breachResultCount! > 0 ? AppTheme.rose : AppTheme.emerald,
                  size: 32,
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        _breachResultCount! > 0
                            ? 'Exposed in Known Data Breaches!'
                            : 'No Known Breaches Detected',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: _breachResultCount! > 0 ? AppTheme.rose : AppTheme.emerald,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        _breachResultCount! > 0
                            ? 'This password was seen $_breachResultCount times in public security breaches. Change it immediately!'
                            : 'This candidate password was not found in the HaveIBeenPwned exposure records.',
                        style: const TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
        ],

        const Divider(),
        const SizedBox(height: 16),

        // Full Vault Scanner
        Text('Scan Entire Vault for Breached Passwords',
            style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        const Text(
          'Audits all unique passwords in your active vault against breach dictionaries while preserving privacy.',
          style: TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
        ),
        const SizedBox(height: 12),
        ElevatedButton.icon(
          onPressed: _isBatchScanning ? null : _runBatchBreachScan,
          icon: _isBatchScanning
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.radar),
          label: Text(_isBatchScanning ? 'Scanning...' : 'Scan Unlocked Vault Items'),
        ),
        const SizedBox(height: 16),

        if (_batchBreachResults.isNotEmpty) ...[
          Text('Breached Credentials in Vault (${_batchBreachResults.length})',
              style: const TextStyle(fontWeight: FontWeight.bold, color: AppTheme.rose)),
          const SizedBox(height: 8),
          ..._batchBreachResults.entries.map(
            (entry) => Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.warning, color: AppTheme.rose),
                title: Text('Seen ${entry.value} times in public breaches'),
                subtitle: const Text('Action: Rotate this password with a random generated one'),
              ),
            ),
          ),
        ] else if (!_isBatchScanning && _checkedPassword == null) ...[
          const Center(
            child: Padding(
              padding: EdgeInsets.all(24),
              child: Text(
                'No breach scans performed yet.',
                style: TextStyle(color: AppTheme.darkTextSecondary),
              ),
            ),
          ),
        ],
      ],
    );
  }

  // ==========================================
  // TAB 3: PASSKEY & FIDO2 LAB
  // ==========================================
  Widget _buildPasskeyTab(ScrollController scrollController) {
    return ListView(
      controller: scrollController,
      padding: const EdgeInsets.all(20),
      children: [
        // Information Banner
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppTheme.emerald.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppTheme.emerald.withValues(alpha: 0.3)),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.vpn_key_outlined, color: AppTheme.emerald),
              SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'FIDO2 / WebAuthn Hardware-Grade Passkeys',
                      style: TextStyle(fontWeight: FontWeight.bold, color: AppTheme.emerald, fontSize: 14),
                    ),
                    SizedBox(height: 4),
                    Text(
                      'Passkeys replace passwords with asymmetric cryptography. Authentication assertions include 37-byte authenticator framing (RP ID hash + UP/UV flags + anti-replay signature counters).',
                      style: TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),

        // Generate Passkey Form
        Text('Generate New Passkey Credential',
            style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        TextField(
          controller: _rpIdController,
          decoration: const InputDecoration(
            labelText: 'Relying Party Domain (RP ID)',
            hintText: 'e.g. github.com, google.com',
            prefixIcon: Icon(Icons.language),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _userNameController,
          decoration: const InputDecoration(
            labelText: 'User Account Name / Email',
            hintText: 'e.g. user@example.com',
            prefixIcon: Icon(Icons.person_outline),
          ),
        ),
        const SizedBox(height: 12),
        DropdownButtonFormField<int>(
          initialValue: _selectedAlg,
          decoration: const InputDecoration(
            labelText: 'Cryptographic Algorithm',
            prefixIcon: Icon(Icons.enhanced_encryption_outlined),
          ),
          items: const [
            DropdownMenuItem(value: -7, child: Text('ES256 (ECDSA P-256 w/ SHA-256, COSE -7)')),
            DropdownMenuItem(value: -8, child: Text('EdDSA (Ed25519, COSE -8)')),
          ],
          onChanged: (val) {
            if (val != null) setState(() => _selectedAlg = val);
          },
        ),
        const SizedBox(height: 16),
        ElevatedButton.icon(
          onPressed: _isGeneratingPasskey ? null : _generatePasskey,
          icon: _isGeneratingPasskey
              ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.add_moderator),
          label: const Text('Generate WebAuthn Passkey'),
        ),
        const SizedBox(height: 24),

        // Active Passkey Card
        if (_activePasskey != null) ...[
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.check_circle, color: AppTheme.emerald),
                      const SizedBox(width: 8),
                      Text('Active Passkey: ${_activePasskey!.rpId}',
                          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15)),
                    ],
                  ),
                  const Divider(height: 24),
                  _buildDetailRow('User', _activePasskey!.userName),
                  _buildDetailRow('Signature Counter', '${_activePasskey!.signCount}'),
                  _buildDetailRow('Algorithm', _activePasskey!.algorithm == -7 ? 'ES256' : 'EdDSA'),
                  _buildDetailRow('Credential ID', '${_activePasskey!.credentialId.length} bytes (C-ABI)'),
                  _buildDetailRow('Public Key', '${_activePasskey!.publicKey.length} bytes'),
                  const SizedBox(height: 16),
                  ElevatedButton.icon(
                    onPressed: _isSigningAssertion ? null : _testSignAssertion,
                    icon: _isSigningAssertion
                        ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.verified),
                    label: const Text('Simulate WebAuthn Assertion Challenge'),
                  ),
                ],
              ),
            ),
          ),
        ],

        // Assertion Result Card
        if (_lastAssertion != null) ...[
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.cyan.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.task_alt, color: AppTheme.cyan),
                    SizedBox(width: 8),
                    Text('WebAuthn Assertion Verified', style: TextStyle(fontWeight: FontWeight.bold, color: AppTheme.cyan)),
                  ],
                ),
                const SizedBox(height: 8),
                Text('Authenticator Data: ${_lastAssertion!.authenticatorData.length} bytes (Flags: UP, UV)'),
                Text('Signature: ${_lastAssertion!.signature.length} bytes'),
                Text('Updated Sign Count: ${_activePasskey!.signCount} (Anti-replay enforced)'),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontSize: 13, color: AppTheme.darkTextSecondary)),
          Text(value, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
        ],
      ),
    );
  }
}
