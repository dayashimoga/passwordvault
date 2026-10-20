import 'package:flutter/material.dart';
import '../core/ffi/vault_ffi_bindings.dart';
import '../core/theme/app_theme.dart';
import '../models/vault_models.dart';
import '../services/biometric_service.dart';
import '../services/vault_state.dart';

/// Vault unlock and initial onboarding screen.
class UnlockView extends StatefulWidget {
  const UnlockView({super.key});

  @override
  State<UnlockView> createState() => _UnlockViewState();
}

class _UnlockViewState extends State<UnlockView> {
  bool _isCreateMode = false;
  bool _obscurePassphrase = true;
  bool _isLoading = false;
  String? _errorMessage;

  final TextEditingController _passphraseController = TextEditingController();
  final TextEditingController _confirmController = TextEditingController();
  final TextEditingController _vaultNameController =
      TextEditingController(text: 'Personal Vault');

  CrackTimeEstimate? _liveStrength;

  @override
  void initState() {
    super.initState();
    _passphraseController.addListener(_onPassphraseChanged);
  }

  @override
  void dispose() {
    _passphraseController.dispose();
    _confirmController.dispose();
    _vaultNameController.dispose();
    super.dispose();
  }

  void _onPassphraseChanged() {
    if (_isCreateMode && _passphraseController.text.isNotEmpty) {
      final estimate = RustVaultFfi.instance.estimateCrackTime(_passphraseController.text);
      setState(() {
        _liveStrength = estimate;
      });
    }
  }

  Future<void> _handleUnlock() async {
    final pw = _passphraseController.text.trim();
    if (pw.isEmpty) {
      setState(() => _errorMessage = 'Please enter your master passphrase');
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      await VaultState.instance.unlockVault(pw);
    } catch (e) {
      setState(() {
        _errorMessage = e is FormatException ? e.message : 'Unlock failed: ${e.toString()}';
      });
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _handleCreate() async {
    final pw = _passphraseController.text.trim();
    final confirm = _confirmController.text.trim();
    final name = _vaultNameController.text.trim();

    if (pw.length < 8) {
      setState(() => _errorMessage = 'Master passphrase must be at least 8 characters');
      return;
    }
    if (pw != confirm) {
      setState(() => _errorMessage = 'Passphrases do not match');
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      await VaultState.instance.createVault(pw, name.isEmpty ? 'Personal Vault' : name);
    } catch (e) {
      setState(() => _errorMessage = 'Failed to create vault: $e');
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _handleBiometric() async {
    final bio = BiometricService.instance;
    final success = await bio.authenticate(localizedReason: 'Authenticate to unlock your vault');
    if (success) {
      // In production, master DEK is retrieved from Windows Hello / Android KeyStore
      if (_passphraseController.text.isNotEmpty) {
        _handleUnlock();
      } else {
        setState(() => _errorMessage = 'Enter master passphrase once to bind ${bio.biometricName}');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Shield Icon with Cyberpunk Accent
                    Container(
                      width: 64,
                      height: 64,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: LinearGradient(
                          colors: [
                            AppTheme.cyan.withValues(alpha: 0.2),
                            AppTheme.emerald.withValues(alpha: 0.2),
                          ],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        border: Border.all(color: AppTheme.cyan.withValues(alpha: 0.4), width: 2),
                      ),
                      child: const Icon(
                        Icons.shield_outlined,
                        color: AppTheme.cyan,
                        size: 32,
                      ),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'PWDVAULT',
                      style: theme.textTheme.headlineSmall?.copyWith(
                        fontWeight: FontWeight.w800,
                        letterSpacing: 2.0,
                        color: AppTheme.cyan,
                      ),
                    ),
                    Text(
                      'Zero-Knowledge Personal Cryptographic Vault',
                      textAlign: TextAlign.center,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: AppTheme.darkTextSecondary,
                      ),
                    ),
                    const SizedBox(height: 24),

                    // Mode Toggle (Unlock vs Create)
                    SegmentedButton<bool>(
                      segments: const [
                        ButtonSegment(
                          value: false,
                          label: Text('Unlock Vault'),
                          icon: Icon(Icons.lock_open_outlined, size: 16),
                        ),
                        ButtonSegment(
                          value: true,
                          label: Text('New Vault'),
                          icon: Icon(Icons.add_circle_outline, size: 16),
                        ),
                      ],
                      selected: {_isCreateMode},
                      onSelectionChanged: (newVal) {
                        setState(() {
                          _isCreateMode = newVal.first;
                          _errorMessage = null;
                        });
                      },
                    ),
                    const SizedBox(height: 24),

                    // Error Banner
                    if (_errorMessage != null) ...[
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppTheme.rose.withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppTheme.rose.withValues(alpha: 0.3)),
                        ),
                        child: Row(
                          children: [
                            const Icon(Icons.error_outline, color: AppTheme.rose, size: 18),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                _errorMessage!,
                                style: const TextStyle(color: AppTheme.rose, fontSize: 13),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 16),
                    ],

                    // Create Mode: Vault Name
                    if (_isCreateMode) ...[
                      TextField(
                        controller: _vaultNameController,
                        decoration: const InputDecoration(
                          labelText: 'Vault Name',
                          prefixIcon: Icon(Icons.badge_outlined),
                        ),
                      ),
                      const SizedBox(height: 16),
                    ],

                    // Master Passphrase Input
                    TextField(
                      controller: _passphraseController,
                      obscureText: _obscurePassphrase,
                      autofocus: true,
                      onSubmitted: (_) => _isCreateMode ? _handleCreate() : _handleUnlock(),
                      decoration: InputDecoration(
                        labelText: 'Master Passphrase',
                        prefixIcon: const Icon(Icons.key_outlined),
                        suffixIcon: IconButton(
                          icon: Icon(
                            _obscurePassphrase ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                          ),
                          onPressed: () => setState(() => _obscurePassphrase = !_obscurePassphrase),
                        ),
                      ),
                    ),

                    // Create Mode: Strength Gauge & Confirm Input
                    if (_isCreateMode) ...[
                      const SizedBox(height: 8),
                      if (_liveStrength != null) ...[
                        Row(
                          children: [
                            Text(
                              'Strength: ${_liveStrength!.rating}',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: _ratingColor(_liveStrength!.rating),
                              ),
                            ),
                            const Spacer(),
                            Text(
                              'GPU Crack Time: ${_liveStrength!.offlineGpuTime}',
                              style: const TextStyle(fontSize: 11, color: AppTheme.darkTextSecondary),
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(4),
                          child: LinearProgressIndicator(
                            value: (_liveStrength!.entropyBits / 100.0).clamp(0.05, 1.0),
                            backgroundColor: AppTheme.darkBorder,
                            color: _ratingColor(_liveStrength!.rating),
                            minHeight: 6,
                          ),
                        ),
                      ],
                      const SizedBox(height: 16),
                      TextField(
                        controller: _confirmController,
                        obscureText: _obscurePassphrase,
                        onSubmitted: (_) => _handleCreate(),
                        decoration: const InputDecoration(
                          labelText: 'Confirm Master Passphrase',
                          prefixIcon: Icon(Icons.lock_reset_outlined),
                        ),
                      ),
                    ],

                    const SizedBox(height: 24),

                    // Primary Action Button
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton(
                        onPressed: _isLoading ? null : (_isCreateMode ? _handleCreate : _handleUnlock),
                        child: _isLoading
                            ? const SizedBox(
                                height: 20,
                                width: 20,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                              )
                            : Text(_isCreateMode ? 'Create Encrypted Vault' : 'Unlock Vault'),
                      ),
                    ),

                    // Biometric Convenience Unlock Button
                    if (!_isCreateMode) ...[
                      const SizedBox(height: 12),
                      SizedBox(
                        width: double.infinity,
                        child: OutlinedButton.icon(
                          onPressed: _isLoading ? null : _handleBiometric,
                          icon: const Icon(Icons.fingerprint, color: AppTheme.cyan),
                          label: Text('Unlock with ${BiometricService.instance.biometricName}'),
                        ),
                      ),
                    ],

                    const SizedBox(height: 20),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.offline_bolt_outlined, size: 14, color: AppTheme.emerald),
                        const SizedBox(width: 6),
                        Flexible(
                          child: Text(
                            'Strictly Offline • Argon2id • XChaCha20-Poly1305',
                            overflow: TextOverflow.ellipsis,
                            textAlign: TextAlign.center,
                            style: theme.textTheme.bodySmall?.copyWith(
                              fontSize: 11,
                              color: AppTheme.darkTextSecondary,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
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
