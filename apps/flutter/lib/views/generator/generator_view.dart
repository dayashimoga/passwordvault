import 'package:flutter/material.dart';
import '../../core/ffi/vault_ffi_bindings.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';

/// Interactive cryptographically secure generator sheet and view.
class GeneratorView extends StatefulWidget {
  final ValueChanged<String>? onSelectPassword;

  const GeneratorView({super.key, this.onSelectPassword});

  @override
  State<GeneratorView> createState() => _GeneratorViewState();
}

class _GeneratorViewState extends State<GeneratorView> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Password Options
  int _length = 20;
  bool _includeUppercase = true;
  bool _includeLowercase = true;
  bool _includeDigits = true;
  bool _includeSymbols = true;
  bool _excludeAmbiguous = true;
  final String _customExcluded = '';

  // Passphrase Options
  int _wordCount = 5;
  String _separator = '-';
  String _capitalization = 'TitleCase';
  bool _insertNumber = true;

  // Active Output
  String _generatedSecret = '';
  CrackTimeEstimate? _estimate;
  final List<String> _history = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _tabController.addListener(() {
      if (!_tabController.indexIsChanging) {
        _generate();
      }
    });
    _generate();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  void _generate() {
    final ffi = RustVaultFfi.instance;
    String secret;

    if (_tabController.index == 0) {
      secret = ffi.generatePassword(
        length: _length,
        uppercase: _includeUppercase,
        lowercase: _includeLowercase,
        digits: _includeDigits,
        symbols: _includeSymbols,
        excludeAmbiguous: _excludeAmbiguous,
        customExcluded: _customExcluded,
      );
    } else {
      secret = ffi.generatePassphrase(
        wordCount: _wordCount,
        separator: _separator,
        capitalization: _capitalization,
        insertNumber: _insertNumber,
      );
    }

    final est = ffi.estimateCrackTime(secret);

    setState(() {
      _generatedSecret = secret;
      _estimate = est;
      if (!_history.contains(secret)) {
        _history.insert(0, secret);
        if (_history.length > 10) _history.removeLast();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Password & Passphrase Generator'),
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.cyan,
          tabs: const [
            Tab(icon: Icon(Icons.password_outlined), text: 'Random Password'),
            Tab(icon: Icon(Icons.format_quote_outlined), text: 'EFF Passphrase'),
          ],
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 680),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Generated Secret Display Box
                Card(
                  color: AppTheme.darkSurfaceSubtle,
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: SelectableText(
                                _generatedSecret,
                                style: const TextStyle(
                                  fontFamily: 'monospace',
                                  fontSize: 20,
                                  fontWeight: FontWeight.bold,
                                  letterSpacing: 1.2,
                                  color: AppTheme.cyan,
                                ),
                              ),
                            ),
                            IconButton(
                              tooltip: 'Regenerate',
                              icon: const Icon(Icons.refresh, color: AppTheme.cyan),
                              onPressed: _generate,
                            ),
                            IconButton(
                              tooltip: 'Copy to Clipboard',
                              icon: const Icon(Icons.copy_outlined, color: AppTheme.emerald),
                              onPressed: () {
                                VaultState.instance.copySecret(context, _generatedSecret, 'Generated password');
                                if (widget.onSelectPassword != null) {
                                  widget.onSelectPassword!(_generatedSecret);
                                }
                              },
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        if (_estimate != null) ...[
                          Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                decoration: BoxDecoration(
                                  color: _ratingColor(_estimate!.rating).withValues(alpha: 0.15),
                                  borderRadius: BorderRadius.circular(6),
                                  border: Border.all(color: _ratingColor(_estimate!.rating)),
                                ),
                                child: Text(
                                  '${_estimate!.entropyBits} bits • ${_estimate!.rating}',
                                  style: TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.bold,
                                    color: _ratingColor(_estimate!.rating),
                                  ),
                                ),
                              ),
                              const Spacer(),
                              Text(
                                'GPU Crack Time: ${_estimate!.offlineGpuTime}',
                                style: const TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                              ),
                            ],
                          ),
                          const SizedBox(height: 8),
                          ClipRRect(
                            borderRadius: BorderRadius.circular(4),
                            child: LinearProgressIndicator(
                              value: (_estimate!.entropyBits / 100.0).clamp(0.05, 1.0),
                              backgroundColor: AppTheme.darkBorder,
                              color: _ratingColor(_estimate!.rating),
                              minHeight: 6,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Tab Content: Sliders & Options
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: _tabController.index == 0 ? _buildPasswordControls() : _buildPassphraseControls(),
                  ),
                ),

                const SizedBox(height: 24),

                // Generation History
                if (_history.length > 1) ...[
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              const Icon(Icons.history_outlined, size: 18, color: AppTheme.darkTextSecondary),
                              const SizedBox(width: 8),
                              Text('Session History (Zeroized on Lock)', style: theme.textTheme.titleSmall),
                            ],
                          ),
                          const SizedBox(height: 12),
                          ListView.separated(
                            shrinkWrap: true,
                            physics: const NeverScrollableScrollPhysics(),
                            itemCount: _history.length,
                            separatorBuilder: (context, index) => const Divider(height: 1),
                            itemBuilder: (ctx, idx) {
                              final item = _history[idx];
                              return ListTile(
                                dense: true,
                                contentPadding: EdgeInsets.zero,
                                title: Text(
                                  item,
                                  style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                                ),
                                trailing: IconButton(
                                  icon: const Icon(Icons.copy_outlined, size: 16),
                                  onPressed: () => VaultState.instance.copySecret(context, item, 'Password'),
                                ),
                              );
                            },
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildPasswordControls() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text('Password Length', style: TextStyle(fontWeight: FontWeight.w600)),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: AppTheme.darkSurfaceSubtle,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppTheme.darkBorder),
              ),
              child: Text(
                '$_length chars',
                style: const TextStyle(fontWeight: FontWeight.bold, color: AppTheme.cyan),
              ),
            ),
          ],
        ),
        Slider(
          value: _length.toDouble(),
          min: 8,
          max: 128,
          divisions: 120,
          activeColor: AppTheme.cyan,
          onChanged: (val) {
            setState(() => _length = val.round());
            _generate();
          },
        ),
        const SizedBox(height: 16),
        const Text('Character Sets', style: TextStyle(fontWeight: FontWeight.w600)),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilterChip(
              label: const Text('A-Z (Uppercase)'),
              selected: _includeUppercase,
              onSelected: (val) {
                setState(() => _includeUppercase = val);
                _ensureAtLeastOneClass();
                _generate();
              },
            ),
            FilterChip(
              label: const Text('a-z (Lowercase)'),
              selected: _includeLowercase,
              onSelected: (val) {
                setState(() => _includeLowercase = val);
                _ensureAtLeastOneClass();
                _generate();
              },
            ),
            FilterChip(
              label: const Text('0-9 (Digits)'),
              selected: _includeDigits,
              onSelected: (val) {
                setState(() => _includeDigits = val);
                _ensureAtLeastOneClass();
                _generate();
              },
            ),
            FilterChip(
              label: const Text('!@#\$ (Symbols)'),
              selected: _includeSymbols,
              onSelected: (val) {
                setState(() => _includeSymbols = val);
                _ensureAtLeastOneClass();
                _generate();
              },
            ),
          ],
        ),
        const SizedBox(height: 16),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Exclude Ambiguous Characters'),
          subtitle: const Text('Excludes visually identical characters: 1, l, I, 0, O, 8, B'),
          value: _excludeAmbiguous,
          onChanged: (val) {
            setState(() => _excludeAmbiguous = val);
            _generate();
          },
        ),
      ],
    );
  }

  void _ensureAtLeastOneClass() {
    if (!_includeUppercase && !_includeLowercase && !_includeDigits && !_includeSymbols) {
      _includeLowercase = true;
    }
  }

  Widget _buildPassphraseControls() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text('Word Count', style: TextStyle(fontWeight: FontWeight.w600)),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: AppTheme.darkSurfaceSubtle,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppTheme.darkBorder),
              ),
              child: Text(
                '$_wordCount words',
                style: const TextStyle(fontWeight: FontWeight.bold, color: AppTheme.cyan),
              ),
            ),
          ],
        ),
        Slider(
          value: _wordCount.toDouble(),
          min: 3,
          max: 10,
          divisions: 7,
          activeColor: AppTheme.cyan,
          onChanged: (val) {
            setState(() => _wordCount = val.round());
            _generate();
          },
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: DropdownButtonFormField<String>(
                initialValue: _separator,
                decoration: const InputDecoration(labelText: 'Separator'),
                items: const [
                  DropdownMenuItem(value: '-', child: Text('Hyphen (-)')),
                  DropdownMenuItem(value: ' ', child: Text('Space ( )')),
                  DropdownMenuItem(value: '.', child: Text('Period (.)')),
                  DropdownMenuItem(value: '_', child: Text('Underscore (_)')),
                  DropdownMenuItem(value: '/', child: Text('Slash (/)')),
                ],
                onChanged: (val) {
                  if (val != null) {
                    setState(() => _separator = val);
                    _generate();
                  }
                },
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: DropdownButtonFormField<String>(
                initialValue: _capitalization,
                decoration: const InputDecoration(labelText: 'Capitalization'),
                items: const [
                  DropdownMenuItem(value: 'TitleCase', child: Text('Title Case')),
                  DropdownMenuItem(value: 'Lowercase', child: Text('lowercase')),
                  DropdownMenuItem(value: 'Uppercase', child: Text('UPPERCASE')),
                ],
                onChanged: (val) {
                  if (val != null) {
                    setState(() => _capitalization = val);
                    _generate();
                  }
                },
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Insert Random Number'),
          subtitle: const Text('Appends 2-digit number for additional entropy'),
          value: _insertNumber,
          onChanged: (val) {
            setState(() => _insertNumber = val);
            _generate();
          },
        ),
      ],
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
