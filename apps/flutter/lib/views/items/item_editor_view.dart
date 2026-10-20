import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../models/vault_models.dart';
import '../../services/vault_state.dart';
import '../generator/generator_view.dart';

/// Form editor to create or modify a vault item.
class ItemEditorView extends StatefulWidget {
  final VaultItem? item;
  final ItemCategory initialCategory;

  const ItemEditorView({super.key, this.item, this.initialCategory = ItemCategory.login});

  @override
  State<ItemEditorView> createState() => _ItemEditorViewState();
}

class _ItemEditorViewState extends State<ItemEditorView> {
  late TextEditingController _titleController;
  late TextEditingController _usernameController;
  late TextEditingController _passwordController;
  late TextEditingController _totpSeedController;
  late TextEditingController _notesController;
  late ItemCategory _selectedCategory;
  final List<TextEditingController> _urlControllers = [];
  final List<CustomField> _customFields = [];

  bool _obscurePassword = true;

  @override
  void initState() {
    super.initState();
    final item = widget.item;
    _selectedCategory = item?.category ?? widget.initialCategory;
    _titleController = TextEditingController(text: item?.title ?? '');
    _usernameController = TextEditingController(text: item?.username ?? '');
    _passwordController = TextEditingController(text: item?.password ?? '');
    _totpSeedController = TextEditingController(text: item?.totpSeed ?? '');
    _notesController = TextEditingController(text: item?.notes ?? '');

    if (item != null && item.urls.isNotEmpty) {
      for (final u in item.urls) {
        _urlControllers.add(TextEditingController(text: u));
      }
    } else {
      _urlControllers.add(TextEditingController());
    }

    if (item != null && item.customFields.isNotEmpty) {
      for (final f in item.customFields) {
        _customFields.add(CustomField(name: f.name, value: f.value, fieldType: f.fieldType));
      }
    }
  }

  @override
  void dispose() {
    _titleController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _totpSeedController.dispose();
    _notesController.dispose();
    for (final c in _urlControllers) {
      c.dispose();
    }
    super.dispose();
  }

  void _handleSave() {
    final title = _titleController.text.trim();
    if (title.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter an item title')),
      );
      return;
    }

    final urls = _urlControllers
        .map((c) => c.text.trim())
        .where((u) => u.isNotEmpty)
        .toList();

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final item = VaultItem(
      id: widget.item?.id ?? 'item-${DateTime.now().microsecondsSinceEpoch}',
      title: title,
      category: _selectedCategory,
      username: _usernameController.text.trim().isEmpty ? null : _usernameController.text.trim(),
      password: _passwordController.text.isEmpty ? null : _passwordController.text,
      urls: urls,
      notes: _notesController.text.trim().isEmpty ? null : _notesController.text.trim(),
      totpSeed: _totpSeedController.text.trim().isEmpty ? null : _totpSeedController.text.trim(),
      favorite: widget.item?.favorite ?? false,
      customFields: _customFields,
      revisionHistory: widget.item?.revisionHistory ?? [],
      trashedAt: widget.item?.trashedAt,
      createdAt: widget.item?.createdAt ?? now,
      updatedAt: now,
    );

    VaultState.instance.saveItem(item);
    Navigator.of(context).pop();
  }

  void _openGeneratorModal() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => FractionallySizedBox(
        heightFactor: 0.85,
        child: GeneratorView(
          onSelectPassword: (newPw) {
            setState(() {
              _passwordController.text = newPw;
              _obscurePassword = false;
            });
            Navigator.of(ctx).pop();
          },
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isNew = widget.item == null;

    return Scaffold(
      appBar: AppBar(
        title: Text(isNew ? 'New Vault Item' : 'Edit Item'),
        actions: [
          ElevatedButton.icon(
            onPressed: _handleSave,
            icon: const Icon(Icons.check, size: 18),
            label: const Text('Save'),
          ),
          const SizedBox(width: 16),
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
                // Category Selector & Title
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      children: [
                        DropdownButtonFormField<ItemCategory>(
                          initialValue: _selectedCategory,
                          decoration: const InputDecoration(
                            labelText: 'Category',
                            prefixIcon: Icon(Icons.category_outlined),
                          ),
                          items: ItemCategory.values.map((cat) {
                            return DropdownMenuItem(
                              value: cat,
                              child: Text(cat.displayName),
                            );
                          }).toList(),
                          onChanged: (val) {
                            if (val != null) setState(() => _selectedCategory = val);
                          },
                        ),
                        const SizedBox(height: 16),
                        TextField(
                          controller: _titleController,
                          decoration: const InputDecoration(
                            labelText: 'Title *',
                            prefixIcon: Icon(Icons.title_outlined),
                            hintText: 'e.g. GitHub, Google, Work VPN',
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Credentials Block
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('Credentials', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                        const SizedBox(height: 16),
                        TextField(
                          controller: _usernameController,
                          decoration: const InputDecoration(
                            labelText: 'Username / Email',
                            prefixIcon: Icon(Icons.person_outline),
                          ),
                        ),
                        const SizedBox(height: 16),
                        TextField(
                          controller: _passwordController,
                          obscureText: _obscurePassword,
                          decoration: InputDecoration(
                            labelText: 'Password',
                            prefixIcon: const Icon(Icons.lock_outline),
                            suffixIcon: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                IconButton(
                                  tooltip: _obscurePassword ? 'Show' : 'Hide',
                                  icon: Icon(_obscurePassword ? Icons.visibility_outlined : Icons.visibility_off_outlined),
                                  onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
                                ),
                                IconButton(
                                  tooltip: 'Open Password Generator',
                                  icon: const Icon(Icons.auto_awesome, color: AppTheme.cyan),
                                  onPressed: _openGeneratorModal,
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        TextField(
                          controller: _totpSeedController,
                          decoration: InputDecoration(
                            labelText: 'Two-Factor Authenticator (TOTP Key / URI)',
                            hintText: 'Base32 secret or otpauth://totp/ URI',
                            prefixIcon: const Icon(Icons.timer_outlined, color: AppTheme.amber),
                            suffixIcon: _totpSeedController.text.isNotEmpty
                                ? IconButton(
                                    icon: const Icon(Icons.clear),
                                    onPressed: () => setState(() => _totpSeedController.clear()),
                                  )
                                : null,
                          ),
                          onChanged: (val) {
                            if (val.trim().toLowerCase().startsWith('otpauth://')) {
                              final config = VaultState.instance.parseTotpUri(val.trim());
                              if (config != null) {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(
                                    content: Text('Auto-parsed 2FA key for ${config.issuer ?? "account"} (${config.digits} digits, ${config.periodSeconds}s)'),
                                  ),
                                );
                              }
                            }
                          },
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // URLs Block
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text('URLs & Web Domains', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                            TextButton.icon(
                              onPressed: () => setState(() => _urlControllers.add(TextEditingController())),
                              icon: const Icon(Icons.add, size: 16),
                              label: const Text('Add URL'),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        for (int i = 0; i < _urlControllers.length; i++) ...[
                          Row(
                            children: [
                              Expanded(
                                child: TextField(
                                  controller: _urlControllers[i],
                                  decoration: InputDecoration(
                                    labelText: 'URL #${i + 1}',
                                    prefixIcon: const Icon(Icons.link_outlined),
                                    hintText: 'https://example.com/login',
                                  ),
                                ),
                              ),
                              if (_urlControllers.length > 1)
                                IconButton(
                                  icon: const Icon(Icons.remove_circle_outline, color: AppTheme.rose),
                                  onPressed: () {
                                    setState(() {
                                      _urlControllers[i].dispose();
                                      _urlControllers.removeAt(i);
                                    });
                                  },
                                ),
                            ],
                          ),
                          if (i < _urlControllers.length - 1) const SizedBox(height: 12),
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Notes Block
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('Encrypted Notes', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                        const SizedBox(height: 12),
                        TextField(
                          controller: _notesController,
                          maxLines: 5,
                          decoration: const InputDecoration(
                            hintText: 'Markdown or plain text notes (fully encrypted in vault)...',
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Custom Fields Block
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text('Custom Fields', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                            TextButton.icon(
                              onPressed: () {
                                setState(() {
                                  _customFields.add(CustomField(name: '', value: ''));
                                });
                              },
                              icon: const Icon(Icons.add, size: 16),
                              label: const Text('Add Field'),
                            ),
                          ],
                        ),
                        if (_customFields.isEmpty)
                          const Padding(
                            padding: EdgeInsets.symmetric(vertical: 8),
                            child: Text(
                              'No custom fields attached.',
                              style: TextStyle(color: AppTheme.darkTextSecondary, fontSize: 13),
                            ),
                          ),
                        for (int i = 0; i < _customFields.length; i++) ...[
                          Row(
                            children: [
                              Expanded(
                                flex: 2,
                                child: TextFormField(
                                  initialValue: _customFields[i].name,
                                  decoration: const InputDecoration(labelText: 'Field Name'),
                                  onChanged: (val) => _customFields[i].name = val,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                flex: 3,
                                child: TextFormField(
                                  initialValue: _customFields[i].value,
                                  decoration: const InputDecoration(labelText: 'Value'),
                                  onChanged: (val) => _customFields[i].value = val,
                                ),
                              ),
                              IconButton(
                                icon: const Icon(Icons.delete_outline, color: AppTheme.rose),
                                onPressed: () => setState(() => _customFields.removeAt(i)),
                              ),
                            ],
                          ),
                          if (i < _customFields.length - 1) const SizedBox(height: 12),
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 32),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
