import 'package:flutter/material.dart';
import '../core/theme/app_theme.dart';
import '../models/vault_models.dart';
import '../services/vault_state.dart';
import 'generator/generator_view.dart';
import 'items/item_detail_view.dart';
import 'items/item_editor_view.dart';
import 'settings/settings_view.dart';

/// Responsive shell coordinating Desktop (3-column) and Mobile layouts.
class VaultShell extends StatefulWidget {
  const VaultShell({super.key});

  @override
  State<VaultShell> createState() => _VaultShellState();
}

class _VaultShellState extends State<VaultShell> {
  int _mobileTabIndex = 0;
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: VaultState.instance,
      builder: (context, _) {
        final state = VaultState.instance;
        final screenWidth = MediaQuery.of(context).size.width;
        final isDesktop = screenWidth >= 900;

        if (isDesktop) {
          return _buildDesktopLayout(context, state);
        } else {
          return _buildMobileLayout(context, state);
        }
      },
    );
  }

  Widget _buildDesktopLayout(BuildContext context, VaultState state) {
    final theme = Theme.of(context);
    final items = state.getFilteredItems();

    return Scaffold(
      body: Row(
        children: [
          // 1. Left Sidebar (Navigation & Categories)
          Container(
            width: 260,
            decoration: BoxDecoration(
              color: AppTheme.darkSurface,
              border: Border(right: BorderSide(color: theme.dividerColor)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Vault Logo Header
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppTheme.cyan.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(Icons.shield_outlined, color: AppTheme.cyan, size: 20),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              state.payload?.vaultName ?? 'Personal Vault',
                              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                              overflow: TextOverflow.ellipsis,
                            ),
                            const Text(
                              'Argon2id Encrypted',
                              style: TextStyle(color: AppTheme.emerald, fontSize: 11),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                const Divider(),

                // Navigation list
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    children: [
                      _buildNavTile(
                        icon: Icons.list_alt_outlined,
                        title: 'All Items',
                        count: state.totalActiveCount,
                        isSelected: state.selectedCategory == null && !state.favoritesOnly && !state.showTrash,
                        onTap: () => state.setSelectedCategory(null),
                      ),
                      _buildNavTile(
                        icon: Icons.star_border,
                        title: 'Favorites',
                        count: state.favoritesCount,
                        isSelected: state.favoritesOnly,
                        onTap: () => state.setFavoritesOnly(true),
                      ),
                      const SizedBox(height: 12),
                      const Padding(
                        padding: EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                        child: Text(
                          'CATEGORIES',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            letterSpacing: 1.0,
                            color: AppTheme.darkTextSecondary,
                          ),
                        ),
                      ),
                      for (final cat in ItemCategory.values)
                        _buildNavTile(
                          icon: _categoryIcon(cat),
                          title: cat.displayName,
                          count: state.countForCategory(cat),
                          isSelected: state.selectedCategory == cat,
                          onTap: () => state.setSelectedCategory(cat),
                        ),
                      const SizedBox(height: 12),
                      _buildNavTile(
                        icon: Icons.delete_outline,
                        title: 'Trash',
                        count: state.trashCount,
                        isSelected: state.showTrash,
                        onTap: () => state.setShowTrash(true),
                      ),
                    ],
                  ),
                ),
                const Divider(),

                // Bottom Sidebar Actions
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    children: [
                      OutlinedButton.icon(
                        style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(40)),
                        icon: const Icon(Icons.auto_awesome, size: 16, color: AppTheme.cyan),
                        label: const Text('Password Generator'),
                        onPressed: () {
                          showDialog(
                            context: context,
                            builder: (ctx) => Dialog(
                              child: ConstrainedBox(
                                constraints: const BoxConstraints(maxWidth: 680, maxHeight: 720),
                                child: const GeneratorView(),
                              ),
                            ),
                          );
                        },
                      ),
                      const SizedBox(height: 8),
                      Row(
                        children: [
                          Expanded(
                            child: IconButton(
                              tooltip: 'Settings',
                              icon: const Icon(Icons.settings_outlined),
                              onPressed: () {
                                Navigator.of(context).push(
                                  MaterialPageRoute(builder: (ctx) => const SettingsView()),
                                );
                              },
                            ),
                          ),
                          Expanded(
                            child: IconButton(
                              tooltip: 'Lock Vault',
                              icon: const Icon(Icons.lock_outline, color: AppTheme.rose),
                              onPressed: () => state.lock(),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          // 2. Middle Column (Search & Item List)
          Container(
            width: 340,
            decoration: BoxDecoration(
              color: AppTheme.darkBg,
              border: Border(right: BorderSide(color: theme.dividerColor)),
            ),
            child: Column(
              children: [
                // Search bar & Add Button
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _searchController,
                          decoration: InputDecoration(
                            isDense: true,
                            hintText: 'Search vault...',
                            prefixIcon: const Icon(Icons.search, size: 20),
                            suffixIcon: _searchController.text.isNotEmpty
                                ? IconButton(
                                    icon: const Icon(Icons.clear, size: 16),
                                    onPressed: () {
                                      _searchController.clear();
                                      state.setSearchQuery('');
                                    },
                                  )
                                : null,
                          ),
                          onChanged: (val) => state.setSearchQuery(val),
                        ),
                      ),
                      const SizedBox(width: 8),
                      IconButton.filled(
                        style: IconButton.styleFrom(backgroundColor: AppTheme.cyan, foregroundColor: Colors.black),
                        tooltip: 'New Item',
                        icon: const Icon(Icons.add),
                        onPressed: () {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (ctx) => ItemEditorView(
                                initialCategory: state.selectedCategory ?? ItemCategory.login,
                              ),
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ),
                const Divider(),

                // Item List
                Expanded(
                  child: items.isEmpty
                      ? Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.folder_open_outlined, size: 40, color: AppTheme.darkTextSecondary),
                              const SizedBox(height: 12),
                              Text(
                                state.showTrash ? 'Trash is empty' : 'No items found',
                                style: const TextStyle(color: AppTheme.darkTextSecondary),
                              ),
                            ],
                          ),
                        )
                      : ListView.builder(
                          itemCount: items.length,
                          itemBuilder: (ctx, idx) {
                            final item = items[idx];
                            final isSelected = state.selectedItem?.id == item.id;

                            return Container(
                              margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                              decoration: BoxDecoration(
                                color: isSelected ? AppTheme.cyan.withValues(alpha: 0.12) : Colors.transparent,
                                borderRadius: BorderRadius.circular(8),
                                border: isSelected ? Border.all(color: AppTheme.cyan.withValues(alpha: 0.4)) : null,
                              ),
                              child: ListTile(
                                dense: true,
                                leading: Icon(_categoryIcon(item.category), color: isSelected ? AppTheme.cyan : AppTheme.darkTextSecondary),
                                title: Text(
                                  item.title,
                                  style: TextStyle(
                                    fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                                    color: isSelected ? AppTheme.cyan : null,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                                subtitle: Text(
                                  item.username ?? (item.urls.isNotEmpty ? item.urls.first : item.category.displayName),
                                  style: const TextStyle(fontSize: 12, color: AppTheme.darkTextSecondary),
                                  overflow: TextOverflow.ellipsis,
                                ),
                                trailing: item.favorite ? const Icon(Icons.star, size: 16, color: AppTheme.amber) : null,
                                onTap: () => state.selectItem(item),
                              ),
                            );
                          },
                        ),
                ),
              ],
            ),
          ),

          // 3. Right Column (Item Detail Pane)
          Expanded(
            child: state.selectedItem != null
                ? ItemDetailView(item: state.selectedItem!)
                : const Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.shield_outlined, size: 64, color: AppTheme.darkBorder),
                        SizedBox(height: 16),
                        Text('Select an item to view credentials', style: TextStyle(color: AppTheme.darkTextSecondary)),
                      ],
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildMobileLayout(BuildContext context, VaultState state) {
    if (_mobileTabIndex == 1) {
      return const GeneratorView();
    } else if (_mobileTabIndex == 2) {
      return const SettingsView();
    }

    final items = state.getFilteredItems();

    return Scaffold(
      appBar: AppBar(
        title: Text(state.payload?.vaultName ?? 'Personal Vault'),
        actions: [
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (ctx) => ItemEditorView(
                    initialCategory: state.selectedCategory ?? ItemCategory.login,
                  ),
                ),
              );
            },
          ),
          IconButton(
            icon: const Icon(Icons.lock_outline, color: AppTheme.rose),
            onPressed: () => state.lock(),
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(56),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                isDense: true,
                hintText: 'Search vault...',
                prefixIcon: const Icon(Icons.search, size: 20),
                suffixIcon: _searchController.text.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear, size: 16),
                        onPressed: () {
                          _searchController.clear();
                          state.setSearchQuery('');
                        },
                      )
                    : null,
              ),
              onChanged: (val) => state.setSearchQuery(val),
            ),
          ),
        ),
      ),
      body: items.isEmpty
          ? const Center(child: Text('No items in vault', style: TextStyle(color: AppTheme.darkTextSecondary)))
          : ListView.builder(
              itemCount: items.length,
              itemBuilder: (ctx, idx) {
                final item = items[idx];
                return ListTile(
                  leading: Icon(_categoryIcon(item.category), color: AppTheme.cyan),
                  title: Text(item.title, style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text(item.username ?? item.category.displayName),
                  trailing: item.favorite ? const Icon(Icons.star, size: 16, color: AppTheme.amber) : null,
                  onTap: () {
                    Navigator.of(context).push(
                      MaterialPageRoute(builder: (ctx) => ItemDetailView(item: item)),
                    );
                  },
                );
              },
            ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _mobileTabIndex,
        onDestinationSelected: (idx) => setState(() => _mobileTabIndex = idx),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.shield_outlined), label: 'Vault'),
          NavigationDestination(icon: Icon(Icons.auto_awesome_outlined), label: 'Generator'),
          NavigationDestination(icon: Icon(Icons.settings_outlined), label: 'Settings'),
        ],
      ),
    );
  }

  Widget _buildNavTile({
    required IconData icon,
    required String title,
    required int count,
    required bool isSelected,
    required VoidCallback onTap,
  }) {
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2),
      decoration: BoxDecoration(
        color: isSelected ? AppTheme.cyan.withValues(alpha: 0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: ListTile(
        dense: true,
        leading: Icon(icon, size: 18, color: isSelected ? AppTheme.cyan : AppTheme.darkTextSecondary),
        title: Text(
          title,
          style: TextStyle(
            fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
            color: isSelected ? AppTheme.cyan : null,
            fontSize: 13,
          ),
        ),
        trailing: count > 0
            ? Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: isSelected ? AppTheme.cyan : AppTheme.darkSurfaceSubtle,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '$count',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    color: isSelected ? Colors.black : AppTheme.darkTextSecondary,
                  ),
                ),
              )
            : null,
        onTap: onTap,
      ),
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
}
