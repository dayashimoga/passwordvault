import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../core/ffi/vault_ffi_bindings.dart';
import '../models/vault_models.dart';

/// Central state coordinator for vault lifecycle, search, items, and security timers.
class VaultState extends ChangeNotifier {
  static final VaultState instance = VaultState._internal();
  VaultState._internal() {
    try {
      final host = Platform.localHostname;
      final os = Platform.operatingSystem;
      _deviceId = 'dev-${os.toLowerCase()}-${host.hashCode.abs() % 100000}';
      _deviceName = '$os ($host)';
    } catch (_) {
      _deviceId = 'dev-client-1';
      _deviceName = 'Local Device';
    }
  }

  bool _isLocked = true;
  VaultPayload? _payload;
  String? _masterPassphrase;
  String _vaultFilePath = 'personal_vault.vault.v1';

  // Synchronization and multi-device logical clock state
  String _deviceId = 'dev-client-1';
  String _deviceName = 'Local Device';
  VectorClock _vectorClock = VectorClock();
  String? _syncKeyHex;

  // Navigation and filtering state
  ItemCategory? _selectedCategory;
  bool _favoritesOnly = false;
  bool _showTrash = false;
  String _searchQuery = '';
  VaultItem? _selectedItem;

  // Auto-lock settings
  int _autoLockSeconds = 300; // 5 minutes
  Timer? _inactivityTimer;

  bool get isLocked => _isLocked;
  VaultPayload? get payload => _payload;
  String get vaultFilePath => _vaultFilePath;
  ItemCategory? get selectedCategory => _selectedCategory;
  bool get favoritesOnly => _favoritesOnly;
  bool get showTrash => _showTrash;
  String get searchQuery => _searchQuery;
  VaultItem? get selectedItem => _selectedItem;
  int get autoLockSeconds => _autoLockSeconds;

  VectorClock get vectorClock => _vectorClock;
  String get deviceId => _deviceId;
  String get deviceName => _deviceName;
  String? get syncKeyHex => _syncKeyHex;

  int get totalActiveCount => _payload?.items.where((i) => !i.isTrashed).length ?? 0;
  int get trashCount => _payload?.items.where((i) => i.isTrashed).length ?? 0;
  int get favoritesCount => _payload?.items.where((i) => !i.isTrashed && i.favorite).length ?? 0;

  int countForCategory(ItemCategory cat) {
    return _payload?.items.where((i) => !i.isTrashed && i.category == cat).length ?? 0;
  }

  void setSelectedCategory(ItemCategory? cat) {
    _selectedCategory = cat;
    _favoritesOnly = false;
    _showTrash = false;
    _updateSelectionAfterFilter();
    resetInactivityTimer();
    notifyListeners();
  }

  void setFavoritesOnly(bool value) {
    _favoritesOnly = value;
    _selectedCategory = null;
    _showTrash = false;
    _updateSelectionAfterFilter();
    resetInactivityTimer();
    notifyListeners();
  }

  void setShowTrash(bool value) {
    _showTrash = value;
    _selectedCategory = null;
    _favoritesOnly = false;
    _updateSelectionAfterFilter();
    resetInactivityTimer();
    notifyListeners();
  }

  void setSearchQuery(String query) {
    _searchQuery = query;
    _updateSelectionAfterFilter();
    resetInactivityTimer();
    notifyListeners();
  }

  void selectItem(VaultItem? item) {
    _selectedItem = item;
    resetInactivityTimer();
    notifyListeners();
  }

  void setAutoLockSeconds(int seconds) {
    _autoLockSeconds = seconds;
    resetInactivityTimer();
    notifyListeners();
  }

  void resetInactivityTimer() {
    _inactivityTimer?.cancel();
    if (!_isLocked && _autoLockSeconds > 0) {
      _inactivityTimer = Timer(Duration(seconds: _autoLockSeconds), () {
        lock();
      });
    }
  }

  /// Creates a new encrypted vault.
  Future<void> createVault(String passphrase, String vaultName, {String? filePath}) async {
    final targetPath = filePath ?? _vaultFilePath;
    final ffi = RustVaultFfi.instance;

    final bytes = ffi.createVault(passphrase, vaultName);
    await File(targetPath).writeAsBytes(bytes, flush: true);

    _vaultFilePath = targetPath;
    _masterPassphrase = passphrase;
    _payload = ffi.unlockVault(bytes, passphrase);
    _isLocked = false;

    resetInactivityTimer();
    notifyListeners();
  }

  /// Unlocks an existing vault file.
  Future<void> unlockVault(String passphrase, {String? filePath}) async {
    final targetPath = filePath ?? _vaultFilePath;
    final file = File(targetPath);

    if (!await file.exists()) {
      throw FileSystemException('Vault file does not exist at $targetPath');
    }

    final bytes = await file.readAsBytes();
    final ffi = RustVaultFfi.instance;

    final payload = ffi.unlockVault(bytes, passphrase);
    _vaultFilePath = targetPath;
    _masterPassphrase = passphrase;
    _payload = payload;
    _isLocked = false;
    _updateSelectionAfterFilter();

    resetInactivityTimer();
    notifyListeners();
  }

  /// Locks the vault and sanitizes sensitive memory references.
  void lock() {
    _inactivityTimer?.cancel();
    _isLocked = true;
    _masterPassphrase = null;
    _payload = null;
    _selectedItem = null;
    notifyListeners();
  }

  /// Saves or creates an item, automatically writing through to encrypted storage.
  Future<void> saveItem(VaultItem item) async {
    if (_payload == null || _masterPassphrase == null) return;

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    item.updatedAt = now;

    final index = _payload!.items.indexWhere((i) => i.id == item.id);
    if (index >= 0) {
      // Snapshot previous revision before replacing
      final existing = _payload!.items[index];
      item.revisionHistory = List.from(existing.revisionHistory)
        ..add(ItemRevision(
          timestamp: existing.updatedAt,
          title: existing.title,
          username: existing.username,
          password: existing.password,
          urls: existing.urls,
          notes: existing.notes,
          customFields: existing.customFields,
        ));
      _payload!.items[index] = item;
    } else {
      item.createdAt = now;
      _payload!.items.add(item);
    }

    _selectedItem = item;
    await _commitVaultToDisk();
    resetInactivityTimer();
    notifyListeners();
  }

  /// Moves an item to the encrypted trash bin.
  Future<void> trashItem(String itemId) async {
    if (_payload == null) return;
    final item = _payload!.items.firstWhere((i) => i.id == itemId);
    item.trashedAt = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    _updateSelectionAfterFilter();
    await _commitVaultToDisk();
    notifyListeners();
  }

  /// Restores an item from the trash bin.
  Future<void> restoreItem(String itemId) async {
    if (_payload == null) return;
    final item = _payload!.items.firstWhere((i) => i.id == itemId);
    item.trashedAt = null;
    _updateSelectionAfterFilter();
    await _commitVaultToDisk();
    notifyListeners();
  }

  /// Permanently removes an item.
  Future<void> deletePermanently(String itemId) async {
    if (_payload == null) return;
    _payload!.items.removeWhere((i) => i.id == itemId);
    if (_selectedItem?.id == itemId) {
      _selectedItem = null;
    }
    _updateSelectionAfterFilter();
    await _commitVaultToDisk();
    notifyListeners();
  }

  /// Empties all items currently in trash.
  Future<void> emptyTrash() async {
    if (_payload == null) return;
    _payload!.items.removeWhere((i) => i.isTrashed);
    _selectedItem = null;
    await _commitVaultToDisk();
    notifyListeners();
  }

  /// Toggles favorite status.
  Future<void> toggleFavorite(String itemId) async {
    if (_payload == null) return;
    final item = _payload!.items.firstWhere((i) => i.id == itemId);
    item.favorite = !item.favorite;
    await _commitVaultToDisk();
    notifyListeners();
  }

  /// Re-encrypts payload using new master passphrase.
  Future<void> changeMasterPassphrase(String newPassphrase) async {
    if (_payload == null) return;
    _masterPassphrase = newPassphrase;
    await _commitVaultToDisk();
    notifyListeners();
  }

  /// Evaluates in-memory search and category filters.
  List<VaultItem> getFilteredItems() {
    if (_payload == null) return [];

    if (_showTrash) {
      final trashed = _payload!.items.where((i) => i.isTrashed).toList();
      if (_searchQuery.isEmpty) return trashed;
      final q = _searchQuery.toLowerCase();
      return trashed
          .where((i) =>
              i.title.toLowerCase().contains(q) ||
              (i.username?.toLowerCase().contains(q) ?? false))
          .toList();
    }

    final ffi = RustVaultFfi.instance;
    return ffi.search(
      _payload!,
      _searchQuery,
      category: _selectedCategory,
      favoritesOnly: _favoritesOnly,
    );
  }

  /// Copies secret to clipboard and schedules automatic memory clearing after 30 seconds.
  Future<void> copySecret(BuildContext context, String text, String label) async {
    await Clipboard.setData(ClipboardData(text: text));
    resetInactivityTimer();

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              const Icon(Icons.check_circle_outline, color: Colors.greenAccent, size: 20),
              const SizedBox(width: 10),
              Text('$label copied to clipboard. Auto-clearing in 30s.'),
            ],
          ),
          duration: const Duration(seconds: 4),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }

    Timer(const Duration(seconds: 30), () async {
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == text) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }

  /// Copies text to clipboard and schedules 30-second sanitization timer.
  Future<void> copyToClipboard(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
    resetInactivityTimer();
    Timer(const Duration(seconds: 30), () async {
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == text) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }

  /// Replaces the current vault payload (used by restore and import commit) and writes through to disk.
  Future<void> replacePayload(VaultPayload newPayload) async {
    _payload = newPayload;
    _updateSelectionAfterFilter();
    await _commitVaultToDisk();
    resetInactivityTimer();
    notifyListeners();
  }

  void _updateSelectionAfterFilter() {
    final filtered = getFilteredItems();
    if (_selectedItem != null && !filtered.any((i) => i.id == _selectedItem!.id)) {
      _selectedItem = filtered.isNotEmpty ? filtered.first : null;
    } else if (_selectedItem == null && filtered.isNotEmpty) {
      _selectedItem = filtered.first;
    }
  }

  Future<void> _commitVaultToDisk() async {
    if (_payload == null || _masterPassphrase == null) return;
    final ffi = RustVaultFfi.instance;
    final bytes = ffi.saveVault(_masterPassphrase!, _payload!);

    // Atomic write pattern via temp file and rename
    final tempPath = '$_vaultFilePath.tmp';
    await File(tempPath).writeAsBytes(bytes, flush: true);
    await File(tempPath).rename(_vaultFilePath);
  }

  void setDeviceIdentity({String? id, String? name}) {
    if (id != null) _deviceId = id;
    if (name != null) _deviceName = name;
    notifyListeners();
  }

  void setSyncKeyHex(String key) {
    _syncKeyHex = key;
    notifyListeners();
  }

  void updateVectorClock(VectorClock clock) {
    _vectorClock = clock;
    notifyListeners();
  }

  /// Exports an encrypted .syncpack container for offline or LAN synchronization.
  Uint8List exportSyncPack({required String syncKeyHex}) {
    if (_payload == null) {
      throw StateError('Cannot export syncpack from locked vault');
    }
    // Increment local tick
    final clocks = Map<String, int>.from(_vectorClock.clocks);
    clocks[_deviceId] = (clocks[_deviceId] ?? 0) + 1;
    _vectorClock = VectorClock(clocks: clocks);

    final ffi = RustVaultFfi.instance;
    return ffi.createSyncPack(
      payload: _payload!,
      syncKeyHex: syncKeyHex,
      deviceId: _deviceId,
      deviceName: _deviceName,
      clock: _vectorClock,
    );
  }

  /// Ingests and CRDT-merges an encrypted .syncpack container into the local vault.
  Future<SyncApplyResult> ingestSyncPack({
    required Uint8List packBytes,
    required String syncKeyHex,
  }) async {
    if (_payload == null) {
      throw StateError('Cannot apply syncpack into locked vault');
    }
    final ffi = RustVaultFfi.instance;
    final result = ffi.applySyncPack(
      localPayload: _payload!,
      packBytes: packBytes,
      syncKeyHex: syncKeyHex,
      localClock: _vectorClock,
    );

    _vectorClock = result.mergedClock;
    await replacePayload(result.mergedPayload);
    return result;
  }

  VaultAuditReportModel? _auditReport;
  VaultAuditReportModel? get auditReport => _auditReport;

  /// Runs the full local cryptographic and security hygiene audit on the unlocked vault.
  VaultAuditReportModel runSecurityAudit() {
    if (_payload == null) {
      throw StateError('Cannot audit locked vault');
    }
    final report = RustVaultFfi.instance.auditVault(_payload!);
    _auditReport = report;
    notifyListeners();
    return report;
  }

  /// Checks whether a password has appeared in known data breaches using privacy-preserving k-Anonymity.
  /// Invariant: Only the 5-character SHA-1 prefix leaves the client over HTTPS.
  Future<int> checkPasswordBreach(String password) async {
    final ffi = RustVaultFfi.instance;
    final query = ffi.prepareBreachQuery(password);

    try {
      final client = HttpClient();
      client.userAgent = 'RustPwdVault-BreachWatch/1.0';
      final uri = Uri.parse('https://api.pwnedpasswords.com/range/${query.prefix}');
      final request = await client.getUrl(uri).timeout(const Duration(seconds: 4));
      final response = await request.close().timeout(const Duration(seconds: 4));
      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        client.close();
        return ffi.checkBreachResponse(suffix: query.suffix, responseBody: body);
      }
      client.close();
    } catch (_) {
      // Offline fallback: graceful zero return
    }
    return 0;
  }

  /// Generates the current TOTP code and remaining seconds in period.
  TotpGeneratedCode? generateTotpCode(
    String secretBase32, {
    int digits = 6,
    int period = 30,
    String algorithm = 'SHA1',
  }) {
    try {
      return RustVaultFfi.instance.generateTotp(
        secretBase32: secretBase32,
        digits: digits,
        period: period,
        algorithm: algorithm,
      );
    } catch (_) {
      return null;
    }
  }

  /// Parses an `otpauth://totp/` URI and returns the config model.
  TotpConfigModel? parseTotpUri(String uri) {
    try {
      return RustVaultFfi.instance.parseTotpUri(uri);
    } catch (_) {
      return null;
    }
  }
}

