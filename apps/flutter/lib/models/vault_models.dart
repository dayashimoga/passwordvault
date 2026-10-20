import 'dart:convert';

/// Supported item categories.
enum ItemCategory {
  login,
  secureNote,
  paymentCard,
  identity,
  recoveryCode;

  String get displayName {
    switch (this) {
      case ItemCategory.login:
        return 'Logins';
      case ItemCategory.secureNote:
        return 'Secure Notes';
      case ItemCategory.paymentCard:
        return 'Cards';
      case ItemCategory.identity:
        return 'Identities';
      case ItemCategory.recoveryCode:
        return 'Recovery Codes';
    }
  }

  static ItemCategory fromJson(String json) {
    switch (json.toLowerCase()) {
      case 'login':
        return ItemCategory.login;
      case 'securenote':
        return ItemCategory.secureNote;
      case 'paymentcard':
        return ItemCategory.paymentCard;
      case 'identity':
        return ItemCategory.identity;
      case 'recoverycode':
        return ItemCategory.recoveryCode;
      default:
        return ItemCategory.login;
    }
  }

  String toJson() {
    switch (this) {
      case ItemCategory.login:
        return 'Login';
      case ItemCategory.secureNote:
        return 'SecureNote';
      case ItemCategory.paymentCard:
        return 'PaymentCard';
      case ItemCategory.identity:
        return 'Identity';
      case ItemCategory.recoveryCode:
        return 'RecoveryCode';
    }
  }
}

/// Field data types for custom fields.
enum FieldType {
  text,
  concealed,
  boolean,
  date;

  static FieldType fromJson(String json) {
    switch (json.toLowerCase()) {
      case 'text':
        return FieldType.text;
      case 'concealed':
        return FieldType.concealed;
      case 'boolean':
        return FieldType.boolean;
      case 'date':
        return FieldType.date;
      default:
        return FieldType.text;
    }
  }

  String toJson() {
    switch (this) {
      case FieldType.text:
        return 'Text';
      case FieldType.concealed:
        return 'Concealed';
      case FieldType.boolean:
        return 'Boolean';
      case FieldType.date:
        return 'Date';
    }
  }
}

/// Generic custom key-value field.
class CustomField {
  String name;
  String value;
  FieldType fieldType;

  CustomField({
    required this.name,
    required this.value,
    this.fieldType = FieldType.text,
  });

  factory CustomField.fromJson(Map<String, dynamic> json) {
    return CustomField(
      name: json['name'] as String? ?? '',
      value: json['value'] as String? ?? '',
      fieldType: FieldType.fromJson(json['field_type'] as String? ?? 'Text'),
    );
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'value': value,
        'field_type': fieldType.toJson(),
      };
}

/// Encrypted snapshot of an item's prior revision.
class ItemRevision {
  final int timestamp;
  final String title;
  final String? username;
  final String? password;
  final List<String> urls;
  final String? notes;
  final List<CustomField> customFields;

  ItemRevision({
    required this.timestamp,
    required this.title,
    this.username,
    this.password,
    this.urls = const [],
    this.notes,
    this.customFields = const [],
  });

  factory ItemRevision.fromJson(Map<String, dynamic> json) {
    return ItemRevision(
      timestamp: json['timestamp'] as int? ?? 0,
      title: json['title'] as String? ?? '',
      username: json['username'] as String?,
      password: json['password'] as String?,
      urls: (json['urls'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      notes: json['notes'] as String?,
      customFields: (json['custom_fields'] as List<dynamic>?)
              ?.map((e) => CustomField.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
    );
  }

  Map<String, dynamic> toJson() => {
        'timestamp': timestamp,
        'title': title,
        'username': username,
        'password': password,
        'urls': urls,
        'notes': notes,
        'custom_fields': customFields.map((e) => e.toJson()).toList(),
      };
}

/// Strongly-typed vault record entry.
class VaultItem {
  String id;
  String title;
  ItemCategory category;
  String? username;
  String? password;
  List<String> urls;
  String? notes;
  String? totpSeed;
  List<String> tags;
  bool favorite;
  List<CustomField> customFields;
  List<ItemRevision> revisionHistory;
  int? trashedAt;
  int createdAt;
  int updatedAt;

  VaultItem({
    required this.id,
    required this.title,
    this.category = ItemCategory.login,
    this.username,
    this.password,
    this.urls = const [],
    this.notes,
    this.totpSeed,
    this.tags = const [],
    this.favorite = false,
    this.customFields = const [],
    this.revisionHistory = const [],
    this.trashedAt,
    required this.createdAt,
    required this.updatedAt,
  });

  bool get isTrashed => trashedAt != null;

  factory VaultItem.fromJson(Map<String, dynamic> json) {
    return VaultItem(
      id: json['id'] as String? ?? '',
      title: json['title'] as String? ?? 'Untitled',
      category: ItemCategory.fromJson(json['category'] as String? ?? 'Login'),
      username: json['username'] as String?,
      password: json['password'] as String?,
      urls: (json['urls'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      notes: json['notes'] as String?,
      totpSeed: json['totp_seed'] as String?,
      tags: (json['tags'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      favorite: json['favorite'] as bool? ?? false,
      customFields: (json['custom_fields'] as List<dynamic>?)
              ?.map((e) => CustomField.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
      revisionHistory: (json['revision_history'] as List<dynamic>?)
              ?.map((e) => ItemRevision.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
      trashedAt: json['trashed_at'] as int?,
      createdAt: json['created_at'] as int? ?? 0,
      updatedAt: json['updated_at'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'category': category.toJson(),
        'username': username,
        'password': password,
        'urls': urls,
        'notes': notes,
        'totp_seed': totpSeed,
        'tags': tags,
        'favorite': favorite,
        'custom_fields': customFields.map((e) => e.toJson()).toList(),
        'attachments': [],
        'revision_history': revisionHistory.map((e) => e.toJson()).toList(),
        'trashed_at': trashedAt,
        'created_at': createdAt,
        'updated_at': updatedAt,
      };
}

/// Root decrypted payload representing the full in-memory vault database.
class VaultPayload {
  int schemaVersion;
  String vaultName;
  List<VaultItem> items;
  int createdAt;
  int updatedAt;

  VaultPayload({
    this.schemaVersion = 1,
    required this.vaultName,
    this.items = const [],
    required this.createdAt,
    required this.updatedAt,
  });

  factory VaultPayload.fromJson(Map<String, dynamic> json) {
    return VaultPayload(
      schemaVersion: json['schema_version'] as int? ?? 1,
      vaultName: json['vault_name'] as String? ?? 'Personal Vault',
      items: (json['items'] as List<dynamic>?)
              ?.map((e) => VaultItem.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
      createdAt: json['created_at'] as int? ?? 0,
      updatedAt: json['updated_at'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'schema_version': schemaVersion,
        'vault_name': vaultName,
        'items': items.map((e) => e.toJson()).toList(),
        'created_at': createdAt,
        'updated_at': updatedAt,
      };

  String serialize() => jsonEncode(toJson());
}

/// Crack time estimate result.
class CrackTimeEstimate {
  final int entropyBits;
  final String rating;
  final String onlineTime;
  final String offlineGpuTime;
  final String clusterTime;

  CrackTimeEstimate({
    required this.entropyBits,
    required this.rating,
    required this.onlineTime,
    required this.offlineGpuTime,
    required this.clusterTime,
  });

  factory CrackTimeEstimate.fromJson(Map<String, dynamic> json) {
    return CrackTimeEstimate(
      entropyBits: json['entropy_bits'] as int? ?? 0,
      rating: json['rating'] as String? ?? 'Weak',
      onlineTime: json['online_time'] as String? ?? '',
      offlineGpuTime: json['offline_gpu_time'] as String? ?? '',
      clusterTime: json['cluster_time'] as String? ?? '',
    );
  }
}

/// Dry-run verification outcome of an encrypted backup restoration rehearsal.
class BackupRehearsalReport {
  final bool isValid;
  final String vaultName;
  final int itemCount;
  final int trashedCount;
  final Map<String, int> categoryCounts;
  final int backupCreatedAt;
  final String? errorMessage;

  BackupRehearsalReport({
    required this.isValid,
    required this.vaultName,
    required this.itemCount,
    required this.trashedCount,
    required this.categoryCounts,
    required this.backupCreatedAt,
    this.errorMessage,
  });

  factory BackupRehearsalReport.fromJson(Map<String, dynamic> json) {
    final catMap = <String, int>{};
    if (json['category_counts'] is Map) {
      (json['category_counts'] as Map).forEach((k, v) {
        catMap[k.toString()] = (v as num).toInt();
      });
    }

    return BackupRehearsalReport(
      isValid: json['is_valid'] as bool? ?? false,
      vaultName: json['vault_name'] as String? ?? '',
      itemCount: (json['item_count'] as num?)?.toInt() ?? 0,
      trashedCount: (json['trashed_count'] as num?)?.toInt() ?? 0,
      categoryCounts: catMap,
      backupCreatedAt: (json['backup_created_at'] as num?)?.toInt() ?? 0,
      errorMessage: json['error_message'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'is_valid': isValid,
        'vault_name': vaultName,
        'item_count': itemCount,
        'trashed_count': trashedCount,
        'category_counts': categoryCounts,
        'backup_created_at': backupCreatedAt,
        'error_message': errorMessage,
      };
}

/// Offline Emergency Recovery Kit printable payload.
class RecoveryKitDocument {
  final String vaultName;
  final int createdAt;
  final String formattedKey;
  final String storageInstructions;

  RecoveryKitDocument({
    required this.vaultName,
    required this.createdAt,
    required this.formattedKey,
    required this.storageInstructions,
  });

  factory RecoveryKitDocument.fromJson(Map<String, dynamic> json) {
    return RecoveryKitDocument(
      vaultName: json['vault_name'] as String? ?? '',
      createdAt: (json['created_at'] as num?)?.toInt() ?? 0,
      formattedKey: json['formatted_key'] as String? ?? '',
      storageInstructions: json['storage_instructions'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
        'vault_name': vaultName,
        'created_at': createdAt,
        'formatted_key': formattedKey,
        'storage_instructions': storageInstructions,
      };

  String renderMarkdown() {
    return '# PWDVAULT EMERGENCY RECOVERY KIT\n\n'
        '> **CRITICAL SECURITY NOTICE**: This recovery key grants administrative access to decrypt your vault without your master passphrase. Keep it strictly offline.\n\n'
        '- **Vault Name**: $vaultName\n'
        '- **Created At**: ${DateTime.fromMillisecondsSinceEpoch(createdAt * 1000).toUtc().toIso8601String()}\n'
        '- **Format**: Crockford Base32 (256-bit entropy)\n\n'
        '## YOUR RECOVERY KEY\n\n'
        '```\n$formattedKey\n```\n\n'
        '## Storage Guidelines\n$storageInstructions\n\n'
        '## How to Restore\n'
        '1. Open PwdVault on your device.\n'
        '2. Select \'Restore from Backup\' or \'Emergency Unlock\'.\n'
        '3. Choose your encrypted `.vault.v1` or `.vaultbak` archive.\n'
        '4. Enter the recovery key shown above exactly as formatted.\n'
        '5. Set a new master passphrase and generate a fresh recovery kit immediately.\n';
  }
}

/// Deduplication classification for imported items.
enum CandidateStatus {
  newCandidate,
  exactDuplicate,
  conflict;

  static CandidateStatus fromJson(String val) {
    switch (val.toLowerCase()) {
      case 'new':
        return CandidateStatus.newCandidate;
      case 'exactduplicate':
        return CandidateStatus.exactDuplicate;
      case 'conflict':
        return CandidateStatus.conflict;
      default:
        return CandidateStatus.newCandidate;
    }
  }

  String toJson() {
    switch (this) {
      case CandidateStatus.newCandidate:
        return 'New';
      case CandidateStatus.exactDuplicate:
        return 'ExactDuplicate';
      case CandidateStatus.conflict:
        return 'Conflict';
    }
  }
}

/// Strategy for resolving incoming import candidates.
enum ResolutionStrategy {
  skip,
  overwrite,
  keepBoth;

  static ResolutionStrategy fromJson(String val) {
    switch (val.toLowerCase()) {
      case 'skip':
        return ResolutionStrategy.skip;
      case 'overwrite':
        return ResolutionStrategy.overwrite;
      case 'keepboth':
        return ResolutionStrategy.keepBoth;
      default:
        return ResolutionStrategy.keepBoth;
    }
  }

  String toJson() {
    switch (this) {
      case ResolutionStrategy.skip:
        return 'Skip';
      case ResolutionStrategy.overwrite:
        return 'Overwrite';
      case ResolutionStrategy.keepBoth:
        return 'KeepBoth';
    }
  }
}

/// Diff inspection for conflicting items during import.
class ConflictDiff {
  final String? currentPassword;
  final String? incomingPassword;
  final String? currentNotes;
  final String? incomingNotes;

  ConflictDiff({
    this.currentPassword,
    this.incomingPassword,
    this.currentNotes,
    this.incomingNotes,
  });

  factory ConflictDiff.fromJson(Map<String, dynamic> json) {
    return ConflictDiff(
      currentPassword: json['current_password'] as String?,
      incomingPassword: json['incoming_password'] as String?,
      currentNotes: json['current_notes'] as String?,
      incomingNotes: json['incoming_notes'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'current_password': currentPassword,
        'incoming_password': incomingPassword,
        'current_notes': currentNotes,
        'incoming_notes': incomingNotes,
      };
}

/// Single import candidate entry.
class ImportCandidate {
  final int index;
  final CandidateStatus status;
  final VaultItem item;
  final String? existingItemId;
  final String? existingItemTitle;
  final ConflictDiff? diff;
  ResolutionStrategy selectedStrategy;

  ImportCandidate({
    required this.index,
    required this.status,
    required this.item,
    this.existingItemId,
    this.existingItemTitle,
    this.diff,
    this.selectedStrategy = ResolutionStrategy.keepBoth,
  });

  factory ImportCandidate.fromJson(Map<String, dynamic> json) {
    return ImportCandidate(
      index: (json['index'] as num?)?.toInt() ?? 0,
      status: CandidateStatus.fromJson(json['status'] as String? ?? 'New'),
      item: VaultItem.fromJson(json['item'] as Map<String, dynamic>),
      existingItemId: json['existing_item_id'] as String?,
      existingItemTitle: json['existing_item_title'] as String?,
      diff: json['diff'] != null ? ConflictDiff.fromJson(json['diff'] as Map<String, dynamic>) : null,
      selectedStrategy: ResolutionStrategy.fromJson(json['selected_strategy'] as String? ?? 'KeepBoth'),
    );
  }

  Map<String, dynamic> toJson() => {
        'index': index,
        'status': status.toJson(),
        'item': item.toJson(),
        'existing_item_id': existingItemId,
        'existing_item_title': existingItemTitle,
        'diff': diff?.toJson(),
        'selected_strategy': selectedStrategy.toJson(),
      };
}

/// Complete preview report generated prior to executing an import.
class ImportPreview {
  final int totalIncoming;
  final int newCount;
  final int duplicateCount;
  final int conflictCount;
  final List<ImportCandidate> candidates;

  ImportPreview({
    required this.totalIncoming,
    required this.newCount,
    required this.duplicateCount,
    required this.conflictCount,
    required this.candidates,
  });

  factory ImportPreview.fromJson(Map<String, dynamic> json) {
    return ImportPreview(
      totalIncoming: (json['total_incoming'] as num?)?.toInt() ?? 0,
      newCount: (json['new_count'] as num?)?.toInt() ?? 0,
      duplicateCount: (json['duplicate_count'] as num?)?.toInt() ?? 0,
      conflictCount: (json['conflict_count'] as num?)?.toInt() ?? 0,
      candidates: (json['candidates'] as List<dynamic>?)
              ?.map((e) => ImportCandidate.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
    );
  }

  Map<String, dynamic> toJson() => {
        'total_incoming': totalIncoming,
        'new_count': newCount,
        'duplicate_count': duplicateCount,
        'conflict_count': conflictCount,
        'candidates': candidates.map((e) => e.toJson()).toList(),
      };
}

/// Monotonic vector clock for multi-device logical causality.
class VectorClock {
  final Map<String, int> clocks;

  VectorClock({Map<String, int>? clocks}) : clocks = clocks ?? {};

  factory VectorClock.fromJson(Map<String, dynamic> json) {
    final map = <String, int>{};
    final rawClocks = json['clocks'] as Map<String, dynamic>? ?? json;
    rawClocks.forEach((k, v) {
      if (v is num) map[k] = v.toInt();
    });
    return VectorClock(clocks: map);
  }

  Map<String, dynamic> toJson() => {
        'clocks': clocks,
      };
}

/// Statistical report of operations executed during a CRDT vault merge.
class SyncMergeReport {
  final int added;
  final int updated;
  final int conflictsPreserved;
  final int tombstonesApplied;

  SyncMergeReport({
    required this.added,
    required this.updated,
    required this.conflictsPreserved,
    required this.tombstonesApplied,
  });

  factory SyncMergeReport.fromJson(Map<String, dynamic> json) {
    return SyncMergeReport(
      added: (json['added'] as num?)?.toInt() ?? 0,
      updated: (json['updated'] as num?)?.toInt() ?? 0,
      conflictsPreserved: (json['conflicts_preserved'] as num?)?.toInt() ?? 0,
      tombstonesApplied: (json['tombstones_applied'] as num?)?.toInt() ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'added': added,
        'updated': updated,
        'conflicts_preserved': conflictsPreserved,
        'tombstones_applied': tombstonesApplied,
      };
}

/// Result returned from applying a syncpack.
class SyncApplyResult {
  final SyncMergeReport report;
  final VaultPayload mergedPayload;
  final VectorClock mergedClock;

  SyncApplyResult({
    required this.report,
    required this.mergedPayload,
    required this.mergedClock,
  });

  factory SyncApplyResult.fromJson(Map<String, dynamic> json) {
    return SyncApplyResult(
      report: SyncMergeReport.fromJson(json['report'] as Map<String, dynamic>),
      mergedPayload: VaultPayload.fromJson(json['merged_payload'] as Map<String, dynamic>),
      mergedClock: VectorClock.fromJson(json['merged_clock'] as Map<String, dynamic>),
    );
  }
}

/// Result returned from directly merging two vault payloads with CRDT resolution.
class SyncMergePayloadsResult {
  final SyncMergeReport report;
  final VaultPayload mergedPayload;

  SyncMergePayloadsResult({
    required this.report,
    required this.mergedPayload,
  });

  factory SyncMergePayloadsResult.fromJson(Map<String, dynamic> json) {
    return SyncMergePayloadsResult(
      report: SyncMergeReport.fromJson(json['report'] as Map<String, dynamic>),
      mergedPayload: VaultPayload.fromJson(json['merged_payload'] as Map<String, dynamic>),
    );
  }

  Map<String, dynamic> toJson() => {
        'report': report.toJson(),
        'merged_payload': mergedPayload.toJson(),
      };
}


/// Authenticated pairing payload encoded within out-of-band QR code.
class PairingPayload {
  final String deviceId;
  final String deviceName;
  final String syncKeyFingerprint;
  final String challengeNonce;
  final List<String> addresses;
  final int createdAt;
  final int expiresAt;

  PairingPayload({
    required this.deviceId,
    required this.deviceName,
    required this.syncKeyFingerprint,
    required this.challengeNonce,
    required this.addresses,
    required this.createdAt,
    required this.expiresAt,
  });

  factory PairingPayload.fromJson(Map<String, dynamic> json) {
    return PairingPayload(
      deviceId: json['device_id'] as String? ?? '',
      deviceName: json['device_name'] as String? ?? '',
      syncKeyFingerprint: json['sync_key_fingerprint'] as String? ?? '',
      challengeNonce: json['challenge_nonce'] as String? ?? '',
      addresses: (json['addresses'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      createdAt: (json['created_at'] as num?)?.toInt() ?? 0,
      expiresAt: (json['expires_at'] as num?)?.toInt() ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'device_id': deviceId,
        'device_name': deviceName,
        'sync_key_fingerprint': syncKeyFingerprint,
        'challenge_nonce': challengeNonce,
        'addresses': addresses,
        'created_at': createdAt,
        'expires_at': expiresAt,
      };
}

/// RFC 6238 TOTP configuration parsed from `otpauth://totp/` or stored on an item.
class TotpConfigModel {
  final List<int> secret;
  final int periodSeconds;
  final int digits;
  final String algorithm;
  final String? issuer;
  final String? accountName;

  TotpConfigModel({
    required this.secret,
    this.periodSeconds = 30,
    this.digits = 6,
    this.algorithm = 'SHA1',
    this.issuer,
    this.accountName,
  });

  factory TotpConfigModel.fromJson(Map<String, dynamic> json) {
    return TotpConfigModel(
      secret: (json['secret'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      periodSeconds: (json['period_seconds'] as num?)?.toInt() ?? 30,
      digits: (json['digits'] as num?)?.toInt() ?? 6,
      algorithm: json['algorithm'] as String? ?? 'SHA1',
      issuer: json['issuer'] as String?,
      accountName: json['account_name'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'secret': secret,
        'period_seconds': periodSeconds,
        'digits': digits,
        'algorithm': algorithm,
        if (issuer != null) 'issuer': issuer,
        if (accountName != null) 'account_name': accountName,
      };
}

/// Current TOTP code and remaining seconds in period.
class TotpGeneratedCode {
  final String code;
  final int remainingSeconds;

  TotpGeneratedCode({
    required this.code,
    required this.remainingSeconds,
  });
}

/// WebAuthn / FIDO2 Passkey credential.
class PasskeyCredentialModel {
  final List<int> credentialId;
  final String rpId;
  final List<int> userHandle;
  final String userName;
  final int signCount;
  final int algorithm;
  final List<int> publicKey;
  final List<int> privateKey;
  final int createdAt;

  PasskeyCredentialModel({
    required this.credentialId,
    required this.rpId,
    required this.userHandle,
    required this.userName,
    required this.signCount,
    required this.algorithm,
    required this.publicKey,
    required this.privateKey,
    required this.createdAt,
  });

  factory PasskeyCredentialModel.fromJson(Map<String, dynamic> json) {
    return PasskeyCredentialModel(
      credentialId: (json['credential_id'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      rpId: json['rp_id'] as String? ?? '',
      userHandle: (json['user_handle'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      userName: json['user_name'] as String? ?? '',
      signCount: (json['sign_count'] as num?)?.toInt() ?? 0,
      algorithm: (json['algorithm'] as num?)?.toInt() ?? -7,
      publicKey: (json['public_key'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      privateKey: (json['private_key'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      createdAt: (json['created_at'] as num?)?.toInt() ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'credential_id': credentialId,
        'rp_id': rpId,
        'user_handle': userHandle,
        'user_name': userName,
        'sign_count': signCount,
        'algorithm': algorithm,
        'public_key': publicKey,
        'private_key': privateKey,
        'created_at': createdAt,
      };
}

/// WebAuthn Assertion response generated during passkey authentication.
class PasskeyAssertionResult {
  final List<int> credentialId;
  final List<int> authenticatorData;
  final String clientDataJson;
  final List<int> signature;
  final List<int> userHandle;

  PasskeyAssertionResult({
    required this.credentialId,
    required this.authenticatorData,
    required this.clientDataJson,
    required this.signature,
    required this.userHandle,
  });

  factory PasskeyAssertionResult.fromJson(Map<String, dynamic> json) {
    return PasskeyAssertionResult(
      credentialId: (json['credential_id'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      authenticatorData: (json['authenticator_data'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      clientDataJson: json['client_data_json'] as String? ?? '',
      signature: (json['signature'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
      userHandle: (json['user_handle'] as List<dynamic>?)?.map((e) => (e as num).toInt()).toList() ?? [],
    );
  }
}

/// Privacy-preserving k-Anonymity breach query pair.
class BreachQueryResult {
  final String prefix;
  final String suffix;

  BreachQueryResult({required this.prefix, required this.suffix});
}

/// Group of accounts sharing the identical password.
class ReusedPasswordGroupModel {
  final int count;
  final List<String> itemTitles;
  final List<String> itemIds;

  ReusedPasswordGroupModel({
    required this.count,
    required this.itemTitles,
    required this.itemIds,
  });

  factory ReusedPasswordGroupModel.fromJson(Map<String, dynamic> json) {
    return ReusedPasswordGroupModel(
      count: (json['count'] as num?)?.toInt() ?? 0,
      itemTitles: (json['item_titles'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      itemIds: (json['item_ids'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
    );
  }
}

/// Weak password finding item.
class WeakPasswordFindingModel {
  final String itemId;
  final String title;
  final int entropyBits;
  final String rating;
  final String reason;

  WeakPasswordFindingModel({
    required this.itemId,
    required this.title,
    required this.entropyBits,
    required this.rating,
    required this.reason,
  });

  factory WeakPasswordFindingModel.fromJson(Map<String, dynamic> json) {
    return WeakPasswordFindingModel(
      itemId: json['item_id'] as String? ?? '',
      title: json['title'] as String? ?? '',
      entropyBits: (json['entropy_bits'] as num?)?.toInt() ?? 0,
      rating: json['rating'] as String? ?? '',
      reason: json['reason'] as String? ?? '',
    );
  }
}

/// Stale password finding (> 90 days).
class StalePasswordFindingModel {
  final String itemId;
  final String title;
  final int ageDays;

  StalePasswordFindingModel({
    required this.itemId,
    required this.title,
    required this.ageDays,
  });

  factory StalePasswordFindingModel.fromJson(Map<String, dynamic> json) {
    return StalePasswordFindingModel(
      itemId: json['item_id'] as String? ?? '',
      title: json['title'] as String? ?? '',
      ageDays: (json['age_days'] as num?)?.toInt() ?? 0,
    );
  }
}

/// Comprehensive vault health audit report.
class VaultAuditReportModel {
  final int totalActiveItems;
  final int healthScore;
  final List<ReusedPasswordGroupModel> reusedGroups;
  final List<WeakPasswordFindingModel> weakItems;
  final List<StalePasswordFindingModel> staleItems;
  final List<String> missing2FaItems;
  final List<String> recommendations;

  VaultAuditReportModel({
    required this.totalActiveItems,
    required this.healthScore,
    required this.reusedGroups,
    required this.weakItems,
    required this.staleItems,
    required this.missing2FaItems,
    required this.recommendations,
  });

  factory VaultAuditReportModel.fromJson(Map<String, dynamic> json) {
    return VaultAuditReportModel(
      totalActiveItems: (json['total_active_items'] as num?)?.toInt() ?? 0,
      healthScore: (json['health_score'] as num?)?.toInt() ?? 100,
      reusedGroups: (json['reused_groups'] as List<dynamic>?)
              ?.map((e) => ReusedPasswordGroupModel.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
      weakItems: (json['weak_items'] as List<dynamic>?)
              ?.map((e) => WeakPasswordFindingModel.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
      staleItems: (json['stale_items'] as List<dynamic>?)
              ?.map((e) => StalePasswordFindingModel.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
      missing2FaItems: (json['missing_2fa_items'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      recommendations: (json['recommendations'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
    );
  }
}

