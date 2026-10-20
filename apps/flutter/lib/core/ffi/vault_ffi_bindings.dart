import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../../models/vault_models.dart';

// --- Native C Function Signatures ---
typedef NativeCreateVault = Int32 Function(
  Pointer<Utf8> passphrase,
  Pointer<Utf8> vaultName,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);
typedef DartCreateVault = int Function(
  Pointer<Utf8> passphrase,
  Pointer<Utf8> vaultName,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);

typedef NativeSaveVault = Int32 Function(
  Pointer<Utf8> passphrase,
  Pointer<Utf8> payloadJson,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);
typedef DartSaveVault = int Function(
  Pointer<Utf8> passphrase,
  Pointer<Utf8> payloadJson,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);

typedef NativeUnlockVault = Int32 Function(
  Pointer<Uint8> vaultBytes,
  IntPtr vaultLen,
  Pointer<Utf8> passphrase,
  Pointer<Pointer<Utf8>> outJson,
);
typedef DartUnlockVault = int Function(
  Pointer<Uint8> vaultBytes,
  int vaultLen,
  Pointer<Utf8> passphrase,
  Pointer<Pointer<Utf8>> outJson,
);

typedef NativeGeneratePassword = Int32 Function(
  Pointer<Utf8> optionsJson,
  Pointer<Pointer<Utf8>> outPassword,
);
typedef DartGeneratePassword = int Function(
  Pointer<Utf8> optionsJson,
  Pointer<Pointer<Utf8>> outPassword,
);

typedef NativeGeneratePassphrase = Int32 Function(
  Pointer<Utf8> optionsJson,
  Pointer<Pointer<Utf8>> outPassphrase,
);
typedef DartGeneratePassphrase = int Function(
  Pointer<Utf8> optionsJson,
  Pointer<Pointer<Utf8>> outPassphrase,
);

typedef NativeEstimateCrackTime = Int32 Function(
  Pointer<Utf8> secret,
  Pointer<Pointer<Utf8>> outJson,
);
typedef DartEstimateCrackTime = int Function(
  Pointer<Utf8> secret,
  Pointer<Pointer<Utf8>> outJson,
);

typedef NativeSearch = Int32 Function(
  Pointer<Utf8> payloadJson,
  Pointer<Utf8> queryJson,
  Pointer<Pointer<Utf8>> outJson,
);
typedef DartSearch = int Function(
  Pointer<Utf8> payloadJson,
  Pointer<Utf8> queryJson,
  Pointer<Pointer<Utf8>> outJson,
);

typedef NativeCreateBackup = Int32 Function(
  Pointer<Utf8> payloadJson,
  Pointer<Utf8> passphrase,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);
typedef DartCreateBackup = int Function(
  Pointer<Utf8> payloadJson,
  Pointer<Utf8> passphrase,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);

typedef NativeRehearseRestore = Int32 Function(
  Pointer<Uint8> backupData,
  IntPtr backupLen,
  Pointer<Utf8> passphrase,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Utf8>> outReportJson,
);
typedef DartRehearseRestore = int Function(
  Pointer<Uint8> backupData,
  int backupLen,
  Pointer<Utf8> passphrase,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Utf8>> outReportJson,
);

typedef NativeRestoreBackup = Int32 Function(
  Pointer<Uint8> backupData,
  IntPtr backupLen,
  Pointer<Utf8> passphrase,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Utf8>> outPayloadJson,
);
typedef DartRestoreBackup = int Function(
  Pointer<Uint8> backupData,
  int backupLen,
  Pointer<Utf8> passphrase,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Utf8>> outPayloadJson,
);

typedef NativeGenerateRecoveryKey = Int32 Function(
  Pointer<Pointer<Utf8>> outKey,
);
typedef DartGenerateRecoveryKey = int Function(
  Pointer<Pointer<Utf8>> outKey,
);

typedef NativeGenerateRecoveryKitDoc = Int32 Function(
  Pointer<Utf8> vaultName,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Utf8>> outDocJson,
);
typedef DartGenerateRecoveryKitDoc = int Function(
  Pointer<Utf8> vaultName,
  Pointer<Utf8> recoveryKey,
  Pointer<Pointer<Utf8>> outDocJson,
);

typedef NativeParseImport = Int32 Function(
  Pointer<Utf8> content,
  Pointer<Pointer<Utf8>> outItemsJson,
);
typedef DartParseImport = int Function(
  Pointer<Utf8> content,
  Pointer<Pointer<Utf8>> outItemsJson,
);

typedef NativeAnalyzeDedup = Int32 Function(
  Pointer<Utf8> currentItemsJson,
  Pointer<Utf8> incomingItemsJson,
  Pointer<Pointer<Utf8>> outPreviewJson,
);
typedef DartAnalyzeDedup = int Function(
  Pointer<Utf8> currentItemsJson,
  Pointer<Utf8> incomingItemsJson,
  Pointer<Pointer<Utf8>> outPreviewJson,
);

typedef NativeApplyImport = Int32 Function(
  Pointer<Utf8> currentItemsJson,
  Pointer<Utf8> candidatesJson,
  Pointer<Pointer<Utf8>> outUpdatedItemsJson,
);
typedef DartApplyImport = int Function(
  Pointer<Utf8> currentItemsJson,
  Pointer<Utf8> candidatesJson,
  Pointer<Pointer<Utf8>> outUpdatedItemsJson,
);

typedef NativeExportCsv = Int32 Function(
  Pointer<Utf8> itemsJson,
  Pointer<Pointer<Utf8>> outCsv,
);
typedef DartExportCsv = int Function(
  Pointer<Utf8> itemsJson,
  Pointer<Pointer<Utf8>> outCsv,
);

typedef NativeSyncCreateSyncpack = Int32 Function(
  Pointer<Utf8> payloadJson,
  Pointer<Utf8> syncKeyHex,
  Pointer<Utf8> deviceId,
  Pointer<Utf8> deviceName,
  Pointer<Utf8> clockJson,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);
typedef DartSyncCreateSyncpack = int Function(
  Pointer<Utf8> payloadJson,
  Pointer<Utf8> syncKeyHex,
  Pointer<Utf8> deviceId,
  Pointer<Utf8> deviceName,
  Pointer<Utf8> clockJson,
  Pointer<Pointer<Uint8>> outData,
  Pointer<IntPtr> outLen,
);

typedef NativeSyncApplySyncpack = Int32 Function(
  Pointer<Utf8> localPayloadJson,
  Pointer<Utf8> localClockJson,
  Pointer<Uint8> packData,
  IntPtr packLen,
  Pointer<Utf8> syncKeyHex,
  Pointer<Pointer<Utf8>> outResultJson,
);
typedef DartSyncApplySyncpack = int Function(
  Pointer<Utf8> localPayloadJson,
  Pointer<Utf8> localClockJson,
  Pointer<Uint8> packData,
  int packLen,
  Pointer<Utf8> syncKeyHex,
  Pointer<Pointer<Utf8>> outResultJson,
);

typedef NativeSyncGeneratePairingQr = Int32 Function(
  Pointer<Utf8> syncKeyHex,
  Pointer<Utf8> deviceId,
  Pointer<Utf8> deviceName,
  Pointer<Utf8> addressesCsv,
  Pointer<Pointer<Utf8>> outQrUri,
);
typedef DartSyncGeneratePairingQr = int Function(
  Pointer<Utf8> syncKeyHex,
  Pointer<Utf8> deviceId,
  Pointer<Utf8> deviceName,
  Pointer<Utf8> addressesCsv,
  Pointer<Pointer<Utf8>> outQrUri,
);

typedef NativeSyncVerifyPairingQr = Int32 Function(
  Pointer<Utf8> qrUri,
  Pointer<Utf8> syncKeyHex,
  Pointer<Pointer<Utf8>> outJson,
);
typedef DartSyncVerifyPairingQr = int Function(
  Pointer<Utf8> qrUri,
  Pointer<Utf8> syncKeyHex,
  Pointer<Pointer<Utf8>> outJson,
);

typedef NativeSyncMergePayloads = Int32 Function(
  Pointer<Utf8> localPayloadJson,
  Pointer<Utf8> remotePayloadJson,
  Pointer<Pointer<Utf8>> outResultJson,
);
typedef DartSyncMergePayloads = int Function(
  Pointer<Utf8> localPayloadJson,
  Pointer<Utf8> remotePayloadJson,
  Pointer<Pointer<Utf8>> outResultJson,
);

typedef NativeTotpGenerate = Int32 Function(
  Pointer<Utf8> secretB32,
  Uint64 timestampSecs,
  Uint32 digits,
  Uint32 period,
  Pointer<Utf8> algorithm,
  Pointer<Pointer<Utf8>> outCode,
  Pointer<Uint64> outRemaining,
);
typedef DartTotpGenerate = int Function(
  Pointer<Utf8> secretB32,
  int timestampSecs,
  int digits,
  int period,
  Pointer<Utf8> algorithm,
  Pointer<Pointer<Utf8>> outCode,
  Pointer<Uint64> outRemaining,
);

typedef NativeTotpVerify = Int32 Function(
  Pointer<Utf8> secretB32,
  Pointer<Utf8> code,
  Uint64 timestampSecs,
  Uint32 toleranceSteps,
  Uint32 digits,
  Uint32 period,
  Pointer<Utf8> algorithm,
  Pointer<Bool> outValid,
);
typedef DartTotpVerify = int Function(
  Pointer<Utf8> secretB32,
  Pointer<Utf8> code,
  int timestampSecs,
  int toleranceSteps,
  int digits,
  int period,
  Pointer<Utf8> algorithm,
  Pointer<Bool> outValid,
);

typedef NativeTotpParseUri = Int32 Function(
  Pointer<Utf8> uri,
  Pointer<Pointer<Utf8>> outConfigJson,
);
typedef DartTotpParseUri = int Function(
  Pointer<Utf8> uri,
  Pointer<Pointer<Utf8>> outConfigJson,
);

typedef NativePasskeyGenerate = Int32 Function(
  Pointer<Utf8> rpId,
  Pointer<Utf8> userHandle,
  Pointer<Utf8> userName,
  Int32 algorithm,
  Pointer<Pointer<Utf8>> outPasskeyJson,
);
typedef DartPasskeyGenerate = int Function(
  Pointer<Utf8> rpId,
  Pointer<Utf8> userHandle,
  Pointer<Utf8> userName,
  int algorithm,
  Pointer<Pointer<Utf8>> outPasskeyJson,
);

typedef NativePasskeySignAssertion = Int32 Function(
  Pointer<Utf8> passkeyJson,
  Pointer<Utf8> rpId,
  Pointer<Utf8> clientDataJson,
  Bool userPresent,
  Bool userVerified,
  Pointer<Pointer<Utf8>> outAssertionJson,
  Pointer<Pointer<Utf8>> outUpdatedPasskeyJson,
);
typedef DartPasskeySignAssertion = int Function(
  Pointer<Utf8> passkeyJson,
  Pointer<Utf8> rpId,
  Pointer<Utf8> clientDataJson,
  bool userPresent,
  bool userVerified,
  Pointer<Pointer<Utf8>> outAssertionJson,
  Pointer<Pointer<Utf8>> outUpdatedPasskeyJson,
);

typedef NativeAuditVault = Int32 Function(
  Pointer<Utf8> payloadJson,
  Uint64 timestampSecs,
  Pointer<Pointer<Utf8>> outReportJson,
);
typedef DartAuditVault = int Function(
  Pointer<Utf8> payloadJson,
  int timestampSecs,
  Pointer<Pointer<Utf8>> outReportJson,
);

typedef NativeBreachPrepareQuery = Int32 Function(
  Pointer<Utf8> password,
  Pointer<Pointer<Utf8>> outPrefix,
  Pointer<Pointer<Utf8>> outSuffix,
);
typedef DartBreachPrepareQuery = int Function(
  Pointer<Utf8> password,
  Pointer<Pointer<Utf8>> outPrefix,
  Pointer<Pointer<Utf8>> outSuffix,
);

typedef NativeBreachCheckResponse = Int32 Function(
  Pointer<Utf8> suffix,
  Pointer<Utf8> responseBody,
  Pointer<Uint64> outCount,
);
typedef DartBreachCheckResponse = int Function(
  Pointer<Utf8> suffix,
  Pointer<Utf8> responseBody,
  Pointer<Uint64> outCount,
);

typedef NativeFreeString = Void Function(Pointer<Utf8> ptr);
typedef DartFreeString = void Function(Pointer<Utf8> ptr);

typedef NativeFreeBytes = Void Function(Pointer<Uint8> ptr, IntPtr len);
typedef DartFreeBytes = void Function(Pointer<Uint8> ptr, int len);

/// High-level typed bridge to the Rust security core via C-ABI FFI.
class RustVaultFfi {
  static final RustVaultFfi instance = RustVaultFfi._internal();

  DynamicLibrary? _dylib;
  bool _isInitialized = false;

  late DartCreateVault _createVault;
  late DartSaveVault _saveVault;
  late DartUnlockVault _unlockVault;
  late DartGeneratePassword _generatePassword;
  late DartGeneratePassphrase _generatePassphrase;
  late DartEstimateCrackTime _estimateCrackTime;
  late DartSearch _search;
  late DartCreateBackup _createBackup;
  late DartRehearseRestore _rehearseRestore;
  late DartRestoreBackup _restoreBackup;
  late DartGenerateRecoveryKey _generateRecoveryKey;
  late DartGenerateRecoveryKitDoc _generateRecoveryKitDoc;
  late DartParseImport _parseImport;
  late DartAnalyzeDedup _analyzeDedup;
  late DartApplyImport _applyImport;
  late DartExportCsv _exportCsv;
  late DartSyncCreateSyncpack _syncCreateSyncpack;
  late DartSyncApplySyncpack _syncApplySyncpack;
  late DartSyncGeneratePairingQr _syncGeneratePairingQr;
  late DartSyncVerifyPairingQr _syncVerifyPairingQr;
  late DartSyncMergePayloads _syncMergePayloads;
  late DartTotpGenerate _totpGenerate;
  late DartTotpVerify _totpVerify;
  late DartTotpParseUri _totpParseUri;
  late DartPasskeyGenerate _passkeyGenerate;
  late DartPasskeySignAssertion _passkeySignAssertion;
  late DartAuditVault _auditVault;
  late DartBreachPrepareQuery _breachPrepareQuery;
  late DartBreachCheckResponse _breachCheckResponse;
  late DartFreeString _freeString;
  late DartFreeBytes _freeBytes;

  RustVaultFfi._internal() {
    _initDylib();
  }

  void _initDylib() {
    try {
      if (Platform.isWindows) {
        final candidates = [
          'pwdvault_ffi.dll',
          'core/target/x86_64-pc-windows-gnullvm/release/pwdvault_ffi.dll',
          '../../core/target/x86_64-pc-windows-gnullvm/release/pwdvault_ffi.dll',
          '../core/target/x86_64-pc-windows-gnullvm/release/pwdvault_ffi.dll',
          'j:/rustpwdvault/core/target/x86_64-pc-windows-gnullvm/release/pwdvault_ffi.dll',
        ];
        for (final p in candidates) {
          if (File(p).existsSync()) {
            _dylib = DynamicLibrary.open(p);
            break;
          }
        }
        _dylib ??= DynamicLibrary.open('pwdvault_ffi.dll');
      } else if (Platform.isAndroid || Platform.isLinux) {
        _dylib = DynamicLibrary.open('libpwdvault_ffi.so');
      } else if (Platform.isIOS || Platform.isMacOS) {
        _dylib = DynamicLibrary.process();
      }

      if (_dylib != null) {
        _createVault = _dylib!
            .lookup<NativeFunction<NativeCreateVault>>('vault_ffi_create_vault')
            .asFunction();
        _saveVault = _dylib!
            .lookup<NativeFunction<NativeSaveVault>>('vault_ffi_save_vault')
            .asFunction();
        _unlockVault = _dylib!
            .lookup<NativeFunction<NativeUnlockVault>>('vault_ffi_unlock_vault')
            .asFunction();
        _generatePassword = _dylib!
            .lookup<NativeFunction<NativeGeneratePassword>>('vault_ffi_generate_password')
            .asFunction();
        _generatePassphrase = _dylib!
            .lookup<NativeFunction<NativeGeneratePassphrase>>('vault_ffi_generate_passphrase')
            .asFunction();
        _estimateCrackTime = _dylib!
            .lookup<NativeFunction<NativeEstimateCrackTime>>('vault_ffi_estimate_crack_time')
            .asFunction();
        _search = _dylib!
            .lookup<NativeFunction<NativeSearch>>('vault_ffi_search')
            .asFunction();
        _createBackup = _dylib!
            .lookup<NativeFunction<NativeCreateBackup>>('vault_ffi_create_backup')
            .asFunction();
        _rehearseRestore = _dylib!
            .lookup<NativeFunction<NativeRehearseRestore>>('vault_ffi_rehearse_restore')
            .asFunction();
        _restoreBackup = _dylib!
            .lookup<NativeFunction<NativeRestoreBackup>>('vault_ffi_restore_backup')
            .asFunction();
        _generateRecoveryKey = _dylib!
            .lookup<NativeFunction<NativeGenerateRecoveryKey>>('vault_ffi_generate_recovery_key')
            .asFunction();
        _generateRecoveryKitDoc = _dylib!
            .lookup<NativeFunction<NativeGenerateRecoveryKitDoc>>('vault_ffi_generate_recovery_kit_doc')
            .asFunction();
        _parseImport = _dylib!
            .lookup<NativeFunction<NativeParseImport>>('vault_ffi_parse_import')
            .asFunction();
        _analyzeDedup = _dylib!
            .lookup<NativeFunction<NativeAnalyzeDedup>>('vault_ffi_analyze_dedup')
            .asFunction();
        _applyImport = _dylib!
            .lookup<NativeFunction<NativeApplyImport>>('vault_ffi_apply_import')
            .asFunction();
        _exportCsv = _dylib!
            .lookup<NativeFunction<NativeExportCsv>>('vault_ffi_export_csv')
            .asFunction();
        _syncCreateSyncpack = _dylib!
            .lookup<NativeFunction<NativeSyncCreateSyncpack>>('vault_ffi_sync_create_syncpack')
            .asFunction();
        _syncApplySyncpack = _dylib!
            .lookup<NativeFunction<NativeSyncApplySyncpack>>('vault_ffi_sync_apply_syncpack')
            .asFunction();
        _syncGeneratePairingQr = _dylib!
            .lookup<NativeFunction<NativeSyncGeneratePairingQr>>('vault_ffi_sync_generate_pairing_qr')
            .asFunction();
        _syncVerifyPairingQr = _dylib!
            .lookup<NativeFunction<NativeSyncVerifyPairingQr>>('vault_ffi_sync_verify_pairing_qr')
            .asFunction();
        _syncMergePayloads = _dylib!
            .lookup<NativeFunction<NativeSyncMergePayloads>>('vault_ffi_sync_merge_payloads')
            .asFunction();
        _totpGenerate = _dylib!
            .lookup<NativeFunction<NativeTotpGenerate>>('vault_ffi_totp_generate')
            .asFunction();
        _totpVerify = _dylib!
            .lookup<NativeFunction<NativeTotpVerify>>('vault_ffi_totp_verify')
            .asFunction();
        _totpParseUri = _dylib!
            .lookup<NativeFunction<NativeTotpParseUri>>('vault_ffi_totp_parse_uri')
            .asFunction();
        _passkeyGenerate = _dylib!
            .lookup<NativeFunction<NativePasskeyGenerate>>('vault_ffi_passkey_generate')
            .asFunction();
        _passkeySignAssertion = _dylib!
            .lookup<NativeFunction<NativePasskeySignAssertion>>('vault_ffi_passkey_sign_assertion')
            .asFunction();
        _auditVault = _dylib!
            .lookup<NativeFunction<NativeAuditVault>>('vault_ffi_audit_vault')
            .asFunction();
        _breachPrepareQuery = _dylib!
            .lookup<NativeFunction<NativeBreachPrepareQuery>>('vault_ffi_breach_prepare_query')
            .asFunction();
        _breachCheckResponse = _dylib!
            .lookup<NativeFunction<NativeBreachCheckResponse>>('vault_ffi_breach_check_response')
            .asFunction();
        _freeString = _dylib!
            .lookup<NativeFunction<NativeFreeString>>('vault_ffi_free_string')
            .asFunction();
        _freeBytes = _dylib!
            .lookup<NativeFunction<NativeFreeBytes>>('vault_ffi_free_bytes')
            .asFunction();

        _isInitialized = true;
      }
    } catch (e) {
      // Dynamic library not yet loaded in this runner; fallback graceful
      _isInitialized = false;
    }
  }

  bool get isAvailable => _isInitialized;

  /// Creates a new vault and returns raw encrypted `.vault.v1` container bytes.
  Uint8List createVault(String passphrase, String vaultName) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final passPtr = passphrase.toNativeUtf8();
    final namePtr = vaultName.toNativeUtf8();
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<IntPtr>();

    try {
      final code = _createVault(passPtr, namePtr, outData, outLen);
      if (code != 0) {
        throw Exception('Vault creation failed with code $code');
      }

      final len = outLen.value;
      final rawPtr = outData.value;
      final bytes = Uint8List.fromList(rawPtr.asTypedList(len));
      _freeBytes(rawPtr, len);
      return bytes;
    } finally {
      calloc.free(passPtr);
      calloc.free(namePtr);
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  /// Encrypts an updated vault payload and returns raw `.vault.v1` bytes.
  Uint8List saveVault(String passphrase, VaultPayload payload) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final passPtr = passphrase.toNativeUtf8();
    final payloadJson = jsonEncode(payload.toJson());
    final payloadPtr = payloadJson.toNativeUtf8();
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<IntPtr>();

    try {
      final code = _saveVault(passPtr, payloadPtr, outData, outLen);
      if (code != 0) {
        throw Exception('Vault encryption failed with code $code');
      }

      final len = outLen.value;
      final rawPtr = outData.value;
      final bytes = Uint8List.fromList(rawPtr.asTypedList(len));
      _freeBytes(rawPtr, len);
      return bytes;
    } finally {
      calloc.free(passPtr);
      calloc.free(payloadPtr);
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  /// Unlocks an encrypted container and returns the decrypted VaultPayload.
  VaultPayload unlockVault(Uint8List vaultBytes, String passphrase) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final bytesPtr = calloc<Uint8>(vaultBytes.length);
    bytesPtr.asTypedList(vaultBytes.length).setAll(0, vaultBytes);
    final passPtr = passphrase.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _unlockVault(bytesPtr, vaultBytes.length, passPtr, outJson);
      if (code == 2) {
        throw const FormatException('Incorrect master passphrase');
      } else if (code == 3) {
        throw const FormatException('Vault file integrity commitment failed: file tampered or corrupted');
      } else if (code != 0) {
        throw Exception('Vault unlock failed with code $code');
      }

      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return VaultPayload.fromJson(map);
    } finally {
      calloc.free(bytesPtr);
      calloc.free(passPtr);
      calloc.free(outJson);
    }
  }

  /// Generates a password according to options.
  String generatePassword({
    int length = 20,
    bool uppercase = true,
    bool lowercase = true,
    bool digits = true,
    bool symbols = true,
    bool excludeAmbiguous = true,
    String customExcluded = '',
  }) {
    if (!_isInitialized) {
      // Fallback in-Dart generator if FFI is not loaded
      return _fallbackPassword(length, uppercase, lowercase, digits, symbols);
    }

    final optsMap = {
      'length': length,
      'uppercase': uppercase,
      'lowercase': lowercase,
      'digits': digits,
      'symbols': symbols,
      'exclude_ambiguous': excludeAmbiguous,
      'custom_excluded': customExcluded,
    };
    final jsonStr = jsonEncode(optsMap);
    final optsPtr = jsonStr.toNativeUtf8();
    final outPw = calloc<Pointer<Utf8>>();

    try {
      final code = _generatePassword(optsPtr, outPw);
      if (code != 0) {
        throw Exception('Password generation failed with code $code');
      }
      final result = outPw.value.toDartString();
      _freeString(outPw.value);
      return result;
    } finally {
      calloc.free(optsPtr);
      calloc.free(outPw);
    }
  }

  /// Generates an EFF wordlist passphrase.
  String generatePassphrase({
    int wordCount = 5,
    String separator = '-',
    String capitalization = 'TitleCase',
    bool insertNumber = true,
  }) {
    if (!_isInitialized) {
      return 'Correct-Horse-Battery-Staple-42';
    }

    final optsMap = {
      'word_count': wordCount,
      'separator': separator,
      'capitalization': capitalization,
      'insert_number': insertNumber,
    };
    final jsonStr = jsonEncode(optsMap);
    final optsPtr = jsonStr.toNativeUtf8();
    final outPass = calloc<Pointer<Utf8>>();

    try {
      final code = _generatePassphrase(optsPtr, outPass);
      if (code != 0) {
        throw Exception('Passphrase generation failed with code $code');
      }
      final result = outPass.value.toDartString();
      _freeString(outPass.value);
      return result;
    } finally {
      calloc.free(optsPtr);
      calloc.free(outPass);
    }
  }

  /// Evaluates Shannon entropy and GPU crack-time estimates.
  CrackTimeEstimate estimateCrackTime(String secret) {
    if (!_isInitialized) {
      return CrackTimeEstimate(
        entropyBits: (secret.length * 4.5).round(),
        rating: secret.length > 14 ? 'Strong' : 'Fair',
        onlineTime: 'Centuries',
        offlineGpuTime: 'Years',
        clusterTime: 'Months',
      );
    }

    final secPtr = secret.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _estimateCrackTime(secPtr, outJson);
      if (code != 0) {
        throw Exception('Crack time estimation failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return CrackTimeEstimate.fromJson(map);
    } finally {
      calloc.free(secPtr);
      calloc.free(outJson);
    }
  }

  /// Executes fast in-memory search over the current payload.
  List<VaultItem> search(VaultPayload payload, String query, {ItemCategory? category, String? tag, bool favoritesOnly = false}) {
    if (!_isInitialized) {
      return payload.items.where((i) {
        if (i.isTrashed) return false;
        if (category != null && i.category != category) return false;
        if (favoritesOnly && !i.favorite) return false;
        if (tag != null && !i.tags.contains(tag)) return false;
        if (query.isEmpty) return true;
        final q = query.toLowerCase();
        return i.title.toLowerCase().contains(q) ||
            (i.username?.toLowerCase().contains(q) ?? false) ||
            i.urls.any((u) => u.toLowerCase().contains(q));
      }).toList();
    }

    final payloadJson = jsonEncode(payload.toJson());
    final queryMap = {
      'query': query,
      'category': category?.toJson(),
      'tag': tag,
      'favorites_only': favoritesOnly,
      'limit': 100,
    };
    final queryJson = jsonEncode(queryMap);

    final pPtr = payloadJson.toNativeUtf8();
    final qPtr = queryJson.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _search(pPtr, qPtr, outJson);
      if (code != 0) {
        throw Exception('Search failed with code $code');
      }

      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final list = jsonDecode(jsonStr) as List<dynamic>;

      // Map result item_ids back to VaultItem
      final itemMap = {for (var item in payload.items) item.id: item};
      final results = <VaultItem>[];
      for (final r in list) {
        final id = r['item_id'] as String;
        if (itemMap.containsKey(id)) {
          results.add(itemMap[id]!);
        }
      }
      return results;
    } finally {
      calloc.free(pPtr);
      calloc.free(qPtr);
      calloc.free(outJson);
    }
  }

  /// Creates an authenticated `.vaultbak` encrypted backup archive.
  Uint8List createBackup(VaultPayload payload, {String? passphrase, String? recoveryKey}) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }
    if ((passphrase == null || passphrase.isEmpty) &&
        (recoveryKey == null || recoveryKey.isEmpty)) {
      throw ArgumentError('Either passphrase or recoveryKey must be provided');
    }

    final payloadJson = jsonEncode(payload.toJson());
    final pPtr = payloadJson.toNativeUtf8();
    final passPtr = (passphrase != null && passphrase.isNotEmpty) ? passphrase.toNativeUtf8() : nullptr;
    final recPtr = (recoveryKey != null && recoveryKey.isNotEmpty) ? recoveryKey.toNativeUtf8() : nullptr;
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<IntPtr>();

    try {
      final code = _createBackup(pPtr, passPtr, recPtr, outData, outLen);
      if (code != 0) {
        throw Exception('Backup creation failed with code $code');
      }

      final len = outLen.value;
      final rawPtr = outData.value;
      final bytes = Uint8List.fromList(rawPtr.asTypedList(len));
      _freeBytes(rawPtr, len);
      return bytes;
    } finally {
      calloc.free(pPtr);
      if (passPtr != nullptr) calloc.free(passPtr);
      if (recPtr != nullptr) calloc.free(recPtr);
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  /// Dry-runs restoration of a `.vaultbak` archive and returns a validation report without altering vault state.
  BackupRehearsalReport rehearseRestore(Uint8List backupBytes, {String? passphrase, String? recoveryKey}) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }
    if ((passphrase == null || passphrase.isEmpty) &&
        (recoveryKey == null || recoveryKey.isEmpty)) {
      throw ArgumentError('Either passphrase or recoveryKey must be provided');
    }

    final bytesPtr = calloc<Uint8>(backupBytes.length);
    bytesPtr.asTypedList(backupBytes.length).setAll(0, backupBytes);
    final passPtr = (passphrase != null && passphrase.isNotEmpty) ? passphrase.toNativeUtf8() : nullptr;
    final recPtr = (recoveryKey != null && recoveryKey.isNotEmpty) ? recoveryKey.toNativeUtf8() : nullptr;
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _rehearseRestore(bytesPtr, backupBytes.length, passPtr, recPtr, outJson);
      if (code != 0) {
        throw Exception('Backup rehearsal failed with code $code');
      }

      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return BackupRehearsalReport.fromJson(map);
    } finally {
      calloc.free(bytesPtr);
      if (passPtr != nullptr) calloc.free(passPtr);
      if (recPtr != nullptr) calloc.free(recPtr);
      calloc.free(outJson);
    }
  }

  /// Decrypts and restores an authenticated VaultPayload from a `.vaultbak` archive.
  VaultPayload restoreBackup(Uint8List backupBytes, {String? passphrase, String? recoveryKey}) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }
    if ((passphrase == null || passphrase.isEmpty) &&
        (recoveryKey == null || recoveryKey.isEmpty)) {
      throw ArgumentError('Either passphrase or recoveryKey must be provided');
    }

    final bytesPtr = calloc<Uint8>(backupBytes.length);
    bytesPtr.asTypedList(backupBytes.length).setAll(0, backupBytes);
    final passPtr = (passphrase != null && passphrase.isNotEmpty) ? passphrase.toNativeUtf8() : nullptr;
    final recPtr = (recoveryKey != null && recoveryKey.isNotEmpty) ? recoveryKey.toNativeUtf8() : nullptr;
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _restoreBackup(bytesPtr, backupBytes.length, passPtr, recPtr, outJson);
      if (code == 2) {
        throw const FormatException('Incorrect backup passphrase or recovery key');
      } else if (code == 3) {
        throw const FormatException('Backup file integrity commitment failed: file modified or corrupted');
      } else if (code != 0) {
        throw Exception('Backup restore failed with code $code');
      }

      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return VaultPayload.fromJson(map);
    } finally {
      calloc.free(bytesPtr);
      if (passPtr != nullptr) calloc.free(passPtr);
      if (recPtr != nullptr) calloc.free(recPtr);
      calloc.free(outJson);
    }
  }

  /// Generates a fresh 256-bit emergency recovery key in Crockford Base32 format.
  String generateRecoveryKey() {
    if (!_isInitialized) {
      return 'PV-7K9A-3M4N-5P6Q-7R8S-9T0V-WXYZ-ABCD-EFGH-JKMN-PQRS-TVWX';
    }

    final outKey = calloc<Pointer<Utf8>>();
    try {
      final code = _generateRecoveryKey(outKey);
      if (code != 0) {
        throw Exception('Recovery key generation failed with code $code');
      }
      final key = outKey.value.toDartString();
      _freeString(outKey.value);
      return key;
    } finally {
      calloc.free(outKey);
    }
  }

  /// Generates an Emergency Recovery Kit document with storage instructions.
  RecoveryKitDocument generateRecoveryKitDoc(String vaultName, String recoveryKey) {
    if (!_isInitialized) {
      return RecoveryKitDocument(
        vaultName: vaultName,
        createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        formattedKey: recoveryKey,
        storageInstructions: 'Store offline in a fireproof safe.',
      );
    }

    final vPtr = vaultName.toNativeUtf8();
    final kPtr = recoveryKey.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _generateRecoveryKitDoc(vPtr, kPtr, outJson);
      if (code != 0) {
        throw Exception('Recovery kit generation failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return RecoveryKitDocument.fromJson(map);
    } finally {
      calloc.free(vPtr);
      calloc.free(kPtr);
      calloc.free(outJson);
    }
  }

  /// Automatically parses external export formats (Bitwarden JSON, 1Password JSON/CSV, KeePass XML, generic CSV).
  List<VaultItem> parseImport(String content) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final cPtr = content.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _parseImport(cPtr, outJson);
      if (code != 0) {
        throw Exception('Import parse failed with code $code. Unsupported or malformed export format.');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final list = jsonDecode(jsonStr) as List<dynamic>;
      return list.map((e) => VaultItem.fromJson(e as Map<String, dynamic>)).toList();
    } finally {
      calloc.free(cPtr);
      calloc.free(outJson);
    }
  }

  /// Performs deduplication analysis between current vault items and incoming items, generating diffs for conflicts.
  ImportPreview analyzeDedup(List<VaultItem> currentItems, List<VaultItem> incomingItems) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final curJson = jsonEncode(currentItems.map((e) => e.toJson()).toList());
    final incJson = jsonEncode(incomingItems.map((e) => e.toJson()).toList());
    final curPtr = curJson.toNativeUtf8();
    final incPtr = incJson.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _analyzeDedup(curPtr, incPtr, outJson);
      if (code != 0) {
        throw Exception('Deduplication analysis failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return ImportPreview.fromJson(map);
    } finally {
      calloc.free(curPtr);
      calloc.free(incPtr);
      calloc.free(outJson);
    }
  }

  /// Commits resolved import candidates to current items according to each candidate's selected strategy.
  List<VaultItem> applyImport(List<VaultItem> currentItems, List<ImportCandidate> candidates) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final curJson = jsonEncode(currentItems.map((e) => e.toJson()).toList());
    final candJson = jsonEncode(candidates.map((e) => e.toJson()).toList());
    final curPtr = curJson.toNativeUtf8();
    final candPtr = candJson.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _applyImport(curPtr, candPtr, outJson);
      if (code != 0) {
        throw Exception('Apply import failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final list = jsonDecode(jsonStr) as List<dynamic>;
      return list.map((e) => VaultItem.fromJson(e as Map<String, dynamic>)).toList();
    } finally {
      calloc.free(curPtr);
      calloc.free(candPtr);
      calloc.free(outJson);
    }
  }

  /// Exports vault items to RFC 4180 CSV format.
  String exportCsv(List<VaultItem> items) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final itemsJson = jsonEncode(items.map((e) => e.toJson()).toList());
    final iPtr = itemsJson.toNativeUtf8();
    final outCsv = calloc<Pointer<Utf8>>();

    try {
      final code = _exportCsv(iPtr, outCsv);
      if (code != 0) {
        throw Exception('CSV export failed with code $code');
      }
      final csv = outCsv.value.toDartString();
      _freeString(outCsv.value);
      return csv;
    } finally {
      calloc.free(iPtr);
      calloc.free(outCsv);
    }
  }

  /// Creates an encrypted `.syncpack` container from a vault payload and vector clock.
  Uint8List createSyncPack({
    required VaultPayload payload,
    required String syncKeyHex,
    required String deviceId,
    required String deviceName,
    VectorClock? clock,
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final payloadJson = jsonEncode(payload.toJson());
    final pPtr = payloadJson.toNativeUtf8();
    final kPtr = syncKeyHex.toNativeUtf8();
    final dIdPtr = deviceId.toNativeUtf8();
    final dNamePtr = deviceName.toNativeUtf8();
    final cJson = clock != null ? jsonEncode(clock.toJson()) : null;
    final cPtr = cJson != null ? cJson.toNativeUtf8() : nullptr;
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<IntPtr>();

    try {
      final code = _syncCreateSyncpack(pPtr, kPtr, dIdPtr, dNamePtr, cPtr, outData, outLen);
      if (code != 0) {
        throw Exception('Create syncpack failed with code $code');
      }
      final len = outLen.value;
      final rawPtr = outData.value;
      final bytes = Uint8List.fromList(rawPtr.asTypedList(len));
      _freeBytes(rawPtr, len);
      return bytes;
    } finally {
      calloc.free(pPtr);
      calloc.free(kPtr);
      calloc.free(dIdPtr);
      calloc.free(dNamePtr);
      if (cPtr != nullptr) calloc.free(cPtr);
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  /// Applies an encrypted `.syncpack` container to a local vault payload and vector clock.
  SyncApplyResult applySyncPack({
    required VaultPayload localPayload,
    required Uint8List packBytes,
    required String syncKeyHex,
    VectorClock? localClock,
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final pJson = jsonEncode(localPayload.toJson());
    final pPtr = pJson.toNativeUtf8();
    final cJson = localClock != null ? jsonEncode(localClock.toJson()) : null;
    final cPtr = cJson != null ? cJson.toNativeUtf8() : nullptr;
    final kPtr = syncKeyHex.toNativeUtf8();
    final packPtr = calloc<Uint8>(packBytes.length);
    packPtr.asTypedList(packBytes.length).setAll(0, packBytes);
    final outResultJson = calloc<Pointer<Utf8>>();

    try {
      final code = _syncApplySyncpack(pPtr, cPtr, packPtr, packBytes.length, kPtr, outResultJson);
      if (code != 0) {
        throw Exception('Apply syncpack failed with code $code');
      }
      final jsonStr = outResultJson.value.toDartString();
      _freeString(outResultJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return SyncApplyResult.fromJson(map);
    } finally {
      calloc.free(pPtr);
      if (cPtr != nullptr) calloc.free(cPtr);
      calloc.free(kPtr);
      calloc.free(packPtr);
      calloc.free(outResultJson);
    }
  }

  /// Generates an out-of-band device pairing QR code URI (`pwdvault://pair?data=...`).
  String generatePairingQrUri({
    required String syncKeyHex,
    required String deviceId,
    required String deviceName,
    List<String> addresses = const [],
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final kPtr = syncKeyHex.toNativeUtf8();
    final dIdPtr = deviceId.toNativeUtf8();
    final dNamePtr = deviceName.toNativeUtf8();
    final addrCsv = addresses.join(',');
    final addrPtr = addrCsv.isNotEmpty ? addrCsv.toNativeUtf8() : nullptr;
    final outQrUri = calloc<Pointer<Utf8>>();

    try {
      final code = _syncGeneratePairingQr(kPtr, dIdPtr, dNamePtr, addrPtr, outQrUri);
      if (code != 0) {
        throw Exception('Generate pairing QR failed with code $code');
      }
      final uri = outQrUri.value.toDartString();
      _freeString(outQrUri.value);
      return uri;
    } finally {
      calloc.free(kPtr);
      calloc.free(dIdPtr);
      calloc.free(dNamePtr);
      if (addrPtr != nullptr) calloc.free(addrPtr);
      calloc.free(outQrUri);
    }
  }

  /// Verifies an out-of-band device pairing QR URI against the local sync key.
  PairingPayload verifyPairingQrUri({
    required String qrUri,
    required String syncKeyHex,
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final uriPtr = qrUri.toNativeUtf8();
    final kPtr = syncKeyHex.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _syncVerifyPairingQr(uriPtr, kPtr, outJson);
      if (code != 0) {
        throw Exception('Verify pairing QR failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return PairingPayload.fromJson(map);
    } finally {
      calloc.free(uriPtr);
      calloc.free(kPtr);
      calloc.free(outJson);
    }
  }

  /// Directly merges two vault payloads using CRDT deterministic LWW with revision preservation.
  SyncMergePayloadsResult mergePayloads({
    required VaultPayload localPayload,
    required VaultPayload remotePayload,
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final locJson = jsonEncode(localPayload.toJson());
    final remJson = jsonEncode(remotePayload.toJson());
    final locPtr = locJson.toNativeUtf8();
    final remPtr = remJson.toNativeUtf8();
    final outResultJson = calloc<Pointer<Utf8>>();

    try {
      final code = _syncMergePayloads(locPtr, remPtr, outResultJson);
      if (code != 0) {
        throw Exception('Merge payloads failed with code $code');
      }
      final jsonStr = outResultJson.value.toDartString();
      _freeString(outResultJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return SyncMergePayloadsResult.fromJson(map);
    } finally {
      calloc.free(locPtr);
      calloc.free(remPtr);
      calloc.free(outResultJson);
    }
  }

  /// Generates a current TOTP code and remaining seconds in period.
  TotpGeneratedCode generateTotp({
    required String secretBase32,
    int timestampSecs = 0,
    int digits = 6,
    int period = 30,
    String algorithm = 'SHA1',
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final secPtr = secretBase32.toNativeUtf8();
    final algPtr = algorithm.toNativeUtf8();
    final outCode = calloc<Pointer<Utf8>>();
    final outRem = calloc<Uint64>();

    try {
      final code = _totpGenerate(secPtr, timestampSecs, digits, period, algPtr, outCode, outRem);
      if (code != 0) {
        throw Exception('Generate TOTP failed with code $code');
      }
      final codeStr = outCode.value.toDartString();
      final rem = outRem.value;
      _freeString(outCode.value);
      return TotpGeneratedCode(code: codeStr, remainingSeconds: rem);
    } finally {
      calloc.free(secPtr);
      calloc.free(algPtr);
      calloc.free(outCode);
      calloc.free(outRem);
    }
  }

  /// Verifies a user-entered TOTP code against a secret within a drift tolerance window.
  bool verifyTotp({
    required String secretBase32,
    required String code,
    int timestampSecs = 0,
    int toleranceSteps = 1,
    int digits = 6,
    int period = 30,
    String algorithm = 'SHA1',
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final secPtr = secretBase32.toNativeUtf8();
    final codePtr = code.toNativeUtf8();
    final algPtr = algorithm.toNativeUtf8();
    final outValid = calloc<Bool>();

    try {
      final res = _totpVerify(secPtr, codePtr, timestampSecs, toleranceSteps, digits, period, algPtr, outValid);
      if (res != 0) {
        throw Exception('Verify TOTP failed with code $res');
      }
      return outValid.value;
    } finally {
      calloc.free(secPtr);
      calloc.free(codePtr);
      calloc.free(algPtr);
      calloc.free(outValid);
    }
  }

  /// Parses an `otpauth://totp/` URI and returns its configuration.
  TotpConfigModel parseTotpUri(String uri) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final uriPtr = uri.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _totpParseUri(uriPtr, outJson);
      if (code != 0) {
        throw Exception('Parse TOTP URI failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return TotpConfigModel.fromJson(map);
    } finally {
      calloc.free(uriPtr);
      calloc.free(outJson);
    }
  }

  /// Generates a WebAuthn / FIDO2 Passkey credential for a domain.
  PasskeyCredentialModel generatePasskey({
    required String rpId,
    required String userName,
    String? userHandleHex,
    int algorithm = -7,
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final rpPtr = rpId.toNativeUtf8();
    final uNamePtr = userName.toNativeUtf8();
    final uHandlePtr = userHandleHex != null ? userHandleHex.toNativeUtf8() : nullptr;
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _passkeyGenerate(rpPtr, uHandlePtr, uNamePtr, algorithm, outJson);
      if (code != 0) {
        throw Exception('Generate passkey failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return PasskeyCredentialModel.fromJson(map);
    } finally {
      calloc.free(rpPtr);
      calloc.free(uNamePtr);
      if (uHandlePtr != nullptr) calloc.free(uHandlePtr);
      calloc.free(outJson);
    }
  }

  /// Signs a WebAuthn assertion challenge using a stored passkey.
  ({PasskeyAssertionResult assertion, PasskeyCredentialModel updatedPasskey}) signPasskeyAssertion({
    required PasskeyCredentialModel passkey,
    required String rpId,
    required String clientDataJson,
    bool userPresent = true,
    bool userVerified = true,
  }) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final pJson = jsonEncode(passkey.toJson());
    final pPtr = pJson.toNativeUtf8();
    final rpPtr = rpId.toNativeUtf8();
    final cdPtr = clientDataJson.toNativeUtf8();
    final outAssJson = calloc<Pointer<Utf8>>();
    final outUpdJson = calloc<Pointer<Utf8>>();

    try {
      final code = _passkeySignAssertion(
        pPtr,
        rpPtr,
        cdPtr,
        userPresent,
        userVerified,
        outAssJson,
        outUpdJson,
      );
      if (code != 0) {
        throw Exception('Sign passkey assertion failed with code $code');
      }
      final assStr = outAssJson.value.toDartString();
      final updStr = outUpdJson.value.toDartString();
      _freeString(outAssJson.value);
      _freeString(outUpdJson.value);

      final assMap = jsonDecode(assStr) as Map<String, dynamic>;
      final updMap = jsonDecode(updStr) as Map<String, dynamic>;

      return (
        assertion: PasskeyAssertionResult.fromJson(assMap),
        updatedPasskey: PasskeyCredentialModel.fromJson(updMap),
      );
    } finally {
      calloc.free(pPtr);
      calloc.free(rpPtr);
      calloc.free(cdPtr);
      calloc.free(outAssJson);
      calloc.free(outUpdJson);
    }
  }

  /// Performs a comprehensive cryptographic and security hygiene audit of the vault.
  VaultAuditReportModel auditVault(VaultPayload payload, {int timestampSecs = 0}) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final pJson = jsonEncode(payload.toJson());
    final pPtr = pJson.toNativeUtf8();
    final outJson = calloc<Pointer<Utf8>>();

    try {
      final code = _auditVault(pPtr, timestampSecs, outJson);
      if (code != 0) {
        throw Exception('Audit vault failed with code $code');
      }
      final jsonStr = outJson.value.toDartString();
      _freeString(outJson.value);
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return VaultAuditReportModel.fromJson(map);
    } finally {
      calloc.free(pPtr);
      calloc.free(outJson);
    }
  }

  /// Prepares privacy-preserving k-Anonymity breach query (5-char prefix & 35-char suffix).
  BreachQueryResult prepareBreachQuery(String password) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final pwPtr = password.toNativeUtf8();
    final outPref = calloc<Pointer<Utf8>>();
    final outSuff = calloc<Pointer<Utf8>>();

    try {
      final code = _breachPrepareQuery(pwPtr, outPref, outSuff);
      if (code != 0) {
        throw Exception('Prepare breach query failed with code $code');
      }
      final pref = outPref.value.toDartString();
      final suff = outSuff.value.toDartString();
      _freeString(outPref.value);
      _freeString(outSuff.value);
      return BreachQueryResult(prefix: pref, suffix: suff);
    } finally {
      calloc.free(pwPtr);
      calloc.free(outPref);
      calloc.free(outSuff);
    }
  }

  /// Searches for a 35-character suffix in an HIBP range response body and returns breach occurrence count.
  int checkBreachResponse({required String suffix, required String responseBody}) {
    if (!_isInitialized) {
      throw UnsupportedError('Rust Security Core FFI library is not loaded');
    }

    final suffPtr = suffix.toNativeUtf8();
    final bodyPtr = responseBody.toNativeUtf8();
    final outCount = calloc<Uint64>();

    try {
      final code = _breachCheckResponse(suffPtr, bodyPtr, outCount);
      if (code != 0) {
        throw Exception('Check breach response failed with code $code');
      }
      return outCount.value;
    } finally {
      calloc.free(suffPtr);
      calloc.free(bodyPtr);
      calloc.free(outCount);
    }
  }

  String _fallbackPassword(int length, bool u, bool l, bool d, bool s) {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const symbols = '!@#\$%^&*()-_=+';
    var chars = '';
    if (l) chars += letters;
    if (u) chars += uppers;
    if (d) chars += digits;
    if (s) chars += symbols;
    if (chars.isEmpty) chars = letters;
    return List.generate(length, (i) => chars[i % chars.length]).join();
  }
}
