use crate::error::VaultError;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Storage engine managing ACID atomic writes and safety backup retention.
pub struct VaultStorage;

impl VaultStorage {
    /// Commits encrypted vault bytes atomically to physical storage.
    ///
    /// 1. Writes bytes to temporary file `path.tmp`.
    /// 2. Flushes data and filesystem metadata to storage media (`sync_all`).
    /// 3. Backs up existing file to `path.backup` if present.
    /// 4. Atomically replaces target file.
    pub fn save_atomic(target_path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
        let parent = target_path.parent().ok_or_else(|| {
            VaultError::SerializationError("Target path has no parent directory".into())
        })?;

        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                VaultError::SerializationError(format!("Failed to create parent directory: {}", e))
            })?;
        }

        let tmp_path = Self::temp_path(target_path);
        let backup_path = Self::backup_path(target_path);

        // 1. Write to temporary file
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                VaultError::SerializationError(format!("Failed to open temp file: {}", e))
            })?;

        tmp_file.write_all(bytes).map_err(|e| {
            VaultError::SerializationError(format!("Failed to write temp file: {}", e))
        })?;

        // 2. Explicit flush and fsync
        tmp_file.sync_all().map_err(|e| {
            VaultError::SerializationError(format!("Failed to fsync temp file: {}", e))
        })?;
        drop(tmp_file);

        // 3. Backup existing target file if present
        if target_path.exists() {
            let _ = fs::copy(target_path, &backup_path);
        }

        // 4. Atomic rename / replace
        #[cfg(windows)]
        {
            // On Windows, rename fails if destination exists unless removed first
            if target_path.exists() {
                let _ = fs::remove_file(target_path);
            }
            if let Err(e) = fs::rename(&tmp_path, target_path) {
                // If rename failed, try to restore from backup
                if backup_path.exists() && !target_path.exists() {
                    let _ = fs::copy(&backup_path, target_path);
                }
                let _ = fs::remove_file(&tmp_path);
                return Err(VaultError::SerializationError(format!(
                    "Atomic rename failed: {}",
                    e
                )));
            }
        }

        #[cfg(not(windows))]
        {
            if let Err(e) = fs::rename(&tmp_path, target_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(VaultError::SerializationError(format!(
                    "Atomic rename failed: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    /// Reads raw vault bytes from disk.
    pub fn load(path: &Path) -> Result<Vec<u8>, VaultError> {
        fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::TruncatedData
            } else {
                VaultError::SerializationError(format!("Failed to read vault file: {}", e))
            }
        })
    }

    /// Loads vault bytes from the primary path, automatically falling back to safety backup if primary is missing or empty.
    pub fn load_with_recovery_fallback(path: &Path) -> Result<Vec<u8>, VaultError> {
        if path.exists() {
            if let Ok(bytes) = fs::read(path) {
                if !bytes.is_empty() {
                    return Ok(bytes);
                }
            }
        }

        // Fallback to backup
        let backup_path = Self::backup_path(path);
        if backup_path.exists() {
            if let Ok(bytes) = fs::read(&backup_path) {
                if !bytes.is_empty() {
                    return Ok(bytes);
                }
            }
        }

        Err(VaultError::TruncatedData)
    }

    fn temp_path(path: &Path) -> PathBuf {
        let mut p = path.to_path_buf();
        let file_name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        p.set_file_name(format!("{}.tmp", file_name));
        p
    }

    fn backup_path(path: &Path) -> PathBuf {
        let mut p = path.to_path_buf();
        let file_name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        p.set_file_name(format!("{}.backup", file_name));
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_save_and_load() {
        let temp_dir = std::env::temp_dir().join(format!("pwdvault_test_{}", std::process::id()));
        let vault_file = temp_dir.join("test_vault.v1");

        let initial_data = b"initial-vault-payload-data-v1";
        VaultStorage::save_atomic(&vault_file, initial_data).unwrap();

        assert!(vault_file.exists());
        let loaded = VaultStorage::load(&vault_file).unwrap();
        assert_eq!(loaded, initial_data);

        // Update data -> should create .backup and replace target
        let updated_data = b"updated-vault-payload-data-v2";
        VaultStorage::save_atomic(&vault_file, updated_data).unwrap();

        let loaded_updated = VaultStorage::load(&vault_file).unwrap();
        assert_eq!(loaded_updated, updated_data);

        let backup_file = VaultStorage::backup_path(&vault_file);
        assert!(backup_file.exists());
        let backup_data = fs::read(&backup_file).unwrap();
        assert_eq!(backup_data, initial_data);

        // Test fallback when primary is deleted
        fs::remove_file(&vault_file).unwrap();
        let fallback_loaded = VaultStorage::load_with_recovery_fallback(&vault_file).unwrap();
        assert_eq!(fallback_loaded, initial_data);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
