use serde::{Deserialize, Serialize};

/// Supported item categories in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemCategory {
    /// Web login / app credentials.
    Login,
    /// Encrypted markdown or plaintext note.
    SecureNote,
    /// Credit or debit payment card details.
    PaymentCard,
    /// Personal identity credentials.
    Identity,
    /// Multi-code account recovery codes.
    RecoveryCode,
}

/// Field data types for custom fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    /// Plain text string.
    Text,
    /// Masked / hidden secret string.
    Concealed,
    /// Boolean toggle flag.
    Boolean,
    /// ISO 8601 date string.
    Date,
}

/// Generic custom key-value field attached to a vault item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    /// Field display label.
    pub name: String,
    /// Field value.
    pub value: String,
    /// Field data type.
    pub field_type: FieldType,
}

/// Encrypted snapshot of an item's prior revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRevision {
    /// Unix timestamp when this snapshot was created.
    pub timestamp: u64,
    /// Historical title.
    pub title: String,
    /// Historical username.
    pub username: Option<String>,
    /// Historical password.
    pub password: Option<String>,
    /// Historical URLs.
    pub urls: Vec<String>,
    /// Historical secure notes.
    pub notes: Option<String>,
    /// Historical custom fields.
    pub custom_fields: Vec<CustomField>,
}

/// Bounded file attachment metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// Unique attachment identifier.
    pub id: String,
    /// Original file name.
    pub file_name: String,
    /// MIME content type.
    pub mime_type: String,
    /// Size in bytes (bounded to maximum 10 MiB).
    pub size_bytes: usize,
    /// BLAKE3 checksum of decrypted content.
    pub checksum_blake3: [u8; 32],
    /// 24-byte extended nonce used for attachment AEAD encryption.
    pub nonce: [u8; 24],
}

/// Strongly-typed vault record entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    /// Unique item identifier (UUID v4).
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Item category classification.
    pub category: ItemCategory,
    /// Username or account identifier.
    pub username: Option<String>,
    /// Secret password.
    pub password: Option<String>,
    /// Target URLs or web domains.
    pub urls: Vec<String>,
    /// Secure markdown or plaintext notes.
    pub notes: Option<String>,
    /// Base32 encoded TOTP seed secret.
    pub totp_seed: Option<String>,
    /// Categorization tags.
    pub tags: Vec<String>,
    /// Favorite status flag.
    pub favorite: bool,
    /// Custom key-value fields.
    pub custom_fields: Vec<CustomField>,
    /// Bounded file attachment metadata.
    pub attachments: Vec<AttachmentMeta>,
    /// Historical revision snapshots for password recovery.
    pub revision_history: Vec<ItemRevision>,
    /// Timestamp when item was moved to trash (None if active).
    pub trashed_at: Option<u64>,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Last updated timestamp (Unix epoch seconds).
    pub updated_at: u64,
}

impl VaultItem {
    /// Creates a snapshot of the current state for revision history.
    pub fn create_revision(&self, timestamp: u64) -> ItemRevision {
        ItemRevision {
            timestamp,
            title: self.title.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            urls: self.urls.clone(),
            notes: self.notes.clone(),
            custom_fields: self.custom_fields.clone(),
        }
    }
}

/// Root decrypted payload representing the full in-memory vault database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPayload {
    /// Schema version for migrations.
    pub schema_version: u32,
    /// User-friendly vault display name.
    pub vault_name: String,
    /// List of encrypted items.
    pub items: Vec<VaultItem>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last update timestamp.
    pub updated_at: u64,
}

impl VaultPayload {
    /// Creates a new empty `VaultPayload` with the specified name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            vault_name: name.into(),
            items: Vec::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    /// Finds an active (non-trashed) item by ID.
    pub fn get_active_item(&self, id: &str) -> Option<&VaultItem> {
        self.items
            .iter()
            .find(|item| item.id == id && item.trashed_at.is_none())
    }

    /// Finds any item (including trashed) by ID.
    pub fn get_item(&self, id: &str) -> Option<&VaultItem> {
        self.items.iter().find(|item| item.id == id)
    }

    /// Adds a new item to the vault payload.
    pub fn add_item(&mut self, item: VaultItem) {
        self.items.push(item);
    }

    /// Moves an item to the encrypted trash bin.
    pub fn trash_item(&mut self, id: &str, timestamp: u64) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.trashed_at = Some(timestamp);
            item.updated_at = timestamp;
            true
        } else {
            false
        }
    }

    /// Restores an item from the trash bin.
    pub fn restore_item(&mut self, id: &str, timestamp: u64) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.trashed_at = None;
            item.updated_at = timestamp;
            true
        } else {
            false
        }
    }

    /// Permanently deletes an item from the vault.
    pub fn delete_permanently(&mut self, id: &str) -> bool {
        if let Some(pos) = self.items.iter().position(|i| i.id == id) {
            self.items.remove(pos);
            true
        } else {
            false
        }
    }

    /// Empties all items currently in the trash bin.
    pub fn empty_trash(&mut self) -> usize {
        let original_len = self.items.len();
        self.items.retain(|item| item.trashed_at.is_none());
        original_len - self.items.len()
    }
}
