use pwdvault_vault::ItemCategory;
use serde::{Deserialize, Serialize};

fn default_limit() -> usize {
    100
}

/// Query parameters for filtering and ranking vault items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Text search query string.
    pub query: String,
    /// Optional filter by item category.
    pub category: Option<ItemCategory>,
    /// Optional filter by tag.
    pub tag: Option<String>,
    /// Filter for only starred/favorite items.
    pub favorites_only: bool,
    /// Maximum count of top ranked results to return (default: 100, 0 for unlimited).
    #[serde(default = "default_limit")]
    pub limit: usize,
}

impl SearchQuery {
    /// Creates a simple text search query with no additional filters.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            category: None,
            tag: None,
            favorites_only: false,
            limit: 100,
        }
    }

    /// Appends a category filter.
    pub fn with_category(mut self, category: ItemCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Appends a tag filter.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Appends a favorites-only filter.
    pub fn favorites_only(mut self) -> Self {
        self.favorites_only = true;
        self
    }

    /// Configures the maximum number of returned results.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

/// A ranked search result item returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    /// Unique item identifier.
    pub item_id: String,
    /// Relevance score (higher is more relevant).
    pub score: u32,
    /// Item title.
    pub title: String,
    /// Username or account identifier if present.
    pub username: Option<String>,
    /// Item category classification.
    pub category: ItemCategory,
    /// Favorite status flag.
    pub favorite: bool,
}
