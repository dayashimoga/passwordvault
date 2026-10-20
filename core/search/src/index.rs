use crate::query::{SearchQuery, SearchResult};
use pwdvault_vault::{ItemCategory, VaultItem, VaultPayload};
use std::collections::{HashMap, HashSet};

/// Helper to extract clean domain names from URLs.
fn extract_domain(url_str: &str) -> Option<String> {
    let lower = url_str.to_lowercase();
    let without_scheme = if let Some(stripped) = lower.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("http://") {
        stripped
    } else {
        &lower
    };

    let domain = without_scheme.split('/').next()?.split(':').next()?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

/// Helper to generate 3-byte character trigrams from a string.
fn extract_trigrams(text: &str) -> Vec<[u8; 3]> {
    let bytes = text.as_bytes();
    if bytes.len() < 3 {
        return Vec::new();
    }
    let mut trigrams = Vec::with_capacity(bytes.len() - 2);
    for window in bytes.windows(3) {
        trigrams.push([window[0], window[1], window[2]]);
    }
    trigrams
}

/// Metadata stored in memory for indexed searching.
/// Secrets (passwords, notes, keys) are strictly excluded.
#[derive(Debug, Clone)]
struct IndexedEntry {
    id: String,
    title: String,
    title_lower: String,
    username: Option<String>,
    #[allow(dead_code)]
    username_lower: Option<String>,
    category: ItemCategory,
    domains: Vec<String>,
    #[allow(dead_code)]
    tags: Vec<String>,
    tags_lower: Vec<String>,
    favorite: bool,
}

/// In-memory inverted and trigram search index.
#[derive(Debug, Default)]
pub struct SearchIndex {
    entries: Vec<IndexedEntry>,
    id_to_idx: HashMap<String, usize>,
    token_to_indices: HashMap<String, Vec<usize>>,
    prefix_to_indices: HashMap<String, Vec<usize>>,
    trigram_to_indices: HashMap<[u8; 3], Vec<usize>>,
}

impl SearchIndex {
    /// Creates an empty search index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a search index from an unlocked vault payload.
    pub fn from_payload(payload: &VaultPayload) -> Self {
        let mut index = Self::new();
        for item in &payload.items {
            index.insert_item(item);
        }
        index
    }

    /// Inserts a new item into the index.
    pub fn insert_item(&mut self, item: &VaultItem) {
        if self.id_to_idx.contains_key(&item.id) {
            self.remove_item(&item.id);
        }

        let idx = self.entries.len();
        let title_lower = item.title.to_lowercase();
        let username_lower = item.username.as_ref().map(|u| u.to_lowercase());

        let mut domains = Vec::new();
        for url in &item.urls {
            if let Some(dom) = extract_domain(url) {
                domains.push(dom);
            }
        }

        let tags_lower: Vec<String> = item.tags.iter().map(|t| t.to_lowercase()).collect();

        // 1. Index word tokens
        let mut tokens = HashSet::new();
        for token in title_lower.split_whitespace() {
            tokens.insert(token.to_string());
        }
        if let Some(ref u) = username_lower {
            for token in u.split(&['@', '.', '_', '-'][..]) {
                if !token.is_empty() {
                    tokens.insert(token.to_string());
                }
            }
        }
        for dom in &domains {
            tokens.insert(dom.clone());
            for token in dom.split('.') {
                if !token.is_empty() {
                    tokens.insert(token.to_string());
                }
            }
        }
        for tag in &tags_lower {
            tokens.insert(tag.clone());
        }

        for token in &tokens {
            self.token_to_indices
                .entry(token.clone())
                .or_default()
                .push(idx);

            // Index prefixes (1 to 4 chars)
            let chars: Vec<char> = token.chars().collect();
            for len in 1..=chars.len().min(4) {
                let p: String = chars[..len].iter().collect();
                self.prefix_to_indices.entry(p).or_default().push(idx);
            }
        }

        // 2. Index trigrams
        let mut trigrams = HashSet::new();
        for tri in extract_trigrams(&title_lower) {
            trigrams.insert(tri);
        }
        for dom in &domains {
            for tri in extract_trigrams(dom) {
                trigrams.insert(tri);
            }
        }
        for tri in trigrams {
            self.trigram_to_indices.entry(tri).or_default().push(idx);
        }

        let entry = IndexedEntry {
            id: item.id.clone(),
            title: item.title.clone(),
            title_lower,
            username: item.username.clone(),
            username_lower,
            category: item.category.clone(),
            domains,
            tags: item.tags.clone(),
            tags_lower,
            favorite: item.favorite,
        };

        self.id_to_idx.insert(item.id.clone(), idx);
        self.entries.push(entry);
    }

    /// Removes an item by ID.
    pub fn remove_item(&mut self, item_id: &str) {
        if let Some(&idx) = self.id_to_idx.get(item_id) {
            // Soft delete: remove lookup and clear entry ID
            self.entries[idx].id.clear();
            self.id_to_idx.remove(item_id);
        }
    }

    /// Evaluates a query and returns scored results sorted by relevance descending.
    pub fn search(&self, query: &SearchQuery) -> Vec<SearchResult> {
        let total_entries = self.entries.len();
        if total_entries == 0 {
            return Vec::new();
        }

        let q_raw = query.query.trim().to_lowercase();
        let mut scores = vec![0u32; total_entries];
        let mut touched = Vec::with_capacity(1024);

        if q_raw.is_empty() {
            // Empty query returns all entries matching category/tag filters
            for (idx, entry) in self.entries.iter().enumerate() {
                if entry.id.is_empty() {
                    continue;
                }
                scores[idx] = 10 + if entry.favorite { 5 } else { 0 };
                touched.push(idx);
            }
        } else {
            // Collect candidates strictly from inverted index postings
            // 1. Exact token lookups
            for word in q_raw.split_whitespace() {
                if let Some(indices) = self.token_to_indices.get(word) {
                    for &idx in indices {
                        if !self.entries[idx].id.is_empty() {
                            if scores[idx] == 0 {
                                touched.push(idx);
                            }
                            scores[idx] += 200;
                        }
                    }
                }
            }

            // 2. Full query exact token lookup
            if let Some(indices) = self.token_to_indices.get(&q_raw) {
                for &idx in indices {
                    if !self.entries[idx].id.is_empty() {
                        if scores[idx] == 0 {
                            touched.push(idx);
                        }
                        scores[idx] += 300;
                    }
                }
            }

            // 3. Trigram fuzzy / substring lookups
            let q_trigrams = extract_trigrams(&q_raw);
            if !q_trigrams.is_empty() {
                for tri in &q_trigrams {
                    if let Some(indices) = self.trigram_to_indices.get(tri) {
                        for &idx in indices {
                            if !self.entries[idx].id.is_empty() {
                                if scores[idx] == 0 {
                                    touched.push(idx);
                                }
                                scores[idx] += 15;
                            }
                        }
                    }
                }
            } else {
                // Short queries (< 3 chars): use prefix index
                if let Some(indices) = self.prefix_to_indices.get(&q_raw) {
                    for &idx in indices {
                        if !self.entries[idx].id.is_empty() {
                            if scores[idx] == 0 {
                                touched.push(idx);
                            }
                            scores[idx] += 100;
                        }
                    }
                }
            }

            // 4. Boost exact and prefix matches for touched candidates ONLY
            for &idx in &touched {
                let entry = &self.entries[idx];
                if entry.title_lower == q_raw {
                    scores[idx] += 1000;
                } else if entry.title_lower.starts_with(&q_raw) {
                    scores[idx] += 500;
                } else if entry.title_lower.contains(&q_raw) {
                    scores[idx] += 250;
                }

                for dom in &entry.domains {
                    if dom == &q_raw {
                        scores[idx] += 400;
                    } else if dom.contains(&q_raw) {
                        scores[idx] += 150;
                    }
                }
            }
        }

        // Apply filters & construct candidate list
        let mut candidate_list: Vec<(u32, usize)> = Vec::with_capacity(touched.len());
        for idx in touched {
            let entry = &self.entries[idx];
            if entry.id.is_empty() {
                continue;
            }

            // Category filter
            if let Some(ref cat) = query.category {
                if &entry.category != cat {
                    continue;
                }
            }

            // Favorites only filter
            if query.favorites_only && !entry.favorite {
                continue;
            }

            // Tag filter
            if let Some(ref tag) = query.tag {
                let tag_lower = tag.to_lowercase();
                if !entry.tags_lower.contains(&tag_lower) {
                    continue;
                }
            }

            let mut final_score = scores[idx];
            if entry.favorite {
                final_score += 20;
            }

            candidate_list.push((final_score, idx));
        }

        // Sort descending by score, tiebreak by entry idx
        candidate_list.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        // Truncate to limit before materializing SearchResult strings
        let limit = if query.limit == 0 {
            candidate_list.len()
        } else {
            query.limit
        };
        candidate_list.truncate(limit);

        // Materialize SearchResult only for the winning candidates
        let mut results = Vec::with_capacity(candidate_list.len());
        for (score, idx) in candidate_list {
            let entry = &self.entries[idx];
            results.push(SearchResult {
                item_id: entry.id.clone(),
                score,
                title: entry.title.clone(),
                username: entry.username.clone(),
                category: entry.category.clone(),
                favorite: entry.favorite,
            });
        }

        results
    }

    /// Total count of indexed entries.
    pub fn len(&self) -> usize {
        self.id_to_idx.len()
    }

    /// Whether index is empty.
    pub fn is_empty(&self) -> bool {
        self.id_to_idx.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_item(
        id: &str,
        title: &str,
        username: Option<&str>,
        urls: Vec<&str>,
        tags: Vec<&str>,
    ) -> VaultItem {
        VaultItem {
            id: id.to_string(),
            title: title.to_string(),
            category: ItemCategory::Login,
            username: username.map(|u| u.to_string()),
            password: Some("secret123".to_string()),
            urls: urls.into_iter().map(|u| u.to_string()).collect(),
            notes: Some("sample note".to_string()),
            totp_seed: None,
            tags: tags.into_iter().map(|t| t.to_string()).collect(),
            favorite: false,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            revision_history: Vec::new(),
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[test]
    fn test_search_exact_and_prefix() {
        let mut index = SearchIndex::new();
        index.insert_item(&sample_item(
            "1",
            "GitHub",
            Some("octocat"),
            vec!["https://github.com"],
            vec!["dev"],
        ));
        index.insert_item(&sample_item(
            "2",
            "Google Mail",
            Some("user@gmail.com"),
            vec!["https://mail.google.com"],
            vec!["email"],
        ));
        index.insert_item(&sample_item(
            "3",
            "GitLab",
            Some("dev_user"),
            vec!["https://gitlab.com"],
            vec!["dev"],
        ));

        // Search "github" -> GitHub must be #1 by a wide margin
        let res = index.search(&SearchQuery::new("github"));
        assert!(!res.is_empty());
        assert_eq!(res[0].item_id, "1");
        if res.len() > 1 {
            assert!(res[0].score > res[1].score);
        }

        // Prefix search "git" -> should rank GitHub and GitLab
        let res_git = index.search(&SearchQuery::new("git"));
        assert!(res_git.len() >= 2);
        assert!(res_git.iter().any(|r| r.item_id == "1"));
        assert!(res_git.iter().any(|r| r.item_id == "3"));

        // Domain search "google.com"
        let res_google = index.search(&SearchQuery::new("google.com"));
        assert_eq!(res_google[0].item_id, "2");
    }

    #[test]
    fn test_search_tag_and_category_filter() {
        let mut index = SearchIndex::new();
        let mut item1 = sample_item(
            "1",
            "ProtonMail",
            Some("user"),
            vec![],
            vec!["privacy", "email"],
        );
        item1.favorite = true;
        let item2 = sample_item("2", "Fastmail", Some("user"), vec![], vec!["email"]);

        index.insert_item(&item1);
        index.insert_item(&item2);

        // Filter by tag "privacy"
        let res_privacy = index.search(&SearchQuery::new("").with_tag("privacy"));
        assert_eq!(res_privacy.len(), 1);
        assert_eq!(res_privacy[0].item_id, "1");

        // Favorites only
        let res_fav = index.search(&SearchQuery::new("").favorites_only());
        assert_eq!(res_fav.len(), 1);
        assert_eq!(res_fav[0].item_id, "1");
    }
}
