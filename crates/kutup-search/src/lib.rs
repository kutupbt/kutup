//! Kutup's word index (docs/plans/mail-body-search.md).
//!
//! Words are folded first ([`fold`]): İ, I, ı and i all become i, accents are
//! removed and everything is lowercased, so "istanbul" finds "İstanbul" and
//! "cagri" finds "çağrı". A query word matches every indexed word it begins
//! ("kitap" finds "kitaplar"); every query word must match.
//!
//! The index ([`Index`]) is Chat's layout (`kutup-chat-core/src/search.rs`)
//! over named records the caller keeps sealed: time is split into 30-day
//! periods; each period has a table of its documents and, per three-letter
//! word start, a shard from words to the documents holding them. A new
//! document rewrites only its period's table and its words' shards; a query
//! reads periods newest first and can stop once it has enough.
//!
//! Storage is the caller's and may be asynchronous (IndexedDB), so each
//! change or query comes in two steps: `plan_*` names the records it needs,
//! the caller loads them, and the step itself returns the records it
//! changed, for the caller to seal and store with the directory.

mod index;

pub use index::{
    Hit, Index, NewDoc, Records, SearchError, BUCKET_MS, DIRECTORY_KEY, INDEX_VERSION,
};

use std::collections::BTreeSet;

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// Longer words are cut to this many characters (a query word is too).
pub const MAX_WORD_CHARS: usize = 64;

/// Folds text for searching: Turkish dotted and dotless I to i, accents
/// removed (canonical decomposition, combining marks dropped), lowercase.
pub fn fold(text: &str) -> String {
    let turkish: String = text
        .chars()
        .map(|c| match c {
            'İ' | 'I' | 'ı' => 'i',
            other => other,
        })
        .collect();
    turkish
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .collect()
}

/// The distinct folded words of `text`: runs of letters and digits.
pub fn words(text: &str) -> Vec<String> {
    let folded = fold(text);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for word in folded.split(|c: char| !c.is_alphanumeric()) {
        if word.is_empty() {
            continue;
        }
        let word: String = word.chars().take(MAX_WORD_CHARS).collect();
        if seen.insert(word.clone()) {
            out.push(word);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_turkish_and_accents() {
        assert_eq!(fold("İSTANBUL Iğdır"), "istanbul igdir");
        assert_eq!(fold("Çağrı ŞÖLEN"), "cagri solen");
        assert_eq!(fold("Café Ñandú"), "cafe nandu");
    }

    /// The vectors Chat's index and its web client are held to.
    #[test]
    fn folding_matches_the_shared_vectors() {
        #[derive(serde::Deserialize)]
        struct Vectors {
            cases: Vec<Case>,
        }
        #[derive(serde::Deserialize)]
        struct Case {
            input: String,
            folded: String,
            words: Vec<String>,
        }
        let vectors: Vectors = serde_json::from_str(include_str!(
            "../../kutup-chat-core/tests/vectors/search_fold.json"
        ))
        .unwrap();
        for case in vectors.cases {
            assert_eq!(fold(&case.input), case.folded, "fold {:?}", case.input);
            assert_eq!(words(&case.input), case.words, "words {:?}", case.input);
        }
    }

    #[test]
    fn words_are_distinct_folded_runs() {
        assert_eq!(
            words("Fatura, fatura! 2026-10 FATURA"),
            ["fatura", "2026", "10"]
        );
        assert_eq!(words("—"), Vec::<String>::new());
        assert_eq!(words(&"a".repeat(100))[0].chars().count(), MAX_WORD_CHARS);
    }
}
