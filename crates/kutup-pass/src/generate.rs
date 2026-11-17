//! Passwords and passphrases for the `kutup` CLI (docs/plans/pass-gaps-3.md,
//! B2), by the website generator's rules (`frontend/apps/pass/src/lib/
//! generator.ts`, `passphrase.ts`): chosen character sets with at least one
//! of each, also-use and never-use characters, look-alikes left out if
//! asked; or words from the EFF large list (CC BY 3.0,
//! https://www.eff.org/dice). Every choice is `kutup_crypto`'s
//! `random_below`, without modulo bias.

use kutup_crypto::primitives::random_below;

/// The EFF large word list, the same file the website serves (a test keeps
/// the two equal).
const WORDLIST: &str = include_str!("wordlists/eff_large.txt");
pub const WORDLIST_SIZE: usize = 7776;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&*+-.:;=?@^_~";
const LOOK_ALIKES: &str = "0O1lI|";

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 128;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSpec {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_look_alikes: bool,
    /// More characters, as their own set.
    pub custom: String,
    /// Characters never used.
    pub exclude: String,
}

impl Default for PasswordSpec {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_look_alikes: false,
            custom: String::new(),
            exclude: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCase {
    Lower,
    First,
    Random,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseSpec {
    pub words: usize,
    pub separator: String,
    pub case: WordCase,
    pub add_number: bool,
    pub add_symbol: bool,
}

impl Default for PassphraseSpec {
    fn default() -> Self {
        Self {
            words: 7,
            separator: "-".into(),
            case: WordCase::Lower,
            add_number: false,
            add_symbol: false,
        }
    }
}

fn below(n: usize) -> usize {
    random_below(n as u64) as usize
}

/// The sets a password draws from, as the website makes them.
pub fn character_sets(spec: &PasswordSpec) -> Vec<Vec<char>> {
    let keep = |c: &char| {
        !spec.exclude.contains(*c)
            && !(spec.avoid_look_alikes && LOOK_ALIKES.contains(*c))
            && !c.is_whitespace()
    };
    let chosen = [
        (spec.lower, LOWER),
        (spec.upper, UPPER),
        (spec.digits, DIGITS),
        (spec.symbols, SYMBOLS),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut sets = Vec::new();
    for set in chosen
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| *set)
        .chain(std::iter::once(spec.custom.as_str()))
    {
        let chars: Vec<char> = set.chars().filter(|c| keep(c) && seen.insert(*c)).collect();
        if !chars.is_empty() {
            sets.push(chars);
        }
    }
    sets
}

/// A password, or `None` when no character is left to choose from.
pub fn password(spec: &PasswordSpec) -> Option<String> {
    let sets = character_sets(spec);
    if sets.is_empty() {
        return None;
    }
    let length = spec.length.clamp(MIN_LENGTH, MAX_LENGTH).max(sets.len());
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let mut chars: Vec<char> = sets.iter().map(|set| set[below(set.len())]).collect();
    while chars.len() < length {
        chars.push(all[below(all.len())]);
    }
    // Fisher–Yates, so the required characters are anywhere.
    for i in (1..chars.len()).rev() {
        chars.swap(i, below(i + 1));
    }
    Some(chars.into_iter().collect())
}

/// The word list's words.
pub fn words() -> Vec<&'static str> {
    WORDLIST.lines().filter(|w| !w.is_empty()).collect()
}

/// A passphrase.
pub fn passphrase(spec: &PassphraseSpec) -> String {
    let list = words();
    let count = spec.words.clamp(MIN_WORDS, MAX_WORDS);
    let mut out: Vec<String> = (0..count)
        .map(|_| {
            let word = list[below(list.len())];
            let capital = match spec.case {
                WordCase::Lower => false,
                WordCase::First => true,
                WordCase::Random => below(2) == 1,
            };
            if capital {
                let mut chars = word.chars();
                chars
                    .next()
                    .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                    .unwrap_or_default()
            } else {
                word.to_owned()
            }
        })
        .collect();
    if spec.add_number {
        let at = below(count);
        out[at].push(char::from(b'0' + below(10) as u8));
    }
    if spec.add_symbol {
        let at = below(count);
        let symbols: Vec<char> = SYMBOLS.chars().collect();
        out[at].push(symbols[below(symbols.len())]);
    }
    out.join(&spec.separator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_is_the_websites() {
        let list = words();
        assert_eq!(list.len(), WORDLIST_SIZE);
        assert_eq!(
            list.iter().collect::<std::collections::HashSet<_>>().len(),
            WORDLIST_SIZE
        );
        let served = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../frontend/apps/pass/public/wordlists/eff_large.txt"
        ));
        // Where the frontend is beside the crate (the repository), it is the same file.
        if let Ok(served) = served {
            assert_eq!(served, WORDLIST);
        }
    }

    #[test]
    fn passwords_follow_the_spec() {
        let spec = PasswordSpec {
            length: 12,
            upper: false,
            digits: false,
            symbols: false,
            custom: "çğ ş".into(),
            exclude: "aeiou".into(),
            ..PasswordSpec::default()
        };
        for _ in 0..50 {
            let p = password(&spec).unwrap();
            assert_eq!(p.chars().count(), 12);
            assert!(!p.contains(['a', 'e', 'i', 'o', 'u']));
            assert!(p.contains(['ç', 'ğ', 'ş']));
        }
        assert_eq!(
            password(&PasswordSpec {
                length: 1000,
                ..PasswordSpec::default()
            })
            .unwrap()
            .chars()
            .count(),
            MAX_LENGTH
        );
        let none = PasswordSpec {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..PasswordSpec::default()
        };
        assert_eq!(password(&none), None);
    }

    #[test]
    fn passphrases_are_list_words() {
        let list: std::collections::HashSet<&str> = words().into_iter().collect();
        // A space between them: some list words hold a hyphen ("drop-down").
        let p = passphrase(&PassphraseSpec {
            separator: " ".into(),
            ..PassphraseSpec::default()
        });
        let parts: Vec<&str> = p.split(' ').collect();
        assert_eq!(parts.len(), 7);
        assert!(parts.iter().all(|w| list.contains(w)));
        let first = passphrase(&PassphraseSpec {
            words: 4,
            separator: " ".into(),
            case: WordCase::First,
            ..PassphraseSpec::default()
        });
        assert!(first
            .split(' ')
            .all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
    }
}
