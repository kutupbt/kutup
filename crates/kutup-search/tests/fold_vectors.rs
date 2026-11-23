//! The search fold's vectors (tests/vectors/fold.json): what
//! `kutup_search::fold` gives for a corpus of hard cases, so the browser's
//! fold (the `browser` feature: `String.prototype.normalize`, checked by
//! scripts/test-pass-wasm.mjs) can be held to the native one.

use serde::{Deserialize, Serialize};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fold.json");

/// Turkish I's, accents, ligatures, fullwidth and compatibility forms,
/// final sigma, Hangul, marks in several scripts, emoji sequences.
const INPUTS: &[&str] = &[
    "İSTANBUL istanbul Istanbul ıIiİ",
    "ÇAĞRI çağrı Şeker ŞEKER Öğün ÖĞÜN Ümit ümit Gıda GIDA",
    "Crème brûlée, Ångström, São Paulo, Smørrebrød, Łódź, Dvořák",
    "ﬁne ﬂow ﬀ ﬃ ﬄ ﬅ Æsir œuvre Straße STRASSE",
    "ＡＢＣ１２３ ａｂｃ　ｘｙｚ ｶﾀｶﾅ",
    "x² H₂O ½ ¾ ™ ℃ ㎏ № Ⅻ ⅻ ①",
    "ΆΈΉΊΌΎΏ Σίσυφος ΣΊΣΥΦΟΣ άλφα",
    "Йй Ёё Ўў Ї ї",
    "Tiếng Việt Hà Nội Đà Nẵng",
    "한국어 가나다",
    "مَرْحَبًا بِكُمْ",
    "שָׁלוֹם",
    "हिन्दी नमस्ते",
    "e\u{301} a\u{308}\u{301} Z\u{334}\u{335}\u{336}a\u{337}l\u{338}g\u{339}o",
    "👩🏽‍💻 🇹🇷 ❤️ 1️⃣",
    "ǅ ǈ ǋ ǲ ſ ẞ ﬆ",
    "ÀÉÎÕÜ àéîõü Ññ Çç",
    "Ⓐⓑ ℌ ℍ 𝔄𝔅 𝐀𝐁 ㈜ ㍿",
    "",
    "plain ascii TEXT 123 !@#",
];

#[derive(Serialize, Deserialize)]
struct Case {
    text: String,
    folded: String,
}

#[derive(Serialize, Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

fn cases() -> Vec<Case> {
    INPUTS
        .iter()
        .map(|text| Case {
            text: (*text).into(),
            folded: kutup_search::fold(text),
        })
        .collect()
}

#[test]
fn the_fold_matches_its_vectors() {
    let file: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let now = cases();
    assert_eq!(file.cases.len(), now.len(), "write the vectors again");
    for (stored, case) in file.cases.iter().zip(&now) {
        assert_eq!(stored.text, case.text, "write the vectors again");
        assert_eq!(stored.folded, case.folded, "fold({:?})", case.text);
    }
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_FOLD_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let json = serde_json::to_string_pretty(&Vectors { cases: cases() }).unwrap();
    std::fs::write(PATH, format!("{json}\n")).unwrap();
}
