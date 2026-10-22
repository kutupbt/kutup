//! Recurrence vectors (docs/plans/calendar.md, E2): RFC 5545 §3.8.5.3's
//! examples in Proton's subset and Kutup's own cases, each rule read as
//! written, and its occurrences as python-dateutil (an independent RFC 5545
//! implementation) expands them on the wall clock of DTSTART's zone
//! (`scripts/generate-calendar-recurrence-vectors.py`). The same file runs in
//! the browser through `scripts/test-crypto-wasm.mjs`.

use serde::Deserialize;

use kutup_crypto::calendar_event::EventTime;
use kutup_crypto::calendar_recurrence::{Rule, Series};

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    rule: String,
    take: usize,
    start: Start,
    local: Vec<String>,
    #[serde(default)]
    utc: Vec<String>,
    /// Wall-clock times in DTSTART's form.
    #[serde(default)]
    exdates: Vec<String>,
    /// A rule refused for its DTSTART (no occurrence, or DTSTART not its
    /// first).
    #[serde(default)]
    refused: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Start {
    Date(String),
    Zoned { local: String, tzid: String },
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors/calendar-recurrence-v1.json")).unwrap()
}

#[test]
fn every_case_expands_as_dateutil_does() {
    for case in vectors().cases {
        let start = match &case.start {
            Start::Date(date) => EventTime::Date(date.parse().unwrap()),
            Start::Zoned { local, tzid } if tzid == "UTC" => {
                EventTime::Utc(format!("{local}Z").parse().unwrap())
            }
            Start::Zoned { local, tzid } => EventTime::Zoned {
                local: local.parse().unwrap(),
                tzid: tzid.clone(),
            },
        };
        let rule = Rule::read(&case.rule).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        // The canonical text reads strictly and gives the same rule.
        assert_eq!(Rule::parse(&rule.write()).unwrap(), rule, "{}", case.name);
        let exdates: Vec<EventTime> = case
            .exdates
            .iter()
            .map(|value| match &start {
                EventTime::Date(_) => EventTime::Date(value.parse().unwrap()),
                EventTime::Utc(_) => EventTime::Utc(format!("{value}Z").parse().unwrap()),
                EventTime::Zoned { tzid, .. } => EventTime::Zoned {
                    local: value.parse().unwrap(),
                    tzid: tzid.clone(),
                },
            })
            .collect();
        let series = Series::new(&start, None, Some(&rule), &exdates);
        if case.refused {
            assert!(series.is_err(), "{} is refused", case.name);
            continue;
        }
        let series = series.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let occurrences: Vec<_> = series
            .occurrences()
            .take(case.take)
            .map(Result::unwrap)
            .collect();
        let local: Vec<String> = occurrences
            .iter()
            .map(|o| match &o.start {
                EventTime::Date(date) => date.to_string(),
                EventTime::Zoned { local, .. } => local.strftime("%Y-%m-%dT%H:%M:%S").to_string(),
                EventTime::Utc(at) => at.strftime("%Y-%m-%dT%H:%M:%S").to_string(),
            })
            .collect();
        assert_eq!(local, case.local, "{}", case.name);
        if !case.utc.is_empty() {
            let utc: Vec<String> = occurrences
                .iter()
                .map(|o| o.start_utc.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
                .collect();
            assert_eq!(utc, case.utc, "{}", case.name);
        }
        // A finite series ends with its last occurrence.
        if rule.count.is_some() || rule.until.is_some() {
            let last = occurrences.last().unwrap();
            assert_eq!(
                series.range_end().unwrap(),
                Some(last.end_utc),
                "{}",
                case.name
            );
        }
    }
}
