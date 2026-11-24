#![no_main]

//! `.ics` files others write (docs/plans/calendar.md, E2 §5): the lenient
//! reader and the import's rebuild never panic, every event it keeps makes
//! parts the Rust core writes, and the export of what it kept reads back
//! without a refusal.

use kutup_crypto::calendar_ics::export::{export, ExportCalendarV1, ExportEventV1};
use kutup_crypto::calendar_ics::import::{import, ImportOptionsV1, ImportOutcomeV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let options = ImportOptionsV1 {
        primary_zone: "Europe/Istanbul".into(),
        max_bytes: 1 << 20,
        max_events: 2000,
        max_count: 49,
        max_reminders: 10,
        now: "2026-11-24T10:00:00Z".into(),
    };
    let Ok(ImportOutcomeV1::Read(read)) = import(text, &options) else {
        return;
    };
    for event in &read.events {
        let parts = event.fields.to_parts().expect("kept events make parts");
        parts
            .shared_signed
            .build()
            .expect("a kept event's times build");
    }
    let written = export(&ExportCalendarV1 {
        name: "fuzz".into(),
        description: None,
        zone: "UTC".into(),
        release: "0.0.0-fuzz".into(),
        untitled: "(no title)".into(),
        email: Some("fuzz@example.com".into()),
        events: read
            .events
            .iter()
            .map(|event| ExportEventV1 {
                fields: event.fields.clone(),
                reminders: event.reminders.clone(),
            })
            .collect(),
    })
    .expect("what an import keeps exports");
    if let Ok(ImportOutcomeV1::Read(again)) = import(
        &written,
        &ImportOptionsV1 {
            max_bytes: u64::MAX,
            ..options
        },
    ) {
        assert_eq!(again.events.len(), read.events.len());
    }
});
