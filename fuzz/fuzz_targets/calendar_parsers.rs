#![no_main]

//! Calendar text a server and every client read from others (docs/plans/
//! calendar.md): an `RRULE` in any spelling, the canonical rule, an event's
//! shared signed part, and the series it makes, whose expansion must end.

use kutup_crypto::calendar_event::SharedSigned;
use kutup_crypto::calendar_recurrence::Rule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(rule) = Rule::read(text) {
        // Whatever reads writes canonically, and the canonical text reads
        // back as the same rule.
        assert_eq!(Rule::parse(&rule.write()).ok().as_ref(), Some(&rule));
    }
    let _ = Rule::parse(text);
    if let Ok(part) = SharedSigned::parse(text) {
        let series = part.series().expect("a parsed part is a series");
        // Bounded: no rule runs past 2037.
        let _ = series.range_end();
        let _ = series.occurrences().take(10_000).count();
    }
});
