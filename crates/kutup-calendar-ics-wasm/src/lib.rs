//! Browser bindings for `.ics` files (docs/plans/calendar.md, E2c): the
//! import's reading and rebuild and the export's writing, as
//! `kutup_crypto::calendar_ics` does them. A runtime of its own, loaded the
//! first time a file is imported or exported, so the calendar runtimes don't
//! carry it; E4's invitations (`itip`) in Calendar and Mail load it the same way
//! (docs/plans/calendar-e4.md, Q-4). It holds no key: the events it reads
//! are sealed by the crypto-calendar runtime, and the ones it writes were
//! opened there.

use kutup_crypto::calendar_ics::{export, import, itip};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue, what: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|error| js_error(format!("{what}: {error}")))
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_error)
}

/// Reads an `.ics` file for import (E2 §5): `{"read": {method, events,
/// errors, hidden}}`, each event's fields and reminders rebuilt as Proton's
/// import does, or `{"refused": reason}`.
#[wasm_bindgen(js_name = calendarImportIcs)]
pub fn calendar_import_ics(text: &str, options: JsValue) -> Result<JsValue, JsValue> {
    let options: import::ImportOptionsV1 = from_js(options, "import options")?;
    to_js(&import::import(text, &options).map_err(js_error)?)
}

/// Writes a calendar's events, opened, as one `.ics` file (E2 §6).
#[wasm_bindgen(js_name = calendarExportIcs)]
pub fn calendar_export_ics(calendar: JsValue) -> Result<String, JsValue> {
    let calendar: export::ExportCalendarV1 = from_js(calendar, "export")?;
    export::export(&calendar).map_err(js_error)
}

/// Reads an invitation (E4 §2): `{"read": {method, fields, organizer,
/// attendees, note, …}}` or `{"refused": {error, reason, method}}`.
#[wasm_bindgen(js_name = calendarReadInvitation)]
pub fn calendar_read_invitation(text: &str, options: JsValue) -> Result<JsValue, JsValue> {
    let options: itip::InvitationOptionsV1 = from_js(options, "invitation options")?;
    to_js(&itip::read_invitation(text, &options).map_err(js_error)?)
}

/// Writes a REQUEST, REPLY or CANCEL (E4 §2).
#[wasm_bindgen(js_name = calendarWriteInvitation)]
pub fn calendar_write_invitation(invitation: JsValue) -> Result<String, JsValue> {
    let invitation: itip::WriteInvitationV1 = from_js(invitation, "invitation")?;
    itip::write_invitation(&invitation).map_err(js_error)
}
