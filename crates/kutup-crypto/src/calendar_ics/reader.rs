//! The lenient reader: an iCalendar text as others write it, read into a
//! tree of components and properties, repairing what Proton's
//! `vcalRecovery.ts` and `icsSurgery/ics.ts` repair:
//!
//! - any line ending (`\r\n`, `\n`, a lone `\r`), a byte-order mark, blank
//!   lines;
//! - folding with a space or a tab, and lines folded without one
//!   (`reformatLineBreaks`): a line that isn't a content line continues the
//!   one before it;
//! - a missing `BEGIN:VCALENDAR` / `END:VCALENDAR` (`reformatVcalEnclosing`),
//!   and several calendars in one file, read as one;
//! - names in any case; parameter values quoted or not.
//!
//! Values are kept as written: [`super::value`] reads them, as leniently.
//! A component left open, or closed by another's `END`, is kept as
//! [`Node::Broken`] so the import reports it, and the rest of the file is
//! still read (Proton's `parseVcalendarWithRecoveryAndMaybeErrors`).

use crate::primitives::{Hasher, Suite};

/// Components nest at most this deep (VCALENDAR, VEVENT, VALARM, and room
/// for others' extensions); deeper ones are skipped.
const MAX_DEPTH: usize = 6;

/// A property's parameter: its name (upper case) and values (unquoted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub values: Vec<String>,
}

/// One content line: the name in upper case, the parameters, and the value
/// as written (not unescaped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    pub params: Vec<Param>,
    pub value: String,
}

impl Property {
    /// The first value of parameter `name` (upper case).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|param| param.name == name)
            .and_then(|param| param.values.first())
            .map(String::as_str)
    }
}

/// A component: its name in upper case, its properties in order, and its
/// subcomponents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub properties: Vec<Property>,
    pub components: Vec<Node>,
    /// SHA-256 of its unfolded lines, `BEGIN` to `END`: what an event
    /// without a UID is named by (Proton's `generateVeventHashUID`).
    pub digest: [u8; 32],
}

impl Component {
    fn new(name: String) -> Self {
        Component {
            name,
            properties: Vec::new(),
            components: Vec::new(),
            digest: [0; 32],
        }
    }

    /// The first property named `name` (upper case).
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|prop| prop.name == name)
    }

    /// Every property named `name`, in order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> + 'a {
        self.properties.iter().filter(move |prop| prop.name == name)
    }

    /// The subcomponents that read whole, named `name`.
    pub fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Component> + 'a {
        self.components.iter().filter_map(move |node| match node {
            Node::Component(component) if component.name == name => Some(component),
            _ => None,
        })
    }
}

/// A subcomponent: read whole, or not (left open, or closed by another
/// component's `END`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Component(Component),
    Broken { name: String },
}

/// Why a text is not a calendar at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Nothing but white space.
    Empty,
    /// No component, or one that isn't a calendar's (a vCard).
    NotACalendar,
}

/// The components a calendar may hold without its own `BEGIN:VCALENDAR`.
const CALENDAR_PARTS: [&str; 5] = ["VEVENT", "VTODO", "VJOURNAL", "VFREEBUSY", "VTIMEZONE"];

/// RFC 5545 and RFC 7986 property names (Proton's `PROPERTIES`) and RFC
/// 9074's: a line starting with another name followed by `:` or `;`
/// continues a text value it was cut from (below).
const KNOWN: &[&str] = &[
    "ACKNOWLEDGED",
    "ACTION",
    "ATTACH",
    "ATTENDEE",
    "BEGIN",
    "CALSCALE",
    "CATEGORIES",
    "CLASS",
    "COLOR",
    "COMMENT",
    "COMPLETED",
    "CONFERENCE",
    "CONTACT",
    "CREATED",
    "DESCRIPTION",
    "DTEND",
    "DTSTAMP",
    "DTSTART",
    "DUE",
    "DURATION",
    "END",
    "EXDATE",
    "EXRULE",
    "FREEBUSY",
    "GEO",
    "IMAGE",
    "LAST-MODIFIED",
    "LOCATION",
    "METHOD",
    "NAME",
    "ORGANIZER",
    "PERCENT-COMPLETE",
    "PRIORITY",
    "PRODID",
    "PROXIMITY",
    "RDATE",
    "RECURRENCE-ID",
    "REFRESH-INTERVAL",
    "RELATED-TO",
    "REPEAT",
    "REQUEST-STATUS",
    "RESOURCES",
    "RRULE",
    "SEQUENCE",
    "SOURCE",
    "STATUS",
    "SUMMARY",
    "TRANSP",
    "TRIGGER",
    "TZID",
    "TZNAME",
    "TZOFFSETFROM",
    "TZOFFSETTO",
    "TZURL",
    "UID",
    "URL",
    "VERSION",
];

/// Text properties a line cut without folding most often belongs to.
const TEXT: [&str; 5] = [
    "DESCRIPTION",
    "SUMMARY",
    "LOCATION",
    "COMMENT",
    "X-ALT-DESC",
];

/// Reads `text` as one calendar (its components, however many calendars
/// the file joined). The result is a `VCALENDAR`.
pub fn read(text: &str) -> Result<Component, ReadError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim().is_empty() {
        return Err(ReadError::Empty);
    }
    let lines = logical_lines(text);
    let mut builder = Builder::default();
    for line in &lines {
        builder.line(line)?;
    }
    builder.finish()
}

/// The text's content lines, unfolded and repaired.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split('\n').flat_map(|line| line.split('\r')) {
        if let Some(rest) = raw.strip_prefix([' ', '\t']) {
            // Folded (RFC 5545 §3.1): the rest continues the line before.
            if let Some(last) = out.last_mut() {
                last.push_str(rest);
            }
            continue;
        }
        if raw.trim().is_empty() {
            continue;
        }
        match line_name(raw) {
            Some(name) if is_property_name(&name) => out.push(raw.to_owned()),
            // An unknown name after a text value: most likely that value
            // went on after a line break without folding.
            Some(_) if !out.last().is_some_and(|last| continues_text(last)) => {
                out.push(raw.to_owned())
            }
            // Not a content line: folded without the space (Proton's
            // reformatLineBreaks).
            _ => {
                if let Some(last) = out.last_mut() {
                    last.push_str(raw);
                }
            }
        }
    }
    out
}

/// The name a content line starts with, upper case: letters, digits and
/// `-` up to the first `;` or `:`.
fn line_name(line: &str) -> Option<String> {
    let end = line.find([';', ':'])?;
    let name = &line[..end];
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then(|| name.to_ascii_uppercase())
}

fn is_property_name(name: &str) -> bool {
    name.starts_with("X-") || KNOWN.binary_search(&name).is_ok()
}

fn continues_text(line: &str) -> bool {
    line_name(line).is_some_and(|name| TEXT.contains(&name.as_str()))
}

/// Splits a content line into its name, parameters and value: the value
/// starts at the first `:` outside a quoted parameter value.
pub(crate) fn content_line(line: &str) -> Option<Property> {
    let mut quoted = false;
    let mut colon = None;
    for (index, byte) in line.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b':' if !quoted => {
                colon = Some(index);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let mut parts = split_outside_quotes(head, ';').into_iter();
    let name = parts.next()?.trim().to_ascii_uppercase();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    let params = parts
        .filter_map(|param| {
            let (name, values) = param.split_once('=')?;
            let name = name.trim().to_ascii_uppercase();
            if name.is_empty() {
                return None;
            }
            let values = split_outside_quotes(values, ',')
                .into_iter()
                .map(|value| {
                    let value = value.trim();
                    value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(value)
                        .to_owned()
                })
                .collect();
            Some(Param { name, values })
        })
        .collect();
    Some(Property {
        name,
        params,
        value: value.to_owned(),
    })
}

fn split_outside_quotes(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, ch) in text.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == separator && !quoted {
            parts.push(&text[start..index]);
            start = index + ch.len_utf8();
        }
    }
    parts.push(&text[start..]);
    parts
}

/// A component being read and the hash of its lines (children of the
/// calendar only).
struct Open {
    component: Component,
    hasher: Option<Hasher>,
}

#[derive(Default)]
struct Builder {
    root: Option<Component>,
    /// The components open below the root, outermost first.
    open: Vec<Open>,
    /// Components skipped for depth, still open.
    skipped: usize,
    /// The root's own `END` was read (another calendar may follow).
    closed: bool,
}

impl Builder {
    fn line(&mut self, line: &str) -> Result<(), ReadError> {
        let Some(prop) = content_line(line) else {
            // A line that names nothing: dropped.
            return Ok(());
        };
        for open in &mut self.open {
            if let Some(hasher) = &mut open.hasher {
                hasher.update(line.as_bytes());
                hasher.update(b"\r\n");
            }
        }
        match prop.name.as_str() {
            "BEGIN" => self.begin(prop.value.trim().to_ascii_uppercase()),
            "END" => {
                self.end(&prop.value.trim().to_ascii_uppercase());
                Ok(())
            }
            _ => {
                if self.skipped > 0 {
                    return Ok(());
                }
                match self.open.last_mut() {
                    Some(open) => open.component.properties.push(prop),
                    None => {
                        // A property before any component, or between two
                        // calendars: the calendar's own.
                        self.root
                            .get_or_insert_with(|| Component::new("VCALENDAR".into()))
                            .properties
                            .push(prop);
                    }
                }
                Ok(())
            }
        }
    }

    fn begin(&mut self, name: String) -> Result<(), ReadError> {
        if self.skipped > 0 || self.open.len() + 1 >= MAX_DEPTH {
            self.skipped += 1;
            return Ok(());
        }
        match &self.root {
            None if name == "VCALENDAR" => {
                self.root = Some(Component::new(name));
                return Ok(());
            }
            None if CALENDAR_PARTS.contains(&name.as_str()) => {
                // A calendar's component without the calendar around it.
                self.root = Some(Component::new("VCALENDAR".into()));
            }
            None => return Err(ReadError::NotACalendar),
            // A second calendar in the same file: its components join the
            // first's.
            Some(_) if name == "VCALENDAR" && self.open.is_empty() => {
                self.closed = false;
                return Ok(());
            }
            Some(_) => {}
        }
        // A calendar's component never nests in another: the one open was
        // never closed.
        if CALENDAR_PARTS.contains(&name.as_str()) {
            self.close_open();
        }
        let mut hasher = None;
        if self.open.is_empty() {
            let mut fresh = Hasher::new(Suite::V1);
            fresh.update(format!("BEGIN:{name}\r\n").as_bytes());
            hasher = Some(fresh);
        }
        self.open.push(Open {
            component: Component::new(name),
            hasher,
        });
        Ok(())
    }

    fn end(&mut self, name: &str) {
        if self.skipped > 0 {
            self.skipped -= 1;
            return;
        }
        if self.open.is_empty() {
            if name == "VCALENDAR" {
                self.closed = true;
            }
            return;
        }
        if name == "VCALENDAR" {
            self.close_open();
            self.closed = true;
            return;
        }
        let Some(at) = self
            .open
            .iter()
            .rposition(|open| open.component.name == name)
        else {
            // An END for nothing open: dropped.
            return;
        };
        // Components still open inside the one closed were never closed.
        while self.open.len() > at + 1 {
            let open = self.open.pop().expect("deeper than at");
            self.attach(Node::Broken {
                name: open.component.name,
            });
        }
        let open = self.open.pop().expect("at is open");
        let mut component = open.component;
        if let Some(hasher) = open.hasher {
            component.digest = hasher.finish().into();
        }
        self.attach(Node::Component(component));
    }

    fn attach(&mut self, node: Node) {
        match self.open.last_mut() {
            Some(parent) => parent.component.components.push(node),
            None => self
                .root
                .get_or_insert_with(|| Component::new("VCALENDAR".into()))
                .components
                .push(node),
        }
    }

    /// Every component still open, reported as never closed.
    fn close_open(&mut self) {
        while let Some(open) = self.open.pop() {
            self.attach(Node::Broken {
                name: open.component.name,
            });
        }
    }

    fn finish(mut self) -> Result<Component, ReadError> {
        // What the file left open is reported, not read.
        self.close_open();
        let _ = self.closed;
        self.root.ok_or(ReadError::NotACalendar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_are_sorted_for_the_search() {
        let mut sorted = KNOWN.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, KNOWN);
    }

    #[test]
    fn folding_line_ends_and_enclosing_are_repaired() {
        let text = "\u{feff}BEGIN:VEVENT\nUID:a\r\nSUMMARY:Long\r\n  title\rDESCRIPTION:one\ntwo, still\n\tthree\nEND:VEVENT\n";
        let calendar = read(text).unwrap();
        assert_eq!(calendar.name, "VCALENDAR");
        let event = calendar.children("VEVENT").next().unwrap();
        assert_eq!(event.property("SUMMARY").unwrap().value, "Long title");
        // "two, still" names nothing: a line folded without its space.
        assert_eq!(
            event.property("DESCRIPTION").unwrap().value,
            "onetwo, stillthree"
        );
    }

    #[test]
    fn parameters_are_read_with_quotes_and_lists() {
        let prop =
            content_line(r#"attendee;cn="Doe; Jane";member="mailto:a@x","mailto:b@x":mailto:j@x"#)
                .unwrap();
        assert_eq!(prop.name, "ATTENDEE");
        assert_eq!(prop.param("CN"), Some("Doe; Jane"));
        assert_eq!(prop.params[1].values, vec!["mailto:a@x", "mailto:b@x"]);
        assert_eq!(prop.value, "mailto:j@x");
    }

    #[test]
    fn unclosed_and_misclosed_components_are_kept_as_broken() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:1\r\nBEGIN:VALARM\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:2\r\nEND:VCALENDAR";
        let calendar = read(text).unwrap();
        // The first event reads (its alarm doesn't); the second never ended.
        let first = calendar.children("VEVENT").next().unwrap();
        assert_eq!(
            first.components,
            vec![Node::Broken {
                name: "VALARM".into()
            }]
        );
        assert!(calendar
            .components
            .iter()
            .any(|node| matches!(node, Node::Broken { name } if name == "VEVENT")));
    }

    #[test]
    fn two_calendars_read_as_one_and_others_are_refused() {
        let text = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:1\nEND:VEVENT\nEND:VCALENDAR\nBEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:2\nEND:VEVENT\nEND:VCALENDAR\n";
        assert_eq!(read(text).unwrap().children("VEVENT").count(), 2);
        assert_eq!(read("  \r\n"), Err(ReadError::Empty));
        assert_eq!(
            read("BEGIN:VCARD\nFN:x\nEND:VCARD"),
            Err(ReadError::NotACalendar)
        );
        assert_eq!(read("hello"), Err(ReadError::NotACalendar));
    }

    #[test]
    fn the_digest_names_an_event_by_its_lines() {
        let one = read("BEGIN:VEVENT\nSUMMARY:a\nEND:VEVENT").unwrap();
        let same =
            read("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:a\r\nEND:VEVENT\r\nEND:VCALENDAR")
                .unwrap();
        let other = read("BEGIN:VEVENT\nSUMMARY:b\nEND:VEVENT").unwrap();
        let digest = |c: &Component| c.children("VEVENT").next().unwrap().digest;
        assert_eq!(digest(&one), digest(&same));
        assert_ne!(digest(&one), digest(&other));
    }

    #[test]
    fn deep_nesting_is_skipped() {
        let mut text = String::from("BEGIN:VCALENDAR\n");
        for _ in 0..20 {
            text.push_str("BEGIN:X-DEEP\n");
        }
        for _ in 0..20 {
            text.push_str("END:X-DEEP\n");
        }
        text.push_str("BEGIN:VEVENT\nUID:1\nEND:VEVENT\nEND:VCALENDAR\n");
        let calendar = read(&text).unwrap();
        assert_eq!(calendar.children("VEVENT").count(), 1);
    }
}
