//! Custom mail domains (docs/plans/mail-custom-domains.md): an account's own
//! domains, verified by a TXT record before any mail flows, checked as
//! Proton checks them, kept in step with Stalwart.
//!
//! - [`name`]: what may be added.
//! - [`records`]: each DNS record's state, in Proton's numbers.
//! - [`policy`]: what a check does to the domain (the grace by cause).
//! - [`reconcile`]: Stalwart's domains and DKIM signatures follow the
//!   database.

pub mod name;
pub mod policy;
pub mod reconcile;
pub mod records;
