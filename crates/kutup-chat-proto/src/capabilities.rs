//! Device capabilities (docs/plans/format-evolution.md, rule 8): what a
//! device of an account can read, signed per device in the account manifest
//! ([`crate::AccountManifestDeviceV3::capabilities`]). A sender uses a new
//! format or action toward an account only when every device that must read
//! it lists the matching capability; a device that learns to read something
//! new lists it in the next manifest it publishes.
//!
//! A code is a `u16`. A manifest keeps the codes it doesn't know, signed as
//! received, and ignores them (an open enum of class *skip*); 0 is never a
//! code. New codes are added at the end of [`Capability`], never reused.

use crate::DeviceKind;

/// The most capability codes one device lists.
pub const MAX_DEVICE_CAPABILITIES: usize = 64;

/// The capabilities this build knows. Each names what a device that lists it
/// reads; the codes are the wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum Capability {
    /// Reads group state and changes (`GroupChangeV1`) with the actions of
    /// the wipe's release: every action [`crate::group::GroupActionV1`]
    /// lists today. A new action names a capability of its own
    /// ([`crate::group::GroupActionV1::capability`]).
    GroupChangesV1 = 1,
    /// Reads Drive in the block format: file metadata `v` 2, its block
    /// manifests and blocks (`kutup_crypto::file_metadata`,
    /// `kutup_crypto::blocks`).
    DriveBlocksV2 = 2,
}

impl Capability {
    /// Every capability this build knows, by code.
    pub const ALL: &'static [Capability] = &[Self::GroupChangesV1, Self::DriveBlocksV2];

    pub fn code(self) -> u16 {
        self as u16
    }

    /// What a device of `kind` built from this source lists: a Chat device
    /// reads groups; an editor reads Drive. The CLI reads Drive, and groups
    /// only when it takes Chat (`chat`).
    pub fn of_this_build(kind: &DeviceKind, chat: bool) -> Vec<u16> {
        let mut out: Vec<u16> = match kind {
            DeviceKind::Chat => vec![Self::GroupChangesV1.code()],
            DeviceKind::Editor => vec![Self::DriveBlocksV2.code()],
            DeviceKind::Cli if chat => {
                vec![Self::GroupChangesV1.code(), Self::DriveBlocksV2.code()]
            }
            DeviceKind::Cli => vec![Self::DriveBlocksV2.code()],
            DeviceKind::Other(_) => Vec::new(),
        };
        out.sort_unstable();
        out
    }
}

impl From<Capability> for u16 {
    fn from(value: Capability) -> Self {
        value.code()
    }
}

impl TryFrom<u16> for Capability {
    type Error = u16;

    /// The capability `code` names; an unknown code back as the error (the
    /// caller keeps and ignores it).
    fn try_from(code: u16) -> Result<Self, u16> {
        Self::ALL
            .iter()
            .copied()
            .find(|capability| capability.code() == code)
            .ok_or(code)
    }
}

/// A device's capability codes as a manifest carries them: strictly
/// ascending (so each once, in one order), none 0, at most
/// [`MAX_DEVICE_CAPABILITIES`]. Unknown codes pass.
pub fn check_capabilities(codes: &[u16]) -> Result<(), String> {
    if codes.len() > MAX_DEVICE_CAPABILITIES {
        return Err("a device lists at most 64 capabilities".into());
    }
    if codes.first() == Some(&0) {
        return Err("capability code 0 is reserved".into());
    }
    if codes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("capabilities must be strictly ascending".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_pinned_and_round_trip() {
        assert_eq!(Capability::GroupChangesV1.code(), 1);
        assert_eq!(Capability::DriveBlocksV2.code(), 2);
        for capability in Capability::ALL {
            assert_eq!(Capability::try_from(capability.code()), Ok(*capability));
        }
        assert_eq!(Capability::try_from(0), Err(0));
        assert_eq!(Capability::try_from(999), Err(999));
        let mut codes: Vec<u16> = Capability::ALL.iter().map(|c| c.code()).collect();
        codes.dedup();
        assert_eq!(codes.len(), Capability::ALL.len());
    }

    #[test]
    fn lists_are_checked_but_unknown_codes_pass() {
        check_capabilities(&[]).unwrap();
        check_capabilities(&[1, 2, 999]).unwrap();
        assert!(check_capabilities(&[0, 1]).is_err());
        assert!(check_capabilities(&[2, 1]).is_err());
        assert!(check_capabilities(&[1, 1]).is_err());
        let many: Vec<u16> = (1..=65).collect();
        assert!(check_capabilities(&many).is_err());
        for kind in [DeviceKind::Chat, DeviceKind::Editor, DeviceKind::Cli] {
            for chat in [false, true] {
                check_capabilities(&Capability::of_this_build(&kind, chat)).unwrap();
            }
        }
    }
}
