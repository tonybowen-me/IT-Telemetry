#[derive(Debug, Clone, PartialEq)]
pub enum ZtnaEvent {
    SessionHeartbeat,
    IdentityVerified,
    ResourceAccessed,
    PrivilegedActionTaken,
}

impl ZtnaEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SessionHeartbeat      => "SessionHeartbeat",
            Self::IdentityVerified      => "IdentityVerified",
            Self::ResourceAccessed      => "ResourceAccessed",
            Self::PrivilegedActionTaken => "PrivilegedActionTaken",
        }
    }
    pub fn css_class(&self) -> &'static str {
        match self {
            Self::SessionHeartbeat      => "ev-hb",
            Self::IdentityVerified      => "ev-id",
            Self::ResourceAccessed      => "ev-res",
            Self::PrivilegedActionTaken => "ev-priv",
        }
    }
}

pub struct ZtnaEntry {
    pub ts:      u64,
    pub session: &'static str,
    pub actor:   &'static str,
    pub event:   ZtnaEvent,
    pub detail:  &'static str,
}
