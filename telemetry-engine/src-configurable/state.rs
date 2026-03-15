use std::collections::HashMap;

/// PrivilegedActionTaken requires a SessionHeartbeat within this many seconds.
pub const HEARTBEAT_WINDOW: u64 = 30;

/// PrivilegedActionTaken requires an IdentityVerified within this many seconds.
pub const IDENTITY_WINDOW: u64 = 300;

#[derive(Debug, Clone, Default)]
pub struct SessionState {
    pub last_heartbeat_at: Option<u64>,
    pub last_identity_at:  Option<u64>,
    pub last_resource_at:  Option<u64>,
    pub privileged_count:  usize,
}

impl SessionState {
    pub fn heartbeat_fresh(&self, ts: u64) -> bool {
        self.last_heartbeat_at
            .map(|t| t <= ts && ts - t <= HEARTBEAT_WINDOW)
            .unwrap_or(false)
    }
    pub fn identity_fresh(&self, ts: u64) -> bool {
        self.last_identity_at
            .map(|t| t <= ts && ts - t <= IDENTITY_WINDOW)
            .unwrap_or(false)
    }
    pub fn has_resource_access(&self) -> bool {
        self.last_resource_at.is_some()
    }
}

pub type SessionStore = HashMap<String, SessionState>;
