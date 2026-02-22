use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct AuthState {
    pub logins:          Vec<u64>,
    pub token_issued_at: Option<u64>,
    pub token_used:      bool,
}

impl AuthState {
    pub fn has_login(&self)  -> bool        { !self.logins.is_empty() }
    pub fn last_login(&self) -> Option<u64> { self.logins.last().copied() }

    /// Most recent login within `window` seconds of `ts`, if any.
    pub fn login_within(&self, ts: u64, window: u64) -> Option<u64> {
        self.logins
            .iter()
            .filter(|&&t| t <= ts && ts - t <= window)
            .copied()
            .max()
    }
}

pub type StateStore = HashMap<String, AuthState>;
