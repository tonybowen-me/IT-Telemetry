#[derive(Debug, Clone, PartialEq)]
pub enum AuthEvent {
    LoginSuccess,
    AuthTokenIssued,
    AuthTokenUsed,
}

impl AuthEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::LoginSuccess    => "LoginSuccess",
            Self::AuthTokenIssued => "AuthTokenIssued",
            Self::AuthTokenUsed   => "AuthTokenUsed",
        }
    }
}

pub struct Event {
    pub ts:   u64,
    pub user: &'static str,
    pub kind: AuthEvent,
}

impl Event {
    pub fn new(ts: u64, user: &'static str, kind: AuthEvent) -> Self {
        Self { ts, user, kind }
    }
}
