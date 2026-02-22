use crate::events::{AuthEvent, Event};
use crate::state::StateStore;
use crate::variance::{Severity, Variance};

pub const WINDOW: u64 = 300; // 5-minute freshness window

pub struct Engine {
    pub state: StateStore,
}

impl Engine {
    pub fn new() -> Self { Self { state: StateStore::new() } }

    /// Ingest one event, update state, evaluate invariants, return any variances.
    pub fn ingest(&mut self, ev: &Event) -> Vec<Variance> {
        match ev.kind {
            AuthEvent::LoginSuccess    => self.on_login(ev),
            AuthEvent::AuthTokenIssued => self.on_issued(ev),
            AuthEvent::AuthTokenUsed   => self.on_used(ev),
        }
    }

    fn on_login(&mut self, ev: &Event) -> Vec<Variance> {
        self.state.entry(ev.user.to_owned()).or_default().logins.push(ev.ts);
        // Contract 1 ("must issue AuthTokenIssued") is deferred — checked at finalize.
        vec![]
    }

    fn on_issued(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.user.to_owned()).or_default();
        s.token_issued_at = Some(ev.ts);

        // Invariant: AuthTokenIssued requires a LoginSuccess within the window.
        if s.login_within(ev.ts, WINDOW).is_none() {
            return vec![Variance {
                severity: Severity::Critical,
                rule:     "AuthTokenIssued requires LoginSuccess within 5-min window",
                detail:   format!("'{}': token issued with no valid login on record", ev.user),
            }];
        }
        vec![]
    }

    fn on_used(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.user.to_owned()).or_default();
        s.token_used = true;

        let mut out = Vec::new();

        // Invariant A: must have a LoginSuccess within the window.
        if !s.has_login() {
            out.push(Variance {
                severity: Severity::Critical,
                rule:     "AuthTokenUsed requires prior LoginSuccess",
                detail:   format!("'{}': no LoginSuccess on record", ev.user),
            });
        } else if s.login_within(ev.ts, WINDOW).is_none() {
            let elapsed = ev.ts - s.last_login().unwrap_or(0);
            out.push(Variance {
                severity: Severity::Critical,
                rule:     "AuthTokenUsed must be within 5-min window of LoginSuccess",
                detail:   format!(
                    "'{}': last login was {}s ago — window is {}s",
                    ev.user, elapsed, WINDOW
                ),
            });
        }

        // Invariant B: an AuthTokenIssued must have preceded this use.
        if s.token_issued_at.is_none() {
            out.push(Variance {
                severity: Severity::Warning,
                rule:     "AuthTokenUsed requires prior AuthTokenIssued",
                detail:   format!("'{}': no AuthTokenIssued on record", ev.user),
            });
        }

        out
    }

    /// Called once the stream ends.  Emits deferred variances for incomplete contracts.
    pub fn finalize(&self) -> Vec<(String, Variance)> {
        let mut out = Vec::new();
        for (user, s) in &self.state {
            // Contract 1: LoginSuccess must eventually be followed by AuthTokenIssued.
            if s.has_login() && s.token_issued_at.is_none() && !s.token_used {
                out.push((user.clone(), Variance {
                    severity: Severity::Warning,
                    rule:     "LoginSuccess must be followed by AuthTokenIssued",
                    detail:   format!(
                        "'{}': login recorded but token was never issued", user
                    ),
                }));
            }
        }
        out
    }
}
