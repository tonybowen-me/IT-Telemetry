use crate::events::{DomainEvent, IdentityEvent, Event};
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
        match &ev.kind {
            DomainEvent::Identity(inner) => match inner {
                IdentityEvent::LoginSuccess    => self.on_login(ev),
                IdentityEvent::AuthTokenIssued => self.on_issued(ev),
                IdentityEvent::AuthTokenUsed   => self.on_used(ev),
            },
            _ => vec![], // other domains handled by their own engines
        }
    }

    fn on_login(&mut self, ev: &Event) -> Vec<Variance> {
        self.state.entry(ev.entity.to_owned()).or_default().logins.push(ev.ts);
        // Contract 1 ("must issue AuthTokenIssued") is deferred — checked at finalize.
        vec![]
    }

    fn on_issued(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.token_issued_at = Some(ev.ts);

        // Invariant: AuthTokenIssued requires a LoginSuccess within the window.
        if s.login_within(ev.ts, WINDOW).is_none() {
            return vec![Variance {
                severity: Severity::Critical,
                rule:     "AuthTokenIssued requires LoginSuccess within 5-min window",
                detail:   format!("'{}': token issued with no valid login on record", ev.entity),
            }];
        }
        vec![]
    }

    fn on_used(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.token_used = true;

        let mut out = Vec::new();

        // Invariant A: must have a LoginSuccess within the window.
        if !s.has_login() {
            out.push(Variance {
                severity: Severity::Critical,
                rule:     "AuthTokenUsed requires prior LoginSuccess",
                detail:   format!("'{}': no LoginSuccess on record", ev.entity),
            });
        } else if s.login_within(ev.ts, WINDOW).is_none() {
            let elapsed = ev.ts - s.last_login().unwrap_or(0);
            out.push(Variance {
                severity: Severity::Critical,
                rule:     "AuthTokenUsed must be within 5-min window of LoginSuccess",
                detail:   format!(
                    "'{}': last login was {}s ago — window is {}s",
                    ev.entity, elapsed, WINDOW
                ),
            });
        }

        // Invariant B: an AuthTokenIssued must have preceded this use.
        if s.token_issued_at.is_none() {
            out.push(Variance {
                severity: Severity::Warning,
                rule:     "AuthTokenUsed requires prior AuthTokenIssued",
                detail:   format!("'{}': no AuthTokenIssued on record", ev.entity),
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{DomainEvent, IdentityEvent, Event};
    use crate::variance::Severity;

    fn login(entity: &'static str, ts: u64) -> Event {
        Event::identity(ts, entity, IdentityEvent::LoginSuccess)
    }
    fn issued(entity: &'static str, ts: u64) -> Event {
        Event::identity(ts, entity, IdentityEvent::AuthTokenIssued)
    }
    fn used(entity: &'static str, ts: u64) -> Event {
        Event::identity(ts, entity, IdentityEvent::AuthTokenUsed)
    }

    // ── Contract correctness ──────────────────────────────────────────────────

    /// Scenario A baseline: full happy path produces zero variances.
    #[test]
    fn happy_path_no_variances() {
        let mut e = Engine::new();
        assert!(e.ingest(&login("alice", 0)).is_empty());
        assert!(e.ingest(&issued("alice", 10)).is_empty());
        assert!(e.ingest(&used("alice", 120)).is_empty());
        assert!(e.finalize().is_empty());
    }

    /// Token used with no prior login at all → Critical.
    #[test]
    fn token_used_no_login() {
        let mut e = Engine::new();
        let v = e.ingest(&used("bob", 200));
        assert_eq!(v.len(), 2); // Critical (no login) + Warning (no issued)
        assert!(v.iter().any(|v| v.severity == Severity::Critical));
    }

    /// Token issued with no prior login → Critical.
    #[test]
    fn token_issued_no_login() {
        let mut e = Engine::new();
        let v = e.ingest(&issued("charlie", 100));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    /// Token used outside the 5-minute window → Critical.
    #[test]
    fn token_used_expired_window() {
        let mut e = Engine::new();
        e.ingest(&login("dave", 0));
        e.ingest(&issued("dave", 10));
        let v = e.ingest(&used("dave", 700)); // 700s > WINDOW (300s)
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
        assert!(v[0].rule.contains("5-min window"));
    }

    /// Token used without a prior AuthTokenIssued → Warning.
    #[test]
    fn token_used_no_issued() {
        let mut e = Engine::new();
        e.ingest(&login("eve", 0));
        let v = e.ingest(&used("eve", 10));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Warning);
        assert!(v[0].rule.contains("AuthTokenIssued"));
    }

    /// Login with no subsequent token issued → Warning emitted at finalize.
    #[test]
    fn finalize_orphaned_login() {
        let mut e = Engine::new();
        e.ingest(&login("judy", 900));
        let deferred = e.finalize();
        assert_eq!(deferred.len(), 1);
        let (entity, v) = &deferred[0];
        assert_eq!(entity, "judy");
        assert_eq!(v.severity, Severity::Warning);
        assert!(v.rule.contains("AuthTokenIssued"));
    }

    /// Multiple users in one stream are tracked independently.
    #[test]
    fn multi_entity_isolation() {
        let mut e = Engine::new();
        // alice: happy path
        e.ingest(&login("alice", 0));
        e.ingest(&issued("alice", 10));
        assert!(e.ingest(&used("alice", 50)).is_empty());
        // bob: no login
        let v = e.ingest(&used("bob", 60));
        assert!(v.iter().any(|v| v.severity == Severity::Critical));
        // alice's state unaffected
        let alice = e.state.get("alice").unwrap();
        assert!(alice.token_used);
    }

    // ── Event model ───────────────────────────────────────────────────────────

    /// DomainEvent correctly reports its domain tag.
    #[test]
    fn domain_event_tag() {
        let ev = DomainEvent::Identity(IdentityEvent::LoginSuccess);
        assert_eq!(ev.domain(), crate::events::Domain::Identity);
        assert_eq!(ev.name(), "LoginSuccess");
    }

    /// Event::identity() convenience constructor wraps correctly.
    #[test]
    fn identity_constructor() {
        let ev = Event::identity(42, "alice", IdentityEvent::AuthTokenUsed);
        assert_eq!(ev.ts, 42);
        assert_eq!(ev.entity, "alice");
        assert_eq!(ev.kind, DomainEvent::Identity(IdentityEvent::AuthTokenUsed));
    }
}
