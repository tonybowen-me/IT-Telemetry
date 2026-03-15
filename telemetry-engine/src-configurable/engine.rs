use crate::events::{ZtnaEntry, ZtnaEvent};
use crate::state::{SessionStore, HEARTBEAT_WINDOW, IDENTITY_WINDOW};

#[derive(Debug, Clone, PartialEq)]
pub enum Severity { Warning, Critical }

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Warning => "warning", Self::Critical => "critical" }
    }
}

#[derive(Debug, Clone)]
pub struct Variance {
    pub severity: Severity,
    pub rule:     &'static str,
    pub detail:   String,
}

pub struct ZtnaEngine {
    pub sessions: SessionStore,
}

impl ZtnaEngine {
    pub fn new() -> Self { Self { sessions: SessionStore::new() } }

    pub fn ingest(&mut self, ev: &ZtnaEntry) -> Vec<Variance> {
        let s = self.sessions.entry(ev.session.to_owned()).or_default();
        match &ev.event {
            ZtnaEvent::SessionHeartbeat => {
                s.last_heartbeat_at = Some(ev.ts);
                vec![]
            }
            ZtnaEvent::IdentityVerified => {
                s.last_identity_at = Some(ev.ts);
                vec![]
            }
            ZtnaEvent::ResourceAccessed => {
                s.last_resource_at = Some(ev.ts);
                vec![]
            }
            ZtnaEvent::PrivilegedActionTaken => {
                let mut out = Vec::new();

                // PRIV-1: live session heartbeat required within 30s
                if !s.heartbeat_fresh(ev.ts) {
                    out.push(Variance {
                        severity: Severity::Critical,
                        rule: "PRIV-1: SessionHeartbeat required within 30s",
                        detail: match s.last_heartbeat_at {
                            None    => format!("'{}': no SessionHeartbeat on record — session may be spoofed", ev.session),
                            Some(t) => format!("'{}': last heartbeat {}s ago — window is {}s", ev.session, ev.ts - t, HEARTBEAT_WINDOW),
                        },
                    });
                }

                // PRIV-2: fresh identity verification required within 5 min
                if !s.identity_fresh(ev.ts) {
                    out.push(Variance {
                        severity: Severity::Critical,
                        rule: "PRIV-2: IdentityVerified required within 5-min window",
                        detail: match s.last_identity_at {
                            None    => format!("'{}': no IdentityVerified on record — identity unconfirmed", ev.session),
                            Some(t) => format!("'{}': last verification {}s ago — window is {}s", ev.session, ev.ts - t, IDENTITY_WINDOW),
                        },
                    });
                }

                // PRIV-3: cold privilege escalation — no prior resource access in session
                if !s.has_resource_access() {
                    out.push(Variance {
                        severity: Severity::Critical,
                        rule: "PRIV-3: Prior ResourceAccessed required — cold privilege escalation detected",
                        detail: format!(
                            "'{}': no ResourceAccessed on record — actor escalated to PrivilegedActionTaken without establishing resource-level session context",
                            ev.session
                        ),
                    });
                }

                s.privileged_count += 1;
                out
            }
        }
    }
}
