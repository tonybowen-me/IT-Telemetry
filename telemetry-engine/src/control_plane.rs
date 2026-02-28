use std::collections::HashMap;

use crate::events::{ControlPlaneEvent, DomainEvent, Event};
use crate::variance::{Severity, Variance};

pub const CP_WINDOW: u64 = 3600; // 1-hour role validity window

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ControlPlaneState {
    pub role_assigned_at:    Option<u64>,
    pub admin_action_taken:  bool,
}

impl ControlPlaneState {
    pub fn has_role(&self) -> bool { self.role_assigned_at.is_some() }

    /// Most recent role assignment within `window` seconds of `ts`, if any.
    pub fn role_within(&self, ts: u64, window: u64) -> Option<u64> {
        self.role_assigned_at.filter(|&t| t <= ts && ts - t <= window)
    }
}

pub type ControlPlaneStore = HashMap<String, ControlPlaneState>;

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct ControlPlaneEngine {
    pub state: ControlPlaneStore,
}

impl ControlPlaneEngine {
    pub fn new() -> Self { Self { state: ControlPlaneStore::new() } }

    pub fn ingest(&mut self, ev: &Event) -> Vec<Variance> {
        match &ev.kind {
            DomainEvent::ControlPlane(inner) => match inner {
                ControlPlaneEvent::RoleAssigned     => self.on_role_assigned(ev),
                ControlPlaneEvent::AdminActionTaken => self.on_admin_action(ev),
            },
            _ => vec![],
        }
    }

    fn on_role_assigned(&mut self, ev: &Event) -> Vec<Variance> {
        self.state.entry(ev.entity.to_owned()).or_default().role_assigned_at = Some(ev.ts);
        // Contract CP-1 (RoleAssigned → AdminActionTaken) is informational; no deferred check yet.
        vec![]
    }

    fn on_admin_action(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.admin_action_taken = true;

        let mut out = Vec::new();

        if !s.has_role() {
            out.push(Variance {
                severity: Severity::Critical,
                rule:     "AdminActionTaken requires prior RoleAssigned",
                detail:   format!("'{}': admin action with no role assignment on record", ev.entity),
            });
        } else if s.role_within(ev.ts, CP_WINDOW).is_none() {
            let elapsed = ev.ts - s.role_assigned_at.unwrap_or(0);
            out.push(Variance {
                severity: Severity::Critical,
                rule:     "AdminActionTaken must be within 1-hour window of RoleAssigned",
                detail:   format!(
                    "'{}': role was assigned {}s ago — window is {}s, exceeded by {}s",
                    ev.entity, elapsed, CP_WINDOW, elapsed - CP_WINDOW
                ),
            });
        }

        out
    }

    /// Called at stream end. Currently no deferred CP contracts.
    pub fn finalize(&self) -> Vec<(String, Variance)> { vec![] }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{ControlPlaneEvent, Event};
    use crate::variance::Severity;

    fn role(entity: &'static str, ts: u64) -> Event {
        Event::control_plane(ts, entity, ControlPlaneEvent::RoleAssigned)
    }
    fn action(entity: &'static str, ts: u64) -> Event {
        Event::control_plane(ts, entity, ControlPlaneEvent::AdminActionTaken)
    }

    /// Scenario B baseline: valid role → admin action within window → no variance.
    #[test]
    fn happy_path_no_variances() {
        let mut e = ControlPlaneEngine::new();
        assert!(e.ingest(&role("svc_alpha", 1000)).is_empty());
        assert!(e.ingest(&action("svc_alpha", 1030)).is_empty());
        assert!(e.finalize().is_empty());
    }

    /// Admin action with no prior role assignment → Critical.
    #[test]
    fn admin_action_no_role() {
        let mut e = ControlPlaneEngine::new();
        let v = e.ingest(&action("rogue_svc", 1100));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
        assert!(v[0].rule.contains("RoleAssigned"));
    }

    /// Admin action outside 1-hour window → Critical.
    #[test]
    fn admin_action_stale_role() {
        let mut e = ControlPlaneEngine::new();
        e.ingest(&role("svc_beta", 1200));
        let v = e.ingest(&action("svc_beta", 5000)); // 3800s > CP_WINDOW (3600s)
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
        assert!(v[0].rule.contains("1-hour window"));
    }

    /// Multiple services are tracked independently.
    #[test]
    fn multi_service_isolation() {
        let mut e = ControlPlaneEngine::new();
        e.ingest(&role("svc_alpha", 1000));
        assert!(e.ingest(&action("svc_alpha", 1030)).is_empty());
        let v = e.ingest(&action("rogue_svc", 1100));
        assert!(v.iter().any(|v| v.severity == Severity::Critical));
        let alpha = e.state.get("svc_alpha").unwrap();
        assert!(alpha.admin_action_taken);
    }
}
