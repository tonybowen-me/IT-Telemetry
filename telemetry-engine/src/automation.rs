use std::collections::HashMap;

use crate::events::{AutomationEvent, DomainEvent, Event};
use crate::variance::{Severity, Variance};

/// AutomationTriggered must be backed by a StateValidated within this many seconds.
pub const VALIDATION_WINDOW: u64 = 300; // 5-minute freshness window

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AutomationState {
    /// When system state was last explicitly validated.
    pub last_validated_at: Option<u64>,
    /// Consecutive automation triggers without a fresh StateValidated.
    pub trigger_count: usize,
    /// When the most recent trigger fired.
    pub last_trigger_at: Option<u64>,
}

impl AutomationState {
    pub fn has_validation(&self) -> bool { self.last_validated_at.is_some() }

    /// Returns the validation timestamp if it falls within `window` seconds of `ts`.
    pub fn validation_within(&self, ts: u64, window: u64) -> Option<u64> {
        self.last_validated_at.filter(|&t| t <= ts && ts - t <= window)
    }
}

pub type AutomationStore = HashMap<String, AutomationState>;

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct AutomationEngine {
    pub state: AutomationStore,
}

impl AutomationEngine {
    pub fn new() -> Self { Self { state: AutomationStore::new() } }

    pub fn ingest(&mut self, ev: &Event) -> Vec<Variance> {
        match &ev.kind {
            DomainEvent::Automation(AutomationEvent::StateValidated)      => self.on_validated(ev),
            DomainEvent::Automation(AutomationEvent::AutomationTriggered) => self.on_triggered(ev),
            _ => vec![],
        }
    }

    fn on_validated(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.last_validated_at = Some(ev.ts);
        s.trigger_count = 0; // fresh validation resets the cascade counter
        vec![]
    }

    fn on_triggered(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.last_trigger_at = Some(ev.ts);

        let justified = s.validation_within(ev.ts, VALIDATION_WINDOW).is_some();

        if justified {
            s.trigger_count = 0;
            return vec![];
        }

        // Trigger on stale or absent validation — escalate on repetition
        s.trigger_count += 1;

        if s.trigger_count == 1 {
            vec![Variance {
                severity: Severity::Warning,
                rule:     "AUTO-1: AutomationTriggered must be backed by StateValidated within 5-min window",
                detail:   format!(
                    "'{}': automation fired on unvalidated state — no StateValidated within {}s",
                    ev.entity, VALIDATION_WINDOW
                ),
            }]
        } else {
            vec![Variance {
                severity: Severity::Critical,
                rule:     "AUTO-2: Repeated automation on unvalidated state — amplification invariant violated",
                detail:   format!(
                    "'{}': {} consecutive triggers without StateValidated — automation is amplifying unresolved deviation",
                    ev.entity, s.trigger_count
                ),
            }]
        }
    }

    pub fn finalize(&self) -> Vec<(String, Variance)> { vec![] }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AutomationEvent, Event};
    use crate::variance::Severity;

    fn validated(entity: &'static str, ts: u64) -> Event {
        Event::automation(ts, entity, AutomationEvent::StateValidated)
    }
    fn triggered(entity: &'static str, ts: u64) -> Event {
        Event::automation(ts, entity, AutomationEvent::AutomationTriggered)
    }

    /// Trigger immediately after validation → no variance.
    #[test]
    fn justified_trigger_no_variance() {
        let mut e = AutomationEngine::new();
        assert!(e.ingest(&validated("orchestrator", 9000)).is_empty());
        assert!(
            e.ingest(&triggered("orchestrator", 9100)).is_empty(),
            "trigger backed by fresh validation should not produce variance"
        );
    }

    /// Trigger with no validation at all → Warning.
    #[test]
    fn trigger_no_validation_is_warning() {
        let mut e = AutomationEngine::new();
        let vs = e.ingest(&triggered("orchestrator", 9400));
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Warning);
    }

    /// Trigger after validation window expires → Warning.
    #[test]
    fn trigger_stale_validation_is_warning() {
        let mut e = AutomationEngine::new();
        e.ingest(&validated("orchestrator", 9000));
        let vs = e.ingest(&triggered("orchestrator", 9400)); // 400s > VALIDATION_WINDOW (300s)
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Warning);
    }

    /// Second consecutive trigger on stale state → Critical.
    #[test]
    fn cascade_escalates_to_critical() {
        let mut e = AutomationEngine::new();
        e.ingest(&validated("orchestrator", 9000));
        e.ingest(&triggered("orchestrator", 9400)); // Warning
        let vs = e.ingest(&triggered("orchestrator", 9600)); // Critical
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Critical);
    }

    /// StateValidated resets trigger_count — subsequent trigger is justified.
    #[test]
    fn revalidation_resets_cascade() {
        let mut e = AutomationEngine::new();
        e.ingest(&validated("orchestrator", 9000));
        e.ingest(&triggered("orchestrator", 9400)); // Warning, trigger_count → 1
        e.ingest(&validated("orchestrator", 9500)); // resets trigger_count to 0
        let vs = e.ingest(&triggered("orchestrator", 9550));
        assert!(vs.is_empty(), "trigger after revalidation should be justified");
    }

    /// Two orchestrators are tracked independently.
    #[test]
    fn multi_orchestrator_isolation() {
        let mut e = AutomationEngine::new();
        e.ingest(&validated("orchestrator_a", 9000));
        assert!(e.ingest(&triggered("orchestrator_a", 9100)).is_empty());
        // orchestrator_b has no validation
        let vs = e.ingest(&triggered("orchestrator_b", 9200));
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Warning, "orchestrator_b should flag independently");
    }
}
