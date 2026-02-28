use std::collections::HashMap;

use crate::events::{DomainEvent, Event, ThermalEvent};
use crate::variance::{Severity, Variance};

/// A WorkloadScheduled event justifies thermal bias for this many seconds.
pub const JUSTIFICATION_WINDOW: u64 = 1800; // 30 minutes

/// Baseline temperature in °C.
pub const NOMINAL_TEMP: u64 = 45;

/// °C above nominal that constitutes asymmetric thermal bias.
pub const BIAS_THRESHOLD: u64 = 5;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ThermalState {
    /// When the most recent workload was declared for this rack.
    pub last_workload_at: Option<u64>,
    /// Count of consecutive unjustified high-temperature readings.
    pub bias_count: usize,
    /// Most recent temperature reading.
    pub last_temp: Option<u64>,
}

impl ThermalState {
    pub fn has_workload(&self) -> bool { self.last_workload_at.is_some() }

    /// Returns the workload timestamp if it falls within `window` seconds of `ts`.
    pub fn workload_within(&self, ts: u64, window: u64) -> Option<u64> {
        self.last_workload_at.filter(|&t| t <= ts && ts - t <= window)
    }
}

pub type ThermalStore = HashMap<String, ThermalState>;

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct ThermalEngine {
    pub state: ThermalStore,
}

impl ThermalEngine {
    pub fn new() -> Self { Self { state: ThermalStore::new() } }

    pub fn ingest(&mut self, ev: &Event) -> Vec<Variance> {
        match &ev.kind {
            DomainEvent::Thermal(ThermalEvent::WorkloadScheduled)    => self.on_workload_scheduled(ev),
            DomainEvent::Thermal(ThermalEvent::ThermalReading(temp)) => self.on_reading(ev, *temp),
            _ => vec![],
        }
    }

    fn on_workload_scheduled(&mut self, ev: &Event) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.last_workload_at = Some(ev.ts);
        s.bias_count = 0; // declared workload resets the unjustified-bias counter
        vec![]
    }

    fn on_reading(&mut self, ev: &Event, temp: u64) -> Vec<Variance> {
        let s = self.state.entry(ev.entity.to_owned()).or_default();
        s.last_temp = Some(temp);

        let is_biased = temp > NOMINAL_TEMP + BIAS_THRESHOLD;
        let justified = s.workload_within(ev.ts, JUSTIFICATION_WINDOW).is_some();

        if !is_biased || justified {
            return vec![];
        }

        // Unjustified thermal bias — escalate on repetition
        s.bias_count += 1;

        if s.bias_count == 1 {
            vec![Variance {
                severity: Severity::Warning,
                rule:     "TH-1: ThermalReading bias must be causally justified by WorkloadScheduled",
                detail:   format!(
                    "'{}': temp={}°C exceeds nominal+threshold ({}+{}={}°C) — no workload declared on record",
                    ev.entity, temp, NOMINAL_TEMP, BIAS_THRESHOLD, NOMINAL_TEMP + BIAS_THRESHOLD
                ),
            }]
        } else {
            vec![Variance {
                severity: Severity::Critical,
                rule:     "TH-2: Sustained unjustified thermal bias — equilibrium invariant violated",
                detail:   format!(
                    "'{}': {} consecutive readings above threshold (last={}°C) with no workload justification",
                    ev.entity, s.bias_count, temp
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
    use crate::events::{Event, ThermalEvent};
    use crate::variance::Severity;

    fn workload(entity: &'static str, ts: u64) -> Event {
        Event::thermal(ts, entity, ThermalEvent::WorkloadScheduled)
    }
    fn reading(entity: &'static str, ts: u64, temp: u64) -> Event {
        Event::thermal(ts, entity, ThermalEvent::ThermalReading(temp))
    }

    /// rack_a: workload declared, temp above threshold but justified → no variance.
    #[test]
    fn justified_bias_no_variance() {
        let mut e = ThermalEngine::new();
        assert!(e.ingest(&workload("rack_a", 6000)).is_empty());
        assert!(
            e.ingest(&reading("rack_a", 6300, 52)).is_empty(),
            "bias justified by workload should not produce variance"
        );
    }

    /// Temp at or below nominal+threshold → no variance even without workload.
    #[test]
    fn nominal_temp_no_variance() {
        let mut e = ThermalEngine::new();
        let vs = e.ingest(&reading("rack_b", 6000, 48));
        assert!(vs.is_empty(), "temp within threshold should not produce variance");
    }

    /// First unjustified high reading → Warning.
    #[test]
    fn first_unjustified_bias_is_warning() {
        let mut e = ThermalEngine::new();
        let vs = e.ingest(&reading("rack_b", 6600, 56));
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Warning);
    }

    /// Second consecutive unjustified high reading → Critical.
    #[test]
    fn sustained_bias_escalates_to_critical() {
        let mut e = ThermalEngine::new();
        e.ingest(&reading("rack_b", 6600, 56));
        let vs = e.ingest(&reading("rack_b", 7200, 61));
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Critical);
    }

    /// WorkloadScheduled resets the bias counter — subsequent high reading is justified.
    #[test]
    fn workload_resets_bias_count() {
        let mut e = ThermalEngine::new();
        e.ingest(&reading("rack_b", 6600, 56));     // bias_count → 1
        e.ingest(&workload("rack_b", 6900));        // resets bias_count to 0
        let vs = e.ingest(&reading("rack_b", 7200, 61));
        assert!(vs.is_empty(), "workload declaration should reset and justify subsequent bias");
    }

    /// rack_a and rack_b are tracked independently.
    #[test]
    fn multi_rack_isolation() {
        let mut e = ThermalEngine::new();
        e.ingest(&workload("rack_a", 6000));
        assert!(
            e.ingest(&reading("rack_a", 6300, 52)).is_empty(),
            "rack_a justified bias should not produce variance"
        );
        let vs = e.ingest(&reading("rack_b", 6600, 56));
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].severity, Severity::Warning, "rack_b should flag independently");
    }
}
