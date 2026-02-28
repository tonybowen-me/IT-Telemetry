mod automation;
mod control_plane;
mod engine;
mod events;
mod state;
mod thermal;
mod variance;

use automation::{AutomationEngine, AutomationState, AutomationStore, VALIDATION_WINDOW};
use control_plane::{ControlPlaneEngine, ControlPlaneState, ControlPlaneStore, CP_WINDOW};
use engine::{Engine, WINDOW};
use events::{AutomationEvent, ControlPlaneEvent, DomainEvent, Domain, IdentityEvent, ThermalEvent, Event};
use state::{AuthState, StateStore};
use thermal::{ThermalEngine, ThermalState, ThermalStore, JUSTIFICATION_WINDOW, NOMINAL_TEMP, BIAS_THRESHOLD};
use variance::Variance;

use std::collections::HashMap;
use std::fmt::Write;

// ── Step data structures ──────────────────────────────────────────────────────

struct CheckInfo {
    rule:          String,
    lookup:        Vec<(String, String, String)>,
    result:        &'static str,
    result_text:   String,
    result_detail: String,
}

struct VarInfo {
    severity: &'static str,
    rule:     String,
    detail:   String,
}

struct EntityState {
    domain: &'static str,
    /// (label, value, status_class) — rendered generically in the state panel
    fields: Vec<(String, String, String)>,
}

/// (phase_label, heading, body)
type Phase = (&'static str, &'static str, &'static str);

struct StepData {
    seq:         usize,
    ts:          u64,
    user:        String,
    event:       &'static str,
    group:       String,
    group_label: String,
    is_deferred: bool,
    check:       CheckInfo,
    variances:   Vec<VarInfo>,
    state_snap:  Vec<(String, EntityState)>,
    phases:      Vec<Phase>,
    /// All events seen for this user up to and including this step (seq, ts, event_name)
    history:     Vec<(usize, u64, &'static str)>,
}

// ── Step-through narratives (3 phases per step × 5 steps) ────────────────────

static NARRATIVES: &[&[Phase]] = &[
    // ── Step 1: RoleAssigned(svc_alpha, t=1000) ── Scenario A ────────────────
    &[
        ("Event Arrives",
         "RoleAssigned — svc_alpha @ t=1000s",
         "The ControlPlane engine receives its first event: svc_alpha has been \
          granted a role. Contract CP-2 states that any AdminActionTaken must be \
          backed by a RoleAssigned within the 1-hour validity window. \
          The engine records the assignment timestamp and opens the window."),
        ("State Lookup",
         "Creating svc_alpha's ControlPlane state",
         "No prior entry exists for svc_alpha. The engine initialises: \
          role_assigned_at=1000, admin_action_taken=false. \
          The 1-hour validity window runs t=1000s → t=4600s. \
          Role assignment triggers no immediate check."),
        ("Invariant Result",
         "⏳ Pending — role window is open",
         "The role is recorded. The engine is now watching for AdminActionTaken \
          from svc_alpha. Any such event arriving before t=4600s will be \
          considered authorised. After that, the role is stale."),
    ],
    // ── Step 2: AdminActionTaken(svc_alpha, t=1030) ── Scenario A ────────────
    &[
        ("Event Arrives",
         "AdminActionTaken — svc_alpha @ t=1030s",
         "svc_alpha performs an admin action 30 seconds after role assignment. \
          Contract CP-2 fires: the engine checks that a valid RoleAssigned exists \
          within the 1-hour window. The lookup runs now."),
        ("State Lookup",
         "Checking svc_alpha's role state",
         "svc_alpha.role_assigned_at=1000. Elapsed since assignment: 30s. \
          Window: 3600s. 30 < 3600 — the role is current. \
          Contract CP-2 is satisfied. State updated: admin_action_taken=true."),
        ("Invariant Result",
         "✔ Pass — admin action is authorised",
         "svc_alpha's action is backed by a valid, recent role assignment. \
          This is Scenario A — the legitimate variation: a properly authorised \
          service account acts within its declared privilege window. \
          Role assigned → Admin action taken. No invariant violation."),
    ],
    // ── Step 3: AdminActionTaken(rogue_svc, t=1100) ── Scenario B ────────────
    &[
        ("Event Arrives",
         "AdminActionTaken — rogue_svc @ t=1100s",
         "rogue_svc attempts an admin action. This is the first event the engine \
          has ever seen from this service account — there is no role assignment \
          on record. Contract CP-2 fires immediately: has rogue_svc been \
          granted a role?"),
        ("State Lookup",
         "Looking up rogue_svc — no state found",
         "rogue_svc has no entry in the ControlPlane state store. \
          No RoleAssigned. No authorisation chain whatsoever. \
          Yet a privileged admin action is being attempted. \
          This is stealth privilege misuse — the defining Scenario B pattern."),
        ("Invariant Result",
         "✘ Critical — admin action without role assignment",
         "Hard causal failure: a privileged action was taken by a service account \
          that was never granted a role. The contract is explicit: AdminActionTaken \
          MUST have a prior RoleAssigned. None exists. \
          In a real deployment: immediate alert, lateral movement suspected."),
    ],
    // ── Step 4: RoleAssigned(svc_beta, t=1200) ── Scenario B ─────────────────
    &[
        ("Event Arrives",
         "RoleAssigned — svc_beta @ t=1200s",
         "svc_beta receives a role assignment at t=1200s. This opens a 1-hour \
          validity window expiring at t=4800s. The engine records this and \
          waits. What happens if svc_beta's admin action arrives after the window closes?"),
        ("State Lookup",
         "Creating svc_beta's ControlPlane state",
         "svc_beta.role_assigned_at=1200, admin_action_taken=false. \
          Window: [1200s, 4800s]. Everything is in order for now. \
          The engine records the assignment and notes the critical deadline: t=4800s."),
        ("Invariant Result",
         "⏳ Pending — window closes at t=4800s",
         "Same deferred pattern as svc_alpha's first event. \
          The next AdminActionTaken from svc_beta will be the deciding moment. \
          If it arrives after t=4800s, Contract CP-2 will fail — expired role."),
    ],
    // ── Step 5: AdminActionTaken(svc_beta, t=5000) ── Scenario B ─────────────
    &[
        ("Event Arrives",
         "AdminActionTaken — svc_beta @ t=5000s",
         "svc_beta attempts an admin action at t=5000s. The role was assigned \
          at t=1200s. The window expired at t=4800s. \
          The engine calculates: 5000 − 1200 = 3800s since assignment. \
          The window is 3600s. svc_beta is 200 seconds past the deadline."),
        ("State Lookup",
         "svc_beta.role_assigned_at=1200s, elapsed=3800s, window=3600s",
         "3800 > 3600. The role has expired. The engine does not care that the \
          role was legitimately assigned — what matters is the age of the \
          RoleAssigned at the time of the admin action. \
          At t=5000s, svc_beta's role is stale by exactly 200 seconds."),
        ("Invariant Result",
         "✘ Critical — role expired, admin action denied",
         "Contract CP-2 violated. Deterministic proof: 5000 − 1200 = 3800 > 3600. \
          The role assignment is outside the validity window at the time of action. \
          This could represent a delayed execution, a stale credential being replayed, \
          or a service that held an elevated role past its intended validity period."),
    ],
    // ── Step 6: WorkloadScheduled(rack_a, t=6000) ── Scenario C ──────────────
    &[
        ("Event Arrives",
         "WorkloadScheduled — rack_a @ t=6000s",
         "Scenario C begins: the Thermal engine receives a workload declaration for rack_a. \
          Contract TH-1 states that any sustained thermal bias must be causally attributable \
          to a declared workload. This declaration opens a 30-minute justification window. \
          Any thermal reading above threshold within that window will be considered justified."),
        ("State Lookup",
         "Creating rack_a's thermal state",
         "No prior entry exists for rack_a. The engine initialises: \
          last_workload_at=6000, bias_count=0, last_temp=null. \
          The justification window runs t=6000s → t=7800s. \
          WorkloadScheduled triggers no immediate contract check."),
        ("Invariant Result",
         "⏳ Pending — justification window is open",
         "The workload is declared. The engine now watches for ThermalReading events \
          from rack_a. Any reading above the 50°C threshold (nominal 45 + bias 5) \
          within the next 1800 seconds will be treated as causally justified. \
          After t=7800s, the justification expires."),
    ],
    // ── Step 7: ThermalReading(rack_a, 52°C, t=6300) ── Scenario C ───────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_a @ t=6300s, 52°C",
         "rack_a reports 52°C — 7°C above nominal (45°C) and above the 50°C threshold. \
          This is a biased reading. Contract TH-1 fires: the engine checks whether \
          a WorkloadScheduled exists within the 30-minute justification window."),
        ("State Lookup",
         "Checking rack_a's workload justification",
         "rack_a.last_workload_at=6000. Elapsed since declaration: 300s. \
          Window: 1800s. 300 < 1800 — the workload is current. \
          temp=52°C > threshold (50°C) — biased, but justified. \
          Contract TH-1 is satisfied. This is the expected outcome for a legitimately loaded rack."),
        ("Invariant Result",
         "✔ Pass — thermal bias is causally justified",
         "rack_a's elevated temperature is explained by the declared workload. \
          This is the Scenario C baseline: bias is permitted when justified. \
          The engine does not flag this reading. \
          Now watch what happens when rack_b — with no declared workload — also runs hot."),
    ],
    // ── Step 8: ThermalReading(rack_b, 56°C, t=6600) ── Scenario C ───────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_b @ t=6600s, 56°C",
         "rack_b reports 56°C. This is the first event the engine has ever seen from rack_b. \
          temp=56°C is 11°C above nominal and 6°C above the 50°C threshold — clearly biased. \
          Contract TH-1 fires: has rack_b declared a workload within the justification window?"),
        ("State Lookup",
         "Looking up rack_b — no workload on record",
         "rack_b has no entry in the thermal state store. No WorkloadScheduled. \
          No justification for the elevated temperature whatsoever. \
          Yet rack_b is running 11°C above nominal. \
          This is the silent scheduler bias pattern: heat without declared cause."),
        ("Invariant Result",
         "⚠ Warning — unjustified thermal bias (first detection)",
         "Contract TH-1 partially violated. bias_count=1. \
          rack_b's temperature exceeds threshold with no workload justification on record. \
          The engine flags this as a Warning — the first occurrence is insufficient \
          to confirm sustained bias. The engine continues watching for further readings."),
    ],
    // ── Step 9: ThermalReading(rack_b, 61°C, t=7200) ── Scenario C ───────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_b @ t=7200s, 61°C",
         "rack_b reports 61°C — now 16°C above nominal. Still no WorkloadScheduled \
          for rack_b has arrived. The engine rechecks Contract TH-1: \
          same entity, same pattern, escalating temperature. bias_count is now 2."),
        ("State Lookup",
         "rack_b.last_workload=NONE, temp=61°C, bias_count → 2",
         "600 seconds have passed since the first biased reading. \
          No workload has been declared for rack_b. \
          temp=61°C > 50°C threshold. bias_count increments to 2. \
          Two consecutive unjustified readings cross the sustained bias threshold."),
        ("Invariant Result",
         "✘ Critical — sustained equilibrium invariant violated",
         "Contract TH-2 violated. Deterministic proof: 2 consecutive ThermalReadings \
          above threshold with no WorkloadScheduled justification. \
          This is not a spike — it is a sustained pattern. \
          In a real deployment: immediate escalation, scheduler audit required."),
    ],
    // ── Step 10: ThermalReading(rack_b, 64°C, t=7800) ── Scenario C ──────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_b @ t=7800s, 64°C",
         "rack_b reaches 64°C — 19°C above nominal. The temperature is still rising. \
          Still no workload declaration. The engine applies Contract TH-2 again: \
          this is the third consecutive unjustified reading. The bias is definitive."),
        ("State Lookup",
         "rack_b.last_workload=NONE, temp=64°C, bias_count → 3",
         "rack_b has now produced 3 consecutive ThermalReadings above the 50°C threshold \
          with zero workload justification. The scheduler has silently biased load \
          onto rack_b without declaring any intent. \
          The causal chain is broken: thermal impact without declared digital cause."),
        ("Invariant Result",
         "✘ Critical — silent scheduler bias proven",
         "Contract TH-2 confirmed: sustained asymmetric thermal bias without declared workload. \
          3 readings (56°C → 61°C → 64°C), no WorkloadScheduled, no justification. \
          Every detection is a deterministic causal proof — the engine did not guess. \
          It observed a broken causal chain and reported it."),
    ],
    // ── Step 11: StateValidated(orchestrator, t=9000) ── Scenario D ──────────
    &[
        ("Event Arrives",
         "StateValidated — orchestrator @ t=9000s",
         "Scenario D begins: the Automation engine receives a state validation event. \
          Mother has audited system state and confirmed coherence. \
          Contract AUTO-1 states that every AutomationTriggered must be backed by a \
          StateValidated within a 5-minute window. This validation opens that window."),
        ("State Lookup",
         "Creating orchestrator's automation state",
         "No prior entry exists for orchestrator. The engine initialises: \
          last_validated_at=9000, trigger_count=0, last_trigger_at=null. \
          The validation window runs t=9000s → t=9300s. \
          StateValidated triggers no immediate contract check."),
        ("Invariant Result",
         "⏳ Pending — validation window is open",
         "System state is confirmed coherent. The engine is now watching for \
          AutomationTriggered events from orchestrator. Any trigger arriving \
          before t=9300s is considered to be acting on validated state. \
          After t=9300s, the validation expires and any trigger becomes unjustified."),
    ],
    // ── Step 12: AutomationTriggered(orchestrator, t=9100) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=9100s",
         "Mother triggers a remediation action 100 seconds after state validation. \
          Contract AUTO-1 fires: is there a StateValidated within the 5-minute window? \
          At t=9100s the window is open — 200 seconds remain. The check runs now."),
        ("State Lookup",
         "Checking orchestrator's validation state",
         "orchestrator.last_validated_at=9000. Elapsed since validation: 100s. \
          Window: 300s. 100 < 300 — validation is fresh. trigger_count stays at 0. \
          This trigger is causally justified by the preceding state validation."),
        ("Invariant Result",
         "✔ Pass — automation is acting on validated state",
         "Contract AUTO-1 satisfied: Mother's remediation is backed by a valid, \
          recent state validation. This is the expected pattern — automation \
          acting on confirmed, coherent state. \
          Now watch what happens after the validation window expires."),
    ],
    // ── Step 13: AutomationTriggered(orchestrator, t=9400) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=9400s",
         "Mother triggers again at t=9400s. The last validation was at t=9000s — \
          400 seconds ago. The window is 300 seconds. \
          The validation has expired. No new StateValidated has arrived. \
          Contract AUTO-1 fires: is this trigger justified?"),
        ("State Lookup",
         "orchestrator.last_validated=9000s, elapsed=400s, window=300s",
         "400 > 300. The validation has expired by 100 seconds. \
          No StateValidated has arrived since t=9000s, yet automation is still firing. \
          trigger_count → 1 (first stale trigger). \
          The previous remediation did not resolve the underlying issue."),
        ("Invariant Result",
         "⚠ Warning — automation acting on stale state",
         "Contract AUTO-1 partially violated. trigger_count=1. \
          Mother is triggering remediation on system state that has not been \
          re-validated since t=9000s. The first occurrence is flagged as a Warning. \
          The engine continues watching: will state be re-validated, or will \
          the automation keep firing into the void?"),
    ],
    // ── Step 14: AutomationTriggered(orchestrator, t=9600) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=9600s",
         "Mother triggers a third time at t=9600s. Still no StateValidated \
          since t=9000s — now 600 seconds ago, twice the window. \
          trigger_count → 2. Contract AUTO-2 fires: this is a cascade."),
        ("State Lookup",
         "orchestrator.last_validated=9000s, elapsed=600s, trigger_count → 2",
         "600 > 300. Validation expired 300 seconds ago. \
          Two consecutive triggers on unvalidated state. \
          The underlying deviation has not been resolved by prior remediations. \
          Mother is not correcting the problem — it is amplifying it."),
        ("Invariant Result",
         "✘ Critical — automation cascade detected",
         "Contract AUTO-2 violated. Deterministic proof: 2 consecutive AutomationTriggered \
          events on state that has not been re-validated. \
          This is the automation amplification pattern: the AI is reacting to \
          manipulated or incoherent telemetry, repeatedly, without confirmation \
          that its actions are having any effect."),
    ],
    // ── Step 15: AutomationTriggered(orchestrator, t=9900) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=9900s",
         "Mother triggers a fourth time at t=9900s. 900 seconds since last validation — \
          three times the window. trigger_count → 3. \
          The automation has now fired four times on unvalidated state, \
          with zero re-validation in between. The pattern is definitive."),
        ("State Lookup",
         "orchestrator.last_validated=9000s, elapsed=900s, trigger_count → 3",
         "900 > 300. 3 consecutive triggers on expired state. \
          No StateValidated has arrived. No evidence that any prior remediation \
          resolved the underlying issue. The automation is in a feedback loop, \
          amplifying an unresolved deviation with each successive trigger."),
        ("Invariant Result",
         "✘ Critical — automation amplification proven",
         "Contract AUTO-2 confirmed: sustained automation triggering on unvalidated state. \
          4 triggers, 1 validation — Mother is reacting to incoherent telemetry. \
          In a real deployment: halt signal required, human escalation mandatory. \
          Every detection is a deterministic causal proof — not a probability, \
          not a heuristic, not a model score. A broken causal chain."),
    ],
];

// ── Helpers ───────────────────────────────────────────────────────────────────

fn js_str(s: &str) -> String {
    format!("\"{}\"",
        s.replace('\\', "\\\\")
         .replace('"', "\\\"")
         .replace('\n', " ")
         .replace('\r', ""),
    )
}

fn snapshot(
    id_store:   &StateStore,
    cp_store:   &ControlPlaneStore,
    th_store:   &ThermalStore,
    au_store:   &AutomationStore,
    current_ts: u64,
) -> Vec<(String, EntityState)> {
    let mut out: Vec<(String, EntityState)> = Vec::new();

    // Identity entities
    for (entity, s) in id_store {
        let last   = s.last_login();
        let in_win = last.map(|t| current_ts.saturating_sub(t) <= WINDOW).unwrap_or(false);
        out.push((entity.clone(), EntityState {
            domain: "Identity",
            fields: vec![
                (
                    "last_login".into(),
                    last.map(|t| format!("t={}s{}", t, if !in_win { " ⚠" } else { "" }))
                        .unwrap_or_else(|| "—".into()),
                    if last.is_none() { "none" } else if in_win { "ok" } else { "fail" }.into(),
                ),
                (
                    "token_issued".into(),
                    s.token_issued_at.map(|t| format!("t={}s", t)).unwrap_or_else(|| "—".into()),
                    if s.token_issued_at.is_some() { "ok" } else { "none" }.into(),
                ),
                (
                    "token_used".into(),
                    if s.token_used { "yes" } else { "no" }.into(),
                    if s.token_used { "ok" } else { "none" }.into(),
                ),
            ],
        }));
    }

    // ControlPlane entities
    for (entity, s) in cp_store {
        let in_win = s.role_within(current_ts, CP_WINDOW).is_some();
        out.push((entity.clone(), EntityState {
            domain: "ControlPlane",
            fields: vec![
                (
                    "role_assigned_at".into(),
                    s.role_assigned_at.map(|t| format!("t={}s{}", t, if !in_win { " ⚠" } else { "" }))
                        .unwrap_or_else(|| "—".into()),
                    if s.role_assigned_at.is_none() { "none" } else if in_win { "ok" } else { "fail" }.into(),
                ),
                (
                    "admin_action".into(),
                    if s.admin_action_taken { "yes" } else { "no" }.into(),
                    if s.admin_action_taken { "ok" } else { "none" }.into(),
                ),
            ],
        }));
    }

    // Thermal entities
    for (entity, s) in th_store {
        let wl_in_win = s.workload_within(current_ts, JUSTIFICATION_WINDOW).is_some();
        let is_biased = s.last_temp.map(|t| t > NOMINAL_TEMP + BIAS_THRESHOLD).unwrap_or(false);
        out.push((entity.clone(), EntityState {
            domain: "Thermal",
            fields: vec![
                (
                    "last_workload_at".into(),
                    s.last_workload_at
                        .map(|t| format!("t={}s{}", t, if !wl_in_win { " ⚠" } else { "" }))
                        .unwrap_or_else(|| "—".into()),
                    if s.last_workload_at.is_none() { "none" }
                    else if wl_in_win { "ok" }
                    else { "fail" }.into(),
                ),
                (
                    "last_temp".into(),
                    s.last_temp.map(|t| format!("{}°C", t)).unwrap_or_else(|| "—".into()),
                    if s.last_temp.is_none() { "none" }
                    else if is_biased { "fail" }
                    else { "ok" }.into(),
                ),
                (
                    "bias_count".into(),
                    s.bias_count.to_string(),
                    if s.bias_count == 0 { "ok" }
                    else if s.bias_count == 1 { "warn" }
                    else { "fail" }.into(),
                ),
            ],
        }));
    }

    // Automation entities
    for (entity, s) in au_store {
        let val_in_win = s.validation_within(current_ts, VALIDATION_WINDOW).is_some();
        out.push((entity.clone(), EntityState {
            domain: "Automation",
            fields: vec![
                (
                    "last_validated_at".into(),
                    s.last_validated_at
                        .map(|t| format!("t={}s{}", t, if !val_in_win { " ⚠" } else { "" }))
                        .unwrap_or_else(|| "—".into()),
                    if s.last_validated_at.is_none() { "none" }
                    else if val_in_win { "ok" }
                    else { "fail" }.into(),
                ),
                (
                    "trigger_count".into(),
                    s.trigger_count.to_string(),
                    if s.trigger_count == 0 { "ok" }
                    else if s.trigger_count == 1 { "warn" }
                    else { "fail" }.into(),
                ),
                (
                    "last_trigger_at".into(),
                    s.last_trigger_at.map(|t| format!("t={}s", t)).unwrap_or_else(|| "—".into()),
                    if s.last_trigger_at.is_some() { "neutral" } else { "none" }.into(),
                ),
            ],
        }));
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn compute_check(
    ev:     &Event,
    id_pre: Option<&AuthState>,
    cp_pre: Option<&ControlPlaneState>,
    th_pre: Option<&ThermalState>,
    au_pre: Option<&AutomationState>,
) -> CheckInfo {
    match &ev.kind {
        DomainEvent::Identity(_)    => compute_identity_check(ev, id_pre),
        DomainEvent::ControlPlane(_)=> compute_cp_check(ev, cp_pre),
        DomainEvent::Thermal(_)     => compute_thermal_check(ev, th_pre),
        DomainEvent::Automation(_)  => compute_automation_check(ev, au_pre),
    }
}

fn compute_automation_check(ev: &Event, pre: Option<&AutomationState>) -> CheckInfo {
    match &ev.kind {
        DomainEvent::Automation(AutomationEvent::StateValidated) => CheckInfo {
            rule: "Contract AUTO-1 — StateValidated(entity) · validation window opens".to_string(),
            lookup: vec![
                ("entity".into(),  ev.entity.to_string(),                                  "neutral".into()),
                ("event".into(),   format!("StateValidated @ t={}s", ev.ts),               "neutral".into()),
                ("action".into(),  "Validation timestamp recorded, trigger_count reset".to_string(), "ok".into()),
                ("window".into(),  format!("automation justified for {}s from now", VALIDATION_WINDOW), "neutral".into()),
            ],
            result:        "pending",
            result_text:   "⏳ PENDING".to_string(),
            result_detail: "State validated — any AutomationTriggered within the next 5 minutes is considered justified".to_string(),
        },

        DomainEvent::Automation(AutomationEvent::AutomationTriggered) => {
            let val_at    = pre.and_then(|s| s.last_validated_at);
            let justified = pre.map(|s| s.validation_within(ev.ts, VALIDATION_WINDOW).is_some()).unwrap_or(false);
            let count     = pre.map(|s| s.trigger_count).unwrap_or(0); // count before this trigger

            let mut lookup = vec![
                ("entity".into(), ev.entity.to_string(),                          "neutral".into()),
                ("event".into(),  format!("AutomationTriggered @ t={}s", ev.ts), "neutral".into()),
            ];

            match val_at {
                None => {
                    lookup.push(("last_validated".into(), "NONE".into(), "fail".into()));
                    lookup.push(("justified?".into(),     "NO — no StateValidated on record".into(), "fail".into()));
                }
                Some(t) => {
                    let elapsed = ev.ts.saturating_sub(t);
                    lookup.push(("last_validated".into(), format!("t={}s", t), "neutral".into()));
                    lookup.push(("elapsed".into(),        format!("{}s", elapsed), if elapsed <= VALIDATION_WINDOW { "ok".into() } else { "fail".into() }));
                    lookup.push(("window".into(),         format!("{}s", VALIDATION_WINDOW), "neutral".into()));
                    lookup.push(("justified?".into(),
                        if justified { "YES — within window".into() }
                        else { format!("NO — validation expired {}s ago", elapsed - VALIDATION_WINDOW) },
                        if justified { "ok".into() } else { "fail".into() }
                    ));
                }
            }

            if justified {
                CheckInfo {
                    rule:          "Contract AUTO-1 — AutomationTriggered backed by fresh StateValidated".to_string(),
                    lookup,
                    result:        "pass",
                    result_text:   "✔ PASS".to_string(),
                    result_detail: format!("Automation is acting on validated state — trigger is causally justified"),
                }
            } else {
                let next_count = count + 1;
                if next_count == 1 {
                    lookup.push(("trigger_count".into(), "1 (first stale trigger)".into(), "warn".into()));
                    CheckInfo {
                        rule:          "Contract AUTO-1 — AutomationTriggered must be backed by StateValidated within 5-min window".to_string(),
                        lookup,
                        result:        "warn",
                        result_text:   "⚠ CONTRACT WARNING".to_string(),
                        result_detail: format!("'{}': automation fired on unvalidated state — monitoring for cascade", ev.entity),
                    }
                } else {
                    lookup.push(("trigger_count".into(), format!("{} (cascade)", next_count), "fail".into()));
                    CheckInfo {
                        rule:          "Contract AUTO-2 — Repeated automation on unvalidated state — amplification invariant violated".to_string(),
                        lookup,
                        result:        "fail",
                        result_text:   "✘ CONTRACT VIOLATED".to_string(),
                        result_detail: format!("'{}': {} consecutive triggers without StateValidated — automation is amplifying unresolved deviation", ev.entity, next_count),
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

fn compute_thermal_check(ev: &Event, pre: Option<&ThermalState>) -> CheckInfo {
    match &ev.kind {
        DomainEvent::Thermal(ThermalEvent::WorkloadScheduled) => CheckInfo {
            rule: "Contract TH-1 — WorkloadScheduled(rack) · justification window opens".to_string(),
            lookup: vec![
                ("entity".into(),  ev.entity.to_string(),                               "neutral".into()),
                ("event".into(),   format!("WorkloadScheduled @ t={}s", ev.ts),          "neutral".into()),
                ("action".into(),  "Workload timestamp recorded to state".to_string(),   "ok".into()),
                ("window".into(),  format!("justification valid for {}s", JUSTIFICATION_WINDOW), "neutral".into()),
            ],
            result:        "pending",
            result_text:   "⏳ PENDING".to_string(),
            result_detail: "Workload declared — any ThermalReading above threshold within 30 min is now justified".to_string(),
        },

        DomainEvent::Thermal(ThermalEvent::ThermalReading(temp)) => {
            let threshold    = NOMINAL_TEMP + BIAS_THRESHOLD;
            let is_biased    = *temp > threshold;
            let wl_at        = pre.and_then(|s| s.last_workload_at);
            let justified    = pre.map(|s| s.workload_within(ev.ts, JUSTIFICATION_WINDOW).is_some()).unwrap_or(false);
            let bias_count   = pre.map(|s| s.bias_count).unwrap_or(0);

            let mut lookup = vec![
                ("entity".into(),    ev.entity.to_string(),                         "neutral".into()),
                ("event".into(),     format!("ThermalReading @ t={}s", ev.ts),       "neutral".into()),
                ("temp".into(),      format!("{}°C", temp),                          if is_biased { "fail".into() } else { "ok".into() }),
                ("threshold".into(), format!("{}°C (nominal {} + bias {})", threshold, NOMINAL_TEMP, BIAS_THRESHOLD), "neutral".into()),
                ("biased?".into(),   if is_biased { "YES".into() } else { "NO".into() }, if is_biased { "fail".into() } else { "ok".into() }),
            ];

            match wl_at {
                None => {
                    lookup.push(("last_workload".into(), "NONE".into(), "none".into()));
                    lookup.push(("justified?".into(),    "NO — no workload declared".into(), "fail".into()));
                }
                Some(t) => {
                    let elapsed = ev.ts.saturating_sub(t);
                    lookup.push(("last_workload".into(), format!("t={}s", t), "neutral".into()));
                    lookup.push(("elapsed".into(),       format!("{}s", elapsed), if elapsed <= JUSTIFICATION_WINDOW { "ok".into() } else { "fail".into() }));
                    lookup.push(("justified?".into(),
                        if justified { "YES — within window".into() }
                        else { format!("NO — workload expired {}s ago", elapsed - JUSTIFICATION_WINDOW) },
                        if justified { "ok".into() } else { "fail".into() }
                    ));
                }
            }

            if !is_biased || justified {
                CheckInfo {
                    rule:          "Contract TH-1 — ThermalReading within justified limits".to_string(),
                    lookup,
                    result:        "pass",
                    result_text:   "✔ PASS".to_string(),
                    result_detail: if !is_biased {
                        format!("temp={}°C is within nominal range — no thermal bias", temp)
                    } else {
                        format!("temp={}°C exceeds threshold but workload declared {}s ago — justified", temp,
                            ev.ts.saturating_sub(wl_at.unwrap_or(0)))
                    },
                }
            } else {
                let next_count = bias_count + 1;
                if next_count == 1 {
                    lookup.push(("bias_count".into(), "1 (first occurrence)".into(), "warn".into()));
                    CheckInfo {
                        rule:          "Contract TH-1 — ThermalReading bias must be justified by WorkloadScheduled".to_string(),
                        lookup,
                        result:        "warn",
                        result_text:   "⚠ CONTRACT WARNING".to_string(),
                        result_detail: format!("'{}': temp={}°C exceeds threshold with no workload justification — monitoring for sustained bias", ev.entity, temp),
                    }
                } else {
                    lookup.push(("bias_count".into(), format!("{} (sustained)", next_count), "fail".into()));
                    CheckInfo {
                        rule:          "Contract TH-2 — Sustained unjustified thermal bias — equilibrium invariant violated".to_string(),
                        lookup,
                        result:        "fail",
                        result_text:   "✘ CONTRACT VIOLATED".to_string(),
                        result_detail: format!("'{}': {} consecutive readings above threshold ({}°C) — no workload justification found", ev.entity, next_count, temp),
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

fn compute_identity_check(ev: &Event, pre: Option<&AuthState>) -> CheckInfo {
    match &ev.kind {
        DomainEvent::Identity(IdentityEvent::LoginSuccess) => CheckInfo {
            rule:   "Contract 1 — LoginSuccess(entity) → must issue AuthTokenIssued(entity)".to_string(),
            lookup: vec![
                ("entity".into(),       ev.entity.to_string(),                        "neutral".into()),
                ("event".into(),        format!("LoginSuccess @ t={}s", ev.ts),       "neutral".into()),
                ("action".into(),       "Login time recorded to state".to_string(),   "ok".into()),
                ("watching for".into(), format!("AuthTokenIssued within {}s", WINDOW),"neutral".into()),
            ],
            result:        "pending",
            result_text:   "⏳ PENDING".to_string(),
            result_detail: "Contract 1 is deferred — verified when AuthTokenIssued arrives or the stream ends".to_string(),
        },

        DomainEvent::Identity(IdentityEvent::AuthTokenIssued) => {
            let last  = pre.and_then(|s| s.last_login());
            let valid = pre.map(|s| s.login_within(ev.ts, WINDOW).is_some()).unwrap_or(false);
            let mut lookup = vec![
                ("entity".into(), ev.entity.to_string(),                      "neutral".into()),
                ("event".into(),  format!("AuthTokenIssued @ t={}s", ev.ts), "neutral".into()),
            ];
            match last {
                None => {
                    lookup.push(("last_login".into(), "NONE".to_string(),              "fail".into()));
                    lookup.push(("window".into(),     format!("{}s", WINDOW),          "neutral".into()));
                    lookup.push(("verdict".into(),    "NO LOGIN ON RECORD".to_string(), "fail".into()));
                }
                Some(t) => {
                    let e = ev.ts - t;
                    lookup.push(("last_login".into(), format!("t={}s", t),  "neutral".into()));
                    lookup.push(("elapsed".into(),    format!("{}s", e),    if e <= WINDOW { "ok".into() } else { "fail".into() }));
                    lookup.push(("window".into(),     format!("{}s", WINDOW), "neutral".into()));
                    lookup.push(("verdict".into(),
                        if valid { "within window ✔".to_string() }
                        else     { format!("EXPIRED — {}s over limit", e - WINDOW) },
                        if valid { "ok".into() } else { "fail".into() }
                    ));
                }
            }
            if valid {
                CheckInfo { rule: "Contract 1 check — AuthTokenIssued requires LoginSuccess within 5-min window".to_string(), lookup, result: "pass",
                    result_text: "✔ PASS".to_string(), result_detail: "Login was recent — token issuance is valid".to_string() }
            } else {
                CheckInfo { rule: "Contract 1 check — AuthTokenIssued requires LoginSuccess within 5-min window".to_string(), lookup, result: "fail",
                    result_text: "✘ CONTRACT VIOLATED".to_string(), result_detail: "Token issued without a valid LoginSuccess in the 5-minute window".to_string() }
            }
        }

        DomainEvent::Identity(IdentityEvent::AuthTokenUsed) => {
            let has_login   = pre.map(|s| s.has_login()).unwrap_or(false);
            let last_login  = pre.and_then(|s| s.last_login());
            let valid_login = pre.map(|s| s.login_within(ev.ts, WINDOW).is_some()).unwrap_or(false);
            let token_at    = pre.and_then(|s| s.token_issued_at);
            let mut lookup  = vec![
                ("entity".into(), ev.entity.to_string(),                   "neutral".into()),
                ("event".into(),  format!("AuthTokenUsed @ t={}s", ev.ts), "neutral".into()),
            ];
            if has_login {
                let t = last_login.unwrap(); let e = ev.ts - t;
                lookup.push(("last_login".into(),  format!("t={}s", t),  "neutral".into()));
                lookup.push(("elapsed".into(),     format!("{}s", e),    if e <= WINDOW { "ok".into() } else { "fail".into() }));
                lookup.push(("window".into(),      format!("{}s", WINDOW), "neutral".into()));
                lookup.push(("login_valid?".into(),
                    if valid_login { "YES".to_string() } else { format!("NO — expired by {}s", e - WINDOW) },
                    if valid_login { "ok".into() } else { "fail".into() }
                ));
            } else {
                lookup.push(("last_login".into(),  "NONE".to_string(),              "fail".into()));
                lookup.push(("login_valid?".into(), "NO — no login on record".to_string(), "fail".into()));
            }
            match token_at {
                Some(t) => lookup.push(("token_issued".into(), format!("t={}s", t), "ok".into())),
                None    => lookup.push(("token_issued".into(), "NONE".into(),        "warn".into())),
            }
            let is_critical = !has_login || !valid_login;
            if !is_critical && token_at.is_some() {
                CheckInfo { rule: "Contract 2 check — AuthTokenUsed requires LoginSuccess within window + AuthTokenIssued".to_string(), lookup,
                    result: "pass", result_text: "✔ PASS".to_string(),
                    result_detail: "Login is recent and token issuance is on record — valid".to_string() }
            } else {
                let detail = if !has_login {
                    "No LoginSuccess on record — unauthenticated token use detected".to_string()
                } else {
                    let e = ev.ts - last_login.unwrap();
                    format!("Session expired: login was {}s ago, window is {}s — exceeded by {}s", e, WINDOW, e - WINDOW)
                };
                CheckInfo { rule: "Contract 2 check — AuthTokenUsed requires LoginSuccess within window + AuthTokenIssued".to_string(), lookup,
                    result: if is_critical { "fail" } else { "warn" },
                    result_text: if is_critical { "✘ CONTRACT VIOLATED".to_string() } else { "⚠ CONTRACT WARNING".to_string() },
                    result_detail: detail }
            }
        }
        _ => unreachable!(), // only called for Identity events
    }
}

fn compute_cp_check(ev: &Event, pre: Option<&ControlPlaneState>) -> CheckInfo {
    match &ev.kind {
        DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned) => {
            let rule = "Contract CP-1 — RoleAssigned(entity) · role validity window opens".to_string();
            CheckInfo {
                lookup: vec![
                    ("entity".into(),   ev.entity.to_string(),                          "neutral".into()),
                    ("event".into(),    format!("RoleAssigned @ t={}s", ev.ts),          "neutral".into()),
                    ("action".into(),   "Role timestamp recorded to state".to_string(),   "ok".into()),
                    ("window".into(),   format!("valid for {}s from now", CP_WINDOW),    "neutral".into()),
                ],
                rule,
                result:        "pending",
                result_text:   "⏳ PENDING".to_string(),
                result_detail: "Role assigned — engine will verify any AdminActionTaken arrives within the 1-hour window".to_string(),
            }
        }
        DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken) => {
            let has_role    = pre.map(|s| s.has_role()).unwrap_or(false);
            let role_at     = pre.and_then(|s| s.role_assigned_at);
            let in_win      = pre.map(|s| s.role_within(ev.ts, CP_WINDOW).is_some()).unwrap_or(false);
            let mut lookup  = vec![
                ("entity".into(), ev.entity.to_string(),                     "neutral".into()),
                ("event".into(),  format!("AdminActionTaken @ t={}s", ev.ts), "neutral".into()),
            ];
            if has_role {
                let t = role_at.unwrap();
                let elapsed = ev.ts - t;
                lookup.push(("role_assigned".into(), format!("t={}s", t),         "neutral".into()));
                lookup.push(("elapsed".into(),        format!("{}s", elapsed),      if elapsed <= CP_WINDOW { "ok".into() } else { "fail".into() }));
                lookup.push(("window".into(),         format!("{}s", CP_WINDOW),    "neutral".into()));
                lookup.push(("role_valid?".into(),
                    if in_win { "YES".into() } else { format!("NO — expired by {}s", elapsed - CP_WINDOW) },
                    if in_win { "ok".into() } else { "fail".into() },
                ));
            } else {
                lookup.push(("role_assigned".into(), "NONE".into(),                            "fail".into()));
                lookup.push(("role_valid?".into(),   "NO — no role assignment on record".into(), "fail".into()));
            }
            let rule = "Contract CP-2 — AdminActionTaken requires RoleAssigned within 1-hour window".to_string();
            if has_role && in_win {
                CheckInfo { rule, lookup, result: "pass",
                    result_text:   "✔ PASS".to_string(),
                    result_detail: "Role is current — admin action is authorised".to_string() }
            } else {
                CheckInfo { rule, lookup, result: "fail",
                    result_text:   "✘ CONTRACT VIOLATED".to_string(),
                    result_detail: if !has_role {
                        "No role assignment on record — privilege misuse detected".to_string()
                    } else {
                        let e = ev.ts - role_at.unwrap();
                        format!("Role expired: assigned {}s ago, window is {}s — exceeded by {}s", e, CP_WINDOW, e - CP_WINDOW)
                    }}
            }
        }
        _ => unreachable!(),
    }
}

// ── Scenario ──────────────────────────────────────────────────────────────────

fn run_scenario() -> Vec<StepData> {
    let mut engine            = Engine::new();
    let mut cp_engine         = ControlPlaneEngine::new();
    let mut thermal_engine    = ThermalEngine::new();
    let mut automation_engine = AutomationEngine::new();
    let mut steps             = Vec::new();
    let mut seq               = 0usize;
    let mut user_history: HashMap<String, Vec<(usize, u64, &'static str)>> = HashMap::new();

    let script: Vec<(&str, &str, u64, &'static str, DomainEvent)> = vec![
        // ── ControlPlane domain — Scenario A (Legitimate Variation) ──────────
        ("svc_alpha", "Scenario A — Legitimate Variation", 1000, "svc_alpha", DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned)),
        ("svc_alpha", "Scenario A — Legitimate Variation", 1030, "svc_alpha", DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        // ── ControlPlane domain — Scenario B (Privilege Misuse) ──────────────
        ("rogue_svc", "Scenario B — Privilege Misuse",     1100, "rogue_svc", DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        ("svc_beta",  "Scenario B — Privilege Misuse",     1200, "svc_beta",  DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned)),
        ("svc_beta",  "Scenario B — Privilege Misuse",     5000, "svc_beta",  DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        // ── Thermal domain — Scenario C (Silent Scheduler Bias) ──────────────
        ("rack_a", "Scenario C — Silent Scheduler Bias", 6000, "rack_a", DomainEvent::Thermal(ThermalEvent::WorkloadScheduled)),
        ("rack_a", "Scenario C — Silent Scheduler Bias", 6300, "rack_a", DomainEvent::Thermal(ThermalEvent::ThermalReading(52))),
        ("rack_b", "Scenario C — Silent Scheduler Bias", 6600, "rack_b", DomainEvent::Thermal(ThermalEvent::ThermalReading(56))),
        ("rack_b", "Scenario C — Silent Scheduler Bias", 7200, "rack_b", DomainEvent::Thermal(ThermalEvent::ThermalReading(61))),
        ("rack_b", "Scenario C — Silent Scheduler Bias", 7800, "rack_b", DomainEvent::Thermal(ThermalEvent::ThermalReading(64))),
        // ── Automation domain — Scenario D (Automation Amplification) ─────────
        ("orchestrator", "Scenario D — Automation Amplification", 9000, "orchestrator", DomainEvent::Automation(AutomationEvent::StateValidated)),
        ("orchestrator", "Scenario D — Automation Amplification", 9100, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
        ("orchestrator", "Scenario D — Automation Amplification", 9400, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
        ("orchestrator", "Scenario D — Automation Amplification", 9600, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
        ("orchestrator", "Scenario D — Automation Amplification", 9900, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
    ];

    for (group, label, ts, user, kind) in &script {
        seq += 1;
        let ev      = Event::new(*ts, user, kind.clone());
        let id_pre  = engine.state.get(ev.entity).cloned();
        let cp_pre  = cp_engine.state.get(ev.entity).cloned();
        let th_pre  = thermal_engine.state.get(ev.entity).cloned();
        let au_pre  = automation_engine.state.get(ev.entity).cloned();
        let check   = compute_check(&ev, id_pre.as_ref(), cp_pre.as_ref(), th_pre.as_ref(), au_pre.as_ref());
        let variances = match ev.kind.domain() {
            Domain::Identity    => engine.ingest(&ev),
            Domain::ControlPlane=> cp_engine.ingest(&ev),
            Domain::Thermal     => thermal_engine.ingest(&ev),
            Domain::Automation  => automation_engine.ingest(&ev),
        };
        let snap   = snapshot(&engine.state, &cp_engine.state, &thermal_engine.state, &automation_engine.state, *ts);
        let phases = NARRATIVES.get(seq - 1).copied().unwrap_or(&[]).to_vec();

        user_history.entry(user.to_string()).or_default().push((seq, *ts, kind.name()));
        let history = user_history.get(*user).cloned().unwrap_or_default();

        steps.push(StepData {
            seq, ts: *ts, user: user.to_string(), event: ev.kind.name(),
            group: group.to_string(), group_label: label.to_string(), is_deferred: false,
            check,
            variances: variances.iter().map(|v: &Variance| VarInfo {
                severity: v.severity.as_str(), rule: v.rule.to_string(), detail: v.detail.clone(),
            }).collect(),
            state_snap: snap, phases, history,
        });
    }

    steps
}

// ── Scenario metadata (POC document Section 6) ────────────────────────────────

/// Declared scenario inputs + expected outcomes, matched against the POC document.
/// Each future domain phase will add its own SCENARIO_X_JS constant.
const SCENARIOS_JS: &str = r#"[
  {id:"A",name:"Legitimate Variation",label:"Scenario A \u2014 Legitimate Variation",domain:"ControlPlane",description:"Valid role assignment followed by admin action within 1-hour window. No invariants broken.",expected:0},
  {id:"B",name:"Privilege Misuse",label:"Scenario B \u2014 Privilege Misuse",domain:"ControlPlane",description:"Stealth admin actions without valid role assignments. Two Critical violations expected.",expected:2},
  {id:"C",name:"Silent Scheduler Bias",label:"Scenario C \u2014 Silent Scheduler Bias",domain:"Thermal",description:"Sustained rack thermal bias with no declared workload shift. Three violations expected: 1 Warning escalating to 2 Critical.",expected:3},
  {id:"D",name:"Automation Amplification",label:"Scenario D \u2014 Automation Amplification",domain:"Automation",description:"Repeated automation triggers on unvalidated system state. Three violations expected: 1 Warning escalating to 2 Critical.",expected:3}
]"#;

// ── Serialize to JS ───────────────────────────────────────────────────────────

fn steps_to_js(steps: &[StepData]) -> String {
    let mut out = String::from("[\n");
    for s in steps {
        out.push_str("  {\n");
        write!(out, "    seq:{},ts:{},user:{},event:{},\n", s.seq, s.ts, js_str(&s.user), js_str(s.event)).unwrap();
        write!(out, "    group:{},group_label:{},is_deferred:{},\n", js_str(&s.group), js_str(&s.group_label), s.is_deferred).unwrap();
        out.push_str("    check:{\n");
        write!(out, "      rule:{},\n", js_str(&s.check.rule)).unwrap();
        out.push_str("      lookup:[\n");
        for (k, v, st) in &s.check.lookup {
            write!(out, "        [{},{},{}],\n", js_str(k), js_str(v), js_str(st)).unwrap();
        }
        out.push_str("      ],\n");
        write!(out, "      result:{},result_text:{},result_detail:{},\n", js_str(s.check.result), js_str(&s.check.result_text), js_str(&s.check.result_detail)).unwrap();
        out.push_str("    },\n    variances:[\n");
        for v in &s.variances {
            write!(out, "      {{severity:{},rule:{},detail:{}}},\n", js_str(v.severity), js_str(&v.rule), js_str(&v.detail)).unwrap();
        }
        out.push_str("    ],\n    state:{\n");
        for (entity, es) in &s.state_snap {
            write!(out, "      {}:{{domain:{},fields:[", js_str(entity), js_str(es.domain)).unwrap();
            for (k, v, cls) in &es.fields {
                write!(out, "[{},{},{}],", js_str(k), js_str(v), js_str(cls)).unwrap();
            }
            out.push_str("]},\n");
        }
        out.push_str("    },\n    history:[\n");
        for (hseq, hts, hev) in &s.history {
            write!(out, "      {{seq:{},ts:{},event:{}}},\n", hseq, hts, js_str(hev)).unwrap();
        }
        out.push_str("    ],\n    phases:[\n");
        for (label, heading, body) in &s.phases {
            write!(out, "      {{label:{},heading:{},body:{}}},\n", js_str(label), js_str(heading), js_str(body)).unwrap();
        }
        out.push_str("    ],\n  },\n");
    }
    out.push(']');
    out
}

// ── CSS ───────────────────────────────────────────────────────────────────────

const CSS: &str = r#"
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#050b14;--surface:#091222;--panel:#0a1628;--border:#163354;
  --green:#00e5a0;--red:#ff3355;--yellow:#ffba3b;--blue:#4facfe;
  --text:#c9d8e8;--muted:#4a6585;--dim:#2a4060;--nbody:#8ba3bc;
}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);
  font-family:'Cascadia Code','Consolas','Courier New',monospace;
  display:flex;flex-direction:column;font-size:13px}
/* Header */
header{flex-shrink:0;background:var(--surface);border-bottom:1px solid var(--border);
  padding:.6rem 1.25rem;display:flex;align-items:center;justify-content:space-between;height:62px}
.hdr-left h1{font-size:.95rem;font-weight:700;letter-spacing:.02em;color:#e2eaf4}
.hdr-left p{font-size:.6rem;color:var(--muted);margin-top:.15rem;letter-spacing:.06em;text-transform:uppercase}
.hdr-contract{background:var(--panel);border:1px solid var(--border);border-radius:6px;
  padding:.3rem .8rem;font-size:.7rem;color:var(--muted);display:flex;align-items:center;gap:.4rem}
.arrow{color:var(--green);font-weight:700}
.hdr-controls{display:flex;gap:.4rem}
button{border:1px solid var(--border);background:var(--panel);color:var(--text);
  padding:.35rem .9rem;border-radius:5px;cursor:pointer;font-family:inherit;font-size:.72rem;
  display:inline-flex;align-items:center;gap:.35rem;transition:all .15s}
button:hover:not(:disabled){border-color:var(--blue);color:var(--blue)}
#play-btn{border-color:var(--green);color:var(--green)}
#play-btn:hover:not(:disabled){background:rgba(0,229,160,.08)}
#step-btn{border-color:var(--blue);color:var(--blue)}
#step-btn:hover:not(:disabled){background:rgba(79,172,254,.08)}
#reset-btn{display:none}
button:disabled{opacity:.4;cursor:not-allowed}
/* Main grid */
.main-grid{flex:1;display:grid;grid-template-columns:22% 1fr 22%;min-height:0;
  border-bottom:1px solid var(--border)}
.panel{background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column;min-height:0}
.panel:last-child{border-right:none}
.panel-title{flex-shrink:0;background:var(--surface);border-bottom:1px solid var(--border);
  padding:.35rem .7rem;font-size:.58rem;text-transform:uppercase;letter-spacing:.12em;
  color:var(--muted);font-weight:700}
.panel-content{flex:1;overflow-y:auto;padding:.55rem}
.panel-content::-webkit-scrollbar{width:3px}
.panel-content::-webkit-scrollbar-thumb{background:var(--border)}
/* Narrator bar */
.narrator{flex-shrink:0;background:#060e1c;border-top:2px solid var(--blue);
  height:0;overflow:hidden;transition:height .25s ease;display:flex;flex-direction:column}
.narrator.active{height:148px}
.narrator-top{flex-shrink:0;display:flex;justify-content:space-between;align-items:center;
  padding:.3rem .75rem;border-bottom:1px solid var(--border)}
.narrator-phase-lbl{font-size:.58rem;text-transform:uppercase;letter-spacing:.14em;
  color:var(--blue);font-weight:700}
.narrator-step-info{font-size:.58rem;color:var(--muted)}
.narrator-main{flex:1;display:flex;align-items:flex-start;gap:.75rem;padding:.5rem .75rem}
.narrator-text{flex:1;min-width:0}
.narrator-heading{font-size:.78rem;font-weight:700;color:var(--text);margin-bottom:.2rem}
.narrator-body{font-size:.66rem;color:var(--nbody);line-height:1.55}
#narrator-next{flex-shrink:0;align-self:center;border-color:var(--blue);color:var(--blue);
  background:rgba(79,172,254,.08);white-space:nowrap;font-size:.72rem;padding:.4rem 1rem}
#narrator-next:disabled{opacity:.35;cursor:not-allowed}
/* Violations */
.violations-section{flex-shrink:0;background:var(--bg);height:190px;display:flex;flex-direction:column}
.viol-header{flex-shrink:0;background:var(--surface);border-top:2px solid var(--border);
  padding:.35rem .75rem;display:flex;align-items:center;gap:.75rem}
.viol-title{font-size:.58rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);font-weight:700}
.viol-count-wrap{display:flex;align-items:center;gap:.3rem;font-size:.62rem;color:var(--muted)}
.viol-count{background:var(--red);color:#fff;border-radius:9999px;
  padding:.1rem .4rem;font-size:.62rem;font-weight:700;min-width:1.3rem;text-align:center;
  transition:transform .2s}
.viol-count.bump{transform:scale(1.45)}
.viol-cards{flex:1;overflow-x:auto;overflow-y:hidden;display:flex;align-items:stretch;
  gap:.45rem;padding:.45rem .75rem;white-space:nowrap}
.viol-card{display:inline-flex;flex-direction:column;gap:.2rem;background:var(--panel);
  border:1px solid var(--border);border-radius:5px;padding:.45rem .55rem;
  min-width:230px;max-width:270px;white-space:normal;flex-shrink:0;
  opacity:0;transform:translateY(10px);transition:opacity .3s,transform .3s}
.viol-card.visible{opacity:1;transform:none}
.viol-card.v-critical{border-color:rgba(255,51,85,.5);border-left:3px solid var(--red)}
.viol-card.v-warning{border-color:rgba(255,186,59,.4);border-left:3px solid var(--yellow)}
.vbadge{display:inline-block;font-size:.56rem;font-weight:700;padding:.1rem .3rem;
  border-radius:3px;letter-spacing:.08em;text-transform:uppercase}
.vbadge.critical{background:rgba(255,51,85,.2);color:var(--red)}
.vbadge.warning{background:rgba(255,186,59,.15);color:var(--yellow)}
.vwho{font-size:.6rem;color:var(--muted)}
.vrule{font-size:.64rem;color:var(--blue);margin-top:.12rem;line-height:1.4}
.vdetail{font-size:.62rem;color:var(--text);line-height:1.4}
/* Event cards */
.event-card{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--border);
  border-radius:4px;padding:.45rem .55rem;margin-bottom:.35rem;
  opacity:0;transform:translateX(-10px);transition:opacity .28s,transform .28s}
.event-card.visible{opacity:1;transform:none}
.event-card.ev-pass{border-left-color:var(--green)}
.event-card.ev-critical{border-left-color:var(--red)}
.event-card.ev-warn{border-left-color:var(--yellow)}
.event-card.ev-pending{border-left-color:var(--blue)}
.ev-head{display:flex;align-items:flex-start;gap:.45rem}
.ev-seq{font-size:.58rem;color:var(--dim);min-width:1.2rem;padding-top:2px;flex-shrink:0}
.ev-body{flex:1;min-width:0}
.ev-type{font-size:.72rem;font-weight:600}
.ev-meta{display:flex;gap:.4rem;margin-top:.12rem}
.ev-user{font-size:.62rem;color:var(--blue);text-transform:capitalize}
.ev-ts{font-size:.62rem;color:var(--muted)}
.ev-payload{display:grid;grid-template-columns:auto 1fr;column-gap:.45rem;row-gap:.06rem;
  margin-top:.28rem;padding:.22rem .38rem;background:rgba(0,0,0,.25);border-radius:3px;
  border:1px solid var(--dim);font-size:.58rem;line-height:1.6}
.pfield{color:var(--muted)}
.pval{color:var(--blue)}
.ev-payload-toggle,.ev-hist-toggle{display:block;width:100%;text-align:left;font-size:.58rem;color:var(--dim);
  background:none;border:none;border-top:1px solid var(--dim);padding:.2rem 0 0;
  margin-top:.22rem;cursor:pointer;font-family:inherit;letter-spacing:.02em;transition:color .12s}
.ev-payload-toggle:hover,.ev-hist-toggle:hover{color:var(--muted)}
.payload-json{display:none;margin-top:.15rem;padding:.3rem .45rem;background:rgba(0,0,0,.3);
  border-radius:3px;border:1px solid var(--dim)}
.payload-json.open{display:block}
.pj-line{font-size:.57rem;line-height:1.72;white-space:pre;overflow:hidden;text-overflow:ellipsis}
.pj-key{color:var(--blue)}.pj-str{color:var(--green)}.pj-num{color:var(--yellow)}
.pj-comment{color:var(--muted);font-style:italic}.pj-brace{color:var(--text)}
.pj-ok{color:var(--green)}.pj-fail{color:var(--red);font-weight:700}
.pj-warn{color:var(--yellow)}.pj-pending{color:var(--blue)}
.ev-history{display:none;margin-top:.18rem;border-radius:3px;overflow:hidden;border:1px solid var(--dim)}
.ev-history.open{display:block}
.eh-row{display:grid;grid-template-columns:1.6rem 1fr auto;gap:.3rem;
  padding:.14rem .35rem;font-size:.58rem;border-bottom:1px solid var(--dim)}
.eh-row:last-child{border-bottom:none}
.eh-row.eh-current{background:rgba(79,172,254,.08)}
.eh-seq{color:var(--dim)}
.eh-event{color:var(--text)}
.eh-ts{color:var(--muted);text-align:right}
/* Check panel */
.check-idle,.state-idle{height:100%;display:flex;align-items:center;justify-content:center;
  color:var(--dim);font-size:.72rem;text-align:center;padding:1rem}
.state-domain-lbl{font-size:.55rem;color:var(--muted);margin-left:.35rem;text-transform:uppercase;letter-spacing:.06em}
.check-hdr{font-size:.58rem;text-transform:uppercase;letter-spacing:.15em;color:var(--muted);font-weight:700;margin-bottom:.45rem}
.check-rule{font-size:.7rem;color:var(--blue);margin-bottom:.65rem;line-height:1.5;
  border-left:2px solid var(--blue);padding-left:.45rem}
.check-evaluating{display:flex;align-items:center;gap:.4rem;color:var(--muted);font-size:.68rem;margin:.4rem 0}
.spinner{width:11px;height:11px;border:2px solid var(--dim);border-top-color:var(--blue);
  border-radius:50%;animation:spin .65s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.lookup-table{border:1px solid var(--border);border-radius:4px;overflow:hidden;margin:.45rem 0}
.lookup-row{display:grid;grid-template-columns:1fr 1fr;border-bottom:1px solid var(--dim)}
.lookup-row:last-child{border-bottom:none}
.lookup-k,.lookup-v{padding:.28rem .45rem;font-size:.65rem}
.lookup-k{color:var(--muted);background:rgba(0,0,0,.2)}
.lookup-v{color:var(--text)}
.lookup-v.ok{color:var(--green)}
.lookup-v.fail{color:var(--red);font-weight:700}
.lookup-v.warn{color:var(--yellow)}
.check-result{border-radius:5px;padding:.55rem .7rem;margin-top:.45rem;border:1px solid}
.result-text{font-size:.82rem;font-weight:700;margin-bottom:.2rem}
.result-detail{font-size:.65rem;line-height:1.5}
.result-pass{border-color:rgba(0,229,160,.4);background:rgba(0,229,160,.06)}
.result-pass .result-text{color:var(--green)}
.result-fail{border-color:rgba(255,51,85,.5);background:rgba(255,51,85,.1);animation:shake .4s ease}
.result-fail .result-text{color:var(--red)}
.result-warn{border-color:rgba(255,186,59,.4);background:rgba(255,186,59,.07)}
.result-warn .result-text{color:var(--yellow)}
.result-pending{border-color:rgba(79,172,254,.3);background:rgba(79,172,254,.06)}
.result-pending .result-text{color:var(--blue)}
@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-5px)}40%{transform:translateX(5px)}60%{transform:translateX(-3px)}80%{transform:translateX(3px)}}
.panel-violated{animation:bflash .55s ease}
@keyframes bflash{0%,100%{box-shadow:none}50%{box-shadow:0 0 0 2px var(--red),inset 0 0 35px rgba(255,51,85,.12)}}
.complete-grid{display:grid;grid-template-columns:1fr 1fr;gap:.45rem;margin:.65rem 0}
.csstat{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:.55rem;text-align:center}
.csval{font-size:1.5rem;font-weight:700;line-height:1}
.cslbl{font-size:.58rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-top:.15rem}
.cs-critical .csval{color:var(--red)}.cs-warn .csval{color:var(--yellow)}.cs-pass .csval{color:var(--green)}.cs-total .csval{color:var(--text)}
.complete-note{font-size:.65rem;color:var(--muted);line-height:1.6;margin-top:.45rem;
  border-top:1px solid var(--border);padding-top:.45rem}
/* State panel */
.state-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;margin-bottom:.35rem;overflow:hidden}
.state-user{background:var(--panel);border-bottom:1px solid var(--border);padding:.28rem .45rem;
  font-size:.68rem;font-weight:700;text-transform:capitalize}
.state-row{display:grid;grid-template-columns:1fr 1fr;border-bottom:1px solid var(--dim)}
.state-row:last-child{border-bottom:none}
.state-k,.state-v{padding:.22rem .45rem;font-size:.62rem}
.state-k{color:var(--muted)}
.state-v.ok{color:var(--green)}.state-v.fail{color:var(--red)}.state-v.warn{color:var(--yellow)}.state-v.none{color:var(--dim)}
/* Flash overlay */
#violation-flash{position:fixed;inset:0;background:rgba(255,51,85,0);pointer-events:none;
  transition:background .12s;z-index:100}
#violation-flash.active{background:rgba(255,51,85,.16)}
/* Scenario summary bar */
.scenario-bar{flex-shrink:0;background:var(--surface);border-top:1px solid var(--border);
  display:flex;flex-direction:column;padding:.25rem 1.25rem;font-size:.65rem;gap:.1rem}
.sc-row{display:flex;align-items:center;gap:.6rem;padding:.1rem 0}
.sc-id{color:var(--blue);font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.sc-name{color:var(--text)}
.sc-domain{color:var(--muted);font-size:.6rem;text-transform:uppercase;letter-spacing:.08em}
.sc-expected{color:var(--muted)}
.sc-sep{color:var(--dim)}
.sc-result{margin-left:auto;font-weight:700;font-size:.7rem;letter-spacing:.02em;transition:color .2s}
.sc-result.pass{color:var(--green)}
.sc-result.fail{color:var(--red)}
.sc-result.pending{color:var(--muted);font-weight:400}
/* Help button */
#help-btn{border-color:var(--muted);color:var(--muted);padding:0;font-size:.75rem;
  width:1.85rem;height:1.85rem;border-radius:50%;justify-content:center;flex-shrink:0}
#help-btn:hover:not(:disabled){border-color:var(--blue);color:var(--blue)}
/* Modal */
#modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:200;
  display:flex;align-items:center;justify-content:center;
  opacity:0;pointer-events:none;transition:opacity .2s}
#modal-overlay.open{opacity:1;pointer-events:all}
#modal{background:var(--panel);border:1px solid var(--border);border-radius:8px;
  width:min(680px,90vw);max-height:82vh;display:flex;flex-direction:column;
  box-shadow:0 24px 64px rgba(0,0,0,.6);transform:translateY(12px);transition:transform .2s}
#modal-overlay.open #modal{transform:translateY(0)}
#modal-head{flex-shrink:0;display:flex;align-items:center;justify-content:space-between;
  padding:.65rem 1rem;border-bottom:1px solid var(--border);background:var(--surface);
  border-radius:8px 8px 0 0}
#modal-title{font-size:.82rem;font-weight:700;color:#e2eaf4;letter-spacing:.02em}
#modal-close{border:none;background:none;color:var(--muted);font-size:1.1rem;
  cursor:pointer;padding:.15rem .45rem;border-radius:4px;line-height:1;transition:color .15s}
#modal-close:hover{color:var(--text)}
#modal-body{flex:1;overflow-y:auto;padding:1.1rem 1.2rem;font-size:.7rem;
  line-height:1.7;color:var(--text)}
#modal-body::-webkit-scrollbar{width:3px}
#modal-body::-webkit-scrollbar-thumb{background:var(--border)}
.modal-section{margin-bottom:1rem}
.modal-section:last-child{margin-bottom:0}
.modal-h{font-size:.72rem;font-weight:700;color:var(--blue);text-transform:uppercase;
  letter-spacing:.1em;margin-bottom:.4rem}
.modal-table{width:100%;border-collapse:collapse;font-size:.67rem;margin-top:.35rem}
.modal-table td{padding:.28rem .5rem;border:1px solid var(--dim);vertical-align:top}
.modal-table tr td:first-child{color:var(--muted);background:rgba(0,0,0,.18);
  white-space:nowrap;font-weight:600}
.modal-pass{color:var(--green);font-weight:700}
.modal-fail{color:var(--red);font-weight:700}
.modal-warn{color:var(--yellow);font-weight:700}
.modal-chain{display:flex;align-items:center;gap:.5rem;font-size:.78rem;
  color:var(--muted);margin:.35rem 0}
.modal-chain .arrow{color:var(--green);font-weight:700}
.modal-chain .window{font-size:.62rem;color:var(--dim);margin-left:.25rem}
/* Speed button */
#speed-btn{min-width:2.6rem;font-variant-numeric:tabular-nums}
/* Print button — hidden until run completes */
#print-btn{display:none;border-color:var(--muted);color:var(--muted)}
#print-btn:hover:not(:disabled){border-color:var(--text);color:var(--text)}
/* Scenario jump — make rows clickable */
.sc-row{cursor:pointer;border-radius:3px;transition:background .12s}
.sc-row:hover{background:rgba(79,172,254,.07)}
.sc-jump-hint{margin-left:auto;font-size:.57rem;color:var(--blue);opacity:0;transition:opacity .15s;flex-shrink:0;padding-right:.1rem}
.sc-row:hover .sc-jump-hint{opacity:1}
/* Completion scenario summary */
.sc-summary-grid{display:flex;flex-direction:column;gap:.22rem;margin-top:.5rem}
.sc-summary-card{display:flex;align-items:center;gap:.5rem;padding:.28rem .45rem;background:var(--panel);border:1px solid var(--border);border-radius:4px;border-left:3px solid var(--border);font-size:.62rem}
.sc-summary-card.pass{border-left-color:var(--green)}
.sc-summary-card.fail{border-left-color:var(--red)}
.sc-summary-id{color:var(--blue);font-weight:700;min-width:2.2rem;flex-shrink:0}
.sc-summary-name{flex:1;color:var(--text)}
.sc-summary-domain{color:var(--muted);font-size:.57rem;min-width:5rem;flex-shrink:0}
.sc-summary-result{font-weight:700;white-space:nowrap;flex-shrink:0}
.sc-summary-result.pass{color:var(--green)}
.sc-summary-result.fail{color:var(--red)}
"#;

// ── JS ────────────────────────────────────────────────────────────────────────

const JS: &str = r#"
const WINDOW_SECS = 300;

// Populate scenario bar from SCENARIOS metadata
(function(){
  const bar = document.getElementById('sc-bar');
  SCENARIOS.forEach(sc => {
    const row = document.createElement('div');
    row.className = 'sc-row';
    row.innerHTML =
      '<span class="sc-id">Scenario ' + sc.id + '</span>' +
      '<span class="sc-sep">\u00b7</span>' +
      '<span class="sc-name">' + sc.name + '</span>' +
      '<span class="sc-sep">\u00b7</span>' +
      '<span class="sc-domain">' + sc.domain + ' Domain</span>' +
      '<span class="sc-sep">\u00b7</span>' +
      '<span class="sc-expected">expected: ' + sc.expected + ' variance' + (sc.expected!==1?'s':'') + '</span>' +
      '<span class="sc-result pending" id="sc-result-' + sc.id + '">awaiting run</span>' +
      '<span class="sc-jump-hint">\u25b6 run</span>';
    row.addEventListener('click', () => jumpToScenario(sc.id));
    bar.appendChild(row);
  });
})();

let running = false;
let stepMode = false;
let stepResolve = null;
let activeSteps = [];
let speedMult = 1;
const SPEED_CYCLE = [1, 2, 3, 0.5];
let speedCycleIdx = 0;

function sleep(ms){ return new Promise(r => setTimeout(r, ms/speedMult)); }

function waitForStep(){
  const btn = document.getElementById('narrator-next');
  btn.disabled = false;
  return new Promise(resolve => { stepResolve = resolve; });
}

document.getElementById('narrator-next').addEventListener('click', () => {
  if (stepResolve){ stepResolve(); stepResolve = null;
    document.getElementById('narrator-next').disabled = true; }
});

async function startDemo(useStepMode, startIdx = 0){
  if (running) return;
  running = true; stepMode = useStepMode;
  activeSteps = STEPS.slice(startIdx);
  document.getElementById('play-btn').disabled = true;
  document.getElementById('step-btn').disabled = true;
  document.getElementById('reset-btn').style.display = 'inline-flex';
  if (stepMode) document.getElementById('narrator').classList.add('active');
  resetAll();
  for (const step of activeSteps) await processStep(step);
  showComplete();
  running = false;
}

async function jumpToScenario(scId){
  if (running) return;
  const sc = SCENARIOS.find(s => s.id === scId);
  if (!sc) return;
  const startIdx = STEPS.findIndex(s => s.group_label === sc.label);
  if (startIdx < 0) return;
  startDemo(false, startIdx);
}

async function processStep(step){
  const phases = step.phases;
  if (stepMode){
    // Phase 1 — event arrives
    addEventCard(step);
    showNarrator(step, phases[0], 1);
    await waitForStep();
    // Phase 2 — contract lookup (skip spinner, go straight to table)
    showPhase2(step);
    showNarrator(step, phases[1], 2);
    await waitForStep();
    // Phase 3 — result + violations + state
    showPhase3(step);
    if (step.variances.length > 0){ flashViolation(); for (const v of step.variances) addViolCard(step, v); }
    updateState(step);
    showNarrator(step, phases[2], 3);
    await waitForStep();
  } else {
    addEventCard(step); await sleep(170);
    showPhase1(step);   await sleep(820);
    showPhase2(step);   await sleep(820);
    showPhase3(step);
    if (step.variances.length > 0){ await sleep(230); flashViolation(); await sleep(420); for (const v of step.variances) addViolCard(step, v); }
    await sleep(230); updateState(step);
    const d = {pass:700,pending:600,fail:1400,warn:1050};
    await sleep(d[step.check.result] || 800);
  }
}

function showNarrator(step, phase, num){
  document.getElementById('narrator-phase-lbl').textContent =
    `Phase ${num} of ${step.phases.length} — ${phase.label}`;
  document.getElementById('narrator-step-info').textContent =
    `Event ${step.seq} of ${STEPS.length} · ${step.group_label}`;
  document.getElementById('narrator-heading').textContent = phase.heading;
  document.getElementById('narrator-body').textContent   = phase.body;
}

function renderPayloadJson(step){
  function kv(key, valHtml){
    return `<div class="pj-line">  <span class="pj-key">"${key}"</span>: ${valHtml},</div>`;
  }
  function sval(v){ return `<span class="pj-str">"${v}"</span>`; }
  function nval(v){ return `<span class="pj-num">${v}</span>`; }
  function cmt(txt){ return `<div class="pj-line">  <span class="pj-comment">// ${txt}</span></div>`; }
  function stval(v, status){
    const cls = status==='ok'?'pj-ok':status==='fail'?'pj-fail':status==='warn'?'pj-warn':'pj-pending';
    return `<span class="${cls}">"${v}"</span>`;
  }
  const out = [];
  out.push(`<div class="pj-line"><span class="pj-brace">{</span></div>`);

  if (step.is_deferred){
    out.push(kv('event',   sval('FINALIZE')));
    out.push(kv('identity', sval(step.user)));
    out.push(kv('trigger', sval('stream_end')));
  } else {
    out.push(kv('event',     sval(step.event)));
    out.push(kv('identity',  sval(step.user)));
    out.push(kv('timestamp', nval(step.ts)));
    if (step.event === 'LoginSuccess'){
      out.push(kv('window_opens',  nval(step.ts)));
      out.push(kv('window_closes', nval(step.ts + 300)));
    }
  }

  const skip = new Set(['user','event']);
  const ctxRows = step.check.lookup.filter(([k]) => !skip.has(k));
  if (ctxRows.length > 0){
    out.push(cmt('engine evaluation'));
    for (const [k, v, status] of ctxRows){
      const isNum = /^\d+$/.test(v);
      out.push(kv(k, isNum ? nval(v) : stval(v, status)));
    }
  }

  const rCls = step.check.result==='pass'?'pj-ok':step.check.result==='fail'?'pj-fail':step.check.result==='warn'?'pj-warn':'pj-pending';
  out.push(cmt('verdict'));
  out.push(`<div class="pj-line">  <span class="pj-key">"result"</span>: <span class="${rCls}">"${step.check.result_text}"</span></div>`);
  out.push(`<div class="pj-line"><span class="pj-brace">}</span></div>`);
  return out.join('');
}

function togglePayload(btn){
  const json = btn.nextElementSibling;
  const open = json.classList.toggle('open');
  btn.textContent = (open ? '▼' : '▶') + btn.textContent.slice(1);
}

function toggleHistory(btn){
  const hist = btn.nextElementSibling;
  const open = hist.classList.toggle('open');
  btn.textContent = (open ? '▼' : '▶') + btn.textContent.slice(1);
}

function addEventCard(step){
  const stream = document.getElementById('event-stream');
  const r = step.variances.length > 0
    ? (step.variances.some(v => v.severity === 'critical') ? 'ev-critical' : 'ev-warn')
    : (step.check.result === 'pending' ? 'ev-pending' : 'ev-pass');
  const card = document.createElement('div');
  card.className = 'event-card ' + r;

  // Compact payload grid (always visible)
  const fields = step.is_deferred
    ? [['event','"FINALIZE"'],['user',`"${step.user}"`],['trigger','"stream_end"']]
    : [['event',`"${step.event}"`],['user',`"${step.user}"`],['ts',step.ts]];
  const payloadHtml = fields
    .map(([k,v]) => `<span class="pfield">${k}:</span><span class="pval">${v}</span>`)
    .join('');

  // History rows for this identity
  const hist = step.history;
  const histHtml = hist.map((h, i) => {
    const cur = (i === hist.length - 1) && !step.is_deferred;
    const tsLabel = h.ts === 9999 ? 'end' : `t=${h.ts}s`;
    return `<div class="eh-row${cur?' eh-current':''}">` +
      `<span class="eh-seq">#${h.seq}</span>` +
      `<span class="eh-event">${h.event}</span>` +
      `<span class="eh-ts">${tsLabel}</span></div>`;
  }).join('');

  const tsDisplay = step.is_deferred ? 'stream-end' : step.ts + 's';
  const ctxCount  = step.check.lookup.filter(([k]) => !['user','event'].includes(k)).length
                  + (step.event === 'LoginSuccess' ? 2 : 0) + 3; // base + ctx + result

  card.innerHTML =
    `<div class="ev-head">` +
      `<div class="ev-seq">#${step.seq}</div>` +
      `<div class="ev-body">` +
        `<div class="ev-type">${step.is_deferred ? '[FINALIZE]' : step.event}</div>` +
        `<div class="ev-meta">` +
          `<span class="ev-user">${step.user}</span>` +
          `<span class="ev-ts">t=${tsDisplay}</span>` +
        `</div>` +
      `</div>` +
    `</div>` +
    `<div class="ev-payload">${payloadHtml}</div>` +
    `<button class="ev-payload-toggle" onclick="togglePayload(this)">▶ { } payload · ${ctxCount} fields</button>` +
    `<div class="payload-json">${renderPayloadJson(step)}</div>` +
    `<button class="ev-hist-toggle" onclick="toggleHistory(this)">▶ ${step.user} · ${hist.length} event${hist.length!==1?'s':''}</button>` +
    `<div class="ev-history">${histHtml}</div>`;

  stream.appendChild(card);
  requestAnimationFrame(() => card.classList.add('visible'));
  stream.scrollTop = stream.scrollHeight;
}

function showPhase1(step){
  document.getElementById('check-panel').innerHTML = `
    <div class="check-hdr">INVARIANT CHECK</div>
    <div class="check-rule">${step.check.rule}</div>
    <div class="check-evaluating"><div class="spinner"></div><span>Evaluating event...</span></div>`;
}

function showPhase2(step){
  const rows = step.check.lookup.map(([k,v,s]) =>
    `<div class="lookup-row"><span class="lookup-k">${k}</span><span class="lookup-v ${s}">${v}</span></div>`
  ).join('');
  document.getElementById('check-panel').innerHTML = `
    <div class="check-hdr">INVARIANT CHECK</div>
    <div class="check-rule">${step.check.rule}</div>
    <div class="lookup-table">${rows}</div>
    <div class="check-evaluating"><div class="spinner"></div><span>Evaluating result...</span></div>`;
}

function showPhase3(step){
  const r = step.check.result;
  const cls = r==='pass'?'result-pass':r==='pending'?'result-pending':r==='warn'?'result-warn':'result-fail';
  const rows = step.check.lookup.map(([k,v,s]) =>
    `<div class="lookup-row"><span class="lookup-k">${k}</span><span class="lookup-v ${s}">${v}</span></div>`
  ).join('');
  const panel = document.getElementById('check-panel');
  panel.innerHTML = `
    <div class="check-hdr">INVARIANT CHECK</div>
    <div class="check-rule">${step.check.rule}</div>
    <div class="lookup-table">${rows}</div>
    <div class="check-result ${cls}">
      <div class="result-text">${step.check.result_text}</div>
      <div class="result-detail">${step.check.result_detail}</div>
    </div>`;
  if (r === 'fail'){
    panel.classList.remove('panel-violated');
    void panel.offsetWidth;
    panel.classList.add('panel-violated');
    setTimeout(() => panel.classList.remove('panel-violated'), 600);
  }
}

function flashViolation(){
  const el = document.getElementById('violation-flash');
  el.classList.add('active');
  setTimeout(() => el.classList.remove('active'), 480);
  const c = document.getElementById('viol-count');
  c.textContent = (parseInt(c.textContent)||0) + 1;
  c.classList.remove('bump'); void c.offsetWidth; c.classList.add('bump');
  setTimeout(() => c.classList.remove('bump'), 280);
}

function addViolCard(step, v){
  const log = document.getElementById('viol-cards');
  const card = document.createElement('div');
  card.className = `viol-card v-${v.severity}`;
  card.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span class="vbadge ${v.severity}">${v.severity}</span>
      <span class="vwho">${step.user} · t=${step.is_deferred?'end':step.ts+'s'}</span>
    </div>
    <div class="vrule">${v.rule}</div>
    <div class="vdetail">${v.detail}</div>`;
  log.appendChild(card);
  requestAnimationFrame(() => card.classList.add('visible'));
  log.scrollLeft = log.scrollWidth;
}

function updateState(step){
  const panel    = document.getElementById('state-panel');
  const entities = Object.keys(step.state).sort();
  panel.innerHTML = entities.map(u => {
    const s = step.state[u];
    const rows = s.fields.map(([k,v,cls]) =>
      `<div class="state-row"><span class="state-k">${k}</span><span class="state-v ${cls}">${v}</span></div>`
    ).join('');
    return `<div class="state-card">
      <div class="state-user">${u}<span class="state-domain-lbl">[${s.domain}]</span></div>
      ${rows}
    </div>`;
  }).join('');
}

function updateScenarioResult(){
  SCENARIOS.forEach(sc => {
    const scSteps = activeSteps.filter(s => s.group_label === sc.label);
    const el      = document.getElementById('sc-result-' + sc.id);
    if(!el) return;
    if(scSteps.length === 0) return; // scenario not run this session — leave as awaiting
    const actual = scSteps.reduce((n,s) => n + s.variances.length, 0);
    if(actual === sc.expected){
      el.textContent = '\u2714 PASS \u2014 ' + actual + ' variance' + (actual!==1?'s':'');
      el.className = 'sc-result pass';
    } else {
      el.textContent = '\u2718 FAIL \u2014 expected ' + sc.expected + ', got ' + actual;
      el.className = 'sc-result fail';
    }
  });
}

function showComplete(){
  document.getElementById('print-btn').style.display = 'inline-flex';
  updateScenarioResult();
  const crit  = activeSteps.reduce((n,s) => n + s.variances.filter(v => v.severity==='critical').length, 0);
  const warn  = activeSteps.reduce((n,s) => n + s.variances.filter(v => v.severity==='warning').length, 0);
  const clean = activeSteps.filter(s => s.variances.length === 0).length;
  const last  = activeSteps[activeSteps.length - 1];
  const entityCount = last ? Object.keys(last.state).length : 0;
  const scCards = SCENARIOS.map(sc => {
    const scSteps = activeSteps.filter(s => s.group_label === sc.label);
    if(scSteps.length === 0) return '';
    const actual = scSteps.reduce((n,s) => n + s.variances.length, 0);
    const passed = actual === sc.expected;
    const cls    = passed ? 'pass' : 'fail';
    return `<div class="sc-summary-card ${cls}">` +
      `<span class="sc-summary-id">Scenario ${sc.id}</span>` +
      `<span class="sc-summary-name">${sc.name}</span>` +
      `<span class="sc-summary-domain">${sc.domain}</span>` +
      `<span class="sc-summary-result ${cls}">${passed?'\u2714 PASS':'\u2718 FAIL'} \u00b7 ${actual} violation${actual!==1?'s':''}</span>` +
      `</div>`;
  }).filter(Boolean).join('');
  document.getElementById('check-panel').innerHTML =
    `<div class="check-hdr">ENGINE COMPLETE</div>` +
    `<div class="complete-grid">` +
      `<div class="csstat cs-total"><div class="csval">${activeSteps.length}</div><div class="cslbl">Events</div></div>` +
      `<div class="csstat cs-critical"><div class="csval">${crit}</div><div class="cslbl">Critical</div></div>` +
      `<div class="csstat cs-warn"><div class="csval">${warn}</div><div class="cslbl">Warnings</div></div>` +
      `<div class="csstat cs-pass"><div class="csval">${clean}</div><div class="cslbl">Clean</div></div>` +
    `</div>` +
    `<div class="complete-note">${crit} critical violation${crit!==1?'s':''} proven across ${entityCount} identities. ` +
    `Every detection is a deterministic causal proof \u2014 not a score, not a threshold, not a model.</div>` +
    (scCards ? `<div class="sc-summary-grid">${scCards}</div>` : '');
}

function resetAll(){
  document.getElementById('print-btn').style.display = 'none';
  document.getElementById('event-stream').innerHTML = '';
  document.getElementById('check-panel').innerHTML  = '<div class="check-idle">Waiting for events...</div>';
  document.getElementById('state-panel').innerHTML  = '<div class="state-idle">State will appear as events are processed</div>';
  document.getElementById('viol-cards').innerHTML   = '';
  document.getElementById('viol-count').textContent = '0';
  SCENARIOS.forEach(sc => {
    const el = document.getElementById('sc-result-' + sc.id);
    if(!el) return;
    el.textContent = 'awaiting run';
    el.className   = 'sc-result pending';
  });
}

document.getElementById('play-btn').addEventListener('click',  () => startDemo(false));
document.getElementById('step-btn').addEventListener('click',  () => startDemo(true));
document.getElementById('speed-btn').addEventListener('click', () => {
  speedCycleIdx = (speedCycleIdx + 1) % SPEED_CYCLE.length;
  speedMult = SPEED_CYCLE[speedCycleIdx];
  document.getElementById('speed-btn').textContent = speedMult + '\u00d7';
});
document.getElementById('reset-btn').addEventListener('click', () => {
  running = false; stepMode = false;
  document.getElementById('narrator').classList.remove('active');
  document.getElementById('play-btn').disabled = false;
  document.getElementById('step-btn').disabled = false;
  document.getElementById('reset-btn').style.display = 'none';
  resetAll();
});
document.getElementById('print-btn').addEventListener('click', printReport);

function printReport(){
  const now   = new Date().toLocaleString();
  const crit  = activeSteps.reduce((n,s) => n + s.variances.filter(v => v.severity==='critical').length, 0);
  const warn  = activeSteps.reduce((n,s) => n + s.variances.filter(v => v.severity==='warning').length, 0);

  const scRows = SCENARIOS.map(sc => {
    const scSteps = activeSteps.filter(s => s.group_label === sc.label);
    if(scSteps.length === 0) return '';
    const actual = scSteps.reduce((n,s) => n + s.variances.length, 0);
    const passed = actual === sc.expected;
    return `<tr><td><strong>Scenario ${sc.id}</strong></td><td>${sc.name}</td><td>${sc.domain}</td>` +
      `<td style="text-align:center">${sc.expected}</td><td style="text-align:center">${actual}</td>` +
      `<td class="${passed?'pass':'fail'}">${passed?'\u2714 PASS':'\u2718 FAIL'}</td></tr>`;
  }).filter(Boolean).join('');

  const violRows = activeSteps.flatMap(s => s.variances.map(v =>
    `<tr><td class="${v.severity}">${v.severity.toUpperCase()}</td>` +
    `<td>${s.user}</td><td>t=${s.is_deferred?'end':s.ts+'s'}</td>` +
    `<td>${v.rule}</td><td>${v.detail}</td></tr>`
  )).join('') || `<tr><td colspan="5" style="text-align:center;color:#64748b">No violations detected</td></tr>`;

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Auth Chain Integrity Engine \u2014 POC Report</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;font-size:12px;color:#1a1a2e;margin:2cm;line-height:1.55}
h1{font-size:17px;margin:0;color:#0f172a}
h2{font-size:11px;border-bottom:1px solid #e2e8f0;padding-bottom:3px;margin:18px 0 6px;
  color:#334155;text-transform:uppercase;letter-spacing:.07em}
.sub{color:#64748b;font-size:11px;margin:2px 0 2px}
.meta{font-size:10px;color:#94a3b8;margin-bottom:16px;border-bottom:1px solid #f1f5f9;padding-bottom:8px}
.stats{display:flex;gap:24px;margin:8px 0 4px}
.stat-val{font-size:20px;font-weight:700;line-height:1}
.stat-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.05em;color:#64748b}
.crit{color:#dc2626}.warn{color:#d97706}
table{width:100%;border-collapse:collapse;margin-top:6px;font-size:11px}
th{background:#f1f5f9;text-align:left;padding:5px 8px;font-size:10px;
  text-transform:uppercase;letter-spacing:.05em;border:1px solid #e2e8f0}
td{padding:5px 8px;border:1px solid #e2e8f0;vertical-align:top}
tr:nth-child(even) td{background:#f8fafc}
.pass{color:#15803d;font-weight:700}.fail{color:#dc2626;font-weight:700}
.CRITICAL{color:#dc2626;font-weight:700}.WARNING{color:#d97706;font-weight:700}
.tagline{margin-top:20px;padding:10px 12px;background:#f1f5f9;
  border-left:3px solid #3b82f6;font-size:11px;color:#475569}
@media print{body{margin:1.5cm}}
</style></head><body>
<h1>Authentication Chain Integrity Engine</h1>
<div class="sub">Cross-Domain Causal Validation Report \u2014 MediaStream.ai Netsapien\u2122 PILOT POC</div>
<div class="meta">Generated: ${now} &nbsp;\u00b7&nbsp; Environment: Isolated digital twin, software-only, stateless
&nbsp;\u00b7&nbsp; Engine: Deterministic invariant enforcement \u00b7 No ML \u00b7 No pattern recognition</div>
<h2>Run Summary</h2>
<div class="stats">
  <div><div class="stat-val">${activeSteps.length}</div><div class="stat-lbl">Events</div></div>
  <div><div class="stat-val crit">${crit}</div><div class="stat-lbl">Critical</div></div>
  <div><div class="stat-val warn">${warn}</div><div class="stat-lbl">Warnings</div></div>
  <div><div class="stat-val">${activeSteps.filter(s=>s.variances.length===0).length}</div><div class="stat-lbl">Clean</div></div>
</div>
<h2>Scenario Results</h2>
<table><thead><tr><th>Scenario</th><th>Name</th><th>Domain</th><th>Expected</th><th>Actual</th><th>Result</th></tr></thead>
<tbody>${scRows}</tbody></table>
<h2>Violations Detected</h2>
<table><thead><tr><th>Severity</th><th>Entity</th><th>Timestamp</th><th>Contract</th><th>Detail</th></tr></thead>
<tbody>${violRows}</tbody></table>
<div class="tagline"><strong>Every violation above is a deterministic causal proof</strong> \u2014 not a risk score,
not a threshold alert, not a model prediction. Each entry traces a broken invariant to a specific event
sequence with a named entity and contract rule.</div>
</body></html>`;

  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
}

// Modal
(function(){
  const overlay = document.getElementById('modal-overlay');
  const openModal  = () => overlay.classList.add('open');
  const closeModal = () => overlay.classList.remove('open');
  document.getElementById('help-btn').addEventListener('click', openModal);
  document.getElementById('modal-close').addEventListener('click', closeModal);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
  if (!localStorage.getItem('acie_modal_seen')) {
    openModal();
    localStorage.setItem('acie_modal_seen', '1');
  }
})();
"#;

// ── HTML ──────────────────────────────────────────────────────────────────────

fn generate_html(steps_js: &str, scenarios_js: &str) -> String {
    format!(
r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Auth Chain Integrity Engine</title>
  <style>{css}</style>
</head>
<body>
<div id="violation-flash"></div>

<header>
  <div class="hdr-left">
    <h1>Authentication Chain Integrity Engine</h1>
    <p>Deterministic invariant enforcement · no ML · no pattern recognition</p>
  </div>
  <div class="hdr-contract">
    RoleAssigned <span class="arrow">→</span>
    AdminActionTaken
    <span style="color:var(--dim);margin-left:.4rem">· 1-hour window</span>
  </div>
  <div class="hdr-controls">
    <button id="play-btn">▶ Play</button>
    <button id="step-btn">⏸ Step Through</button>
    <button id="reset-btn">↺ Reset</button>
    <button id="speed-btn" title="Playback speed">1×</button>
    <button id="print-btn" title="Export findings report">⎙ Report</button>
    <button id="help-btn" title="About this demo">?</button>
  </div>
</header>

<div id="modal-overlay">
  <div id="modal">
    <div id="modal-head">
      <span id="modal-title">Auth Chain Integrity Engine — Overview</span>
      <button id="modal-close" title="Close">✕</button>
    </div>
    <div id="modal-body">
      <div class="modal-section">
        <div class="modal-h">What It Is</div>
        <p>A deterministic causal validation engine that enforces <strong style="color:var(--blue)">integrity across four domains</strong> of a sovereign AI platform — no ML, no probabilistic models, pure logical invariants. When something goes wrong, the engine doesn't guess; it traces the causal chain backwards and proves exactly where it broke.</p>
      </div>
      <div class="modal-section">
        <div class="modal-h">What Each Domain Enforces</div>
        <table class="modal-table">
          <tr>
            <td>ControlPlane</td>
            <td><div class="modal-chain" style="margin:.15rem 0">RoleAssigned <span class="arrow">→</span> AdminActionTaken <span class="window">· 1-hour window</span></div>
            Detects <strong style="color:var(--text)">privilege misuse</strong> — admin actions taken without a valid, current role assignment.</td>
          </tr>
          <tr>
            <td>Thermal</td>
            <td><div class="modal-chain" style="margin:.15rem 0">WorkloadScheduled <span class="arrow">→</span> ThermalReading <span class="window">· 30-min window</span></div>
            Detects <strong style="color:var(--text)">silent scheduler bias</strong> — sustained heat load on a rack with no declared workload to explain it.</td>
          </tr>
          <tr>
            <td>Automation</td>
            <td><div class="modal-chain" style="margin:.15rem 0">StateValidated <span class="arrow">→</span> AutomationTriggered <span class="window">· 5-min window</span></div>
            Detects <strong style="color:var(--text)">automation amplification</strong> — repeated AI-triggered remediations on system state that has not been re-validated, potentially amplifying an attacker's manipulation rather than correcting it.</td>
          </tr>
        </table>
      </div>
      <div class="modal-section">
        <div class="modal-h">What the Demo Shows</div>
        <table class="modal-table">
          <tr><td>Scenario A · ControlPlane</td><td>svc_alpha: role assigned, admin action within 1-hour window</td><td><span class="modal-pass">✔ PASS — 0 variances</span></td></tr>
          <tr><td>Scenario B · ControlPlane</td><td>rogue_svc: admin action with no role on record</td><td><span class="modal-fail">✘ Critical — no role assignment</span></td></tr>
          <tr><td>Scenario B · ControlPlane</td><td>svc_beta: admin action 200 s past role expiry</td><td><span class="modal-fail">✘ Critical — stale role</span></td></tr>
          <tr><td>Scenario C · Thermal</td><td>rack_a: workload declared, high temp reading justified</td><td><span class="modal-pass">✔ PASS — bias justified</span></td></tr>
          <tr><td>Scenario C · Thermal</td><td>rack_b: rising temps (56 → 61 → 64°C), no workload declared</td><td><span class="modal-warn">⚠ Warning</span> + <span class="modal-fail">✘ Critical ×2</span></td></tr>
          <tr><td>Scenario D · Automation</td><td>orchestrator: 3 triggers after 5-min validation window expires</td><td><span class="modal-warn">⚠ Warning</span> + <span class="modal-fail">✘ Critical ×2</span></td></tr>
        </table>
        <p style="color:var(--nbody);margin-top:.5rem">Every violation is a <strong style="color:var(--text)">deterministic proof</strong>, not a risk score — e.g. <em>"validation expired 100 s ago, trigger_count=2: automation is amplifying an unresolved deviation."</em></p>
      </div>
      <div class="modal-section">
        <div class="modal-h">How to Use the Demo</div>
        <ul style="margin:.2rem 0 0 1.2rem;color:var(--nbody);font-size:.68rem;line-height:1.9">
          <li><strong style="color:var(--green)">▶ Play</strong> — steps through all 15 events automatically across all 4 domains</li>
          <li><strong style="color:var(--blue)">⏸ Step Through</strong> — advance one phase at a time with narrator guidance explaining each causal check</li>
          <li><strong style="color:var(--text)">↺ Reset</strong> — clear all state and restart from the beginning</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<div class="main-grid">
  <div class="panel">
    <div class="panel-title">Event Stream</div>
    <div class="panel-content" id="event-stream"></div>
  </div>
  <div class="panel">
    <div class="panel-title">Contract Evaluation</div>
    <div class="panel-content" id="check-panel">
      <div class="check-idle">Press ▶ Play or ⏸ Step Through to begin</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-title">Engine State</div>
    <div class="panel-content" id="state-panel">
      <div class="state-idle">State will appear as events are processed</div>
    </div>
  </div>
</div>

<div class="narrator" id="narrator">
  <div class="narrator-top">
    <span class="narrator-phase-lbl" id="narrator-phase-lbl">Phase 1 of 3</span>
    <span class="narrator-step-info" id="narrator-step-info"></span>
  </div>
  <div class="narrator-main">
    <div class="narrator-text">
      <div class="narrator-heading" id="narrator-heading"></div>
      <div class="narrator-body"    id="narrator-body"></div>
    </div>
    <button id="narrator-next" disabled>Next Phase →</button>
  </div>
</div>

<div class="scenario-bar" id="sc-bar"></div>

<div class="violations-section">
  <div class="viol-header">
    <span class="viol-title">Variance Log</span>
    <span class="viol-count-wrap">violations: <span class="viol-count" id="viol-count">0</span></span>
  </div>
  <div class="viol-cards" id="viol-cards"></div>
</div>

<script>
const STEPS={steps};
const SCENARIOS={scenarios};
{js}
</script>
</body>
</html>"#,
        css       = CSS,
        steps     = steps_js,
        scenarios = scenarios_js,
        js        = JS,
    )
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let steps    = run_scenario();
    let steps_js = steps_to_js(&steps);
    let html     = generate_html(&steps_js, SCENARIOS_JS);
    std::fs::write("dashboard.html", html).expect("cannot write dashboard.html");
    println!("Dashboard → dashboard.html");
    std::process::Command::new("cmd").args(["/c", "start", "", "dashboard.html"]).spawn().ok();
}
