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
         "Scenario A (POC §6) tests three legitimate variations across three domains. \
          Variation 1 — Approved privilege elevation: svc_alpha is granted a role. \
          Under POC Domain 1 (Identity & Privileged Access), a control-plane action \
          must be causally attributable to a valid authority chain. \
          This role grant establishes that chain."),
        ("POC Invariant",
         "Domain 1 — Authority chain prerequisite",
         "POC Domain 1 invariant: \
          'A control-plane action with material infrastructure impact must be \
          causally attributable to a valid authority chain and declared operational scope.' \
          Engine records role_assigned_at=1000. Authority window: t=1000 → t=4600s. \
          Contract defers — no violation possible until AdminActionTaken arrives."),
        ("Invariant Result",
         "⏳ Pending — authority chain opened",
         "Role on record. The engine watches for AdminActionTaken within the 1-hour window. \
          This is the approved privilege elevation baseline: \
          the causal chain starts with a legitimate, declared grant. \
          Variation 1 of Scenario A is in progress."),
    ],
    // ── Step 2: AdminActionTaken(svc_alpha, t=1030) ── Scenario A ────────────
    &[
        ("Event Arrives",
         "AdminActionTaken — svc_alpha @ t=1030s",
         "svc_alpha acts 30 seconds after its role was granted — \
          well within the 1-hour authority window. \
          This closes variation 1: approved privilege elevation (POC §6, Scenario A). \
          The action is causally attributable to a valid authority chain \
          and declared operational scope — exactly what POC Domain 1 requires."),
        ("POC Invariant",
         "Domain 1 — Control-plane action requires current authority",
         "POC Domain 1 invariant check: role_assigned_at=1000, action at t=1030, \
          elapsed=30s, window=3600s. 30 < 3600 ✔. \
          Causal chain: RoleAssigned(t=1000) → AdminActionTaken(t=1030). \
          Authority is current. Contract CP-2 satisfied."),
        ("Invariant Result",
         "✔ All clear — approved privilege elevation confirmed",
         "Zero violations. Variation 1 cleared. The engine passes authorised privilege use \
          without a false positive — a prerequisite for the POC to be trusted. \
          POC Domain 1 detects: 'Credential-valid misuse · Escalation outside declared authority.' \
          Here, authority is fully declared and current."),
    ],
    // ── Step 3: WorkloadScheduled(rack_a, t=2000) ── Scenario A ──────────────
    &[
        ("Event Arrives",
         "WorkloadScheduled — rack_a @ t=2000s",
         "Variation 2 — Authorised workload surge (POC §6, Scenario A). \
          rack_a explicitly declares a high-demand workload before its temperature rises. \
          The scheduler states its intent before imposing physical load. \
          POC Domain 3 (Workload–Thermal Equilibrium): \
          'Bias is not prohibited. Unjustified bias is.' \
          This declaration is the causal justification for any thermal bias that follows."),
        ("POC Invariant",
         "Domain 3 — Workload declaration opens justification window",
         "POC Domain 3 invariant: \
          'Sustained asymmetric GPU density producing persistent thermal bias must be \
          causally attributable to declared workload demand or authorised scheduling logic.' \
          Engine records last_workload_at=2000. Justification window: 1800s. \
          Any ThermalReading above 50°C from rack_a within this window is causally explained."),
        ("Invariant Result",
         "⏳ Pending — thermal justification window open",
         "Workload declared. The engine distinguishes authorised load from silent scheduler bias. \
          rack_a has stated its intent — thermal impact is expected. \
          This is the contrast the POC is built around: \
          the same temperature reading is a pass here and a violation in Scenario C."),
    ],
    // ── Step 4: ThermalReading(rack_a, 52°C, t=2300) ── Scenario A ───────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_a @ t=2300s, 52°C",
         "rack_a reports 52°C — 2°C above the 50°C threshold — 300 seconds after \
          declaring its workload surge. The elevated temperature has a declared cause. \
          POC Domain 3: 'Unjustified bias is prohibited' — but this bias is justified \
          by the WorkloadScheduled at t=2000."),
        ("POC Invariant",
         "Domain 3 — Thermal bias must be causally attributable to declared workload",
         "POC Domain 3 invariant check: temp=52°C > threshold=50°C (biased ✔), \
          WorkloadScheduled at t=2000, elapsed=300s, window=1800s. 300 < 1800 ✔. \
          Bias is causally attributable to declared workload demand. \
          Contract TH-1 satisfied. bias_count stays at 0."),
        ("Invariant Result",
         "✔ All clear — authorised workload surge confirmed",
         "Zero violations. Variation 2 cleared. The engine correctly distinguishes \
          justified elevated temperature from unjustified bias. \
          A threshold-based tool sees '52°C — elevated.' \
          The causal engine sees '52°C, workload declared 300s ago, justified.' \
          This distinction is the POC's core value proposition."),
    ],
    // ── Step 5: StateValidated(orchestrator, t=3000) ── Scenario A ───────────
    &[
        ("Event Arrives",
         "StateValidated — orchestrator @ t=3000s",
         "Variation 3 — Declared scheduling shift (POC §6, Scenario A). \
          The orchestrator ('Mother') validates system state before triggering automation. \
          POC Domain 4 (Automation Amplification Guard): \
          'Automated remediation must be causally justified by validated system state \
          and must not amplify unexplained deviations.' \
          This validation is that justification."),
        ("POC Invariant",
         "Domain 4 — Automation requires fresh StateValidated",
         "POC Domain 4 invariant: \
          'Automated remediation must be causally justified by validated system state.' \
          Engine records last_validated_at=3000, trigger_count reset to 0. \
          Validation window: 300s. \
          Note: this timestamp also anchors Scenario D — \
          the orchestrator will not re-validate before triggering again at t=11000s."),
        ("Invariant Result",
         "⏳ Pending — automation validation window open",
         "System state confirmed coherent. The declared scheduling shift posture is set. \
          Any AutomationTriggered within 5 minutes is acting on confirmed, coherent state. \
          This is variation 3: 'Mother' acting on validated information — \
          the correct behaviour the POC must pass cleanly."),
    ],
    // ── Step 6: AutomationTriggered(orchestrator, t=3100) ── Scenario A ──────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=3100s",
         "The orchestrator triggers an automated action 100 seconds after validating state — \
          acting on recently confirmed, coherent system information. \
          This closes variation 3: declared scheduling shift (POC §6, Scenario A). \
          POC Domain 4: automation acting on verified state is the passing case."),
        ("POC Invariant",
         "Domain 4 — AutomationTriggered backed by fresh StateValidated",
         "POC Domain 4 invariant check: StateValidated at t=3000, \
          elapsed=100s, window=300s. 100 < 300 ✔. trigger_count=0. \
          The automation is causally justified by validated system state. \
          Contract AUTO-1 satisfied."),
        ("Invariant Result",
         "✔ All clear — declared scheduling shift confirmed",
         "Scenario A complete. All three variations cleared: \
          approved privilege elevation ✔, authorised workload surge ✔, declared scheduling shift ✔. \
          Zero violations across three domains. \
          POC §6: 'Expected: no invariant violation.' \
          The detection layer produces no false positives on authorised behaviour."),
    ],
    // ── Step 7: AdminActionTaken(rogue_svc, t=4000) ── Scenario B ────────────
    &[
        ("Event Arrives",
         "AdminActionTaken — rogue_svc @ t=4000s",
         "Scenario B — Privilege Misuse (POC §6). \
          rogue_svc attempts a control-plane admin action with no role on record. \
          This is 'credential-valid escalation' (POC §6, Scenario B): \
          the actor carries valid system credentials but was never granted a role. \
          POC Domain 1 detection target: 'Credential-valid misuse · Escalation outside declared authority.'"),
        ("POC Invariant",
         "Domain 1 — Control-plane action requires prior RoleAssigned",
         "POC Domain 1 invariant: \
          'A control-plane action must be causally attributable to a valid authority chain \
          and declared operational scope.' \
          rogue_svc: no RoleAssigned on record. No authority chain. \
          The causal prerequisite is completely absent. \
          Contract CP-1 violated — Critical."),
        ("Invariant Result",
         "✘ Issue detected — credential-valid escalation",
         "IAM invariant violated (POC §6, Scenario B expected: 'IAM invariant violation'). \
          A control-plane action taken with no authority chain. \
          A credential check passes — rogue_svc has valid credentials. \
          The causal engine catches what credentials alone cannot: \
          the absence of a declared, current authority chain."),
    ],
    // ── Step 8: RoleAssigned(svc_beta, t=4200) ── Scenario B ─────────────────
    &[
        ("Event Arrives",
         "RoleAssigned — svc_beta @ t=4200s",
         "svc_beta receives a legitimate role grant at t=4200s. \
          This sets up the second Scenario B detection: \
          'out-of-scope control-plane mutation' (POC §6). \
          The role is valid now — but the admin action that follows \
          will arrive 200 seconds after the 1-hour window expires. \
          'Credential-valid does not mean currently authorised.'"),
        ("POC Invariant",
         "Domain 1 — Authority window: t=4200 → t=7800s",
         "Engine records role_assigned_at=4200. \
          Authority window: t=4200 → t=7800s (1-hour / 3600s). \
          The role is legitimately assigned. \
          The engine watches: at t=8000s — 200 seconds after window expiry — \
          svc_beta will act. Deterministic proof: 8000 − 4200 = 3800 > 3600."),
        ("Invariant Result",
         "⏳ Pending — window closes at t=7800s",
         "Role on record. The stage is set for out-of-scope mutation detection. \
          POC Domain 1 invariant: authority must be valid at the moment of action. \
          The engine does not care that the role was legitimately granted — \
          what matters is whether it is current when the action arrives."),
    ],
    // ── Step 9: AdminActionTaken(svc_beta, t=8000) ── Scenario B ─────────────
    &[
        ("Event Arrives",
         "AdminActionTaken — svc_beta @ t=8000s",
         "svc_beta acts at t=8000s — 200 seconds after its authority window closed at t=7800s. \
          This is 'out-of-scope control-plane mutation' (POC §6, Scenario B): \
          an action taken outside the declared operational scope. \
          The role was legitimately granted; it is no longer current."),
        ("POC Invariant",
         "Domain 1 — Declared operational scope exceeded",
         "POC Domain 1 invariant check: role_assigned_at=4200, action at t=8000, \
          elapsed=3800s, window=3600s. 3800 > 3600 — exceeded by 200s. \
          Authority has lapsed. \
          'A control-plane action must be causally attributable to a valid authority chain \
          and declared operational scope.' The scope has expired. Contract CP-2 violated — Critical."),
        ("Invariant Result",
         "✘ Issue detected — out-of-scope control-plane mutation",
         "IAM invariant violated. Out-of-scope mutation confirmed. \
          Scenario B complete — 2 Critical violations: \
          credential-valid escalation (no authority chain) and \
          out-of-scope mutation (expired authority). \
          POC §1: 'Detect privilege-to-impact inconsistencies' — demonstrated. \
          Standard access logs would show a credentialed action; the causal layer shows an unauthorised one."),
    ],
    // ── Step 10: ThermalReading(rack_b, 56°C, t=9000) ── Scenario C ──────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_b @ t=9000s, 56°C",
         "Scenario C — Silent Scheduler Bias (POC §6). \
          rack_b reports 56°C with no WorkloadScheduled ever declared for this rack. \
          'Sustained rack skew · No declared workload shift.' \
          The scheduler has imposed thermal load on rack_b without declaring intent. \
          POC Domain 2 detection target: 'Silent scheduler bias · Subtle control-plane manipulation.'"),
        ("POC Invariant",
         "Domain 3 — Thermal bias must be causally attributable to declared workload",
         "POC Domain 3 invariant: \
          'Sustained asymmetric GPU density producing persistent thermal bias must be \
          causally attributable to declared workload demand or authorised scheduling logic.' \
          rack_b: no workload on record. temp=56°C > threshold=50°C. \
          No causal justification. bias_count → 1. Contract TH-1 fires."),
        ("Invariant Result",
         "⚠ Warning — control-plane invariant triggered",
         "First detection: rack skew without declared workload. \
          POC §6, Scenario C expected: 'Control-plane and equilibrium invariant violation.' \
          The causal gap is the signal — not the temperature value alone. \
          A threshold tool might not alert on 56°C. \
          The causal engine detects the absence of a declared cause on the first reading."),
    ],
    // ── Step 11: ThermalReading(rack_b, 61°C, t=9600) ── Scenario C ──────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_b @ t=9600s, 61°C",
         "rack_b reaches 61°C — 600 seconds since the first unjustified reading. \
          Still no WorkloadScheduled declared. The bias is sustained, not a transient spike. \
          POC §1 Objective: 'Detect unjustified workload-induced physical bias.' \
          POC Domain 2: 'Sustained workload redistribution must be causally attributable \
          to declared scheduling objectives.' No scheduling objective was declared."),
        ("POC Invariant",
         "Domain 3 — Sustained bias triggers equilibrium invariant",
         "POC Domain 3 invariant escalation: bias_count → 2. \
          Two consecutive unjustified readings (56°C → 61°C). \
          The equilibrium invariant now applies: \
          'Sustained asymmetric GPU density producing persistent thermal bias.' \
          Contract TH-2: 'Sustained unjustified thermal bias — equilibrium invariant violated.'"),
        ("Invariant Result",
         "✘ Issue detected — equilibrium invariant violated",
         "Both invariants now breached: control-plane invariant (no workload declared) \
          and equilibrium invariant (bias sustained across consecutive readings). \
          POC §1: 'Surface stealth manipulations that evade threshold and correlational tools.' \
          No individual reading triggers a hard alarm — the sustained causal gap does. \
          This is a detection pattern conventional monitoring cannot produce."),
    ],
    // ── Step 12: ThermalReading(rack_b, 64°C, t=10200) ── Scenario C ─────────
    &[
        ("Event Arrives",
         "ThermalReading — rack_b @ t=10200s, 64°C",
         "rack_b reaches 64°C — 1200 seconds of sustained, undeclared thermal bias. \
          Three consecutive readings (56 → 61 → 64°C) with no WorkloadScheduled at any point. \
          POC Domain 2 detection target: 'Silent scheduler bias · Undeclared policy drift.' \
          The scheduler silently routed load to rack_b with no declared scheduling objective."),
        ("POC Invariant",
         "Domains 2+3 — Proxy OT impact without direct OT compromise",
         "bias_count → 3. Causal chain from scheduler intent to physical impact: absent. \
          POC Domain 3 detection target: 'Proxy OT impact without direct OT compromise.' \
          The Thermal domain acts as OT-Proxy: physical impact (rising rack temperature) \
          is traceable to an IT-origin action (scheduler decision) through the causal layer — \
          without any direct OT system being compromised."),
        ("Invariant Result",
         "✘ Issue detected — silent scheduler bias proven",
         "Scenario C confirmed — 3 violations (1 Warning + 2 Critical). \
          POC §6: 'Expected: Control-plane and equilibrium invariant violation.' ✔ \
          POC §1: 'Detect unjustified workload-induced physical bias' — demonstrated. \
          POC §1: 'Surface stealth manipulations that evade threshold tools' — demonstrated. \
          A single-point threshold monitor needs all three readings to be alarming; \
          the causal engine detected the gap on the first reading."),
    ],
    // ── Step 13: AutomationTriggered(orchestrator, t=11000) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=11000s",
         "Scenario D — Automation Amplification (POC §6). \
          The orchestrator fires at t=11000s. \
          Last StateValidated: t=3000s (Scenario A) — 8000 seconds ago. \
          'Automated response to incomplete state.' \
          POC Domain 4 detection target: 'Automation feedback instability · \
          AI reacting to manipulated telemetry.'"),
        ("POC Invariant",
         "Domain 4 — Automation requires StateValidated within 5-min window",
         "POC Domain 4 invariant: \
          'Automated remediation must be causally justified by validated system state \
          and must not amplify unexplained deviations.' \
          last_validated_at=3000, elapsed=8000s, window=300s. \
          8000 >> 300 — validation expired 7700s ago. trigger_count → 1. \
          Contract AUTO-1 fires: automation on unvalidated state."),
        ("Invariant Result",
         "⚠ Warning — automated response to incomplete state",
         "Automation invariant partially triggered. \
          POC §6, Scenario D expected: 'Automation invariant violation.' \
          The orchestrator ('Mother') cannot distinguish acting on real current state \
          from acting on stale — or attacker-modified — state. \
          The causal engine can. trigger_count=1: monitoring for amplification cascade."),
    ],
    // ── Step 14: AutomationTriggered(orchestrator, t=11200) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=11200s",
         "The orchestrator triggers again — 200 seconds after the first stale trigger. \
          No StateValidated since t=3000s. \
          Each automated action may modify environment state, \
          but the system never re-checks whether the modification resolved the issue. \
          POC Domain 4 detection target: 'Automation feedback instability.'"),
        ("POC Invariant",
         "Domain 4 — Amplification invariant: repeated triggers on unvalidated state",
         "trigger_count → 2. Two consecutive AutomationTriggered with no intervening StateValidated. \
          Contract AUTO-2: \
          'Repeated automation on unvalidated state — amplification invariant violated.' \
          POC Domain 4: 'Automated remediation must not amplify unexplained deviations.' \
          The system is in a feedback loop it cannot self-correct."),
        ("Invariant Result",
         "✘ Issue detected — amplification invariant violated",
         "Automation amplification invariant violated. \
          POC §1: 'Detect automation acting on unverified state' — demonstrated. \
          Each trigger potentially compounds the deviation. \
          In a real AI-factory: 'Mother' acting confidently and repeatedly \
          on incoherent telemetry — amplifying rather than resolving the problem."),
    ],
    // ── Step 15: AutomationTriggered(orchestrator, t=11400) ── Scenario D ─────
    &[
        ("Event Arrives",
         "AutomationTriggered — orchestrator @ t=11400s",
         "Third consecutive trigger on unvalidated state. \
          8400 seconds since the last StateValidated. \
          Three automated responses to an environment never re-confirmed. \
          POC Domain 4: 'AI reacting to manipulated telemetry.' \
          The amplification pattern is definitively established."),
        ("POC Invariant",
         "Domain 4 — Amplification cascade: 3 triggers, 28× validation gap",
         "trigger_count → 3. Validation gap: 8400s — 28 times the required window. \
          Every trigger operates on the same stale, unconfirmed state. \
          In production: if the underlying deviation was attacker-injected, \
          each 'Mother' action could be amplifying the attack rather than resolving it. \
          The causal engine halts on the first unvalidated trigger; the system never did."),
        ("Invariant Result",
         "✘ Issue detected — automation amplification proven",
         "Scenario D confirmed — 3 violations (1 Warning + 2 Critical). \
          POC §6: 'Expected: Automation invariant violation.' ✔ \
          All four POC §1 objectives demonstrated across Scenarios A–D: \
          privilege-to-impact inconsistencies ✔ (Scenario B), \
          unjustified workload-induced physical bias ✔ (Scenario C), \
          automation on unverified state ✔ (Scenario D), \
          stealth manipulations evading threshold tools ✔ (all three detection scenarios)."),
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
        // ── Scenario A — Legitimate Variation (multi-domain, 0 violations) ────
        ("svc_alpha",    "Scenario A — Legitimate Variation",  1000,  "svc_alpha",    DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned)),
        ("svc_alpha",    "Scenario A — Legitimate Variation",  1030,  "svc_alpha",    DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        ("rack_a",       "Scenario A — Legitimate Variation",  2000,  "rack_a",       DomainEvent::Thermal(ThermalEvent::WorkloadScheduled)),
        ("rack_a",       "Scenario A — Legitimate Variation",  2300,  "rack_a",       DomainEvent::Thermal(ThermalEvent::ThermalReading(52))),
        ("orchestrator", "Scenario A — Legitimate Variation",  3000,  "orchestrator", DomainEvent::Automation(AutomationEvent::StateValidated)),
        ("orchestrator", "Scenario A — Legitimate Variation",  3100,  "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
        // ── Scenario B — Privilege Misuse (ControlPlane, 2 Critical) ──────────
        ("rogue_svc",    "Scenario B — Privilege Misuse",      4000,  "rogue_svc",    DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        ("svc_beta",     "Scenario B — Privilege Misuse",      4200,  "svc_beta",     DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned)),
        ("svc_beta",     "Scenario B — Privilege Misuse",      8000,  "svc_beta",     DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        // ── Scenario C — Silent Scheduler Bias (Thermal, 1 Warning + 2 Critical)
        ("rack_b",       "Scenario C — Silent Scheduler Bias", 9000,  "rack_b",       DomainEvent::Thermal(ThermalEvent::ThermalReading(56))),
        ("rack_b",       "Scenario C — Silent Scheduler Bias", 9600,  "rack_b",       DomainEvent::Thermal(ThermalEvent::ThermalReading(61))),
        ("rack_b",       "Scenario C — Silent Scheduler Bias", 10200, "rack_b",       DomainEvent::Thermal(ThermalEvent::ThermalReading(64))),
        // ── Scenario D — Automation Amplification (Automation, 1 Warning + 2 Critical)
        ("orchestrator", "Scenario D — Automation Amplification", 11000, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
        ("orchestrator", "Scenario D — Automation Amplification", 11200, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
        ("orchestrator", "Scenario D — Automation Amplification", 11400, "orchestrator", DomainEvent::Automation(AutomationEvent::AutomationTriggered)),
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
  {id:"A",name:"Legitimate Variation",label:"Scenario A \u2014 Legitimate Variation",domain:"Multi-Domain",description:"Authorised workload surge \u00b7 Approved privilege elevation \u00b7 Declared scheduling shift. All three domains behave correctly. Expected: no invariant violations.",expected:0},
  {id:"B",name:"Privilege Misuse",label:"Scenario B \u2014 Privilege Misuse",domain:"ControlPlane",description:"Credential-valid escalation \u00b7 Out-of-scope control-plane mutation. Expected: IAM invariant violation.",expected:2},
  {id:"C",name:"Silent Scheduler Bias",label:"Scenario C \u2014 Silent Scheduler Bias",domain:"Thermal",description:"Sustained rack skew \u00b7 No declared workload shift. Expected: control-plane and equilibrium invariant violation.",expected:3},
  {id:"D",name:"Automation Amplification",label:"Scenario D \u2014 Automation Amplification",domain:"Automation",description:"Automated response to incomplete state. Expected: automation invariant violation.",expected:3}
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
.sc-name{color:var(--text);flex:1;min-width:0;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.sc-domain{color:var(--muted);font-size:.6rem;text-transform:uppercase;letter-spacing:.08em;flex-shrink:0;min-width:8rem}
.sc-expected{color:var(--muted);flex-shrink:0}
.sc-sep{color:var(--dim);flex-shrink:0}
.sc-result{font-weight:700;font-size:.7rem;letter-spacing:.02em;transition:color .2s;flex-shrink:0;min-width:9rem;text-align:right}
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
.sc-jump-hint{font-size:.57rem;color:var(--blue);opacity:0;transition:opacity .15s;flex-shrink:0;padding-right:.1rem}
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
/* ── Story / Technical mode ─────────────────────────────────────────────── */
body:not(.technical-mode) .technical-only{display:none!important}
body.technical-mode .story-only{display:none!important}
#mode-btn{font-size:.68rem;letter-spacing:.01em}
/* Story center panel */
.story-panel{display:flex;flex-direction:column;gap:.52rem}
.story-tag{font-size:.57rem;text-transform:uppercase;letter-spacing:.1em;color:var(--blue);font-weight:700}
.story-poc-domain{font-size:.56rem;color:var(--muted);font-style:italic;margin-top:.05rem;line-height:1.4}
.story-event-box{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:.4rem .55rem}
.story-ev-name{font-size:.88rem;font-weight:700;color:var(--text);margin-bottom:.12rem}
.story-ev-meta{font-size:.62rem;color:var(--muted)}.story-ev-meta span{color:var(--text);font-weight:600}
.story-block{display:flex;flex-direction:column;gap:.18rem}
.story-block-lbl{font-size:.56rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:700}
.story-block-body{font-size:.7rem;line-height:1.65;color:var(--nbody)}
.story-verdict{border-radius:4px;padding:.45rem .6rem;border:1px solid}
.story-verdict.pass{border-color:rgba(0,229,160,.4);background:rgba(0,229,160,.06)}
.story-verdict.fail{border-color:rgba(255,51,85,.5);background:rgba(255,51,85,.1)}
.story-verdict.warn{border-color:rgba(255,186,59,.4);background:rgba(255,186,59,.07)}
.story-verdict.pending{border-color:rgba(79,172,254,.3);background:rgba(79,172,254,.06)}
.story-verdict-title{font-size:.77rem;font-weight:700;margin-bottom:.18rem}
.story-verdict.pass .story-verdict-title{color:var(--green)}
.story-verdict.fail .story-verdict-title{color:var(--red)}
.story-verdict.warn .story-verdict-title{color:var(--yellow)}
.story-verdict.pending .story-verdict-title{color:var(--blue)}
.story-verdict-body{font-size:.67rem;line-height:1.6;color:var(--nbody)}
"#;

// ── JS ────────────────────────────────────────────────────────────────────────

const JS: &str = r#"
const WINDOW_SECS = 300;

// ── Story mode lookup tables ───────────────────────────────────────────────
const PLAIN_EVENTS = {
  LoginSuccess:        'Login successful',
  AuthTokenIssued:     'Access token issued',
  AuthTokenUsed:       'Access token used',
  RoleAssigned:        'Role granted',
  AdminActionTaken:    'Admin action taken',
  WorkloadScheduled:   'Workload declared',
  ThermalReading:      'Temperature reading',
  StateValidated:      'System state verified',
  AutomationTriggered: 'Automation action fired',
};
const PLAIN_FIELDS = {
  last_login:        'Last login',
  token_issued:      'Token issued',
  token_used:        'Token used',
  role_assigned_at:  'Role granted at',
  admin_action:      'Admin action taken',
  last_workload_at:  'Workload declared at',
  last_temp:         'Temperature',
  bias_count:        'Unexplained high readings',
  last_validated_at: 'State last verified',
  trigger_count:     'Triggers since last check',
  last_trigger_at:   'Last action at',
};
const PLAIN_DOMAINS = { ControlPlane: 'Control Plane' };

// Maps scenario domain to the exact POC document domain label (§3)
const POC_DOMAINS = {
  'ControlPlane': 'Domain\u00a01\u20132: Identity & Privileged Access / Cloud Control Plane Integrity',
  'Thermal':      'Domain\u00a03: Workload\u2013Thermal Equilibrium (OT-Proxy)',
  'Automation':   'Domain\u00a04: Automation Amplification Guard',
  'Multi-Domain': 'Domains\u00a01\u20134: Cross-Domain Baseline Validation',
};

function storyCenter(step, phaseIdx){
  const evName   = PLAIN_EVENTS[step.event] || (step.is_deferred ? 'End of stream check' : step.event);
  const scenario = SCENARIOS.find(s => s.label === step.group_label);
  const domName  = scenario ? (PLAIN_DOMAINS[scenario.domain] || scenario.domain) : '';
  const scTag    = scenario ? `Scenario ${scenario.id} \u00b7 ${domName} Domain` : step.group_label;
  const pocDom   = scenario ? (POC_DOMAINS[scenario.domain] || '') : '';
  let h = `<div class="story-panel">
    <div class="story-tag">${scTag}</div>
    ${pocDom ? `<div class="story-poc-domain">POC \u00a7 ${pocDom}</div>` : ''}
    <div class="story-event-box">
      <div class="story-ev-name">${evName}</div>
      <div class="story-ev-meta">Entity: <span>${step.user}</span></div>
    </div>`;
  if (step.phases[0])
    h += `<div class="story-block">
      <div class="story-block-lbl">What happened</div>
      <div class="story-block-body">${step.phases[0].body}</div>
    </div>`;
  if (phaseIdx >= 1 && step.phases[1])
    h += `<div class="story-block">
      <div class="story-block-lbl">POC Invariant</div>
      <div class="story-block-body">${step.phases[1].body}</div>
    </div>`;
  if (phaseIdx >= 2 && step.phases[2]){
    const r = step.check.result;
    const vCls   = r==='pass'?'pass':r==='pending'?'pending':r==='warn'?'warn':'fail';
    const vTitle = r==='pass'   ? '\u2714 All clear'
                 : r==='pending'? '\u23f3 Pending'
                 : r==='warn'   ? '\u26a0\ufe0f Warning'
                 : '\u2718 Issue detected';
    h += `<div class="story-verdict ${vCls}">
      <div class="story-verdict-title">${vTitle}</div>
      <div class="story-verdict-body">${step.phases[2].body}</div>
    </div>`;
  }
  h += `</div>`;
  return h;
}

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

  const plainEvName = PLAIN_EVENTS[step.event] || (step.is_deferred ? 'End of stream check' : step.event);
  card.innerHTML =
    `<div class="ev-head">` +
      `<div class="ev-seq">#${step.seq}</div>` +
      `<div class="ev-body">` +
        `<div class="ev-type technical-only">${step.is_deferred ? '[FINALIZE]' : step.event}</div>` +
        `<div class="ev-type story-only">${plainEvName}</div>` +
        `<div class="ev-meta">` +
          `<span class="ev-user">${step.user}</span>` +
          `<span class="ev-ts">t=${tsDisplay}</span>` +
        `</div>` +
      `</div>` +
    `</div>` +
    `<div class="ev-payload technical-only">${payloadHtml}</div>` +
    `<button class="ev-payload-toggle technical-only" onclick="togglePayload(this)">▶ { } payload · ${ctxCount} fields</button>` +
    `<div class="payload-json">${renderPayloadJson(step)}</div>` +
    `<button class="ev-hist-toggle technical-only" onclick="toggleHistory(this)">▶ ${step.user} · ${hist.length} event${hist.length!==1?'s':''}</button>` +
    `<div class="ev-history">${histHtml}</div>`;

  stream.appendChild(card);
  requestAnimationFrame(() => card.classList.add('visible'));
  stream.scrollTop = stream.scrollHeight;
}

function showPhase1(step){
  document.getElementById('check-panel').innerHTML =
    `<div class="technical-only"><div class="check-hdr">INVARIANT CHECK</div>` +
    `<div class="check-rule">${step.check.rule}</div>` +
    `<div class="check-evaluating"><div class="spinner"></div><span>Evaluating event...</span></div></div>` +
    `<div class="story-only">${storyCenter(step, 0)}</div>`;
}

function showPhase2(step){
  const rows = step.check.lookup.map(([k,v,s]) =>
    `<div class="lookup-row"><span class="lookup-k">${k}</span><span class="lookup-v ${s}">${v}</span></div>`
  ).join('');
  document.getElementById('check-panel').innerHTML =
    `<div class="technical-only"><div class="check-hdr">INVARIANT CHECK</div>` +
    `<div class="check-rule">${step.check.rule}</div>` +
    `<div class="lookup-table">${rows}</div>` +
    `<div class="check-evaluating"><div class="spinner"></div><span>Evaluating result...</span></div></div>` +
    `<div class="story-only">${storyCenter(step, 1)}</div>`;
}

function showPhase3(step){
  const r = step.check.result;
  const cls = r==='pass'?'result-pass':r==='pending'?'result-pending':r==='warn'?'result-warn':'result-fail';
  const rows = step.check.lookup.map(([k,v,s]) =>
    `<div class="lookup-row"><span class="lookup-k">${k}</span><span class="lookup-v ${s}">${v}</span></div>`
  ).join('');
  const panel = document.getElementById('check-panel');
  panel.innerHTML =
    `<div class="technical-only"><div class="check-hdr">INVARIANT CHECK</div>` +
    `<div class="check-rule">${step.check.rule}</div>` +
    `<div class="lookup-table">${rows}</div>` +
    `<div class="check-result ${cls}"><div class="result-text">${step.check.result_text}</div>` +
    `<div class="result-detail">${step.check.result_detail}</div></div></div>` +
    `<div class="story-only">${storyCenter(step, 2)}</div>`;
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
    <div class="vrule technical-only">${v.rule}</div>
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
      `<div class="state-row">` +
      `<span class="state-k technical-only">${k}</span>` +
      `<span class="state-k story-only">${PLAIN_FIELDS[k]||k}</span>` +
      `<span class="state-v ${cls}">${v}</span></div>`
    ).join('');
    const domStory = PLAIN_DOMAINS[s.domain] || s.domain;
    return `<div class="state-card">` +
      `<div class="state-user">${u}` +
      `<span class="state-domain-lbl technical-only">[${s.domain}]</span>` +
      `<span class="state-domain-lbl story-only">[${domStory}]</span></div>` +
      rows +
      `</div>`;
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
document.getElementById('mode-btn').addEventListener('click', () => {
  const isTechnical = document.body.classList.toggle('technical-mode');
  document.getElementById('mode-btn').textContent = isTechnical ? '\ud83d\udcd6 Story' : '\ud83d\udd2c Technical';
});

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
&nbsp;\u00b7&nbsp; Engine: Deterministic invariant enforcement</div>
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
    <p>Deterministic invariant enforcement</p>
  </div>
  <div class="hdr-controls">
    <button id="play-btn">▶ Play</button>
    <button id="step-btn">⏸ Step Through</button>
    <button id="reset-btn">↺ Reset</button>
    <button id="speed-btn" title="Playback speed">1×</button>
    <button id="print-btn" title="Export findings report">⎙ Report</button>
    <button id="mode-btn" title="Switch view mode">🔬 Technical</button>
    <button id="help-btn" title="About this demo">?</button>
  </div>
</header>

<div id="modal-overlay">
  <div id="modal">
    <div id="modal-head">
      <span id="modal-title">Cross-Domain Causal Validation — POC Demo</span>
      <button id="modal-close" title="Close">✕</button>
    </div>
    <div id="modal-body">
      <div class="modal-section">
        <div class="modal-h">What This Proves</div>
        <p>This POC answers one question: <strong style="color:var(--text)">can a deterministic causal engine detect integrity violations across multiple domains of a sovereign AI platform — with zero false positives and zero model dependency?</strong></p>
        <p style="margin-top:.5rem">The engine watches events arriving in real time and enforces declared rules about what must happen before something else is allowed to happen. When a rule breaks, it doesn't guess — it produces a proof: the exact entity, the exact event, the exact rule that failed, and by how much.</p>
      </div>

      <div class="modal-section">
        <div class="modal-h">The Four Scenarios</div>
        <p style="color:var(--muted);font-size:.65rem;margin-bottom:.45rem">Directly from the POC specification. Scenarios B, C, and D inject violations. Scenario A must produce zero — false positives are a failure.</p>
        <table class="modal-table">
          <tr>
            <td style="white-space:nowrap"><strong style="color:var(--green)">A</strong> · Legitimate Variation</td>
            <td>
              <div style="color:var(--muted);font-size:.63rem;margin-bottom:.2rem">Approved privilege elevation · Authorised workload surge · Declared scheduling shift</div>
              Three domains each perform a fully authorised operation. The engine must pass all of them and produce <strong style="color:var(--green)">zero violations</strong>.
            </td>
            <td style="white-space:nowrap"><span class="modal-pass">✔ 0 violations</span></td>
          </tr>
          <tr>
            <td style="white-space:nowrap"><strong style="color:var(--red)">B</strong> · Privilege Misuse</td>
            <td>
              <div style="color:var(--muted);font-size:.63rem;margin-bottom:.2rem">Credential-valid escalation · Out-of-scope control-plane mutation</div>
              A service acts with no role on record. A second acts after its role expired. Both have valid credentials — but credentials are not authorisation.
            </td>
            <td style="white-space:nowrap"><span class="modal-fail">✘ 2 Critical</span></td>
          </tr>
          <tr>
            <td style="white-space:nowrap"><strong style="color:var(--red)">C</strong> · Silent Scheduler Bias</td>
            <td>
              <div style="color:var(--muted);font-size:.63rem;margin-bottom:.2rem">Sustained rack skew · No declared workload shift</div>
              A rack runs progressively hotter (56°C → 61°C → 64°C) with no workload declaration to explain it. The scheduler is silently biasing load without declaring intent.
            </td>
            <td style="white-space:nowrap"><span class="modal-warn">⚠ 1 Warning</span><br><span class="modal-fail">✘ 2 Critical</span></td>
          </tr>
          <tr>
            <td style="white-space:nowrap"><strong style="color:var(--red)">D</strong> · Automation Amplification</td>
            <td>
              <div style="color:var(--muted);font-size:.63rem;margin-bottom:.2rem">Automated response to incomplete state</div>
              An orchestrator fires three automated remediations on system state that was last validated over 2 hours ago. It cannot know whether its actions are helping or making things worse.
            </td>
            <td style="white-space:nowrap"><span class="modal-warn">⚠ 1 Warning</span><br><span class="modal-fail">✘ 2 Critical</span></td>
          </tr>
        </table>
      </div>

      <div class="modal-section">
        <div class="modal-h">What You're Watching</div>
        <table class="modal-table">
          <tr><td style="white-space:nowrap">Events panel</td><td>The raw event stream as it arrives — each card shows who, what, and when.</td></tr>
          <tr><td style="white-space:nowrap">Center panel</td><td>The causal check in progress — what rule is being tested, what the engine found, and the verdict.</td></tr>
          <tr><td style="white-space:nowrap">Status panel</td><td>Live state of every tracked entity after each event — role assignments, temperatures, validation timestamps.</td></tr>
          <tr><td style="white-space:nowrap">Violation log</td><td>Every detected violation, in order — severity, entity, rule, and the exact proof.</td></tr>
        </table>
      </div>

      <div class="modal-section">
        <div class="modal-h">How to Use</div>
        <ul style="margin:.2rem 0 0 1.2rem;color:var(--nbody);font-size:.68rem;line-height:2">
          <li><strong style="color:var(--green)">▶ Play</strong> — runs all 15 events across all 4 scenarios automatically</li>
          <li><strong style="color:var(--blue)">⏸ Step Through</strong> — pauses at each phase with a plain-language explanation of every check</li>
          <li><strong style="color:var(--text)">Click any scenario</strong> in the bar at the bottom to jump directly to that scenario</li>
          <li><strong style="color:var(--text)">🔬 Technical</strong> — toggle to reveal the full invariant check tables and contract rules</li>
          <li><strong style="color:var(--text)">⎙ Report</strong> — generates a printable summary after a run completes</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<div class="main-grid">
  <div class="panel">
    <div class="panel-title"><span class="technical-only">Event Stream</span><span class="story-only">Events</span></div>
    <div class="panel-content" id="event-stream"></div>
  </div>
  <div class="panel">
    <div class="panel-title"><span class="technical-only">Contract Evaluation</span><span class="story-only">What's Happening</span></div>
    <div class="panel-content" id="check-panel">
      <div class="check-idle">Press ▶ Play or ⏸ Step Through to begin</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-title"><span class="technical-only">Engine State</span><span class="story-only">System Status</span></div>
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
    <span class="viol-title"><span class="technical-only">Variance Log</span><span class="story-only">Issues Found</span></span>
    <span class="viol-count-wrap"><span class="technical-only">violations: </span><span class="story-only">issues: </span><span class="viol-count" id="viol-count">0</span></span>
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
