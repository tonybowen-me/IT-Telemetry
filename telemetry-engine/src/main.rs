mod control_plane;
mod engine;
mod events;
mod state;
mod variance;

use control_plane::{ControlPlaneEngine, ControlPlaneState, ControlPlaneStore, CP_WINDOW};
use engine::{Engine, WINDOW};
use events::{ControlPlaneEvent, DomainEvent, Domain, IdentityEvent, Event};
use state::{AuthState, StateStore};
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

// ── Step-through narratives (3 phases per step × 9 steps) ────────────────────

static NARRATIVES: &[&[Phase]] = &[
    // ── Step 1: LoginSuccess(alice, t=0) ──────────────────────────────────────
    &[
        ("Event Arrives",
         "LoginSuccess — alice @ t=0s",
         "The engine receives its first event: alice has authenticated. \
          Contract 1 states that every LoginSuccess must eventually be followed \
          by an AuthTokenIssued. The engine records this login, creates alice's \
          auth state, and opens a deferred obligation. No invariant fires yet."),
        ("State Lookup",
         "Creating alice's auth state",
         "No prior entry exists for alice. The engine initialises: \
          logins=[0], token_issued_at=null, token_used=false. \
          The 5-minute freshness window opens at t=0s and expires at t=300s. \
          LoginSuccess triggers no immediate check — only a deferred one."),
        ("Invariant Result",
         "⏳ Pending — Contract 1 is deferred",
         "LoginSuccess alone satisfies no invariant immediately. The engine \
          is not deciding yet — it is watching. Contract 1 will be evaluated \
          when AuthTokenIssued arrives, or flagged at stream end if it never does."),
    ],
    // ── Step 2: AuthTokenIssued(alice, t=10) ─────────────────────────────────
    &[
        ("Event Arrives",
         "AuthTokenIssued — alice @ t=10s",
         "A token has been issued to alice 10 seconds after login. \
          This triggers Contract 1's deferred check: the engine must verify \
          that this issuance is backed by a LoginSuccess within the \
          5-minute freshness window. The lookup runs now."),
        ("State Lookup",
         "Checking alice's login history",
         "alice.logins = [0]. Last login: t=0s. Elapsed since login: 10s. \
          Window: 300s. 10 < 300 — the login is fresh. \
          The engine finds a valid login within the window and confirms \
          Contract 1. State updated: token_issued_at = 10."),
        ("Invariant Result",
         "✔ Pass — token issuance is valid",
         "Contract 1 confirmed: alice's token was issued 10 seconds after a \
          valid login. The issuance is legitimate. The engine continues \
          watching for AuthTokenUsed, which will trigger Contract 2."),
    ],
    // ── Step 3: AuthTokenUsed(alice, t=120) ──────────────────────────────────
    &[
        ("Event Arrives",
         "AuthTokenUsed — alice @ t=120s",
         "alice exercises her token 120 seconds after login. Contract 2 fires: \
          the engine checks (A) a valid LoginSuccess exists within the window, \
          and (B) an AuthTokenIssued was previously recorded. \
          Both checks run simultaneously."),
        ("State Lookup",
         "Checking alice's complete auth state",
         "alice.logins=[0], elapsed=120s < 300s → login valid. \
          alice.token_issued_at=10 → issuance on record. \
          Both preconditions of Contract 2 are met. \
          State updated: token_used=true."),
        ("Invariant Result",
         "✔ Pass — full auth chain verified",
         "Alice's complete authentication chain is confirmed: \
          Login (t=0) → Token Issued (t=10) → Token Used (t=120). \
          All events within the 5-minute window, in the correct order. \
          This is the baseline. Every other scenario deviates from this."),
    ],
    // ── Step 4: AuthTokenUsed(bob, t=200) ────────────────────────────────────
    &[
        ("Event Arrives",
         "AuthTokenUsed — bob @ t=200s",
         "bob attempts to use a token. This is the first event the engine \
          has ever seen from bob — there is no prior state for this identity. \
          Contract 2 fires immediately: has bob ever authenticated? \
          Is there a token issuance on record?"),
        ("State Lookup",
         "Looking up bob — no state found",
         "bob has no entry in the engine's state store. \
          No LoginSuccess. No AuthTokenIssued. \
          Yet a token is being exercised. \
          The engine cannot find a login within any window \
          because there is no window — there was never a login."),
        ("Invariant Result",
         "✘ Critical — token used without authentication",
         "Hard causal failure: a token was exercised by an identity that \
          never authenticated. This is not probabilistic — it is a proven \
          invariant violation. The contract is explicit: AuthTokenUsed \
          MUST have a prior LoginSuccess. None exists. \
          In a real deployment: immediate alert, possible credential theft."),
    ],
    // ── Step 5: LoginSuccess(dave, t=400) ────────────────────────────────────
    &[
        ("Event Arrives",
         "LoginSuccess — dave @ t=400s",
         "Scenario 3 begins. dave logs in at t=400s. The engine records this \
          and opens dave's 5-minute freshness window. \
          The window runs t=400s → t=700s. \
          Any AuthTokenUsed arriving after t=700s will violate Contract 2."),
        ("State Lookup",
         "Initialising dave's auth state",
         "dave.logins=[400], token_issued_at=null, token_used=false. \
          Window: [400s, 700s]. Everything is in order. \
          The engine records the deferred Contract 1 obligation \
          and waits for AuthTokenIssued."),
        ("Invariant Result",
         "⏳ Pending — window is open",
         "Same deferred pattern as alice's first event. The engine records \
          state and waits. Note the critical deadline: t=700s. \
          The next events will determine whether dave's session \
          respects the freshness contract."),
    ],
    // ── Step 6: AuthTokenIssued(dave, t=401) ─────────────────────────────────
    &[
        ("Event Arrives",
         "AuthTokenIssued — dave @ t=401s",
         "dave's token is issued one second after login. Contract 1 fires: \
          was there a LoginSuccess within the 5-minute window? \
          At t=401s the window is wide open — 299 seconds remain. \
          The check should pass easily."),
        ("State Lookup",
         "dave.last_login=400s, elapsed=1s",
         "Login was 1 second ago. Window: 300s. 1 < 300 — valid. \
          Contract 1 satisfied. State: token_issued_at=401. \
          Notice: the clock is at t=401s. The window closes at t=700s. \
          If AuthTokenUsed arrives after t=700s, Contract 2 will fail."),
        ("Invariant Result",
         "✔ Pass — but the window is closing",
         "Token issued legitimately. However, the engine has recorded \
          dave's login at t=400s. When AuthTokenUsed arrives, \
          the engine recalculates elapsed from t=400s — not from t=401s. \
          If that event arrives after t=700s, the session is expired."),
    ],
    // ── Step 7: AuthTokenUsed(dave, t=720) ───────────────────────────────────
    &[
        ("Event Arrives",
         "AuthTokenUsed — dave @ t=720s",
         "dave uses his token at t=720s. The window closed at t=700s. \
          The engine calculates: 720 − 400 = 320s since login. \
          The window is 300s. Dave is 20 seconds past the deadline. \
          Contract 2 evaluates now."),
        ("State Lookup",
         "dave.last_login=400s, elapsed=320s, window=300s",
         "320 > 300. The session has expired. The engine does not care \
          that the token was validly issued at t=401s — what matters is \
          the age of the LoginSuccess at the moment of token use. \
          At t=720s, dave's login is stale by exactly 20 seconds."),
        ("Invariant Result",
         "✘ Critical — session expired",
         "Contract 2 violated. Deterministic proof: 720 − 400 = 320 > 300. \
          The login is outside the freshness window at the time of token use. \
          This could represent a delayed replay, a stolen long-lived token, \
          or a client that held a credential past its validity period. \
          The engine flags it regardless — no interpretation required."),
    ],
    // ── Step 8: LoginSuccess(judy, t=900) ────────────────────────────────────
    &[
        ("Event Arrives",
         "LoginSuccess — judy @ t=900s",
         "Scenario 4 begins. judy logs in. The engine records this and opens \
          Contract 1's deferred obligation. \
          No AuthTokenIssued will arrive before the stream ends — \
          this represents the deferred invariant case: only detectable at finalize."),
        ("State Lookup",
         "Initialising judy's auth state",
         "judy.logins=[900], token_issued_at=null, token_used=false. \
          Window: [900s, 1200s]. Contract 1 obligation is open. \
          The engine holds this in memory, awaiting an AuthTokenIssued \
          that will never come."),
        ("Invariant Result",
         "⏳ Pending — stream will end without AuthTokenIssued",
         "The engine is watching, but this stream ends without a token \
          issuance for judy. The obligation will only be resolved during \
          the finalize pass — when the engine audits all open contracts \
          that could not be evaluated in real-time."),
    ],
    // ── Step 9: RoleAssigned(svc_alpha, t=1000) ── ControlPlane domain ───────
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
    // ── Step 10: AdminActionTaken(svc_alpha, t=1030) ─────────────────────────
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
          This is the ControlPlane equivalent of Scenario A: the full \
          authorisation chain is intact. Role → Action within the window."),
    ],
    // ── Step 11: AdminActionTaken(rogue_svc, t=1100) ─────────────────────────
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
    // ── Step 12: RoleAssigned(svc_beta, t=1200) ──────────────────────────────
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
    // ── Step 13: AdminActionTaken(svc_beta, t=5000) ──────────────────────────
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
    // ── Step 14: FINALIZE(judy) ───────────────────────────────────────────────
    &[
        ("Stream End",
         "FINALIZE — the event stream has ended",
         "No more events will arrive. The engine now runs its deferred \
          contract scan, iterating every identity that holds an open \
          Contract 1 obligation: a LoginSuccess with no AuthTokenIssued \
          before stream end. judy is the only such identity."),
        ("Deferred Check",
         "judy: login recorded, no token ever issued",
         "judy.logins=[900], token_issued_at=null, token_used=false. \
          The stream is over. judy authenticated but received no token. \
          Contract 1's obligation is unfulfilled. \
          The engine emits a deferred Warning variance."),
        ("Invariant Result",
         "⚠ Warning — login without token issuance",
         "Contract 1 deferred violation: judy's login was never followed \
          by AuthTokenIssued before the stream closed. \
          Possible causes: abandoned session, failure in the token issuance \
          pipeline, or a login that was intercepted before completion. \
          The engine cannot determine cause — only that the contract was not satisfied."),
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
    id_store:  &StateStore,
    cp_store:  &ControlPlaneStore,
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

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn compute_check(
    ev:     &Event,
    id_pre: Option<&AuthState>,
    cp_pre: Option<&ControlPlaneState>,
) -> CheckInfo {
    match &ev.kind {
        DomainEvent::Identity(_)     => compute_identity_check(ev, id_pre),
        DomainEvent::ControlPlane(_) => compute_cp_check(ev, cp_pre),
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
    let mut engine       = Engine::new();
    let mut cp_engine    = ControlPlaneEngine::new();
    let mut steps        = Vec::new();
    let mut seq          = 0usize;
    let mut user_history: HashMap<String, Vec<(usize, u64, &'static str)>> = HashMap::new();

    let script: Vec<(&str, &str, u64, &'static str, DomainEvent)> = vec![
        // ── Identity domain — Scenario A (baseline) + violation cases ────────
        ("alice",     "Scenario A — Legitimate Variation",  0,    "alice",     DomainEvent::Identity(IdentityEvent::LoginSuccess)),
        ("alice",     "Scenario A — Legitimate Variation",  10,   "alice",     DomainEvent::Identity(IdentityEvent::AuthTokenIssued)),
        ("alice",     "Scenario A — Legitimate Variation",  120,  "alice",     DomainEvent::Identity(IdentityEvent::AuthTokenUsed)),
        ("bob",       "Scenario 2 — Token Without Login",   200,  "bob",       DomainEvent::Identity(IdentityEvent::AuthTokenUsed)),
        ("dave",      "Scenario 3 — Session Expired",       400,  "dave",      DomainEvent::Identity(IdentityEvent::LoginSuccess)),
        ("dave",      "Scenario 3 — Session Expired",       401,  "dave",      DomainEvent::Identity(IdentityEvent::AuthTokenIssued)),
        ("dave",      "Scenario 3 — Session Expired",       720,  "dave",      DomainEvent::Identity(IdentityEvent::AuthTokenUsed)),
        ("judy",      "Scenario 4 — Login Without Token",   900,  "judy",      DomainEvent::Identity(IdentityEvent::LoginSuccess)),
        // ── ControlPlane domain — Scenario B (privilege misuse) ──────────────
        ("svc_alpha", "Scenario B — Privilege Misuse",      1000, "svc_alpha", DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned)),
        ("svc_alpha", "Scenario B — Privilege Misuse",      1030, "svc_alpha", DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        ("rogue_svc", "Scenario B — Privilege Misuse",      1100, "rogue_svc", DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
        ("svc_beta",  "Scenario B — Privilege Misuse",      1200, "svc_beta",  DomainEvent::ControlPlane(ControlPlaneEvent::RoleAssigned)),
        ("svc_beta",  "Scenario B — Privilege Misuse",      5000, "svc_beta",  DomainEvent::ControlPlane(ControlPlaneEvent::AdminActionTaken)),
    ];

    for (group, label, ts, user, kind) in &script {
        seq += 1;
        let ev      = Event::new(*ts, user, kind.clone());
        let id_pre  = engine.state.get(ev.entity).cloned();
        let cp_pre  = cp_engine.state.get(ev.entity).cloned();
        let check   = compute_check(&ev, id_pre.as_ref(), cp_pre.as_ref());
        let variances = match ev.kind.domain() {
            Domain::Identity     => engine.ingest(&ev),
            Domain::ControlPlane => cp_engine.ingest(&ev),
            _                    => vec![],
        };
        let snap   = snapshot(&engine.state, &cp_engine.state, *ts);
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

    for (user, var) in engine.finalize() {
        seq += 1;
        let snap    = snapshot(&engine.state, &cp_engine.state, 9999);
        let phases  = NARRATIVES.get(seq - 1).copied().unwrap_or(&[]).to_vec();
        let history = user_history.get(&user).cloned().unwrap_or_default();
        steps.push(StepData {
            seq, ts: 9999, user: user.clone(), event: "FINALIZE",
            group: user.clone(), group_label: "Scenario 4 — Login Without Token".to_string(),
            is_deferred: true,
            check: CheckInfo {
                rule: "Deferred — Contract 1: LoginSuccess(user) → AuthTokenIssued(user)".to_string(),
                lookup: vec![
                    ("trigger".into(),      "Stream ended".to_string(),                                  "neutral".into()),
                    ("user".into(),         user.clone(),                                                 "neutral".into()),
                    ("has_login".into(),    "yes".to_string(),                                           "ok".into()),
                    ("token_issued".into(), "NONE".to_string(),                                          "warn".into()),
                    ("contract_1".into(),   "LoginSuccess never followed by AuthTokenIssued".to_string(), "fail".into()),
                ],
                result: "warn",
                result_text: "⚠ CONTRACT WARNING".to_string(),
                result_detail: format!("'{}': login recorded but AuthTokenIssued never arrived before stream end", user),
            },
            variances: vec![VarInfo { severity: var.severity.as_str(), rule: var.rule.to_string(), detail: var.detail.clone() }],
            state_snap: snap, phases, history,
        });
    }
    steps
}

// ── Scenario metadata (POC document Section 6) ────────────────────────────────

/// Declared scenario inputs + expected outcomes, matched against the POC document.
/// Each future domain phase will add its own SCENARIO_X_JS constant.
const SCENARIOS_JS: &str = r#"[
  {id:"A",name:"Legitimate Variation",label:"Scenario A \u2014 Legitimate Variation",domain:"Identity",description:"Full authentication chain within 5-min window. No invariants broken.",expected:0},
  {id:"B",name:"Privilege Misuse",label:"Scenario B \u2014 Privilege Misuse",domain:"ControlPlane",description:"Stealth admin actions without valid role assignments. Two Critical violations expected.",expected:2}
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
      '<span class="sc-result pending" id="sc-result-' + sc.id + '">awaiting run</span>';
    bar.appendChild(row);
  });
})();

let running = false;
let stepMode = false;
let stepResolve = null;

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

function waitForStep(){
  const btn = document.getElementById('narrator-next');
  btn.disabled = false;
  return new Promise(resolve => { stepResolve = resolve; });
}

document.getElementById('narrator-next').addEventListener('click', () => {
  if (stepResolve){ stepResolve(); stepResolve = null;
    document.getElementById('narrator-next').disabled = true; }
});

async function startDemo(useStepMode){
  if (running) return;
  running = true; stepMode = useStepMode;
  document.getElementById('play-btn').disabled = true;
  document.getElementById('step-btn').disabled = true;
  document.getElementById('reset-btn').style.display = 'inline-flex';
  if (stepMode) document.getElementById('narrator').classList.add('active');
  resetAll();
  for (const step of STEPS) await processStep(step);
  showComplete();
  running = false;
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
    const steps  = STEPS.filter(s => s.group_label === sc.label);
    const actual = steps.reduce((n,s) => n + s.variances.length, 0);
    const el     = document.getElementById('sc-result-' + sc.id);
    if(!el) return;
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
  updateScenarioResult();
  const crit = STEPS.reduce((n,s) => n + s.variances.filter(v => v.severity==='critical').length, 0);
  const warn = STEPS.reduce((n,s) => n + s.variances.filter(v => v.severity==='warning').length, 0);
  const clean = STEPS.filter(s => s.variances.length === 0).length;
  document.getElementById('check-panel').innerHTML = `
    <div class="check-hdr">ENGINE COMPLETE</div>
    <div class="complete-grid">
      <div class="csstat cs-total"><div class="csval">${STEPS.length}</div><div class="cslbl">Events</div></div>
      <div class="csstat cs-critical"><div class="csval">${crit}</div><div class="cslbl">Critical</div></div>
      <div class="csstat cs-warn"><div class="csval">${warn}</div><div class="cslbl">Warnings</div></div>
      <div class="csstat cs-pass"><div class="csval">${clean}</div><div class="cslbl">Clean</div></div>
    </div>
    <div class="complete-note">
      ${crit} critical violation${crit!==1?'s':''} proven across ${Object.keys(STEPS[STEPS.length-1].state).length} identities.
      Every detection is a deterministic causal proof — not a score, not a threshold, not a model.
    </div>`;
}

function resetAll(){
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
document.getElementById('reset-btn').addEventListener('click', () => {
  running = false; stepMode = false;
  document.getElementById('narrator').classList.remove('active');
  document.getElementById('play-btn').disabled = false;
  document.getElementById('step-btn').disabled = false;
  document.getElementById('reset-btn').style.display = 'none';
  resetAll();
});
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
    LoginSuccess <span class="arrow">→</span>
    AuthTokenIssued <span class="arrow">→</span>
    AuthTokenUsed
    <span style="color:var(--dim);margin-left:.4rem">· 5-min window</span>
  </div>
  <div class="hdr-controls">
    <button id="play-btn">▶ Play</button>
    <button id="step-btn">⏸ Step Through</button>
    <button id="reset-btn">↺ Reset</button>
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
        <p>A Rust pipeline that enforces authentication contracts through <strong style="color:var(--blue)">deterministic causal reasoning</strong> — no ML, no probabilistic models, pure logical invariants.</p>
      </div>
      <div class="modal-section">
        <div class="modal-h">The Causal Chain</div>
        <div class="modal-chain">
          LoginSuccess <span class="arrow">→</span> AuthTokenIssued <span class="arrow">→</span> AuthTokenUsed
          <span class="window">· 5-minute freshness window</span>
        </div>
        <p style="color:var(--nbody)">Each step must causally follow the prior one within the window. The engine ingests an event stream and asks: did every token use have a valid, recent, complete auth chain behind it?</p>
      </div>
      <div class="modal-section">
        <div class="modal-h">What the Demo Shows</div>
        <table class="modal-table">
          <tr><td>alice</td><td>Happy path — full chain within window</td><td><span class="modal-pass">✔ All contracts satisfied</span></td></tr>
          <tr><td>bob</td><td>Token used with no prior login</td><td><span class="modal-fail">✘ Critical — unauthenticated access</span></td></tr>
          <tr><td>dave</td><td>Token used 320 s after login (window = 300 s)</td><td><span class="modal-fail">✘ Critical — session expired</span></td></tr>
          <tr><td>judy</td><td>Login recorded, token never issued before stream ends</td><td><span class="modal-warn">⚠ Warning — deferred obligation unfulfilled</span></td></tr>
        </table>
        <p style="color:var(--nbody);margin-top:.5rem">Every violation produces a <strong style="color:var(--text)">deterministic proof</strong>, not a risk score — e.g. <em>"login was 320 s ago, window is 300 s, exceeded by 20 s."</em></p>
      </div>
      <div class="modal-section">
        <div class="modal-h">How to Use the Demo</div>
        <ul style="margin:.2rem 0 0 1.2rem;color:var(--nbody);font-size:.68rem;line-height:1.9">
          <li><strong style="color:var(--green)">▶ Play</strong> — steps through all events automatically</li>
          <li><strong style="color:var(--blue)">⏸ Step Through</strong> — advance one phase at a time with narrator guidance</li>
          <li><strong style="color:var(--text)">↺ Reset</strong> — clear state and restart from the beginning</li>
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
