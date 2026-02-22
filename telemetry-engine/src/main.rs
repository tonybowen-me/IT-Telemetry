mod engine;
mod events;
mod state;
mod variance;

use engine::{Engine, WINDOW};
use events::{AuthEvent, Event};
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

struct UserState {
    last_login:   Option<u64>,
    token_issued: Option<u64>,
    token_used:   bool,
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
    state_snap:  Vec<(String, UserState)>,
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
    // ── Step 9: FINALIZE(judy) ────────────────────────────────────────────────
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

fn snapshot(store: &StateStore) -> Vec<(String, UserState)> {
    let mut users: Vec<_> = store.keys().cloned().collect();
    users.sort();
    users.into_iter().map(|user| {
        let s = store.get(&user).unwrap();
        (user, UserState {
            last_login:   s.last_login(),
            token_issued: s.token_issued_at,
            token_used:   s.token_used,
        })
    }).collect()
}

fn compute_check(ev: &Event, pre: Option<&AuthState>) -> CheckInfo {
    match ev.kind {
        AuthEvent::LoginSuccess => CheckInfo {
            rule:   "Contract 1 — LoginSuccess(user) → must issue AuthTokenIssued(user)".to_string(),
            lookup: vec![
                ("user".into(),         ev.user.to_string(),                          "neutral".into()),
                ("event".into(),        format!("LoginSuccess @ t={}s", ev.ts),       "neutral".into()),
                ("action".into(),       "Login time recorded to state".to_string(),   "ok".into()),
                ("watching for".into(), format!("AuthTokenIssued within {}s", WINDOW),"neutral".into()),
            ],
            result:        "pending",
            result_text:   "⏳ PENDING".to_string(),
            result_detail: "Contract 1 is deferred — verified when AuthTokenIssued arrives or the stream ends".to_string(),
        },

        AuthEvent::AuthTokenIssued => {
            let last  = pre.and_then(|s| s.last_login());
            let valid = pre.map(|s| s.login_within(ev.ts, WINDOW).is_some()).unwrap_or(false);
            let mut lookup = vec![
                ("user".into(),  ev.user.to_string(),                        "neutral".into()),
                ("event".into(), format!("AuthTokenIssued @ t={}s", ev.ts), "neutral".into()),
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

        AuthEvent::AuthTokenUsed => {
            let has_login   = pre.map(|s| s.has_login()).unwrap_or(false);
            let last_login  = pre.and_then(|s| s.last_login());
            let valid_login = pre.map(|s| s.login_within(ev.ts, WINDOW).is_some()).unwrap_or(false);
            let token_at    = pre.and_then(|s| s.token_issued_at);
            let mut lookup  = vec![
                ("user".into(),  ev.user.to_string(),                     "neutral".into()),
                ("event".into(), format!("AuthTokenUsed @ t={}s", ev.ts), "neutral".into()),
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
    }
}

// ── Scenario ──────────────────────────────────────────────────────────────────

fn run_scenario() -> Vec<StepData> {
    let mut engine       = Engine::new();
    let mut steps        = Vec::new();
    let mut seq          = 0usize;
    let mut user_history: HashMap<String, Vec<(usize, u64, &'static str)>> = HashMap::new();

    let script: &[(&str, &str, u64, &'static str, AuthEvent)] = &[
        ("alice", "Scenario 1 — Happy Path",              0,   "alice", AuthEvent::LoginSuccess),
        ("alice", "Scenario 1 — Happy Path",              10,  "alice", AuthEvent::AuthTokenIssued),
        ("alice", "Scenario 1 — Happy Path",              120, "alice", AuthEvent::AuthTokenUsed),
        ("bob",   "Scenario 2 — Token Without Login",     200, "bob",   AuthEvent::AuthTokenUsed),
        ("dave",  "Scenario 3 — Session Expired",         400, "dave",  AuthEvent::LoginSuccess),
        ("dave",  "Scenario 3 — Session Expired",         401, "dave",  AuthEvent::AuthTokenIssued),
        ("dave",  "Scenario 3 — Session Expired",         720, "dave",  AuthEvent::AuthTokenUsed),
        ("judy",  "Scenario 4 — Login Without Token",     900, "judy",  AuthEvent::LoginSuccess),
    ];

    for (group, label, ts, user, kind) in script {
        seq += 1;
        let ev        = Event::new(*ts, user, kind.clone());
        let pre_state = engine.state.get(ev.user).cloned();
        let check     = compute_check(&ev, pre_state.as_ref());
        let variances = engine.ingest(&ev);
        let snap      = snapshot(&engine.state);
        let phases    = NARRATIVES.get(seq - 1).copied().unwrap_or(&[]).to_vec();

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
        let snap    = snapshot(&engine.state);
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
        for (user, us) in &s.state_snap {
            write!(out, "      {}:{{last_login:{},token_issued:{},token_used:{}}},\n",
                js_str(user),
                us.last_login.map(|t| t.to_string()).unwrap_or("null".into()),
                us.token_issued.map(|t| t.to_string()).unwrap_or("null".into()),
                us.token_used).unwrap();
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
"#;

// ── JS ────────────────────────────────────────────────────────────────────────

const JS: &str = r#"
const WINDOW_SECS = 300;
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
  const panel = document.getElementById('state-panel');
  const users = Object.keys(step.state).sort();
  panel.innerHTML = users.map(u => {
    const s = step.state[u];
    const age = s.last_login !== null ? step.ts - s.last_login : null;
    const inWin = age !== null && age <= WINDOW_SECS;
    const lCls = s.last_login !== null ? (inWin ? 'ok' : 'fail') : 'none';
    const lVal = s.last_login !== null ? `t=${s.last_login}s${!inWin?' ⚠':''}` : '—';
    return `<div class="state-card">
      <div class="state-user">${u}</div>
      <div class="state-row"><span class="state-k">last_login</span><span class="state-v ${lCls}">${lVal}</span></div>
      <div class="state-row"><span class="state-k">token_issued</span><span class="state-v ${s.token_issued!==null?'ok':'none'}">${s.token_issued!==null?'t='+s.token_issued+'s':'—'}</span></div>
      <div class="state-row"><span class="state-k">token_used</span><span class="state-v ${s.token_used?'ok':'none'}">${s.token_used?'yes':'no'}</span></div>
    </div>`;
  }).join('');
}

function showComplete(){
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
"#;

// ── HTML ──────────────────────────────────────────────────────────────────────

fn generate_html(steps_js: &str) -> String {
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
  </div>
</header>

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

<div class="violations-section">
  <div class="viol-header">
    <span class="viol-title">Variance Log</span>
    <span class="viol-count-wrap">violations: <span class="viol-count" id="viol-count">0</span></span>
  </div>
  <div class="viol-cards" id="viol-cards"></div>
</div>

<script>
const STEPS={steps};
{js}
</script>
</body>
</html>"#,
        css   = CSS,
        steps = steps_js,
        js    = JS,
    )
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let steps    = run_scenario();
    let steps_js = steps_to_js(&steps);
    let html     = generate_html(&steps_js);
    std::fs::write("dashboard.html", html).expect("cannot write dashboard.html");
    println!("Dashboard → dashboard.html");
    std::process::Command::new("cmd").args(["/c", "start", "", "dashboard.html"]).spawn().ok();
}
