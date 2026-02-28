// ── Domain tag ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Domain {
    Identity,
    ControlPlane,
    Thermal,    // Phase 3
    Automation, // Phase 4
}

impl Domain {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Identity     => "Identity",
            Self::ControlPlane => "ControlPlane",
            Self::Thermal      => "Thermal",
            Self::Automation   => "Automation",
        }
    }
}

// ── Identity domain events ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum IdentityEvent {
    LoginSuccess,
    AuthTokenIssued,
    AuthTokenUsed,
}

impl IdentityEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::LoginSuccess    => "LoginSuccess",
            Self::AuthTokenIssued => "AuthTokenIssued",
            Self::AuthTokenUsed   => "AuthTokenUsed",
        }
    }
}

// ── ControlPlane domain events ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ControlPlaneEvent {
    RoleAssigned,
    AdminActionTaken,
}

impl ControlPlaneEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::RoleAssigned     => "RoleAssigned",
            Self::AdminActionTaken => "AdminActionTaken",
        }
    }
}

// ── Top-level domain event ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DomainEvent {
    Identity(IdentityEvent),
    ControlPlane(ControlPlaneEvent),
    // Thermal(ThermalEvent),     // Phase 3
    // Automation(AutomationEvent), // Phase 4
}

impl DomainEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Identity(e)     => e.name(),
            Self::ControlPlane(e) => e.name(),
        }
    }

    pub fn domain(&self) -> Domain {
        match self {
            Self::Identity(_)     => Domain::Identity,
            Self::ControlPlane(_) => Domain::ControlPlane,
        }
    }
}

// ── Event ─────────────────────────────────────────────────────────────────────

pub struct Event {
    pub ts:     u64,
    pub entity: &'static str,
    pub kind:   DomainEvent,
}

impl Event {
    pub fn new(ts: u64, entity: &'static str, kind: DomainEvent) -> Self {
        Self { ts, entity, kind }
    }

    pub fn identity(ts: u64, entity: &'static str, kind: IdentityEvent) -> Self {
        Self::new(ts, entity, DomainEvent::Identity(kind))
    }

    pub fn control_plane(ts: u64, entity: &'static str, kind: ControlPlaneEvent) -> Self {
        Self::new(ts, entity, DomainEvent::ControlPlane(kind))
    }
}
