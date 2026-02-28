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

// ── Thermal domain events ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ThermalEvent {
    WorkloadScheduled,
    ThermalReading(u64), // temperature in °C
}

impl ThermalEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::WorkloadScheduled  => "WorkloadScheduled",
            Self::ThermalReading(_)  => "ThermalReading",
        }
    }
}

// ── Automation domain events ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AutomationEvent {
    StateValidated,
    AutomationTriggered,
}

impl AutomationEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::StateValidated      => "StateValidated",
            Self::AutomationTriggered => "AutomationTriggered",
        }
    }
}

// ── Top-level domain event ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DomainEvent {
    Identity(IdentityEvent),
    ControlPlane(ControlPlaneEvent),
    Thermal(ThermalEvent),
    Automation(AutomationEvent),
}

impl DomainEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Identity(e)    => e.name(),
            Self::ControlPlane(e)=> e.name(),
            Self::Thermal(e)     => e.name(),
            Self::Automation(e)  => e.name(),
        }
    }

    pub fn domain(&self) -> Domain {
        match self {
            Self::Identity(_)    => Domain::Identity,
            Self::ControlPlane(_)=> Domain::ControlPlane,
            Self::Thermal(_)     => Domain::Thermal,
            Self::Automation(_)  => Domain::Automation,
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

    pub fn thermal(ts: u64, entity: &'static str, kind: ThermalEvent) -> Self {
        Self::new(ts, entity, DomainEvent::Thermal(kind))
    }

    pub fn automation(ts: u64, entity: &'static str, kind: AutomationEvent) -> Self {
        Self::new(ts, entity, DomainEvent::Automation(kind))
    }
}
