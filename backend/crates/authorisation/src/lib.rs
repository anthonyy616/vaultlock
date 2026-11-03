//! Central policy evaluation, roles, and resource permissions.
//!
//! Deny-by-default: every protected resource must have an explicit allow
//! decision computed by the policy engine. The engine consults the actor's
//! roles on the resource's owning scope (personal or organisation) plus any
//! resource-level grants.

use std::fmt::Display;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// Role assigned to a member within a scope (personal or organisation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Role {
    /// Can view and download.
    Viewer,
    /// Can view, download, and update.
    Member,
    /// Can view, download, update, share, and manage members (not ownership).
    Admin,
    /// Full control including ownership transfer.
    Owner,
}

impl Role {
    /// True when this role can perform the given permission.
    pub fn may(self, permission: Permission) -> bool {
        matches!(
            (self, permission),
            (Role::Owner, _)
                | (
                    Role::Admin,
                    Permission::View
                        | Permission::Download
                        | Permission::Update
                        | Permission::Share
                        | Permission::Admin
                )
                | (
                    Role::Member,
                    Permission::View | Permission::Download | Permission::Update
                )
                | (Role::Viewer, Permission::View | Permission::Download)
        )
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Viewer => write!(f, "viewer"),
            Role::Member => write!(f, "member"),
            Role::Admin => write!(f, "admin"),
            Role::Owner => write!(f, "owner"),
        }
    }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Granular permissions supported by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Permission {
    /// Browse permitted resources.
    View,
    /// Retrieve permitted resources.
    Download,
    /// Modify permitted resources.
    Update,
    /// Share permitted resources.
    Share,
    /// Manage permissions and ownership.
    Admin,
}

impl Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::View => write!(f, "view"),
            Permission::Download => write!(f, "download"),
            Permission::Update => write!(f, "update"),
            Permission::Share => write!(f, "share"),
            Permission::Admin => write!(f, "admin"),
        }
    }
}

// ---------------------------------------------------------------------------
// Policy context
// ---------------------------------------------------------------------------

/// The actor context used for authorisation decisions.
pub struct Actor {
    /// The user making the request.
    pub user_id: Uuid,
    /// The organisation scope the actor is operating within, if any.
    pub org_id: Option<Uuid>,
    /// The actor's role within the current scope.
    pub role: Option<Role>,
}

impl Actor {
    /// Create a new actor with no organisation scope.
    pub fn new(user_id: Uuid) -> Self {
        Self {
            user_id,
            org_id: None,
            role: None,
        }
    }

    /// Set the organisation scope and role for this actor.
    pub fn with_org(mut self, org_id: Uuid, role: Role) -> Self {
        self.org_id = Some(org_id);
        self.role = Some(role);
        self
    }
}

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// Central authorisation policy. Deny-by-default.
pub struct Policy;

impl Policy {
    /// Allow if the actor owns the resource or has the required permission
    /// via their role on the owning scope.
    ///
    /// Personal resources: owned by a user. The actor must be that user.
    /// Organisation resources: the actor must be a member of the owning org
    /// with sufficient role.
    pub fn allow(actor: &Actor, resource_owner: ResourceOwner, required: Permission) -> bool {
        match resource_owner {
            ResourceOwner::Personal(user_id) => actor.user_id == user_id,
            ResourceOwner::Organisation(org_id, base_role) => {
                let Some(actor_org) = &actor.org_id else {
                    return false;
                };
                if *actor_org != org_id {
                    return false;
                }
                if actor.user_id == org_id {
                    // Organisation owner is also the personal owner.
                    return true;
                }
                let Some(actor_role) = actor.role else {
                    return false;
                };
                // The resource's base_role is the minimum role needed to
                // access it. The actor's role must satisfy both the
                // resource's requirement and the requested permission.
                actor_role >= base_role && actor_role.may(required)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Resource ownership
// ---------------------------------------------------------------------------

/// Who owns a resource and what role is required to access it.
#[derive(Debug, Clone)]
pub enum ResourceOwner {
    /// Belongs to a single user. Only that user may access it.
    Personal(Uuid),
    /// Belongs to an organisation. `base_role` is the minimum role required
    /// to access the resource at all.
    Organisation(Uuid, Role),
}

impl ResourceOwner {
    /// Convenience for personal resources with a minimum permission gate.
    /// The caller still checks the specific permission via `Policy::allow`.
    pub fn personal(user_id: Uuid) -> Self {
        ResourceOwner::Personal(user_id)
    }

    /// Convenience for organisation resources owned by the given org with
    /// the given minimum role.
    pub fn organisation(org_id: Uuid, min_role: Role) -> Self {
        ResourceOwner::Organisation(org_id, min_role)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from authorisation checks.
#[derive(Debug, thiserror::Error)]
pub enum AuthorisationError {
    /// The actor is not authenticated or the token is invalid.
    #[error("unauthorised")]
    Unauthorised,
    /// The requested resource does not exist.
    #[error("resource not found")]
    NotFound,
    /// The actor is forbidden from performing this action.
    #[error("forbidden: {0}")]
    Forbidden(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(user_id: Uuid, org_id: Option<Uuid>, role: Option<Role>) -> Actor {
        let mut a = Actor::new(user_id);
        if let Some(o) = org_id {
            a = a.with_org(o, role.unwrap_or(Role::Viewer));
        }
        a
    }

    #[test]
    fn personal_owner_can_do_everything() {
        let id = Uuid::new_v4();
        let res = ResourceOwner::personal(id);
        let a = actor(id, None, None);
        assert!(Policy::allow(&a, res.clone(), Permission::View));
        assert!(Policy::allow(&a, res, Permission::Admin));
    }

    #[test]
    fn personal_non_owner_is_denied() {
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        let res = ResourceOwner::personal(owner);
        let a = actor(other, None, None);
        assert!(!Policy::allow(&a, res, Permission::View));
    }

    #[test]
    fn org_member_can_view() {
        let org = Uuid::new_v4();
        let res = ResourceOwner::organisation(org, Role::Member);
        let a = actor(Uuid::new_v4(), Some(org), Some(Role::Member));
        assert!(Policy::allow(&a, res.clone(), Permission::View));
        assert!(Policy::allow(&a, res, Permission::Download));
    }

    #[test]
    fn org_viewer_cannot_update() {
        let org = Uuid::new_v4();
        let res = ResourceOwner::organisation(org, Role::Viewer);
        let a = actor(Uuid::new_v4(), Some(org), Some(Role::Viewer));
        assert!(Policy::allow(&a, res.clone(), Permission::View));
        assert!(!Policy::allow(&a, res, Permission::Update));
    }

    #[test]
    fn org_cross_tenant_is_denied() {
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let res = ResourceOwner::organisation(org_a, Role::Viewer);
        let a = actor(Uuid::new_v4(), Some(org_b), Some(Role::Owner));
        assert!(!Policy::allow(&a, res, Permission::View));
    }

    #[test]
    fn roles_are_hierarchical() {
        assert!(Role::Owner.may(Permission::Admin));
        assert!(Role::Admin.may(Permission::Share));
        assert!(Role::Member.may(Permission::Update));
        assert!(Role::Viewer.may(Permission::Download));
        assert!(!Role::Viewer.may(Permission::Update));
        assert!(!Role::Member.may(Permission::Admin));
    }
}
