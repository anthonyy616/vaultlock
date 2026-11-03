-- Vaultlock baseline schema: identity, sessions, devices, CLI device
-- authorisation, email tokens, audit events and kms key receipts.

create table users (
    id uuid primary key,
    email text not null,
    display_name text,
    password_hash text,
    recovery_code_hash text,          -- account recovery (Phase 8)
    email_verified_at timestamptz,
    password_changed_at timestamptz,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    deleted_at timestamptz
);
create unique index users_email_unique on users (lower(email)) where deleted_at is null;

create table oauth_identities (
    id uuid primary key,
    provider text not null check (provider in ('google', 'github')),
    provider_account_id text not null,
    user_id uuid not null references users (id) on delete cascade,
    created_at timestamptz not null,
    unique (provider, provider_account_id)
);

create table devices (
    id uuid primary key,
    user_id uuid not null references users (id) on delete cascade,
    name text not null,
    platform text not null,
    created_at timestamptz not null,
    last_seen_at timestamptz,
    revoked_at timestamptz
);

create table sessions (
    id uuid primary key,
    token_hash bytea not null,
    token_kind text not null check (token_kind in ('session', 'personal_access')),
    user_id uuid not null references users (id) on delete cascade,
    device_id uuid references devices (id),
    expires_at timestamptz not null,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_at timestamptz not null
);
create unique index sessions_token_hash_unique on sessions (token_hash);
create index sessions_user_idx on sessions (user_id, expires_at);

create table email_tokens (
    id uuid primary key,
    token_hash bytea not null,
    token_kind text not null check (token_kind in ('verify_email', 'password_reset')),
    user_id uuid not null references users (id) on delete cascade,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz not null
);
create unique index email_tokens_hash_unique on email_tokens (token_hash);

create table device_authorizations (
    id uuid primary key,
    device_code_hash bytea not null,
    user_code text not null,
    status text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'expired')),
    user_id uuid references users (id),
    device_id uuid references devices (id),
    device_name text,
    device_platform text,
    interval_secs int not null default 5,
    expires_at timestamptz not null,
    created_at timestamptz not null
);
create unique index device_auth_code_hash on device_authorizations (device_code_hash);
create index device_auth_user_code on device_authorizations (user_code, expires_at);

create table audit_events (
    id uuid primary key,
    actor_user_id uuid,
    org_id uuid,
    action text not null,
    resource_type text,
    resource_id uuid,
    metadata jsonb not null default '{}'::jsonb,
    request_id text,
    ip text,
    user_agent text,
    created_at timestamptz not null default now()
);
create index audit_events_created_idx on audit_events (created_at desc);
create index audit_events_actor_idx on audit_events (actor_user_id, created_at desc);
create index audit_events_org_idx on audit_events (org_id, created_at desc);

create table kms_keys (
    key_id uuid primary key,
    master_version int not null,
    wrapped_key bytea not null,
    created_at timestamptz not null,
    rotated_from uuid
);
