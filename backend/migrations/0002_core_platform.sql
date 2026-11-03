-- Vaultlock core platform schema: organisations, projects, vaults, files,
-- snapshots, secrets, and sharing metadata. Complements migration 0001.

create table organisations (
    id uuid primary key,
    name text not null,
    slug text not null,
    created_by uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);
create unique index org_slug_unique on organisations (slug) where deleted_at is null;

create table projects (
    id uuid primary key,
    organisation_id uuid not null references organisations (id) on delete cascade,
    name text not null,
    description text,
    created_by uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);
create index projects_org_idx on projects (organisation_id, deleted_at);

create table vaults (
    id uuid primary key,
    project_id uuid not null references projects (id) on delete cascade,
    name text not null,
    description text,
    created_by uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);
create index vaults_project_idx on vaults (project_id, deleted_at);

create table files (
    id uuid primary key,
    vault_id uuid not null references vaults (id) on delete cascade,
    parent_id uuid references files (id) on delete cascade,
    name text not null,
    path text not null,
    storage_key text not null,
    content_type text,
    size_bytes bigint not null default 0,
    checksum text,
    version int not null default 1,
    created_by uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);
create unique index files_path_unique on files (vault_id, path) where deleted_at is null;
create index files_vault_idx on files (vault_id, deleted_at);
create index files_parent_idx on files (parent_id, deleted_at) where parent_id is not null;

create table snapshots (
    id uuid primary key,
    file_id uuid not null references files (id) on delete cascade,
    version int not null,
    storage_key text not null,
    size_bytes bigint not null default 0,
    checksum text,
    created_by uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now()
);
create unique index snapshots_file_version_unique on snapshots (file_id, version);
create index snapshots_file_idx on snapshots (file_id);

create table secrets (
    id uuid primary key,
    vault_id uuid not null references vaults (id) on delete cascade,
    name text not null,
    value_encrypted bytea not null,
    content_type text not null default 'application/octet-stream',
    version int not null default 1,
    created_by uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);
create unique index secrets_name_unique on secrets (vault_id, name) where deleted_at is null;
create index secrets_vault_idx on secrets (vault_id, deleted_at);

create table sharing (
    id uuid primary key,
    resource_type text not null check (resource_type in ('file', 'secret', 'vault', 'project')),
    resource_id uuid not null,
    granted_to uuid not null references users (id) on delete cascade,
    granted_by uuid not null references users (id) on delete cascade,
    role text not null check (role in ('viewer', 'member', 'admin')),
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);
create unique index sharing_resource_grant_unique on sharing (resource_type, resource_id, granted_to) where revoked_at is null;
create index sharing_granted_to_idx on sharing (granted_to, revoked_at);
create index sharing_resource_idx on sharing (resource_type, resource_id, revoked_at);

-- Ensure sharing resource_id references exist per resource_type (enforced in application layer
-- for v0.1; PostgreSQL foreign keys are polymorphic and not expressible in a single constraint).
