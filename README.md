# capyrls

**Supabase RLS → any Postgres.** A converter that rewrites `auth.uid()`-style
row-level-security policies into portable, vanilla PostgreSQL.

Supabase RLS is standard `CREATE POLICY` plus a platform-provided context:
`auth.uid()`, `auth.jwt()`, `auth.role()`, the `anon`/`authenticated`/
`service_role` pseudo-roles, and PostgREST injecting a verified JWT into a
session GUC on every request. None of that exists on plain Postgres - which is
why RLS is usually the thing that keeps a project stuck. capyrls re-homes the
policies so they run on plain Postgres: RDS, self-hosted, any Postgres. On a
managed platform whose database role cannot create roles (CapyDB included), use
the single role model - see [Role models](#role-models).

```bash
# from your Supabase migrations folder
capyrls convert supabase/migrations

# from a schema dump
pg_dump --schema-only "$SUPABASE_URL" | capyrls convert -

# straight from the running database (most faithful: server-normalized policies)
capyrls convert --db "$SUPABASE_URL"
```

Output is a small SQL bundle plus a report:

```
capyrls_out/
  capyrls_01_prelude.sql    # the new auth context (schema + accessor functions)
  capyrls_02_roles.sql      # role separation (or FORCE RLS for single-role setups)
  capyrls_03_policies.sql   # your policies, converted
  capyrls_report.md         # the contract your app now fulfils + anything needing a human
```

## What the conversion does

**Vanilla mode (default)** - the idiomatic plain-Postgres convention: a small
`app.*` schema of `stable` accessor functions over transaction-local GUCs. The
database stops knowing JWTs exist; your app verifies the caller at the edge and
sets typed facts per transaction:

| Supabase | becomes |
|---|---|
| `auth.uid()` | `(select app.user_id())` |
| `auth.jwt() ->> 'org_id'` | `(select app.org_id())` - each claim promoted to its own GUC |
| `auth.role()` / `auth.email()` | `(select app.role())` / `(select app.email())` |
| deep claim paths | `(select app.claims())` blob fallback, flagged in the report |
| `TO authenticated` | runtime role + `(select app.user_id()) is not null` |
| `TO anon` | `(select app.user_id()) is null` |
| `service_role` | a `BYPASSRLS` role (or the single-role service escape) |
| `FOR ALL` policies | split into per-command policies (disable with `--keep-for-all`) |

Your app sets the context inside each transaction - `set_config(..., true)` is
`SET LOCAL` semantics, safe behind transaction pooling:

```sql
begin;
select set_config('app.user_id', '5f4d...', true);
-- queries run under RLS here
commit;
```

Unset context reads as NULL, so every policy fails closed.

**Compat mode (`--mode supabase-compat`)** - a lift-and-shift: emits an
`auth.*` shim backed by the `request.jwt.claims` GUC and ports policies
verbatim. Two limits to know before choosing it:

- With the default split role model it recreates `anon`, `authenticated` and
  `service_role` as real roles. `CREATE ROLE` needs `CREATEROLE`, which a
  managed database role usually lacks (a CapyDB customer role does not have
  it). With `--role-model single` no roles are created.
- It emits no service escape. Under `--role-model single` every table is
  FORCEd and nothing bypasses the policies, so `service_role` call sites have
  no path until you give them one.

A reasonable first step; adopt the vanilla convention later.

## Role models

- `--role-model split` (default): creates `app_user` (runtime, cannot bypass
  RLS) and `app_service` (`BYPASSRLS`, replaces `service_role`). Owners bypass
  RLS in Postgres - runtime traffic must never connect as the role that owns
  the tables, and this model makes that structural. Applying it needs
  `CREATEROLE`, and creating the `BYPASSRLS` role needs more privilege still.
- `--role-model single`: for managed platforms where the app connects as the
  table owner. Emits `FORCE ROW LEVEL SECURITY` plus, in vanilla mode, an
  optional GUC-gated service escape (`--no-service-escape` to omit). The escape
  adds convenience, not exposure: an owner can disable RLS anyway.

## What it refuses to guess

Anything that cannot port mechanically is surfaced, never silently dropped or
mistranslated:

- policies referencing `auth.users` (port that data into your own schema first)
- policies on Supabase-managed schemas (`storage`, `realtime`, ...)
- function bodies referencing `auth.*` (listed for manual review)
- deep `auth.jwt()` paths that fall back to the claims blob

Run with `--strict` in CI to fail when anything needs manual attention.

## Rewrite mode

If you want to keep your existing migration history instead of adopting a
fresh bundle:

```bash
capyrls rewrite supabase/migrations --out rewritten/
```

rewrites `auth.*` calls in place (byte-identical everywhere else), keeps your
`TO` clauses, and emits role stubs for `anon`/`authenticated`/`service_role`.

## Library

The converter is an importable, dependency-free Go library:

```go
import "github.com/capydatabase/capyrls"

result, err := capyrls.Convert(sources, capyrls.Options{})
```

Live introspection lives in `github.com/capydatabase/capyrls/live` and takes any
`*sql.DB`.

## Install

```bash
go install github.com/capydatabase/capyrls/cmd/capyrls@latest
```

Or grab a release binary. CapyDB users get the same converter as
`capydb migrate rls`.

## Development

```bash
make check   # fmt + vet + test
```

## License

MIT
