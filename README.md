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
- Under `--role-model single` the service path is claims-based: the bundle
  emits a service escape that admits a transaction whose verified claims carry
  `"role": "service_role"` - what a Supabase service key's JWT said. Set that
  role only from server code that used the service key, never from a token
  your users can shape. `--no-service-escape` removes it.

A reasonable first step; adopt the vanilla convention later.

## Non-uuid user ids (`--uid-type text`)

Supabase's `auth.uid()` returns `uuid`, and by default so do the converted
accessors (`auth.uid()` in compat mode, `app.user_id()` in vanilla mode). If
your identity provider's subjects are not uuids - Clerk's `user_2abc...`, for
one - every policy that calls the accessor raises
`invalid input syntax for type uuid`. Pass `--uid-type text` and the accessor
returns the subject as `text`, uncast.

Every column the user id is compared to must then be `text` as well: Postgres
has no implicit text-to-uuid conversion. That failure is loud, never silent -
applying the bundle stops at the first policy comparing it to a uuid column
(`42883 operator does not exist: text = uuid`) or at a uuid column defaulted to
it (`42804`). The report names each such uuid column it can see (unaliased
references in policies, and column defaults) with the fix; run it before you
apply:

```sql
alter table public.todos alter column owner_id type text using owner_id::text;
```

capyrls does not cast the column side (`owner_id::text = ...`) for you: that
predicate cannot use the column's index, and a uuid column cannot hold a
non-uuid subject anyway, so every such policy would silently match nothing.
One case is not caught at apply time: a `plpgsql` function body is only
type-checked when called, so helpers listed under "Functions to review" need
the same change by hand.

## Role models

- `--role-model split` (default): creates `app_user` (runtime, cannot bypass
  RLS) and `app_service` (`BYPASSRLS`, replaces `service_role`). Owners bypass
  RLS in Postgres - runtime traffic must never connect as the role that owns
  the tables, and this model makes that structural. Applying it needs
  `CREATEROLE`, and creating the `BYPASSRLS` role needs more privilege still.
- `--role-model single`: for managed platforms where the app connects as the
  table owner. Emits `FORCE ROW LEVEL SECURITY` plus a service escape
  (`--no-service-escape` to omit): `app.role = 'service'` in vanilla mode,
  claims with `"role": "service_role"` in compat mode. The escape is also ORed
  into every restrictive policy, because a permissive policy cannot lift a
  restrictive one and `service_role`'s `BYPASSRLS` skipped those too. It adds
  convenience, not exposure: an owner can disable RLS anyway.

### The split model on CapyDB (`--target capydb`)

`--target capydb` rejects `--role-model split` before producing anything
(`capydb migrate rls` always sets it). The split model needs a role that does
not own the tables, and a CapyDB database role can neither create one
(`CREATEROLE`) nor make one bypass RLS (`BYPASSRLS`). Nor does one exist to
grant to instead: every login CapyDB issues is a member of the owning role and
switches to it on connect (`SET role`), so it IS the owner for row security.

What it would take is a platform change, not a converter change: a second,
platform-created login role per database that is `NOSUPERUSER NOCREATEROLE
NOBYPASSRLS` and **not** a member of the owner, with the owner granted
membership in it `WITH INHERIT FALSE, SET TRUE` (Postgres 16+) so one
credential can also `SET ROLE` to it, and its own credential exposed next to
the owner's. The owner itself would then be the service path (owners bypass
RLS on tables that are not FORCEd), so no `BYPASSRLS` role is needed and the
bundle's roles file becomes grants only. Until then, use the single role
model.

## What it refuses to guess

Anything that cannot port mechanically is surfaced, never silently dropped or
mistranslated:

- policies referencing `auth.users` (port that data into your own schema first)
- policies on Supabase-managed schemas (`storage`, `realtime`, ...)
- function bodies referencing `auth.*` (listed for manual review)
- deep `auth.jwt()` paths that fall back to the claims blob
- `SECURITY DEFINER` functions that write to a table which ends up FORCEd
  (every RLS table under the single role model). A definer runs as the owner,
  FORCE applies policies to the owner, so the cross-user write that is usually
  why the function is a definer now fails with `42501`. The report lists each
  one with the fix for your configuration: raise the service escape inside the
  body and restore it on the way out, or, under the split model, hand the
  function to the `BYPASSRLS` role. Writes through `EXECUTE` are not seen.

Run with `--strict` in CI to fail when anything needs manual attention.

## Rewrite mode

If you want to keep your existing migration history instead of adopting a
fresh bundle:

```bash
capyrls rewrite supabase/migrations --out rewritten/
```

rewrites `auth.*` calls in place (byte-identical everywhere else), keeps your
`TO` clauses, and emits role stubs for `anon`/`authenticated`/`service_role`.

## In the browser

`cmd/capyrls-wasm` builds the converter for WebAssembly; it registers one global,
`capyrlsConvert(sourcesJSON, optionsJSON)`, taking `[{"name", "sql"}]` and the
CLI's options by the same names (`mode`, `role_model`, `uid_type`, `target`,
`keep_for_all`, `no_service_escape`, `prefix`), and returns the files, the
report and its Markdown as JSON. The CapyDB web converter at
https://capydb.dev/tools/rls-converter runs it entirely in the page.

```bash
GOOS=js GOARCH=wasm go build -trimpath -ldflags='-s -w' -o capyrls.wasm ./cmd/capyrls-wasm
# load it with $(go env GOROOT)/lib/wasm/wasm_exec.js from the same toolchain
```

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

The live tests (`apply_live_test.go`, `live/live_test.go`) apply converted
bundles to a real Postgres as a role with no `SUPERUSER`, `CREATEROLE` or
`BYPASSRLS` and check who can read and write what. They are skipped unless
`CAPYRLS_TEST_DATABASE_URL` points at a superuser connection they may create
roles and databases with:

```bash
docker run -d --name capyrls-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55731:5432 postgres:18
CAPYRLS_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:55731/postgres?sslmode=disable' make test
```

## License

MIT
