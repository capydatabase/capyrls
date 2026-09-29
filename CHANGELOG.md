# Changelog

All notable changes to capyrls are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.16.0] - 2026-09-30

### Added

- **The split role model works on CapyDB.** `--role-model split --target capydb`
  (`Options{RoleModel: RoleSplit, Target: TargetCapyDB}`) is no longer refused: it uses the runtime
  role CapyDB creates when a project enables it (`POST /v1/projects/{projectID}/roles/app`),
  `app_user` - a login that owns nothing, cannot bypass RLS and is not a member of the owner, with
  the owner allowed to `SET ROLE app_user`. The bundle creates no roles. `capyrls_02_roles.sql`
  checks that `app_user` exists and otherwise stops with how to enable it, then grants to
  `app_user` only (schema usage, table and sequence privileges, default privileges for what the
  owner creates later). The owner is the service path - it bypasses row security on tables that
  are not FORCEd - so there is no `BYPASSRLS` service role and nothing is granted to one; a
  `service_role`-only policy is reported as covered by the owner. `anon`, `authenticated` and
  `service_role` are not recreated in either mode: policies target `app_user` and keep the
  anon/authenticated distinction as a predicate, as the single role model does. The report warns
  about tables the source FORCEd (FORCE confines the owner too) and gives a CapyDB-specific fix for
  `SECURITY DEFINER` functions that write to them: drop FORCE, not "hand the function to the
  `BYPASSRLS` role". Live tests apply the bundle as a CapyDB-shaped owner next to a platform-shaped
  `app_user` on postgres:16 and postgres:18.

### Changed

- **`ErrSplitRolesUnsupported` now means a custom runtime role on CapyDB.** It is returned for
  `TargetCapyDB` with the split model and an `AppRole` other than `app_user` (the bundle cannot
  create it); the split model itself is accepted. `ServiceRole` is unused on CapyDB.

## [1.15.0] - 2026-09-29

### Added

- **Compat mode has a service path.** `--mode supabase-compat --role-model single` now emits the
  service escape too, keyed on the claims: a transaction whose verified `request.jwt.claims` carry
  `"role": "service_role"` - what a Supabase service key's JWT said - passes
  `capyrls_service_escape` on every table and skips the row filters. Before, compat mode FORCEd
  every table and nothing bypassed the policies, so `service_role` call sites had nowhere to go. It
  needs no roles, so it applies as a managed database role; a `service_role`-only policy is now
  reported as covered by the escape. `--no-service-escape` still removes it. Verified on
  postgres:18 as a role with no `SUPERUSER`, `CREATEROLE` or `BYPASSRLS`.
- **`--target capydb` (`Options.Target = TargetCapyDB`).** Rejects `--role-model split` before
  producing anything, with `ErrSplitRolesUnsupported` naming why: the split model creates a
  non-owning runtime role and a `BYPASSRLS` service role, a CapyDB database role has neither
  `CREATEROLE` nor `BYPASSRLS`, and every CapyDB login acts as the owner, so no existing role can
  stand in. The README states the platform change that would make it possible.
- **The report flags `SECURITY DEFINER` functions that write to FORCEd tables.** A definer runs as
  the owner and FORCE applies policies to the owner, so the cross-user write that is usually why a
  function is a definer fails with `42501` after conversion (or vanishes into an
  `exception when others` handler). capyrls reads each definer's body (from the sources, or
  `pg_proc` with `--db`) for `INSERT`/`UPDATE`/`DELETE`/`MERGE` targets, matches them against the
  tables that end up FORCEd, and lists them under "SECURITY DEFINER functions under FORCE"
  (`security_definer_writes` in JSON) with the fix for the configuration: raise the service escape
  inside the body and restore it on the way out (the compat form merges the role into the claims,
  so `auth.uid()` still names the caller), or, under the split model, hand the function to the
  `BYPASSRLS` role. `alter function ... set app.role` is not offered: a managed role gets `42501`
  setting a custom parameter on a function. Writes through `EXECUTE` are not seen.
- **`cmd/capyrls-wasm`, the converter for the browser.** A `js/wasm` build that registers
  `capyrlsConvert(sourcesJSON, optionsJSON)` with the CLI's option names and returns the files,
  the report and its Markdown. CI builds it and runs its tests under Node. `Source` and `OutFile`
  now carry `name`/`sql` JSON tags.
- **Live tests.** `CAPYRLS_TEST_DATABASE_URL` runs bundles against a real Postgres as a
  CapyDB-shaped role and checks the service path, confinement of other callers, restrictive
  policies and the definer fix; skipped when unset.

### Fixed

- **The service escape now passes restrictive policies.** It is a permissive policy, and
  restrictive policies are ANDed with everything, so a service context was still filtered by every
  restrictive policy - `service_role`'s `BYPASSRLS` never was. When the escape is emitted (either
  mode), it is ORed into each restrictive policy's `USING` and `WITH CHECK`.
- **`capyrls rewrite --role-model single` no longer says a roles file creates the Supabase roles.**
  That model emits no roles file; the warning now says the roles must exist, and that `convert`
  needs none.
- **The FORCE note no longer says there is no way to see every row.** The service escape is that
  way, when it is emitted.

## [1.14.0] - 2026-09-29

### Added

- **`--uid-type text` for identity providers whose subjects are not uuids.** The user-id accessor
  (`auth.uid()` in compat mode, `<prefix>.user_id()` in vanilla mode) returned `uuid` by casting
  the claim or GUC, so a Clerk-style `user_2abc...` subject made every policy calling it raise
  `22P02 invalid input syntax for type uuid`. With `--uid-type text` (`Options.UIDType = UIDText`)
  it returns the subject as `text`, uncast. `uuid` stays the default, and its output is unchanged.
  The report carries the choice (`uid_type` in JSON, "user id type" in Markdown) and the context
  contract types `<prefix>.user_id` as `text`.
- **The report names the uuid columns `--uid-type text` breaks.** Postgres has no implicit
  text-to-uuid conversion, so a policy comparing the text user id to a uuid column fails
  `CREATE POLICY` with `42883`, and a uuid column defaulted to it fails with `42804` - verified on
  postgres:18, loud at apply time and never silent. capyrls reads column types from
  `CREATE TABLE`/`ALTER TABLE` in the sources (and from `pg_attribute` with `--db`), flags each
  policy that compares the user id to a uuid column directly (including the
  `( SELECT auth.uid() AS uid)` form a live database renders), and emits one warning per column
  with the `alter column ... type text` fix. It deliberately does not cast the column side: that
  predicate cannot use the column's index, and a uuid column cannot hold a non-uuid subject, so the
  policy would silently match nothing. References through a table alias are not resolved, and
  `plpgsql` function bodies are only type-checked when called; the warning says so.

### Fixed

- **`capyrls version` and the report header print the real version.** `Version` had been `1.1.0`
  since the first release.

## [1.13.1] - 2026-09-24

### Fixed

- **Compat mode with the single role model no longer claims a service escape it never emits.** A
  `service_role`-only policy was reported as "already bypasses RLS" and the bundle defined
  `<prefix>.is_service` and documented `<prefix>.role = 'service'` as the escape, but compat mode
  emits no escape: that access was gone. The report now says no service path exists (as it already
  did with `--no-service-escape`), and the escape helper and its GUC note appear only when the
  escape is emitted (vanilla, single role model, no `--no-service-escape`).
- **README no longer calls compat mode zero-risk or promises the bundle runs on CapyDB as-is.**
  It now states the two limits of `--mode supabase-compat`: with the default split role model it
  recreates `anon`/`authenticated`/`service_role` with `CREATE ROLE`, which needs `CREATEROLE` that
  a managed database role (CapyDB's included) does not have; and it never emits the service
  escape, so under `--role-model single` nothing bypasses the policies. The role-model section
  notes what the split model needs to apply, and that the service escape is vanilla-only.

## [1.13.0] - 2026-09-11

### Added

- **The FORCE block now carries a foreign-key warning.** `FORCE ROW LEVEL SECURITY` is what makes
  the single-role model work, but Postgres applies row security to the scan that validates a
  **foreign key** while leaving runtime enforcement and `CHECK` validation alone — verified on
  17.11. So once a parent is FORCEd, `ADD CONSTRAINT ... FOREIGN KEY` and `VALIDATE CONSTRAINT`
  fail with `23503` naming rows that exist and are only invisible. Data is fine; existing keys hold
  and every write is still checked. It is the two DDL paths that stop — which means
  **`drizzle-kit push` adding a foreign key to an existing table hits it.**

  The emitted `capyrls_02_force_rls.sql` now explains that, and carries the recipe: drop `FORCE` on
  the **parent only**, for the length of the statement, in a `DO` block whose exception handler
  restores it. It also states the other consequence people misread as data loss — under FORCE the
  owner has no privileged view, so a `count(*)` is what the policies admit, not what the table
  holds, and there is no `service_role` to fall back on. A test pins the warning so it cannot vanish
  quietly.

## [1.12.0] - 2026-09-10

### Fixed

- **Vanilla mode no longer emits initplan sublinks on a table that carries a self-referencing
  policy.** Compat lost the wrap entirely in the change below; vanilla keeps it — it is a real
  per-row optimisation — but gives it up where it is unsafe. The check is **table-scoped, not
  policy-scoped**: Postgres rejects a policy that reaches table T if *any* policy on T carries a
  sublink, so cleaning only the self-referencing policy is not enough. Verified on postgres:17: an
  innocent sibling `SELECT` policy's initplan still produced `infinite recursion detected in policy`
  until every policy on the table was emitted sublink-free.

  The generated `capyrls_service_escape` policy is no longer wrapped either, for the same reason —
  it sits on the same tables. `is_service()` only reads a GUC, so the initplan bought almost nothing
  there and cost correctness for the whole table.

  End to end on postgres:17 with a non-superuser owner under `FORCE ROW LEVEL SECURITY`: a
  self-referencing `INSERT` that previously failed with `infinite recursion detected in policy` now
  succeeds, isolation still holds (a user sees only their own rows), and anon sees nothing.

### Added

- **Skipped `service_role`-only policies now leave a commented stub in the bundle.** They were listed
  in the report and nowhere else, so the access they granted simply vanished — on myroomiev3 that
  silently denied the compatibility-score cron's write path, found in production. The bundle now
  carries the original policy and a `system`-gated replacement, both commented out, so the operator
  deletes them deliberately instead of discovering the gap later.

### Fixed

- **`supabase-compat` no longer emits initplan sublinks, which broke self-referencing policies.**
  Both the role predicate (`(select auth.role()) = 'authenticated'`) and every rewritten auth call
  in a policy's own expression (`(select auth.uid())`) were wrapped as scalar subqueries. That sets
  the policy's `hasSubLinks` flag, and Postgres's static RLS recursion check then rejects any policy
  that reaches the same table through it — the common trigger being an `INSERT` whose `WITH CHECK`
  looks for a prior row, which fails with `infinite recursion detected in policy for relation ...`.

  Both sites now emit the plain call. Verified on postgres:17 with a non-superuser owner under
  `FORCE ROW LEVEL SECURITY`: wrapped fails, unwrapped inserts correctly and still denies anon.
  The initplan is a per-row-cost optimisation for expensive predicates; these read a GUC, so what it
  bought was negligible and what it cost was a whole class of working policy sets. A source policy
  that wants the initplan already spells it that way, and compat preserves that text verbatim.

  Vanilla mode still wraps (`(select app.user_id())`) and carries the same hazard for corpora with
  self-referencing policies — tracked separately; it rewrites policy text anyway, so the fidelity
  argument that settles compat does not apply there.

## [1.11.1] - 2026-09-09

### Changed

- **`supabase-compat` with the single role model no longer needs `CREATE ROLE`.** It previously kept
  `TO anon` / `TO authenticated` / `TO service_role` as literal role targets and emitted
  `create role ...` stubs plus membership grants. A managed-Postgres owning credential has neither
  `SUPERUSER` nor `CREATEROLE`, so that bundle could not be applied by the customer it was written
  for. Those targets now become predicates on `auth.role()`, the way the vanilla mode already
  handled them. The split role model is unchanged: it creates the roles itself, so keeping the
  vocabulary there is both possible and more faithful.

  This is also more accurate than what it replaced. Membership grants made the runtime role a member
  of both `anon` and `authenticated`, so an anon-only policy applied to authenticated sessions too;
  a predicate distinguishes them.

- **The compat presence predicate tests `auth.role()`, not `auth.uid()`.** `role` is what PostgREST
  actually switched on, and the shim defaults it to `anon` when no claims are set, so an absent
  token reads as anon exactly as it did on Supabase. It also avoids `auth.uid()`'s `::uuid` cast,
  which raises for providers whose subject is not a uuid (Clerk ids are `user_...`).

- A `service_role`-only policy dropped under `--role-model single --no-service-escape` now reports
  that no service path exists and the access is denied, instead of claiming the service path
  "already bypasses RLS" — true for the other configurations, false for that one.

## [1.2.0] - 2026-09-02

### Changed

- The Go module path is now `github.com/capydatabase/capyrls`. Update imports of the library package and the `live` subpackage, and install the CLI with `go install github.com/capydatabase/capyrls/cmd/capyrls@latest`. ([4836ec6](https://github.com/capydatabase/capyrls/commit/4836ec6))

## [1.1.0] - 2026-09-01

### Added

- Helper-linkage in the conversion report: policies that authorize via custom
  functions whose bodies read `auth.*` (e.g. `clerk_user_id()`) are annotated
  on their per-policy outcome, rolled up into a summary warning, and counted
  per routine in "Functions to review" - such policies convert cleanly while
  silently depending on an unconverted helper.

## [0.1.0] - 2026-08-03

### Added

- `capyrls convert` - builds a portable SQL bundle (context prelude, role
  setup, converted policies) from Supabase migration folders, schema dumps,
  stdin, or a live database (`--db`).
- `capyrls rewrite` - rewrites `auth.*` calls inside existing SQL files while
  keeping migration history byte-identical elsewhere.
- Vanilla convention output: `app.*` accessor functions over transaction-local
  GUCs, JWT claim promotion (`auth.jwt() ->> 'org_id'` → `app.org_id()`),
  claims-blob fallback for deep paths, `TO anon/authenticated` translated to
  presence predicates, `FOR ALL` split into per-command policies, initplan
  `(select ...)` wrapping.
- Supabase-compat output (`--mode supabase-compat`): `auth.*` shim over
  `request.jwt.claims`, policies ported verbatim, pseudo-roles recreated as
  membership roles.
- Role models: `split` (app_user/app_service, BYPASSRLS service path) and
  `single` (FORCE ROW LEVEL SECURITY + optional GUC-gated service escape).
- Conversion report (markdown + `--json`): the GUC contract the application
  must fulfil, promoted claims, per-policy outcomes, and everything that needs
  a human (`auth.users` references, Supabase-managed schemas, function bodies).
- Importable, dependency-free Go library (`capyrls` package) and `live`
  subpackage for `*sql.DB` introspection.

[Unreleased]: https://github.com/capydatabase/capyrls/compare/v1.16.0...HEAD
[1.16.0]: https://github.com/capydatabase/capyrls/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/capydatabase/capyrls/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/capydatabase/capyrls/compare/v1.13.1...v1.14.0
[1.13.1]: https://github.com/capydatabase/capyrls/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/capydatabase/capyrls/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/capydatabase/capyrls/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/capydatabase/capyrls/compare/v1.2.0...v1.11.1
[1.2.0]: https://github.com/capydatabase/capyrls/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/capydatabase/capyrls/compare/v0.1.0...v1.1.0
[0.1.0]: https://github.com/capydatabase/capyrls/releases/tag/v0.1.0
