# Changelog

All notable changes to capyrls are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [Unreleased]

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

[Unreleased]: https://github.com/capy-base/capyrls/compare/v1.12.0...HEAD
[1.12.0]: https://github.com/capy-base/capyrls/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/capy-base/capyrls/compare/v1.2.0...v1.11.1
[1.2.0]: https://github.com/capy-base/capyrls/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/capy-base/capyrls/compare/v0.1.0...v1.1.0
[0.1.0]: https://github.com/capy-base/capyrls/releases/tag/v0.1.0
