# Changelog

All notable changes to capyrls are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/capy-base/capyrls/compare/v1.11.1...HEAD
[1.11.1]: https://github.com/capy-base/capyrls/compare/v1.2.0...v1.11.1
[1.2.0]: https://github.com/capy-base/capyrls/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/capy-base/capyrls/compare/v0.1.0...v1.1.0
[0.1.0]: https://github.com/capy-base/capyrls/releases/tag/v0.1.0
