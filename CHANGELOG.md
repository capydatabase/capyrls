# Changelog

All notable changes to capyrls are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
