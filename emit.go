package capyrls

import (
	"fmt"
	"strings"
)

// Schemas owned by the Supabase platform: policies on their tables have no
// meaning on vanilla Postgres and are reported, not converted.
var supabaseManagedSchemas = map[string]bool{
	"auth": true, "storage": true, "realtime": true, "_realtime": true,
	"vault": true, "graphql": true, "graphql_public": true, "extensions": true,
	"pgsodium": true, "pgsodium_masks": true, "supabase_functions": true,
	"supabase_migrations": true, "net": true, "cron": true, "_analytics": true,
	"pgbouncer": true,
}

// Roles that exist only inside a Supabase project.
var supabaseInternalRoles = map[string]bool{
	"postgres": true, "supabase_admin": true, "supabase_auth_admin": true,
	"supabase_storage_admin": true, "supabase_realtime_admin": true,
	"supabase_replication_admin": true, "supabase_read_only_user": true,
	"supabase_functions_admin": true, "dashboard_user": true,
	"authenticator": true, "pgbouncer": true,
}

// The Supabase pseudo-roles that carry authorization meaning in policies.
const (
	roleAnon    = "anon"
	roleAuthed  = "authenticated"
	roleService = "service_role"
)

type renderedPolicy struct {
	Name       string
	Table      QName
	Permissive bool
	Cmd        PolicyCmd
	Targets    []string
	Using      string
	WithCheck  string
}

type roleAnalysis struct {
	cond    string   // extra predicate ANDed into the policy expressions
	targets []string // TO list for the emitted policy; empty = PUBLIC
	skip    string   // non-empty: skip the policy for this reason
	// skippedServiceOnly marks the one skip reason that removes real access
	// rather than being covered elsewhere: a service_role-only policy under a
	// configuration with no service path. The caller emits a commented stub so
	// the operator has to delete it rather than discover the gap in production.
	skippedServiceOnly bool
	warnings           []string
	// compat mode: which Supabase pseudo-roles must exist as real roles
	needsRoles []string
}

func analyzeRoles(p *Policy, opts Options, rw *rewriter, selfRef bool) roleAnalysis {
	var res roleAnalysis
	var custom []string
	var dropped []string
	hasPublic := len(p.Roles) == 0
	hasAnon, hasAuthed, hasService := false, false, false

	for _, role := range p.Roles {
		switch {
		case role == "public":
			hasPublic = true
		case role == roleAnon:
			hasAnon = true
		case role == roleAuthed:
			hasAuthed = true
		case role == roleService:
			hasService = true
		case supabaseInternalRoles[role]:
			dropped = append(dropped, role)
		default:
			custom = append(custom, role)
		}
	}
	if len(dropped) > 0 {
		res.warnings = append(res.warnings, fmt.Sprintf(
			"policy %q on %s targeted Supabase-internal role(s) %s - dropped",
			p.Name, p.Table.Key(), strings.Join(dropped, ", ")))
	}

	// Compat + split keeps the Supabase role vocabulary as real NOLOGIN roles:
	// emitRolesSplit creates them and makes the runtime role a member. Under
	// the single-role model there is nobody to create them - a managed
	// instance's owning credential has neither SUPERUSER nor CREATEROLE - so
	// the role targets become predicates on auth.role(), exactly as vanilla
	// does. That is also the more faithful reading: membership grants make an
	// anon-only policy apply to authenticated sessions too, which a predicate
	// does not.
	if opts.Mode == ModeCompat && opts.RoleModel == RoleSplit {
		var targets []string
		if hasPublic {
			targets = nil
		} else {
			if hasAnon {
				targets = append(targets, roleAnon)
				res.needsRoles = append(res.needsRoles, roleAnon)
			}
			if hasAuthed {
				targets = append(targets, roleAuthed)
				res.needsRoles = append(res.needsRoles, roleAuthed)
			}
			if hasService {
				targets = append(targets, roleService)
				res.needsRoles = append(res.needsRoles, roleService)
			}
			targets = append(targets, custom...)
			if len(targets) == 0 {
				res.skip = "targets only Supabase-internal roles"
				return res
			}
		}
		res.targets = targets
		return res
	}

	// Vanilla: role names become predicates on the session context.
	if hasService && !hasPublic && !hasAnon && !hasAuthed && len(custom) == 0 {
		res.skip = "applies only to service_role; the service path (BYPASSRLS role or service escape) already bypasses RLS"
		if opts.RoleModel == RoleSingle && !emitsServiceEscape(opts) {
			// Skipping is still right - there is no role to target - but saying
			// "already bypasses RLS" would be false: this configuration has no
			// service path at all (--no-service-escape, or compat mode, which never
			// emits the escape), so the access is now denied rather than granted
			// elsewhere.
			res.skip = "applies only to service_role, and no service path exists (single role model without the service escape): the access it granted is now denied - re-grant it explicitly if something still needs it"
			res.skippedServiceOnly = true
		}
		return res
	}
	if len(dropped) > 0 && !hasPublic && !hasAnon && !hasAuthed && !hasService && len(custom) == 0 {
		res.skip = "targets only Supabase-internal roles"
		return res
	}

	switch {
	case hasPublic, hasAnon && hasAuthed:
		res.cond = ""
	case hasAuthed:
		res.cond = userPresenceCond(opts, rw, true, selfRef)
	case hasAnon:
		res.cond = userPresenceCond(opts, rw, false, selfRef)
	}

	if len(custom) > 0 {
		res.targets = custom
		if hasAnon || hasAuthed || hasPublic {
			if opts.RoleModel == RoleSplit {
				res.targets = append(res.targets, opts.AppRole)
			}
			res.cond = ""
			res.warnings = append(res.warnings, fmt.Sprintf(
				"policy %q on %s mixed Supabase pseudo-roles with custom role(s) %s - kept the custom roles and dropped the anon/authenticated distinction; review",
				p.Name, p.Table.Key(), strings.Join(custom, ", ")))
		}
		return res
	}

	if opts.RoleModel == RoleSplit {
		res.targets = []string{opts.AppRole}
	}
	return res
}

// expressionReferencesTable reports whether a policy expression names its own
// table. Lexed rather than pattern-matched so a table name inside a string
// literal does not count.
//
// Used to decide whether the initplan `(select ...)` wrap is safe: a sublink
// sets the policy's hasSubLinks flag, and Postgres's static RLS recursion check
// then rejects any policy that reaches the same table through it. When the
// policy touches its own table we give up the optimisation rather than the
// policy. False positives (a column that shares the table's name) cost only
// that optimisation, which is the safe direction to be wrong in.
func expressionReferencesTable(expr string, table QName) bool {
	if strings.TrimSpace(expr) == "" {
		return false
	}
	name := strings.ToLower(table.Name)
	for _, tok := range lexSQL(expr) {
		if tok.Kind == tIdent && tok.Val == name {
			return true
		}
	}
	return false
}

func userPresenceCond(opts Options, rw *rewriter, present, selfRef bool) string {
	// Compat mode tests auth.role(), not auth.uid(): role is what PostgREST
	// actually switched on, and the shim defaults it to 'anon' when no claims
	// are set, so an absent token reads as anon exactly as it did on Supabase.
	// It also avoids auth.uid()'s ::uuid cast, which raises for providers whose
	// subject is not a uuid (Clerk's `user_...` ids).
	// NOT wrapped in `(select ...)`. The initplan form is the usual RLS
	// performance trick, but it sets the policy's hasSubLinks flag, and
	// Postgres's static recursion check then rejects any policy that reaches
	// the same table through this one - e.g. an INSERT whose WITH CHECK looks
	// for a prior row, which is legitimate and common. Verified on postgres:17:
	// with the sublink the insert fails `infinite recursion detected in policy
	// for relation "messages"`; without it the same policy set works and still
	// denies anon. auth.role() only reads a GUC, so the per-row cost this gives
	// up is negligible - correctness wins.
	if opts.Mode == ModeCompat {
		rw.usedRole = true
		if present {
			return "auth.role() = '" + roleAuthed + "'"
		}
		return "auth.role() = '" + roleAnon + "'"
	}
	rw.usedUser = true
	call := "(select " + opts.Prefix + ".user_id())"
	if selfRef {
		// Same reasoning as the compat branch above: this policy reaches its
		// own table, so a sublink here would make Postgres reject it outright.
		call = opts.Prefix + ".user_id()"
	}
	if present {
		return call + " is not null"
	}
	return call + " is null"
}

func combineCond(cond, expr string) string {
	switch {
	case cond == "":
		return expr
	case expr == "":
		return cond
	default:
		return cond + " and (" + expr + ")"
	}
}

// splitAll expands a FOR ALL policy into per-command policies. The split is
// semantics-preserving: INSERT inherits the WITH CHECK (falling back to
// USING, exactly as FOR ALL does), UPDATE keeps both sides.
func splitAll(base renderedPolicy) []renderedPolicy {
	insertCheck := base.WithCheck
	if insertCheck == "" {
		insertCheck = base.Using
	}
	mk := func(suffix string, cmd PolicyCmd, using, check string) renderedPolicy {
		out := base
		out.Name = suffixName(base.Name, suffix)
		out.Cmd = cmd
		out.Using = using
		out.WithCheck = check
		return out
	}
	return []renderedPolicy{
		mk("_select", CmdSelect, base.Using, ""),
		mk("_insert", CmdInsert, "", insertCheck),
		mk("_update", CmdUpdate, base.Using, base.WithCheck),
		mk("_delete", CmdDelete, base.Using, ""),
	}
}

// suffixName appends a suffix while respecting Postgres's 63-byte identifier
// limit.
func suffixName(name, suffix string) string {
	const maxIdent = 63
	if len(name)+len(suffix) <= maxIdent {
		return name + suffix
	}
	return name[:maxIdent-len(suffix)] + suffix
}

func renderPolicySQL(p renderedPolicy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "drop policy if exists %s on %s;\n", QuoteIdent(p.Name), p.Table)
	fmt.Fprintf(&b, "create policy %s on %s", QuoteIdent(p.Name), p.Table)
	if !p.Permissive {
		b.WriteString("\n  as restrictive")
	}
	fmt.Fprintf(&b, "\n  for %s", strings.ToLower(string(p.Cmd)))
	if len(p.Targets) > 0 {
		quoted := make([]string, len(p.Targets))
		for i, role := range p.Targets {
			quoted[i] = QuoteIdent(role)
		}
		fmt.Fprintf(&b, "\n  to %s", strings.Join(quoted, ", "))
	}
	if p.Using != "" {
		fmt.Fprintf(&b, "\n  using (%s)", p.Using)
	}
	if p.WithCheck != "" {
		fmt.Fprintf(&b, "\n  with check (%s)", p.WithCheck)
	}
	b.WriteString(";\n")
	return b.String()
}

// renderOriginalPolicy reconstructs the source policy for comment blocks.
// renderSystemStub renders the policy a service_role-only policy would become
// if its access is still needed: same table and command, gated on the caller
// having stated a system context rather than on a bypass. Emitted commented
// out - it is a starting point for the operator, not a decision capyrls makes.
func renderSystemStub(p *Policy, opts Options) string {
	gate := "auth.jwt() ->> 'app_role' = 'system'"
	if opts.Mode != ModeCompat {
		gate = "(select " + opts.Prefix + ".role()) = 'service'"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "create policy %s on %s", QuoteIdent(p.Name+"_system"), p.Table)
	fmt.Fprintf(&b, " for %s", strings.ToLower(string(p.Cmd)))
	fmt.Fprintf(&b, " using (%s)", gate)
	if p.Cmd == CmdAll || p.Cmd == CmdInsert || p.Cmd == CmdUpdate {
		fmt.Fprintf(&b, " with check (%s)", gate)
	}
	b.WriteString(";")
	return b.String()
}

func renderOriginalPolicy(p *Policy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "create policy %s on %s", QuoteIdent(p.Name), p.Table)
	if !p.Permissive {
		b.WriteString(" as restrictive")
	}
	fmt.Fprintf(&b, " for %s", strings.ToLower(string(p.Cmd)))
	if len(p.Roles) > 0 {
		fmt.Fprintf(&b, " to %s", strings.Join(p.Roles, ", "))
	}
	if p.Using != "" {
		fmt.Fprintf(&b, " using (%s)", p.Using)
	}
	if p.WithCheck != "" {
		fmt.Fprintf(&b, " with check (%s)", p.WithCheck)
	}
	b.WriteString(";")
	return b.String()
}

func commentOut(sql string) string {
	lines := strings.Split(sql, "\n")
	for i, line := range lines {
		lines[i] = "-- " + line
	}
	return strings.Join(lines, "\n")
}

func fileHeader(purpose string) string {
	return fmt.Sprintf("-- Generated by capyrls v%s (https://github.com/capydatabase/capyrls)\n-- %s\n\n", Version, purpose)
}

func writeSQLFunction(b *strings.Builder, comment, name, returns, body string) {
	if comment != "" {
		for line := range strings.SplitSeq(comment, "\n") {
			fmt.Fprintf(b, "-- %s\n", line)
		}
	}
	fmt.Fprintf(b, "create or replace function %s()\nreturns %s\nlanguage sql stable parallel safe\nas $$\n  %s\n$$;\n\n", name, returns, body)
}

// emitPrelude renders the context schema + accessor functions.
func emitPrelude(opts Options, rw *rewriter) string {
	var b strings.Builder
	if opts.Mode == ModeCompat {
		b.WriteString(fileHeader("Supabase-compatible auth shim: auth.uid()/jwt()/role()/email() backed by the request.jwt.claims GUC."))
		b.WriteString(`-- Your application verifies the caller's JWT, then sets the claims for the
-- transaction (true = transaction-local, safe behind transaction pooling):
--
--   begin;
--   select set_config('request.jwt.claims', '{"sub":"<uuid>","role":"authenticated"}', true);
--   -- queries run under RLS here
--   commit;
--
-- Unset claims read as an empty object, so auth.uid() is NULL and policies
-- keyed on identity fail closed. auth.role() falls back to 'anon', which is
-- what TO anon policies were written against, so those still apply to a
-- caller with no token - exactly as on Supabase.

create schema if not exists auth;

`)
		writeSQLFunction(&b, "", "auth.jwt", "jsonb",
			"select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb")
		writeSQLFunction(&b, "", "auth.uid", "uuid",
			"select nullif(auth.jwt() ->> 'sub', '')::uuid")
		writeSQLFunction(&b, "", "auth.role", "text",
			"select coalesce(nullif(auth.jwt() ->> 'role', ''), 'anon')")
		writeSQLFunction(&b, "", "auth.email", "text",
			"select nullif(auth.jwt() ->> 'email', '')")
		return b.String()
	}

	p := opts.Prefix
	b.WriteString(fileHeader("Application auth context: accessor functions over transaction-local GUCs."))
	fmt.Fprintf(&b, `-- Your application authenticates the caller (verify the JWT / session at the
-- edge), then sets the resolved facts for the transaction (true =
-- transaction-local, i.e. SET LOCAL semantics - safe behind transaction
-- pooling, resets at commit/rollback):
--
--   begin;
--   select set_config('%s.user_id', '<uuid>', true);
--   -- queries run under RLS here
--   commit;
--
-- Unset context reads as NULL, so every policy fails closed.

create schema if not exists %s;

`, p, QuoteIdent(p))

	writeSQLFunction(&b, "The authenticated user (was auth.uid() / the JWT 'sub' claim).",
		p+".user_id", "uuid",
		fmt.Sprintf("select nullif(current_setting('%s.user_id', true), '')::uuid", p))

	if rw.usedRole || emitsServiceEscape(opts) {
		writeSQLFunction(&b, "The caller's access class (was auth.role()).",
			p+".role", "text",
			fmt.Sprintf("select nullif(current_setting('%s.role', true), '')", p))
	}
	if emitsServiceEscape(opts) {
		writeSQLFunction(&b, fmt.Sprintf("True when the app declared this transaction a service context (%s.role = 'service').", p),
			p+".is_service", "boolean",
			fmt.Sprintf("select coalesce(current_setting('%s.role', true) = 'service', false)", p))
	}
	if rw.usedMail {
		writeSQLFunction(&b, "The caller's email (was auth.email() / the JWT 'email' claim).",
			p+".email", "text",
			fmt.Sprintf("select nullif(current_setting('%s.email', true), '')", p))
	}
	if rw.usedBlob {
		writeSQLFunction(&b, "Full claims JSON, for expressions that read deep claim paths (was auth.jwt()).",
			p+".claims", "jsonb",
			fmt.Sprintf("select coalesce(nullif(current_setting('%s.claims', true), ''), '{}')::jsonb", p))
	}
	for _, claim := range rw.sortedClaims() {
		writeSQLFunction(&b, fmt.Sprintf("JWT claim %q promoted to a first-class context value.", claim.Claim),
			claim.Accessor[:len(claim.Accessor)-2], "text",
			fmt.Sprintf("select nullif(current_setting('%s', true), '')", claim.GUC))
	}
	return b.String()
}

// emitRolesSplit renders the runtime/service role setup for the role-split
// model.
func emitRolesSplit(opts Options, schemas []string, compatRoles []string) string {
	var b strings.Builder
	b.WriteString(fileHeader("Role separation: the runtime role never owns tables, so RLS actually applies."))
	appRole := opts.AppRole
	svcRole := opts.ServiceRole

	fmt.Fprintf(&b, `-- %s: the runtime connection role. It owns nothing and cannot bypass RLS.
-- %s: for trusted backend jobs (was service_role) - BYPASSRLS skips policies.
--
-- Table owners bypass row security unless the table is FORCEd, which is why
-- runtime traffic must not connect as the role that ran your migrations.
--
-- Both roles are created NOLOGIN. Either give the runtime role a password:
--   alter role %s login password '...';
-- or keep a single credential and switch on connect (e.g. a pool hook):
--   set role %s;

`, appRole, svcRole, appRole, appRole)

	for _, role := range []struct {
		name  string
		attrs string
	}{{appRole, "nologin nobypassrls"}, {svcRole, "nologin bypassrls"}} {
		fmt.Fprintf(&b, `do $$
begin
  if not exists (select from pg_catalog.pg_roles where rolname = '%s') then
    create role %s %s;
  end if;
end;
$$;

`, role.name, QuoteIdent(role.name), role.attrs)
	}

	grantees := QuoteIdent(appRole) + ", " + QuoteIdent(svcRole)
	if opts.Mode == ModeVanilla {
		fmt.Fprintf(&b, "grant usage on schema %s to %s;\n", QuoteIdent(opts.Prefix), grantees)
	} else {
		fmt.Fprintf(&b, "grant usage on schema auth to %s;\n", grantees)
	}
	for _, schema := range schemas {
		s := QuoteIdent(schema)
		fmt.Fprintf(&b, `grant usage on schema %s to %s;
grant select, insert, update, delete on all tables in schema %s to %s;
grant usage, select on all sequences in schema %s to %s;
alter default privileges in schema %s grant select, insert, update, delete on tables to %s;
alter default privileges in schema %s grant usage, select on sequences to %s;
`, s, grantees, s, grantees, s, grantees, s, grantees, s, grantees)
	}

	if len(compatRoles) > 0 {
		b.WriteString(`
-- Supabase's role vocabulary, kept so policies written with TO anon /
-- TO authenticated / TO service_role keep applying. The runtime role is a
-- member of anon and authenticated: anon-only policies therefore also apply
-- to authenticated sessions (they are usually public-read; review if not).
`)
		for _, role := range compatRoles {
			fmt.Fprintf(&b, `do $$
begin
  if not exists (select from pg_catalog.pg_roles where rolname = '%s') then
    create role %s nologin nobypassrls;
  end if;
end;
$$;
`, role, QuoteIdent(role))
			switch role {
			case roleAnon, roleAuthed:
				fmt.Fprintf(&b, "grant %s to %s;\n", QuoteIdent(role), QuoteIdent(appRole))
			case roleService:
				fmt.Fprintf(&b, "grant %s to %s;\n", QuoteIdent(role), QuoteIdent(svcRole))
			}
		}
	}
	return b.String()
}

// forceForeignKeyNote is emitted immediately after the FORCE block.
//
// FORCE has one consequence nobody expects, and it is not capyrls's doing - it
// is an asymmetry in Postgres itself. Verified on postgres:17.11:
//
//	runtime FK enforcement (INSERT/UPDATE)  bypasses RLS   - correct, documented
//	CHECK constraint validation             scans all rows - correct
//	FOREIGN KEY validation                  APPLIES RLS    - sees a filtered parent
//	SET row_security = off (as owner)       refused        - no escape
//
// So adding or validating a foreign key whose PARENT is FORCEd fails with
// 23503, naming rows that exist and are merely invisible. It is loud, never
// silent - but it will stop a routine migration dead, and `drizzle-kit push`
// adding a foreign key to an existing table is exactly that migration.
//
// The note goes in the emitted SQL rather than the README because this is read
// at the moment someone hits it.
const forceForeignKeyNote = `
-- ---------------------------------------------------------------------------
-- Adding a foreign key later? Read this first.
--
-- FORCE applies policies to the owner, and Postgres applies them to the scan
-- that validates a FOREIGN KEY too - but NOT to runtime enforcement, and NOT
-- to CHECK validation. So this fails once the parent is FORCEd:
--
--   alter table child add constraint c_fk foreign key (parent_id)
--     references parent(id);
--   -- ERROR: 23503 ... Key is not present in table "parent"
--
-- The key IS present. Your policy is hiding it from the scan. Existing keys
-- and every INSERT/UPDATE keep working - referential integrity is unaffected.
--
-- To add or validate one, drop FORCE on the PARENT only, for the length of the
-- statement. The window is owner-only and brief; the child stays FORCEd.
--
--   do $$
--   declare was_forced boolean;
--   begin
--     select relforcerowsecurity into was_forced
--       from pg_class where oid = 'public.parent'::regclass;
--     alter table public.parent no force row level security;
--     alter table public.child validate constraint c_fk;   -- or ADD CONSTRAINT
--     if was_forced then
--       alter table public.parent force row level security;
--     end if;
--   exception when others then
--     if was_forced then
--       alter table public.parent force row level security;
--     end if;
--     raise;
--   end $$;
--
-- One more consequence of FORCE, while you are here: as the owner you now have
-- NO privileged view of your own tables. A count is what your policies admit,
-- not what the table holds. There is no service_role to fall back on - that is
-- the point of the single-role model, not a gap in it.
-- ---------------------------------------------------------------------------

`

// emitSingleRole renders FORCE ROW LEVEL SECURITY (plus the optional service
// escape) for setups where the app connects as the table owner.
func emitSingleRole(opts Options, tables []QName, compatRoles []string) string {
	var b strings.Builder
	b.WriteString(fileHeader("Single-role model: the app connects as the table owner, so RLS must be FORCEd."))
	b.WriteString(`-- Owners bypass row security by default. FORCE makes policies apply to the
-- owner too, which is what you want when one credential serves all traffic
-- (the common managed-Postgres setup).

`)
	for _, t := range tables {
		fmt.Fprintf(&b, "alter table %s force row level security;\n", t)
	}
	b.WriteString(forceForeignKeyNote)
	if !opts.NoServiceEscape && opts.Mode == ModeVanilla {
		p := opts.Prefix
		fmt.Fprintf(&b, `
-- Service escape hatch: a transaction that sets %s.role = 'service' skips the
-- row filters (seeds, backfills, admin jobs). The connecting role owns these
-- tables and could ALTER ... DISABLE ROW LEVEL SECURITY anyway, so this adds
-- convenience, not new exposure. Remove it if you split roles later.
`, p)
		for _, t := range tables {
			// NOT wrapped in `(select ...)`. This policy sits on the same table as
			// the app's own, and a sublink in ANY policy on a table is enough for
			// Postgres's static recursion check to reject a sibling policy that
			// reaches that table - verified on postgres:17, where adding this
			// escape turned a working insert into "infinite recursion detected in
			// policy". is_service() only reads a GUC, so the initplan bought
			// almost nothing and cost correctness for the whole table.
			fmt.Fprintf(&b, `drop policy if exists capyrls_service_escape on %s;
create policy capyrls_service_escape on %s
  for all
  using (%s.is_service())
  with check (%s.is_service());
`, t, t, p, p)
		}
	}
	if len(compatRoles) > 0 {
		b.WriteString(`
-- Supabase's role vocabulary. Your connecting role becomes a member of anon
-- and authenticated so those policies keep applying; grant service_role to a
-- dedicated admin credential if you use one.
`)
		for _, role := range compatRoles {
			fmt.Fprintf(&b, `do $$
begin
  if not exists (select from pg_catalog.pg_roles where rolname = '%s') then
    create role %s nologin nobypassrls;
  end if;
end;
$$;
`, role, QuoteIdent(role))
			if role == roleAnon || role == roleAuthed {
				fmt.Fprintf(&b, "grant %s to current_user;\n", QuoteIdent(role))
			}
		}
	}
	return b.String()
}
