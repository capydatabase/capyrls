// Package capyrls converts Supabase row-level-security policies to portable,
// vanilla PostgreSQL.
//
// Supabase RLS is standard CREATE POLICY plus a platform-provided context:
// auth.uid()/auth.jwt()/auth.role(), the anon/authenticated/service_role
// pseudo-roles, and PostgREST injecting a verified JWT into a session GUC.
// None of that exists on plain Postgres. capyrls re-homes the policies onto
// one of two conventions:
//
//   - vanilla (default): a small app.* schema of accessor functions over
//     transaction-local GUCs (app.user_id, app.role, promoted claims). The
//     database stops knowing JWTs exist; the app sets typed facts per
//     transaction. Policies are rewritten to the new accessors.
//   - supabase-compat: an auth.* shim backed by the request.jwt.claims GUC.
//     Policies port verbatim; useful for a zero-risk lift-and-shift.
//
// Input is either SQL sources (Supabase migration folders, pg_dump
// --schema-only) or a live database via the live subpackage. Output is a SQL
// bundle plus a report describing the context contract the application must
// now fulfil.
package capyrls

import (
	"fmt"
	"sort"
	"strings"
)

// Version is the capyrls release version.
const Version = "1.1.0"

// Mode selects the output convention.
type Mode int

const (
	// ModeVanilla rewrites policies onto app.* accessor functions over
	// transaction-local GUCs - the portable, vendor-neutral convention.
	ModeVanilla Mode = iota
	// ModeCompat keeps auth.* calls and emits a shim schema providing them.
	ModeCompat
)

func (m Mode) String() string {
	if m == ModeCompat {
		return "supabase-compat"
	}
	return "vanilla"
}

// RoleModel describes how the converted database separates privileges.
type RoleModel int

const (
	// RoleSplit creates a non-owning runtime role (RLS applies) and a
	// BYPASSRLS service role - the classic three-role convention.
	RoleSplit RoleModel = iota
	// RoleSingle assumes the app connects as the table owner (the common
	// managed-Postgres setup) and FORCEs row security instead.
	RoleSingle
)

func (r RoleModel) String() string {
	if r == RoleSingle {
		return "single"
	}
	return "split"
}

// Options control a conversion. The zero value is the recommended setup:
// vanilla mode, role-split model, FOR ALL policies split per command, service
// escape enabled for the single-role model.
type Options struct {
	Mode      Mode
	RoleModel RoleModel
	// NoSplitAll keeps FOR ALL policies intact instead of splitting them
	// into per-command policies.
	NoSplitAll bool
	// NoServiceEscape suppresses the GUC-gated bypass policies emitted for
	// the single-role model.
	NoServiceEscape bool
	// Prefix is the schema and GUC namespace, default "app".
	Prefix string
	// AppRole and ServiceRole name the roles for the role-split model.
	AppRole     string
	ServiceRole string
}

func (o Options) withDefaults() Options {
	if o.Prefix == "" {
		o.Prefix = "app"
	}
	if o.AppRole == "" {
		o.AppRole = "app_user"
	}
	if o.ServiceRole == "" {
		o.ServiceRole = "app_service"
	}
	return o
}

// Source is one SQL input (a file, a dump, stdin).
type Source struct {
	Name string
	SQL  string
}

// OutFile is one produced file.
type OutFile struct {
	Name string
	SQL  string
}

// Result is a finished conversion.
type Result struct {
	Files  []OutFile
	Report Report
}

// Convert parses SQL sources and converts the final policy state into a
// fresh, ordered SQL bundle (prelude, roles, policies) plus a report.
func Convert(sources []Source, opts Options) (*Result, error) {
	cat, err := ParseSQL(sources)
	if err != nil {
		return nil, err
	}
	return ConvertCatalog(cat, opts)
}

// ConvertCatalog converts an already-built catalog (see ParseSQL and the
// live subpackage).
func ConvertCatalog(cat *Catalog, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	dialect := dialectVanilla
	if opts.Mode == ModeCompat {
		dialect = dialectCompat
	}
	rw := newRewriter(dialect, opts.Prefix)
	rep := Report{
		Tool: "capyrls", Version: Version,
		Mode: opts.Mode.String(), RoleModel: opts.RoleModel.String(),
		Notes: append([]string{}, cat.Notes...),
	}

	policies := append([]*Policy{}, cat.Policies...)
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Table.Key() != policies[j].Table.Key() {
			return policies[i].Table.Key() < policies[j].Table.Key()
		}
		return policies[i].Name < policies[j].Name
	})

	var policySQL strings.Builder
	var blockedSQL strings.Builder
	compatRoles := map[string]bool{}
	rlsTables := map[string]QName{}

	// Routines flagged for review, indexed for helper linkage: apps define
	// custom helpers (e.g. clerk_user_id()) whose bodies read auth.*, then
	// call them from policies - the policy text converts cleanly while
	// silently depending on the unconverted helper.
	reviewedRoutines := map[string]bool{}
	reviewedByName := map[string][]string{}
	for _, routine := range cat.Routines {
		if supabaseManagedSchemas[routine.Name.EffectiveSchema()] {
			continue
		}
		key := routine.Name.Key()
		if reviewedRoutines[key] {
			continue
		}
		reviewedRoutines[key] = true
		reviewedByName[routine.Name.Name] = append(reviewedByName[routine.Name.Name], key)
	}
	routineRefs := map[string]int{}
	linkedPolicies := 0

	for _, t := range cat.sortedTables() {
		if t.RLSEnabled && !supabaseManagedSchemas[t.Name.EffectiveSchema()] {
			rlsTables[t.Name.Key()] = t.Name
		}
	}

	for _, p := range policies {
		schema := p.Table.EffectiveSchema()
		if supabaseManagedSchemas[schema] {
			rep.Policies = append(rep.Policies, PolicyOutcome{
				Policy: p.Name, Table: p.Table.Key(), Status: "skipped",
				Detail: fmt.Sprintf("policies on the Supabase-managed %s schema have no equivalent outside Supabase (%s)", schema, p.Origin),
			})
			continue
		}

		analysis := analyzeRoles(p, opts, rw)
		rep.Warnings = append(rep.Warnings, analysis.warnings...)
		for _, role := range analysis.needsRoles {
			compatRoles[role] = true
		}
		if analysis.skip != "" {
			rep.Policies = append(rep.Policies, PolicyOutcome{
				Policy: p.Name, Table: p.Table.Key(), Status: "skipped", Detail: analysis.skip,
			})
			continue
		}

		usingOutcome := rw.rewriteExpr(p.Using, true)
		checkOutcome := rw.rewriteExpr(p.WithCheck, true)
		blockers := append(usingOutcome.Blockers, checkOutcome.Blockers...)
		if len(blockers) > 0 {
			detail := strings.Join(dedupe(blockers), "; ")
			rep.Policies = append(rep.Policies, PolicyOutcome{
				Policy: p.Name, Table: p.Table.Key(), Status: "blocked", Detail: detail,
			})
			fmt.Fprintf(&blockedSQL, "-- NEEDS ATTENTION: policy %s on %s %s.\n", QuoteIdent(p.Name), p.Table, detail)
			blockedSQL.WriteString(commentOut(renderOriginalPolicy(p)))
			blockedSQL.WriteString("\n\n")
			continue
		}

		using, check := usingOutcome.SQL, checkOutcome.SQL
		if analysis.cond != "" {
			if p.Cmd != CmdInsert {
				using = combineCond(analysis.cond, using)
			}
			if p.Cmd == CmdInsert || check != "" {
				check = combineCond(analysis.cond, check)
			}
		}

		base := renderedPolicy{
			Name: p.Name, Table: p.Table, Permissive: p.Permissive,
			Cmd: p.Cmd, Targets: analysis.targets, Using: using, WithCheck: check,
		}
		rendered := []renderedPolicy{base}
		detail := ""
		if p.Cmd == CmdAll && !opts.NoSplitAll && opts.Mode == ModeVanilla {
			rendered = splitAll(base)
			detail = "FOR ALL split into per-command policies"
		}
		helpers := dedupe(append(
			exprRoutineCalls(p.Using, reviewedRoutines, reviewedByName),
			exprRoutineCalls(p.WithCheck, reviewedRoutines, reviewedByName)...))
		if len(helpers) > 0 {
			sort.Strings(helpers)
			for _, key := range helpers {
				routineRefs[key]++
			}
			linkedPolicies++
			note := fmt.Sprintf("authorizes via helper %s whose body reads auth.* - convert the function body too (see Functions to review)", helperCallList(helpers))
			if opts.Mode == ModeCompat {
				note = fmt.Sprintf("authorizes via helper %s - covered by the auth.* compat shim (see Functions to review)", helperCallList(helpers))
			}
			if detail != "" {
				detail += "; " + note
			} else {
				detail = note
			}
		}
		for _, rp := range rendered {
			policySQL.WriteString(renderPolicySQL(rp))
			policySQL.WriteString("\n")
		}
		rep.Policies = append(rep.Policies, PolicyOutcome{
			Policy: p.Name, Table: p.Table.Key(), Status: "converted", Detail: detail,
		})
		if _, ok := rlsTables[p.Table.Key()]; !ok {
			rlsTables[p.Table.Key()] = p.Table
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"table %s has policies but no ENABLE ROW LEVEL SECURITY was seen in the sources; the bundle enables it", p.Table.Key()))
		}
	}
	sortOutcomes(rep.Policies)

	if linkedPolicies > 0 {
		converted, _, _ := rep.counts()
		linked := make([]string, 0, len(routineRefs))
		for key := range routineRefs {
			linked = append(linked, key)
		}
		sort.Strings(linked)
		if opts.Mode == ModeCompat {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"%d of %d converted policies authorize via helper functions whose bodies read auth.* (%s) - the emitted auth.* shim keeps helper calls working, but bodies touching auth tables still need porting",
				linkedPolicies, converted, strings.Join(linked, ", ")))
		} else {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"%d of %d converted policies authorize via helper functions whose bodies read auth.* (%s) - the SQL bundle rewrites policies, not function bodies; the conversion is incomplete until those functions are ported",
				linkedPolicies, converted, strings.Join(linked, ", ")))
		}
	}

	// Column defaults referencing auth.* become explicit ALTERs.
	var defaultsSQL strings.Builder
	for _, d := range cat.Defaults {
		if supabaseManagedSchemas[d.Table.EffectiveSchema()] {
			continue
		}
		outcome := rw.rewriteExpr(d.Expr, false)
		if len(outcome.Blockers) > 0 {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"column default %s.%s %s - review manually (%s)", d.Table.Key(), d.Column, strings.Join(dedupe(outcome.Blockers), "; "), d.Origin))
			continue
		}
		fmt.Fprintf(&defaultsSQL, "alter table %s alter column %s set default %s;\n",
			d.Table, QuoteIdent(d.Column), outcome.SQL)
		rep.Defaults = append(rep.Defaults, fmt.Sprintf(
			"`%s.%s` default rewritten: `%s` -> `%s`", d.Table.Key(), d.Column, d.Expr, outcome.SQL))
	}

	for _, routine := range cat.Routines {
		entry := fmt.Sprintf("`%s` (%s)", routine.Name.Key(), routine.Origin)
		if n := routineRefs[routine.Name.Key()]; n == 1 {
			entry += " (referenced by 1 policy)"
		} else if n > 1 {
			entry += fmt.Sprintf(" (referenced by %d policies)", n)
		}
		rep.Routines = append(rep.Routines, entry)
	}

	// Assemble the bundle.
	tables := make([]QName, 0, len(rlsTables))
	for _, q := range rlsTables {
		tables = append(tables, q)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Key() < tables[j].Key() })

	schemaSet := map[string]bool{}
	for _, t := range tables {
		schemaSet[t.EffectiveSchema()] = true
	}
	if len(schemaSet) == 0 {
		schemaSet["public"] = true
	}
	schemas := make([]string, 0, len(schemaSet))
	for s := range schemaSet {
		schemas = append(schemas, s)
	}
	sort.Strings(schemas)

	sortedCompatRoles := make([]string, 0, len(compatRoles))
	for role := range compatRoles {
		sortedCompatRoles = append(sortedCompatRoles, role)
	}
	sort.Strings(sortedCompatRoles)

	var files []OutFile
	files = append(files, OutFile{Name: "capyrls_01_prelude.sql", SQL: emitPrelude(opts, rw)})
	if opts.RoleModel == RoleSplit {
		files = append(files, OutFile{Name: "capyrls_02_roles.sql", SQL: emitRolesSplit(opts, schemas, sortedCompatRoles)})
	} else {
		files = append(files, OutFile{Name: "capyrls_02_force_rls.sql", SQL: emitSingleRole(opts, tables, sortedCompatRoles)})
	}

	var body strings.Builder
	body.WriteString(fileHeader("Row-security policies, converted."))
	for _, t := range tables {
		fmt.Fprintf(&body, "alter table %s enable row level security;\n", t)
	}
	body.WriteString("\n")
	body.WriteString(policySQL.String())
	if blockedSQL.Len() > 0 {
		body.WriteString("-- ----------------------------------------------------------------------\n")
		body.WriteString("-- Policies that need manual attention (see the report)\n")
		body.WriteString("-- ----------------------------------------------------------------------\n\n")
		body.WriteString(blockedSQL.String())
	}
	if defaultsSQL.Len() > 0 {
		body.WriteString("-- Column defaults that referenced auth.*\n")
		body.WriteString(defaultsSQL.String())
	}
	files = append(files, OutFile{Name: "capyrls_03_policies.sql", SQL: body.String()})

	rep.Claims = rw.sortedClaims()
	rep.GUCs = buildGUCContract(opts, rw)
	rep.Warnings = append(rep.Warnings, rw.warnings...)
	rep.Warnings = dedupe(rep.Warnings)
	if rep.Defaults == nil {
		rep.Defaults = []string{}
	}
	if rep.Routines == nil {
		rep.Routines = []string{}
	}
	if rep.Policies == nil {
		rep.Policies = []PolicyOutcome{}
	}
	if rep.Claims == nil {
		rep.Claims = []ClaimMapping{}
	}
	if rep.Warnings == nil {
		rep.Warnings = []string{}
	}
	if rep.Notes == nil {
		rep.Notes = []string{}
	}

	return &Result{Files: files, Report: rep}, nil
}

// Rewrite transforms SQL sources in place: auth.* helper calls are rewritten
// to the target convention while everything else stays byte-identical. Use it
// to keep an existing migration history instead of adopting a fresh bundle.
// The returned files mirror the inputs, plus the prelude and report.
func Rewrite(sources []Source, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	cat, err := ParseSQL(sources)
	if err != nil {
		return nil, err
	}
	dialect := dialectVanilla
	if opts.Mode == ModeCompat {
		dialect = dialectCompat
	}
	rw := newRewriter(dialect, opts.Prefix)
	rep := Report{
		Tool: "capyrls", Version: Version,
		Mode: opts.Mode.String(), RoleModel: opts.RoleModel.String(),
		Notes: append([]string{}, cat.Notes...),
	}

	var files []OutFile
	for _, src := range sources {
		rewritten, blockers := rw.rewriteSQLFile(src.SQL)
		for _, blocker := range dedupe(blockers) {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: %s - review manually", src.Name, blocker))
		}
		files = append(files, OutFile{Name: src.Name, SQL: rewritten})
	}

	// Policies keep their TO clauses in rewrite mode; surface which roles
	// must exist and ship stubs for them.
	compatRoles := map[string]bool{}
	for _, p := range cat.Policies {
		for _, role := range p.Roles {
			switch role {
			case roleAnon, roleAuthed, roleService:
				compatRoles[role] = true
			}
		}
		rep.Policies = append(rep.Policies, PolicyOutcome{
			Policy: p.Name, Table: p.Table.Key(), Status: "converted",
			Detail: "expressions rewritten in place; TO clause kept as written",
		})
	}
	sortOutcomes(rep.Policies)
	sortedCompatRoles := make([]string, 0, len(compatRoles))
	for role := range compatRoles {
		sortedCompatRoles = append(sortedCompatRoles, role)
	}
	sort.Strings(sortedCompatRoles)
	if len(sortedCompatRoles) > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"policies reference the Supabase role(s) %s in TO clauses; capyrls_02_roles.sql creates them as membership roles",
			strings.Join(sortedCompatRoles, ", ")))
	}

	files = append(files, OutFile{Name: "capyrls_01_prelude.sql", SQL: emitPrelude(opts, rw)})
	if opts.RoleModel == RoleSplit {
		files = append(files, OutFile{Name: "capyrls_02_roles.sql", SQL: emitRolesSplit(opts, []string{"public"}, sortedCompatRoles)})
	}

	for _, routine := range cat.Routines {
		rep.Routines = append(rep.Routines, fmt.Sprintf("`%s` (%s)", routine.Name.Key(), routine.Origin))
	}
	rep.Claims = rw.sortedClaims()
	rep.GUCs = buildGUCContract(opts, rw)
	rep.Warnings = dedupe(append(rep.Warnings, rw.warnings...))
	if rep.Policies == nil {
		rep.Policies = []PolicyOutcome{}
	}
	if rep.Defaults == nil {
		rep.Defaults = []string{}
	}
	if rep.Routines == nil {
		rep.Routines = []string{}
	}
	if rep.Claims == nil {
		rep.Claims = []ClaimMapping{}
	}
	if rep.Notes == nil {
		rep.Notes = []string{}
	}

	return &Result{Files: files, Report: rep}, nil
}

func buildGUCContract(opts Options, rw *rewriter) []GUCSpec {
	if opts.Mode == ModeCompat {
		return []GUCSpec{{
			Name: "request.jwt.claims", Type: "json (text GUC)",
			Description: "the verified JWT claims; must include `sub` (and `role`/`email` where policies use them)",
		}}
	}
	p := opts.Prefix
	gucs := []GUCSpec{{
		Name: p + ".user_id", Type: "uuid (text GUC)",
		Description: "the authenticated user's id (was `auth.uid()`)",
	}}
	if rw.usedRole || opts.RoleModel == RoleSingle && !opts.NoServiceEscape {
		desc := "the caller's access class (was `auth.role()`)"
		if opts.RoleModel == RoleSingle && !opts.NoServiceEscape {
			desc += "; `service` activates the service escape"
		}
		gucs = append(gucs, GUCSpec{Name: p + ".role", Type: "text", Description: desc})
	}
	if rw.usedMail {
		gucs = append(gucs, GUCSpec{Name: p + ".email", Type: "text", Description: "the caller's email (was `auth.email()`)"})
	}
	for _, claim := range rw.sortedClaims() {
		gucs = append(gucs, GUCSpec{Name: claim.GUC, Type: "text", Description: fmt.Sprintf("JWT claim `%s`", claim.Claim)})
	}
	if rw.usedBlob {
		gucs = append(gucs, GUCSpec{Name: p + ".claims", Type: "json (text GUC)", Description: "full claims JSON, for deep claim paths the converter could not promote"})
	}
	return gucs
}

// helperCallList renders routine keys as call sites: "public.a(), public.b()".
func helperCallList(keys []string) string {
	calls := make([]string, len(keys))
	for i, key := range keys {
		calls[i] = key + "()"
	}
	return strings.Join(calls, ", ")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
