package capyrls

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fixture is a realistic slice of a Supabase project: migration history with
// drops and alters, every auth helper, pseudo-roles, a service_role-only
// policy, an auth.users reference, and a storage policy.
var fixture = []Source{
	{Name: "0001_init.sql", SQL: `
create table public.profiles (
  id uuid primary key default auth.uid(),
  org_id uuid,
  email text
);
create table public.todos (
  id bigint generated always as identity primary key,
  owner_id uuid not null default auth.uid(),
  title text,
  archived boolean not null default false
);
alter table public.profiles enable row level security;
alter table public.todos enable row level security;

create policy "profiles_owner_select" on public.profiles
  for select to authenticated using (auth.uid() = id);

create policy todos_all on public.todos
  for all to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create policy "public read" on public.todos
  for select to anon using (true);

create policy org_read on public.profiles
  for select to authenticated
  using (org_id::text = auth.jwt() ->> 'org_id');

create policy admin_all on public.todos
  for all to service_role using (true);

create policy tier_gate on public.profiles
  for select to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'tier') = 'pro');

create policy has_account on public.profiles
  for select
  using (exists (select 1 from auth.users u where u.id = auth.uid()));

create policy storage_read on storage.objects
  for select using (true);
`},
	{Name: "0002_change.sql", SQL: `
drop policy "public read" on public.todos;
alter policy todos_all on public.todos
  using (auth.uid() = owner_id and not archived);
`},
}

func findFile(t *testing.T, res *Result, name string) string {
	t.Helper()
	for _, f := range res.Files {
		if f.Name == name {
			return f.SQL
		}
	}
	t.Fatalf("file %s not in result (have %v)", name, fileNames(res))
	return ""
}

func fileNames(res *Result) []string {
	var names []string
	for _, f := range res.Files {
		names = append(names, f.Name)
	}
	return names
}

func outcomeFor(t *testing.T, rep Report, policy string) PolicyOutcome {
	t.Helper()
	for _, o := range rep.Policies {
		if o.Policy == policy {
			return o
		}
	}
	t.Fatalf("no outcome for policy %q", policy)
	return PolicyOutcome{}
}

func TestConvertVanillaSplitRoles(t *testing.T) {
	res, err := Convert(fixture, Options{})
	if err != nil {
		t.Fatal(err)
	}

	prelude := findFile(t, res, "capyrls_01_prelude.sql")
	for _, want := range []string{
		"create schema if not exists app;",
		"app.user_id()",
		"'app.user_id'",
		"app.org_id()", // promoted claim
		"app.claims()", // deep-path fallback
	} {
		if !strings.Contains(prelude, want) {
			t.Errorf("prelude missing %q", want)
		}
	}
	if strings.Contains(prelude, "app.email()") {
		t.Error("prelude should not emit unused accessors (email was never referenced)")
	}

	roles := findFile(t, res, "capyrls_02_roles.sql")
	for _, want := range []string{
		"create role app_user nologin nobypassrls;",
		"create role app_service nologin bypassrls;",
		"grant usage on schema app to app_user, app_service;",
		"alter default privileges in schema public",
	} {
		if !strings.Contains(roles, want) {
			t.Errorf("roles file missing %q", want)
		}
	}

	policies := findFile(t, res, "capyrls_03_policies.sql")
	for _, want := range []string{
		"alter table public.profiles enable row level security;",
		"alter table public.todos enable row level security;",
		// TO authenticated became runtime role + presence predicate.
		"to app_user",
		"(select app.user_id()) is not null and ((select app.user_id()) = id)",
		// FOR ALL split into per-command policies, with the ALTERed USING.
		"create policy todos_all_select on public.todos",
		"create policy todos_all_insert on public.todos",
		"create policy todos_all_update on public.todos",
		"create policy todos_all_delete on public.todos",
		"not archived",
		// Promoted claim in use.
		"org_id::text = (select app.org_id())",
		// auth.users policy commented out, not silently dropped.
		"-- NEEDS ATTENTION: policy has_account",
		// Column defaults rewritten without subqueries.
		"alter table public.profiles alter column id set default app.user_id();",
		"alter table public.todos alter column owner_id set default app.user_id();",
	} {
		if !strings.Contains(policies, want) {
			t.Errorf("policies file missing %q", want)
		}
	}
	for _, banned := range []string{
		"auth.uid()", "to authenticated", "to anon",
		`create policy "public read"`, // dropped in migration 0002
		"storage.objects",
	} {
		// The commented-out has_account block legitimately contains auth
		// references; strip comment lines before checking.
		var live []string
		for line := range strings.SplitSeq(policies, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				live = append(live, line)
			}
		}
		if strings.Contains(strings.Join(live, "\n"), banned) {
			t.Errorf("policies file still contains %q outside comments", banned)
		}
	}

	rep := res.Report
	if got := outcomeFor(t, rep, "admin_all").Status; got != "skipped" {
		t.Errorf("service_role-only policy should be skipped, got %s", got)
	}
	if got := outcomeFor(t, rep, "storage_read").Status; got != "skipped" {
		t.Errorf("storage policy should be skipped, got %s", got)
	}
	if got := outcomeFor(t, rep, "has_account").Status; got != "blocked" {
		t.Errorf("auth.users policy should be blocked, got %s", got)
	}
	if got := outcomeFor(t, rep, "todos_all").Status; got != "converted" {
		t.Errorf("todos_all should convert, got %s", got)
	}

	var gucNames []string
	for _, g := range rep.GUCs {
		gucNames = append(gucNames, g.Name)
	}
	for _, want := range []string{"app.user_id", "app.org_id", "app.claims"} {
		if !strings.Contains(strings.Join(gucNames, ","), want) {
			t.Errorf("GUC contract missing %s (have %v)", want, gucNames)
		}
	}
	if len(rep.Claims) != 1 || rep.Claims[0].Claim != "org_id" {
		t.Errorf("claims mapping wrong: %+v", rep.Claims)
	}
}

func TestConvertSingleRoleServiceEscape(t *testing.T) {
	res, err := Convert(fixture, Options{RoleModel: RoleSingle})
	if err != nil {
		t.Fatal(err)
	}
	force := findFile(t, res, "capyrls_02_force_rls.sql")
	for _, want := range []string{
		"alter table public.profiles force row level security;",
		"alter table public.todos force row level security;",
		"create policy capyrls_service_escape on public.todos",
		// Unwrapped: a sublink in ANY policy on a table makes Postgres reject a
		// sibling policy that reaches that table.
		"using (app.is_service())",
	} {
		if !strings.Contains(force, want) {
			t.Errorf("force file missing %q", want)
		}
	}
	policies := findFile(t, res, "capyrls_03_policies.sql")
	if strings.Contains(policies, "to app_user") {
		t.Error("single-role model must not target app_user")
	}

	// Escape hatch off on request.
	res2, err := Convert(fixture, Options{RoleModel: RoleSingle, NoServiceEscape: true})
	if err != nil {
		t.Fatal(err)
	}
	force2 := findFile(t, res2, "capyrls_02_force_rls.sql")
	if strings.Contains(force2, "capyrls_service_escape") {
		t.Error("NoServiceEscape must suppress the escape policies")
	}
}

func TestConvertCompatMode(t *testing.T) {
	res, err := Convert(fixture, Options{Mode: ModeCompat})
	if err != nil {
		t.Fatal(err)
	}
	prelude := findFile(t, res, "capyrls_01_prelude.sql")
	for _, want := range []string{
		"create schema if not exists auth;",
		"auth.jwt",
		"request.jwt.claims",
	} {
		if !strings.Contains(prelude, want) {
			t.Errorf("compat prelude missing %q", want)
		}
	}
	policies := findFile(t, res, "capyrls_03_policies.sql")
	for _, want := range []string{
		// Verbatim and unwrapped - see TestRewriteCompatKeepsAuthCallsVerbatim.
		"auth.uid() = id",
		"to authenticated",
		"to service_role",
	} {
		if !strings.Contains(policies, want) {
			t.Errorf("compat policies missing %q", want)
		}
	}
	// The anon-only policy was dropped by migration 0002, so only
	// authenticated and service_role survive into the role stubs.
	roles := findFile(t, res, "capyrls_02_roles.sql")
	for _, want := range []string{
		"create role authenticated",
		"grant authenticated to app_user;",
		"grant service_role to app_service;",
	} {
		if !strings.Contains(roles, want) {
			t.Errorf("compat roles missing %q", want)
		}
	}
	if strings.Contains(roles, "create role anon") {
		t.Error("anon role stub should not be emitted; its only policy was dropped in history")
	}
	if res.Report.GUCs[0].Name != "request.jwt.claims" {
		t.Errorf("compat GUC contract should be request.jwt.claims, got %+v", res.Report.GUCs)
	}
}

// Compat + single role is the managed-Postgres shape: the app connects as the
// owning credential, which on a managed instance has neither SUPERUSER nor
// CREATEROLE. The bundle must therefore create no roles at all, and express
// `TO anon` / `TO authenticated` as predicates instead.
func TestConvertCompatSingleRoleNeedsNoRoles(t *testing.T) {
	anonSource := append(append([]Source{}, fixture...), Source{Name: "0003_anon.sql", SQL: `
create policy anon_browse on public.todos
  for select to anon using (not archived);
`})
	res, err := Convert(anonSource, Options{
		Mode: ModeCompat, RoleModel: RoleSingle, NoServiceEscape: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Nothing in the bundle may need CREATE ROLE.
	for _, f := range res.Files {
		if strings.Contains(strings.ToLower(f.SQL), "create role") {
			t.Errorf("%s emits CREATE ROLE; compat+single must not need role creation", f.Name)
		}
	}

	policies := findFile(t, res, "capyrls_03_policies.sql")
	for _, want := range []string{
		"auth.role() = 'authenticated'",
		"auth.role() = 'anon'",
	} {
		if !strings.Contains(policies, want) {
			t.Errorf("compat+single policies missing predicate %q", want)
		}
	}
	// Only live SQL counts: the bundle deliberately quotes skipped originals
	// (which do carry `to service_role`) inside comments.
	var live strings.Builder
	for line := range strings.SplitSeq(policies, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			live.WriteString(line)
			live.WriteString("\n")
		}
	}
	for _, unwanted := range []string{"to authenticated", "to anon", "to service_role"} {
		if strings.Contains(live.String(), unwanted) {
			t.Errorf("compat+single policies still carry a role target %q", unwanted)
		}
	}
	// auth.uid() casts to uuid; the presence predicate must not depend on it,
	// or it raises for providers whose subject is not a uuid (Clerk).
	if strings.Contains(policies, "(select auth.uid()) is not null") {
		t.Error("presence predicate must test auth.role(), not auth.uid()")
	}
	// The initplan form sets hasSubLinks, and Postgres's static recursion check
	// then rejects any policy reaching this table through it - an INSERT whose
	// WITH CHECK looks for a prior row fails with "infinite recursion detected
	// in policy". Reproduced on postgres:17; the plain call works.
	if strings.Contains(policies, "(select auth.role())") {
		t.Error("compat role predicate must not be wrapped in (select ...): the sublink breaks self-referencing policies")
	}

	// FORCE is what makes the policies apply to the owning credential at all.
	force := findFile(t, res, "capyrls_02_force_rls.sql")
	if !strings.Contains(force, "alter table public.todos force row level security;") {
		t.Error("compat+single must FORCE row level security")
	}

	// With no service path, a service_role-only policy is not "covered
	// elsewhere" - the access it granted is gone, and the report must say so.
	skipped := outcomeFor(t, res.Report, "admin_all")
	if skipped.Status != "skipped" || !strings.Contains(skipped.Detail, "no service path exists") {
		t.Errorf("service-only policy outcome = %+v; want a skip naming the absent service path", skipped)
	}
}

func TestConvertNoSplitAll(t *testing.T) {
	res, err := Convert(fixture, Options{NoSplitAll: true})
	if err != nil {
		t.Fatal(err)
	}
	policies := findFile(t, res, "capyrls_03_policies.sql")
	if !strings.Contains(policies, "create policy todos_all on public.todos") {
		t.Error("NoSplitAll should keep the FOR ALL policy intact")
	}
	if strings.Contains(policies, "todos_all_select") {
		t.Error("NoSplitAll must not split")
	}
	if !strings.Contains(policies, "for all") {
		t.Error("kept policy should still say FOR ALL")
	}
}

// helperFixture is the pattern found in the wild: a custom helper whose body
// reads auth.*, called from policies whose own text has no auth.* reference,
// plus a plain helper that must stay unannotated.
var helperFixture = []Source{
	{Name: "helpers.sql", SQL: `
create function public.clerk_user_id() returns text language sql stable as $$
  select auth.jwt() ->> 'sub'
$$;
create function public.is_positive(n int) returns boolean language sql immutable as $$
  select n > 0
$$;
create function auth.uid() returns uuid language sql as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;
create table public.notes (id bigint primary key, owner text, n int);
alter table public.notes enable row level security;

create policy notes_owner on public.notes
  for select using (clerk_user_id() = owner);

create policy notes_owner_write on public.notes
  for update using (public.clerk_user_id() = owner);

create policy notes_positive on public.notes
  for select using (is_positive(n));

create policy notes_uid on public.notes
  for delete using (auth.uid()::text = owner);
`},
}

func TestConvertHelperLinkage(t *testing.T) {
	cases := []struct {
		name        string
		opts        Options
		wantDetail  string
		wantWarning string
	}{
		{
			name:        "vanilla",
			opts:        Options{},
			wantDetail:  "authorizes via helper public.clerk_user_id() whose body reads auth.* - convert the function body too (see Functions to review)",
			wantWarning: "2 of 4 converted policies authorize via helper functions whose bodies read auth.* (public.clerk_user_id) - the SQL bundle rewrites policies, not function bodies; the conversion is incomplete until those functions are ported",
		},
		{
			name:        "compat",
			opts:        Options{Mode: ModeCompat},
			wantDetail:  "authorizes via helper public.clerk_user_id() - covered by the auth.* compat shim (see Functions to review)",
			wantWarning: "2 of 4 converted policies authorize via helper functions whose bodies read auth.* (public.clerk_user_id) - the emitted auth.* shim keeps helper calls working, but bodies touching auth tables still need porting",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Convert(helperFixture, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			rep := res.Report
			// Unqualified and qualified call sites both link to the helper.
			for _, policy := range []string{"notes_owner", "notes_owner_write"} {
				if got := outcomeFor(t, rep, policy).Detail; !strings.Contains(got, tc.wantDetail) {
					t.Errorf("%s detail = %q, want it to contain %q", policy, got, tc.wantDetail)
				}
			}
			// A helper without auth.* in its body must not be annotated.
			if got := outcomeFor(t, rep, "notes_positive").Detail; got != "" {
				t.Errorf("notes_positive detail = %q, want empty", got)
			}
			// auth-schema DDL in a full dump must not turn the rewriter's own
			// auth.uid() conversions into false helper linkage.
			if got := outcomeFor(t, rep, "notes_uid").Detail; strings.Contains(got, "authorizes via helper") {
				t.Errorf("notes_uid detail = %q, want no helper annotation", got)
			}
			joined := strings.Join(rep.Warnings, "\n")
			if !strings.Contains(joined, tc.wantWarning) {
				t.Errorf("warnings missing %q, got %v", tc.wantWarning, rep.Warnings)
			}
			// Both call shapes aggregate onto one routine reference count.
			routines := strings.Join(rep.Routines, "\n")
			if !strings.Contains(routines, "`public.clerk_user_id`") || !strings.Contains(routines, "(referenced by 2 policies)") {
				t.Errorf("routines missing reference count, got %v", rep.Routines)
			}
			if strings.Contains(routines, "is_positive") {
				t.Errorf("is_positive should not be flagged for review, got %v", rep.Routines)
			}
		})
	}
}

func TestRewriteInPlace(t *testing.T) {
	res, err := Rewrite(fixture, Options{})
	if err != nil {
		t.Fatal(err)
	}
	first := findFile(t, res, "0001_init.sql")
	for _, want := range []string{
		// Defaults rewritten without subquery wrappers.
		"default app.user_id()",
		// Policy expressions rewritten, TO clauses untouched.
		"to authenticated",
		"app.user_id() = id",
		"org_id::text = app.org_id()",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("rewritten file missing %q", want)
		}
	}
	if strings.Contains(strings.ReplaceAll(first, "auth.users", ""), "auth.uid()") {
		t.Error("auth.uid() should be fully rewritten in place")
	}
	// The prelude rides along; roles stubs are announced.
	findFile(t, res, "capyrls_01_prelude.sql")
	joined := strings.Join(res.Report.Warnings, "\n")
	if !strings.Contains(joined, "authenticated") || !strings.Contains(joined, "service_role") {
		t.Errorf("rewrite report should call out required roles, got %v", res.Report.Warnings)
	}
}

func TestConvertIdempotentSQL(t *testing.T) {
	res, err := Convert(fixture, Options{})
	if err != nil {
		t.Fatal(err)
	}
	policies := findFile(t, res, "capyrls_03_policies.sql")
	var live []string
	for line := range strings.SplitSeq(policies, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			live = append(live, line)
		}
	}
	liveSQL := strings.Join(live, "\n")
	if strings.Count(liveSQL, "drop policy if exists") != strings.Count(liveSQL, "create policy") {
		t.Error("every create policy needs a drop-if-exists so the bundle can re-run")
	}
}

func TestConvertDeterministic(t *testing.T) {
	a, err := Convert(fixture, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Convert(fixture, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Files {
		if a.Files[i].SQL != b.Files[i].SQL {
			t.Fatalf("output for %s is not deterministic", a.Files[i].Name)
		}
	}
}

// Vanilla mode keeps the initplan wrap - a real per-row optimisation - except
// on a TABLE that carries a self-referencing policy, where a sublink in any
// policy makes Postgres reject the one that reaches the table.
func TestConvertVanillaDropsInitplanOnSelfReferencingTable(t *testing.T) {
	source := []Source{{Name: "0001.sql", SQL: `
create table public.threads (id bigint primary key, owner_id uuid, parent_id bigint);
create table public.notes (id bigint primary key, owner_id uuid);
alter table public.threads enable row level security;
alter table public.notes enable row level security;

-- threads: one policy reaches its own table...
create policy threads_reply on public.threads
  for insert to authenticated
  with check (auth.uid() = owner_id
              and exists (select 1 from threads prior where prior.id = parent_id));

-- ...so this sibling must lose the wrap too, even though it is innocent:
-- a sublink in ANY policy on the table triggers the recursion check.
create policy threads_own on public.threads
  for select to authenticated using (auth.uid() = owner_id);

-- notes touches nothing else: the optimisation is safe and must survive.
create policy notes_own on public.notes
  for select to authenticated using (auth.uid() = owner_id);
`}}
	res, err := Convert(source, Options{RoleModel: RoleSingle})
	if err != nil {
		t.Fatal(err)
	}
	policies := findFile(t, res, "capyrls_03_policies.sql")

	inThreads := false
	for line := range strings.SplitSeq(policies, "\n") {
		if strings.Contains(line, "on public.threads") {
			inThreads = true
		} else if strings.Contains(line, "on public.notes") {
			inThreads = false
		}
		if inThreads && strings.Contains(line, "(select app.") {
			t.Errorf("no policy on a self-referencing table may carry a sublink: %s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(policies, "(select app.user_id()) = owner_id") {
		t.Error("a table with no self-referencing policy must keep the initplan wrap")
	}

	// The generated escape policy sits on those tables too, so it is never
	// wrapped either.
	force := findFile(t, res, "capyrls_02_force_rls.sql")
	if strings.Contains(force, "(select app.is_service())") {
		t.Error("the service escape must not carry a sublink - it shares the table")
	}
}

// TestForceCarriesTheForeignKeyWarning pins the note that ships beside FORCE.
//
// FORCE makes Postgres apply policies to the scan that validates a FOREIGN KEY,
// while leaving runtime enforcement and CHECK validation alone (verified on
// postgres:17.11). Adding a foreign key to a FORCEd parent therefore fails with
// 23503 naming rows that exist and are merely invisible - which stops a routine
// `drizzle-kit push` dead, with an error that points at the wrong thing.
//
// The warning is the whole mitigation, so it must not be able to vanish
// quietly: this test is what makes deleting it a failing build rather than a
// silent regression for whoever hits 23503 next.
func TestForceCarriesTheForeignKeyWarning(t *testing.T) {
	for _, opts := range []Options{
		{RoleModel: RoleSingle},
		{RoleModel: RoleSingle, NoServiceEscape: true},
		{Mode: ModeCompat, RoleModel: RoleSingle, NoServiceEscape: true},
	} {
		res, err := Convert(fixture, opts)
		if err != nil {
			t.Fatal(err)
		}
		force := findFile(t, res, "capyrls_02_force_rls.sql")
		for _, want := range []string{
			// Names the symptom someone will paste into a search box.
			"23503",
			// Says plainly that data integrity is NOT the problem.
			"referential integrity is unaffected",
			// The recipe, and the part that keeps the window small.
			"no force row level security",
			"PARENT only",
			// The other consequence of FORCE that misreads as missing data.
			"NO privileged view",
		} {
			if !strings.Contains(force, want) {
				t.Errorf("mode=%v role=%v: force file missing %q", opts.Mode, opts.RoleModel, want)
			}
		}
	}
}

// Compat + single emits the service escape too, keyed on the claims' role:
// `service_role` is what a Supabase service key's JWT carried, so the call
// sites that used it keep a path. The escape must not depend on the vanilla
// accessor schema, and a service_role-only policy is covered, not lost.
func TestConvertCompatSingleEmitsClaimsServiceEscape(t *testing.T) {
	res, err := Convert(fixture, Options{Mode: ModeCompat, RoleModel: RoleSingle})
	if err != nil {
		t.Fatal(err)
	}
	force := findFile(t, res, "capyrls_02_force_rls.sql")
	for _, want := range []string{
		"create policy capyrls_service_escape on public.todos",
		"using (auth.role() = 'service_role')",
		"with check (auth.role() = 'service_role')",
	} {
		if !strings.Contains(force, want) {
			t.Errorf("compat force file missing %q", want)
		}
	}
	if strings.Contains(force, "(select auth.role())") {
		t.Error("escape must not be wrapped in (select ...): the sublink breaks sibling self-referencing policies")
	}
	for _, f := range res.Files {
		if strings.Contains(f.SQL, ".is_service") {
			t.Errorf("%s references is_service, which compat mode does not define", f.Name)
		}
		if strings.Contains(strings.ToLower(f.SQL), "create role") {
			t.Errorf("%s emits CREATE ROLE; the compat escape must need no roles", f.Name)
		}
	}
	skipped := outcomeFor(t, res.Report, "admin_all")
	if skipped.Status != "skipped" || !strings.Contains(skipped.Detail, "already bypasses RLS") {
		t.Errorf("service-only policy outcome = %+v; want a skip covered by the escape", skipped)
	}
	if !strings.Contains(res.Report.GUCs[0].Description, "service_role") {
		t.Errorf("compat GUC contract does not document the escape: %q", res.Report.GUCs[0].Description)
	}
	prelude := findFile(t, res, "capyrls_01_prelude.sql")
	if !strings.Contains(prelude, `"role":"service_role"`) {
		t.Error("compat prelude does not explain the service context")
	}

	// --no-service-escape still removes it, and the report says the access is gone.
	res2, err := Convert(fixture, Options{Mode: ModeCompat, RoleModel: RoleSingle, NoServiceEscape: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(findFile(t, res2, "capyrls_02_force_rls.sql"), "capyrls_service_escape") {
		t.Error("NoServiceEscape must suppress the compat escape")
	}
	skipped2 := outcomeFor(t, res2.Report, "admin_all")
	if !strings.Contains(skipped2.Detail, "no service path exists") {
		t.Errorf("service-only policy outcome = %+v; want a skip naming the absent service path", skipped2)
	}
}

// A permissive escape cannot lift a restrictive policy - restrictive policies
// are ANDed with everything - so each one carries the escape itself, in both
// modes, and only when the escape exists.
func TestServiceEscapeLiftsRestrictivePolicies(t *testing.T) {
	src := []Source{{Name: "r.sql", SQL: `
create table public.docs (id bigint, owner_id uuid, locked boolean);
alter table public.docs enable row level security;
create policy docs_own on public.docs for all to authenticated
  using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
create policy docs_unlocked on public.docs as restrictive for update to authenticated
  using (not locked) with check (not locked);
`}}
	for _, tc := range []struct {
		opts Options
		want string
	}{
		{Options{RoleModel: RoleSingle}, "app.is_service() or ("},
		{Options{Mode: ModeCompat, RoleModel: RoleSingle}, "auth.role() = 'service_role' or ("},
	} {
		res, err := Convert(src, tc.opts)
		if err != nil {
			t.Fatal(err)
		}
		policies := findFile(t, res, "capyrls_03_policies.sql")
		if n := strings.Count(policies, tc.want); n != 2 {
			// Exactly two: USING and WITH CHECK of the restrictive policy. More
			// would mean it leaked into the permissive ones, which the escape
			// policy already covers.
			t.Errorf("mode=%v: want the escape ORed into USING and WITH CHECK of the restrictive policy only (2), got %d:\n%s", tc.opts.Mode, n, policies)
		}
		if got := outcomeFor(t, res.Report, "docs_unlocked"); !strings.Contains(got.Detail, "restrictive") {
			t.Errorf("mode=%v: restrictive outcome detail = %q", tc.opts.Mode, got.Detail)
		}
	}
	res, err := Convert(src, Options{RoleModel: RoleSingle, NoServiceEscape: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(findFile(t, res, "capyrls_03_policies.sql"), "is_service") {
		t.Error("restrictive policies must not reference the escape when it is not emitted")
	}
}

// On CapyDB the split model runs as the platform's runtime role, app_user. A
// custom runtime role would have to be created, which a CapyDB database role
// cannot do, so the conversion refuses it up front.
func TestTargetCapyDBSplitNeedsThePlatformAppRole(t *testing.T) {
	for _, mode := range []Mode{ModeVanilla, ModeCompat} {
		for _, appRole := range []string{"", "app_user"} {
			opts := Options{Mode: mode, RoleModel: RoleSplit, Target: TargetCapyDB, AppRole: appRole}
			if _, err := Convert(fixture, opts); err != nil {
				t.Errorf("mode=%v app role %q convert: %v", mode, appRole, err)
			}
			if _, err := Rewrite(fixture, opts); err != nil {
				t.Errorf("mode=%v app role %q rewrite: %v", mode, appRole, err)
			}
		}
		custom := Options{Mode: mode, RoleModel: RoleSplit, Target: TargetCapyDB, AppRole: "web_runtime"}
		if _, err := Convert(fixture, custom); !errors.Is(err, ErrSplitRolesUnsupported) || !strings.Contains(err.Error(), "web_runtime") {
			t.Errorf("mode=%v custom app role convert: err = %v, want ErrSplitRolesUnsupported naming the role", mode, err)
		}
		if _, err := Rewrite(fixture, custom); !errors.Is(err, ErrSplitRolesUnsupported) {
			t.Errorf("mode=%v custom app role rewrite: err = %v, want ErrSplitRolesUnsupported", mode, err)
		}
		// A custom runtime role is fine anywhere the bundle may create it, and
		// under the single role model, which has no runtime role at all.
		if _, err := Convert(fixture, Options{Mode: mode, RoleModel: RoleSplit, AppRole: "web_runtime"}); err != nil {
			t.Errorf("mode=%v custom app role on postgres: %v", mode, err)
		}
		if _, err := Convert(fixture, Options{Mode: mode, RoleModel: RoleSingle, Target: TargetCapyDB, AppRole: "web_runtime"}); err != nil {
			t.Errorf("mode=%v single on capydb: %v", mode, err)
		}
	}
}

// liveSQL drops comment lines: the bundle quotes skipped originals and advice
// inside comments, and only statements count.
func liveSQL(sql string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(sql, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// Split on CapyDB creates no roles: the runtime role is the platform's (the
// roles file checks it exists) and the owner is the service path, so nothing
// is granted to a service role and no Supabase role is recreated.
func TestConvertSplitOnCapyDB(t *testing.T) {
	anonSource := append(append([]Source{}, fixture...), Source{Name: "0003_anon.sql", SQL: `
create policy anon_browse on public.todos
  for select to anon using (not archived);
`})
	for _, mode := range []Mode{ModeVanilla, ModeCompat} {
		res, err := Convert(anonSource, Options{Mode: mode, RoleModel: RoleSplit, Target: TargetCapyDB, ServiceRole: "ignored_service"})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range res.Files {
			sql := strings.ToLower(liveSQL(f.SQL))
			if strings.Contains(sql, "create role") || strings.Contains(sql, "bypassrls") {
				t.Errorf("mode=%v: %s creates a role; a CapyDB database role cannot", mode, f.Name)
			}
			for _, unwanted := range []string{"app_service", "ignored_service", "service_role", "to anon", "to authenticated"} {
				if strings.Contains(sql, unwanted) {
					t.Errorf("mode=%v: %s references %q", mode, f.Name, unwanted)
				}
			}
		}

		roles := findFile(t, res, "capyrls_02_roles.sql")
		contextSchema := "app"
		if mode == ModeCompat {
			contextSchema = "auth"
		}
		for _, want := range []string{
			"if not exists (select from pg_catalog.pg_roles where rolname = 'app_user') then",
			"raise exception 'role \"app_user\" does not exist: enable the runtime role for this project first",
			"POST /v1/projects/<project id>/roles/app",
			"grant usage on schema " + contextSchema + " to app_user;",
			"grant usage on schema public to app_user;",
			"grant select, insert, update, delete on all tables in schema public to app_user;",
			"grant usage, select on all sequences in schema public to app_user;",
			"alter default privileges in schema public grant select, insert, update, delete on tables to app_user;",
			"alter default privileges in schema public grant usage, select on sequences to app_user;",
		} {
			if !strings.Contains(roles, want) {
				t.Errorf("mode=%v: CapyDB roles file missing %q", mode, want)
			}
		}
		if strings.Contains(strings.ToLower(liveSQL(roles)), "for role") {
			t.Errorf("mode=%v: default privileges must apply to the applying owner, not FOR ROLE another", mode)
		}
		if slices.Contains(fileNames(res), "capyrls_02_force_rls.sql") {
			t.Errorf("mode=%v: the split model must not FORCE row security", mode)
		}

		// Policies target the runtime role; anon/authenticated survive as
		// predicates rather than as roles.
		policies := liveSQL(findFile(t, res, "capyrls_03_policies.sql"))
		authed, anon := "(select app.user_id()) is not null", "(select app.user_id()) is null"
		if mode == ModeCompat {
			authed, anon = "auth.role() = 'authenticated'", "auth.role() = 'anon'"
		}
		for _, want := range []string{"to app_user", authed, anon} {
			if !strings.Contains(policies, want) {
				t.Errorf("mode=%v: policies missing %q", mode, want)
			}
		}
		if skipped := outcomeFor(t, res.Report, "admin_all"); skipped.Status != "skipped" || !strings.Contains(skipped.Detail, "the service path is the owner") {
			t.Errorf("mode=%v: service-only policy outcome = %+v; want a skip naming the owner as the service path", mode, skipped)
		}
	}
}

// A table the source already FORCEd confines the owner too, so on CapyDB the
// split model's service path - the owner - is filtered there, and so is a
// definer the owner owns. The report says so and gives the CapyDB fix, not the
// BYPASSRLS-role one.
func TestSplitOnCapyDBFlagsForcedTables(t *testing.T) {
	src := []Source{{Name: "a.sql", SQL: `
create table public.todos (id int, owner_id uuid);
alter table public.todos enable row level security;
alter table public.todos force row level security;
create policy own on public.todos for all to authenticated using (auth.uid() = owner_id);
create function public.gift(r uuid) returns void language plpgsql security definer as $$
begin insert into public.todos (owner_id) values (r); end $$;
`}}
	res, err := Convert(src, Options{RoleModel: RoleSplit, Target: TargetCapyDB})
	if err != nil {
		t.Fatal(err)
	}
	if w := warningContaining(res.Report, "FORCEd in the source"); !strings.Contains(w, "public.todos") || !strings.Contains(w, "no force row level security") {
		t.Errorf("forced-table warning = %q", w)
	}
	if len(res.Report.DefinerWrites) != 1 {
		t.Fatalf("definer writes = %+v", res.Report.DefinerWrites)
	}
	fix := res.Report.DefinerFix
	if !strings.Contains(fix, "no force row level security") || strings.Contains(fix, "alter function") || strings.Contains(fix, "app_service") {
		t.Errorf("CapyDB split definer fix = %q", fix)
	}
	// Elsewhere the split model still hands definers to its BYPASSRLS role.
	res, err = Convert(src, Options{RoleModel: RoleSplit})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Report.DefinerFix, "owner to app_service") {
		t.Errorf("postgres split definer fix = %q", res.Report.DefinerFix)
	}
	if w := warningContaining(res.Report, "FORCEd in the source"); w != "" {
		t.Errorf("the forced-table warning is CapyDB-only, got %q", w)
	}
}

// Rewrite keeps TO clauses, and the CapyDB roles file cannot create the
// Supabase roles they name.
func TestRewriteSplitOnCapyDBSaysRolesCannotBeCreated(t *testing.T) {
	res, err := Rewrite(fixture, Options{Mode: ModeCompat, RoleModel: RoleSplit, Target: TargetCapyDB})
	if err != nil {
		t.Fatal(err)
	}
	w := warningContaining(res.Report, "TO clauses")
	if strings.Contains(w, "creates them") || !strings.Contains(w, "cannot create") || !strings.Contains(w, "convert") {
		t.Errorf("rewrite split-on-CapyDB warning = %q", w)
	}
	if roles := liveSQL(findFile(t, res, "capyrls_02_roles.sql")); strings.Contains(strings.ToLower(roles), "create role") {
		t.Error("the CapyDB roles file must not create roles in rewrite mode either")
	}
}

func warningContaining(rep Report, substr string) string {
	for _, w := range rep.Warnings {
		if strings.Contains(w, substr) {
			return w
		}
	}
	return ""
}

// The default keeps Supabase's uuid-typed auth.uid(); --uid-type text drops
// the cast so a Clerk-style `user_...` subject cannot raise 22P02.
func TestConvertUIDTypeDefaultIsUUID(t *testing.T) {
	res, err := Convert(fixture, Options{})
	if err != nil {
		t.Fatal(err)
	}
	prelude := findFile(t, res, "capyrls_01_prelude.sql")
	if !strings.Contains(prelude, "returns uuid") || !strings.Contains(prelude, "'app.user_id', true), '')::uuid") {
		t.Errorf("default prelude should keep the uuid accessor:\n%s", prelude)
	}
	if res.Report.UIDType != "uuid" || res.Report.GUCs[0].Type != "uuid (text GUC)" {
		t.Errorf("report uid type %q, user_id GUC type %q", res.Report.UIDType, res.Report.GUCs[0].Type)
	}
	if w := warningContaining(res.Report, "--uid-type text"); w != "" {
		t.Errorf("default mode must not warn about --uid-type text: %s", w)
	}
}

func TestConvertUIDTypeTextVanilla(t *testing.T) {
	res, err := Convert(fixture, Options{UIDType: UIDText})
	if err != nil {
		t.Fatal(err)
	}
	prelude := findFile(t, res, "capyrls_01_prelude.sql")
	if !strings.Contains(prelude, "create or replace function app.user_id()\nreturns text\n") {
		t.Errorf("app.user_id() should return text:\n%s", prelude)
	}
	if strings.Contains(prelude, "::uuid") || strings.Contains(prelude, "<uuid>") {
		t.Errorf("text prelude must not cast to or document uuid:\n%s", prelude)
	}
	if res.Report.UIDType != "text" || res.Report.GUCs[0].Type != "text" {
		t.Errorf("report uid type %q, user_id GUC type %q", res.Report.UIDType, res.Report.GUCs[0].Type)
	}
	if md := res.Report.Markdown(); !strings.Contains(md, "- user id type: `text`") {
		t.Errorf("markdown report should state the user id type:\n%s", md)
	}

	// Both uuid columns the fixture compares to auth.uid() - and defaults to
	// it - are named, with the fix.
	for column, policy := range map[string]string{
		"public.todos.owner_id": "todos_all",
		"public.profiles.id":    "profiles_owner_select",
	} {
		w := warningContaining(res.Report, "uuid column "+column+" ")
		if w == "" {
			t.Errorf("no warning for uuid column %s: %v", column, res.Report.Warnings)
			continue
		}
		for _, want := range []string{
			"is compared to the user id by policy " + policy,
			"takes the user id as its default",
			"type text using",
		} {
			if !strings.Contains(w, want) {
				t.Errorf("warning for %s missing %q: %s", column, want, w)
			}
		}
		if detail := outcomeFor(t, res.Report, policy).Detail; !strings.Contains(detail, "uuid column "+column) {
			t.Errorf("policy %s detail should name %s: %q", policy, column, detail)
		}
	}
	if w := warningContaining(res.Report, "--uid-type text: the user id (`app.user_id()`) is text"); w == "" {
		t.Errorf("missing the general text-mode warning: %v", res.Report.Warnings)
	}
	// Status stays converted: the SQL is right for a text column, and
	// Postgres rejects it loudly at apply time if the column is still uuid.
	if got := outcomeFor(t, res.Report, "todos_all").Status; got != "converted" {
		t.Errorf("todos_all status %q, want converted", got)
	}
	// org_read compares a claim, not the user id.
	if detail := outcomeFor(t, res.Report, "org_read").Detail; strings.Contains(detail, "uuid column") {
		t.Errorf("org_read does not compare the user id: %q", detail)
	}
}

func TestConvertUIDTypeTextCompat(t *testing.T) {
	res, err := Convert(fixture, Options{Mode: ModeCompat, UIDType: UIDText})
	if err != nil {
		t.Fatal(err)
	}
	prelude := findFile(t, res, "capyrls_01_prelude.sql")
	if !strings.Contains(prelude, "create or replace function auth.uid()\nreturns text\nlanguage sql stable parallel safe\nas $$\n  select nullif(auth.jwt() ->> 'sub', '')\n$$;") {
		t.Errorf("auth.uid() shim should return the sub claim as text, uncast:\n%s", prelude)
	}
	if strings.Contains(prelude, "::uuid") {
		t.Errorf("text shim must not cast to uuid:\n%s", prelude)
	}
	if w := warningContaining(res.Report, "--uid-type text: the user id (`auth.uid()`) is text"); w == "" {
		t.Errorf("compat warning should name auth.uid(): %v", res.Report.Warnings)
	}
	if !strings.Contains(res.Report.GUCs[0].Description, "as text") {
		t.Errorf("claims contract should say sub is read as text: %q", res.Report.GUCs[0].Description)
	}
}

// Detection works on the forms a live database renders (pg_get_expr wraps the
// call as a scalar subquery) and skips comparisons that are not text = uuid.
func TestConvertUIDTypeTextDetection(t *testing.T) {
	cat := NewCatalog()
	todos := QName{Schema: "public", Name: "todos"}
	members := QName{Schema: "public", Name: "members"}
	cat.SetTableRLS(todos, true, false)
	cat.SetColumnType(todos, "owner_id", "uuid")
	cat.SetColumnType(todos, "editor_id", "uuid")
	cat.SetColumnType(todos, "reviewer_id", "uuid")
	cat.SetColumnType(members, "user_id", "uuid")
	for _, p := range []struct{ name, using string }{
		{"live_form", "(owner_id = ( SELECT auth.uid() AS uid))"},
		{"qualified_self", "(select auth.uid()) = todos.editor_id"},
		{"other_table", "exists (select 1 from public.members m where public.members.user_id = auth.uid())"},
		{"cast_away", "reviewer_id::text = auth.uid()"},
		{"text_column", "auth.uid() = author_name"},
		{"aliased_miss", "exists (select 1 from public.members m where m.user_id = auth.uid())"},
	} {
		cat.AddPolicy(&Policy{Name: p.name, Table: todos, Permissive: true, Cmd: CmdSelect, Using: p.using, Origin: "test"})
	}
	res, err := ConvertCatalog(cat, Options{UIDType: UIDText})
	if err != nil {
		t.Fatal(err)
	}
	for policy, column := range map[string]string{
		"live_form":      "public.todos.owner_id",
		"qualified_self": "public.todos.editor_id",
		"other_table":    "public.members.user_id",
	} {
		if detail := outcomeFor(t, res.Report, policy).Detail; !strings.Contains(detail, "uuid column "+column) {
			t.Errorf("%s: detail should name %s, got %q", policy, column, detail)
		}
	}
	for _, policy := range []string{"cast_away", "text_column", "aliased_miss"} {
		if detail := outcomeFor(t, res.Report, policy).Detail; strings.Contains(detail, "uuid column") {
			t.Errorf("%s: should not be flagged, got %q", policy, detail)
		}
	}
	if w := warningContaining(res.Report, "uuid column public.todos.reviewer_id"); w != "" {
		t.Errorf("a column cast to text is not a conflict: %s", w)
	}
}

func TestRewriteUIDTypeText(t *testing.T) {
	res, err := Rewrite(fixture, Options{UIDType: UIDText})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.UIDType != "text" {
		t.Errorf("rewrite report uid type %q", res.Report.UIDType)
	}
	if !strings.Contains(findFile(t, res, "capyrls_01_prelude.sql"), "returns text") {
		t.Error("rewrite prelude should emit the text accessor")
	}
	if detail := outcomeFor(t, res.Report, "todos_all").Detail; !strings.Contains(detail, "uuid column public.todos.owner_id") {
		t.Errorf("rewrite should flag todos_all too: %q", detail)
	}
}

// Rewrite keeps TO clauses; under the single role model there is no roles file,
// so the report must not claim one creates them.
func TestRewriteSingleRoleSaysRolesMustExist(t *testing.T) {
	res, err := Rewrite(fixture, Options{Mode: ModeCompat, RoleModel: RoleSingle, Target: TargetCapyDB})
	if err != nil {
		t.Fatal(err)
	}
	w := warningContaining(res.Report, "TO clauses")
	if strings.Contains(w, "capyrls_02_roles.sql") || !strings.Contains(w, "must exist") || !strings.Contains(w, "CapyDB") {
		t.Errorf("rewrite single-role warning = %q", w)
	}
}
