package capyrls

import (
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
		"(select app.is_service())",
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
		"(select auth.uid()) = id",
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
