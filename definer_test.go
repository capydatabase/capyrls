package capyrls

import (
	"slices"
	"strings"
	"testing"
)

func TestWriteTargets(t *testing.T) {
	cases := []struct {
		body string
		want []string
	}{
		{"insert into public.a (x) values (1)", []string{"public.a"}},
		{"INSERT INTO b SELECT 1", []string{"public.b"}},
		{"update only s.c set x = 1", []string{"s.c"}},
		{"update d as dd set x = 1 from e where e.id = dd.id", []string{"public.d"}},
		{"update d dd set x = 1", []string{"public.d"}},
		{"delete from \"Odd\" where true", []string{"public.Odd"}},
		{"merge into m using src on true when matched then delete", []string{"public.m"}},
		// Not writes.
		{"select * from f for update", nil},
		{"select * from f for no key update of f", nil},
		{"insert into g values (1) on conflict (id) do update set x = 1", []string{"public.g"}},
		{"raise exception 'cannot delete from h'", nil},
		{"select 1 from i where exists (select 1 from j)", nil},
	}
	for _, tc := range cases {
		var got []string
		for _, q := range writeTargets(lexSQL(tc.body)) {
			got = append(got, q.Key())
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("writeTargets(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

var definerSource = []Source{{Name: "0001.sql", SQL: `
create table public.invites (id bigint, owner_id uuid, accepted_by uuid);
create table public.audit (id bigint, what text);
create table public.plain (id bigint);
alter table public.invites enable row level security;
alter table public.audit enable row level security;
create policy invites_own on public.invites for all to authenticated using (auth.uid() = owner_id);
create policy audit_read on public.audit for select to authenticated using (true);

create function public.accept_invite(invite bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  update invites set accepted_by = auth.uid() where id = invite;
  insert into audit (what) values ('accepted');
end $$;

-- Reads only: a definer that writes nothing is not affected.
create function public.count_invites() returns bigint
language sql security definer as $$ select count(*) from public.invites $$;

-- Writes a table without row security: FORCE is never applied to it.
create function public.touch_plain() returns void
language sql security definer as $$ insert into public.plain values (1) $$;

-- Invoker functions are subject to policies anyway.
create function public.invoker_write() returns void
language sql as $$ delete from public.invites $$;

-- Redefined as invoker later, then dropped: neither counts.
create function public.was_definer() returns void
language sql security definer as $$ delete from public.invites $$;
create or replace function public.was_definer() returns void
language sql security invoker as $$ delete from public.invites $$;
create function public.gone() returns void
language sql security definer as $$ delete from public.audit $$;
drop function if exists public.gone();
`}}

func TestConvertFlagsDefinersWritingForcedTables(t *testing.T) {
	res, err := Convert(definerSource, Options{RoleModel: RoleSingle})
	if err != nil {
		t.Fatal(err)
	}
	want := []DefinerWrite{{
		Function: "public.accept_invite",
		Tables:   []string{"public.audit", "public.invites"},
		Origin:   "0001.sql:10",
	}}
	got := res.Report.DefinerWrites
	if len(got) != 1 || got[0].Function != want[0].Function || !slices.Equal(got[0].Tables, want[0].Tables) || got[0].Origin != want[0].Origin {
		t.Fatalf("definer writes = %+v, want %+v", got, want)
	}
	if warningContaining(res.Report, "SECURITY DEFINER") == "" {
		t.Error("no summary warning for the definer functions")
	}
	for _, want := range []string{
		"42501",
		"perform set_config('app.role', 'service', true);",
		"perform set_config('app.role', coalesce(prev, ''), true);",
		"before every RETURN",
		"permission denied to set parameter",
	} {
		if !strings.Contains(res.Report.DefinerFix, want) {
			t.Errorf("vanilla definer fix missing %q", want)
		}
	}
	md := res.Report.Markdown()
	if !strings.Contains(md, "## SECURITY DEFINER functions under FORCE") ||
		!strings.Contains(md, "`public.accept_invite` (0001.sql:10) writes `public.audit`, `public.invites`") {
		t.Errorf("markdown report lacks the definer section:\n%s", md)
	}
}

func TestDefinerFixPerConfiguration(t *testing.T) {
	compat, err := Convert(definerSource, Options{Mode: ModeCompat, RoleModel: RoleSingle})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(auth.jwt() || '{"role": "service_role"}')::text`,
		"auth.uid()` still names the caller",
	} {
		if !strings.Contains(compat.Report.DefinerFix, want) {
			t.Errorf("compat definer fix missing %q", want)
		}
	}

	noEscape, err := Convert(definerSource, Options{RoleModel: RoleSingle, NoServiceEscape: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(noEscape.Report.DefinerFix, "no service escape") || strings.Contains(noEscape.Report.DefinerFix, "set_config") {
		t.Errorf("no-escape fix must not offer the escape recipe:\n%s", noEscape.Report.DefinerFix)
	}

	// Split role model: the bundle FORCEs nothing, so only tables the source
	// FORCEd count, and the remedy is ownership by the BYPASSRLS role.
	split, err := Convert(definerSource, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(split.Report.DefinerWrites) != 0 {
		t.Errorf("split model with nothing FORCEd flagged %+v", split.Report.DefinerWrites)
	}
	forcedSource := append(append([]Source{}, definerSource...), Source{Name: "0002.sql", SQL: `
alter table public.audit force row level security;
`})
	split, err = Convert(forcedSource, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(split.Report.DefinerWrites) != 1 || !slices.Equal(split.Report.DefinerWrites[0].Tables, []string{"public.audit"}) {
		t.Fatalf("split model with audit FORCEd: %+v", split.Report.DefinerWrites)
	}
	if !strings.Contains(split.Report.DefinerFix, "owner to app_service") {
		t.Errorf("split fix should hand the function to the BYPASSRLS role:\n%s", split.Report.DefinerFix)
	}

	// Nothing to flag: the field is an empty list, never null.
	clean, err := Convert(fixture, Options{RoleModel: RoleSingle})
	if err != nil {
		t.Fatal(err)
	}
	if clean.Report.DefinerWrites == nil || len(clean.Report.DefinerWrites) != 0 || clean.Report.DefinerFix != "" {
		t.Errorf("clean conversion: writes=%v fix=%q", clean.Report.DefinerWrites, clean.Report.DefinerFix)
	}
}
