package capyrls

import (
	"strings"
	"testing"
)

func mustCatalog(t *testing.T, sql string) *Catalog {
	t.Helper()
	cat, err := ParseSQL([]Source{{Name: "test.sql", SQL: sql}})
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	return cat
}

func TestParseCreatePolicyFullClause(t *testing.T) {
	cat := mustCatalog(t, `
create policy "Owner can read" on public.todos
  as restrictive
  for select
  to authenticated, anon
  using (auth.uid() = owner_id);
`)
	if len(cat.Policies) != 1 {
		t.Fatalf("policies: %d", len(cat.Policies))
	}
	p := cat.Policies[0]
	if p.Name != "Owner can read" || p.Table.Key() != "public.todos" {
		t.Fatalf("name/table wrong: %+v", p)
	}
	if p.Permissive || p.Cmd != CmdSelect {
		t.Fatalf("modifiers wrong: %+v", p)
	}
	if len(p.Roles) != 2 || p.Roles[0] != "authenticated" || p.Roles[1] != "anon" {
		t.Fatalf("roles wrong: %v", p.Roles)
	}
	if p.Using != "auth.uid() = owner_id" {
		t.Fatalf("using wrong: %q", p.Using)
	}
}

func TestParsePolicyHistoryAppliesInOrder(t *testing.T) {
	cat := mustCatalog(t, `
create policy p1 on t using (a = 1);
create policy p2 on t using (b = 2);
alter policy p1 on t using (a = 42);
alter policy p2 on t rename to p2_renamed;
drop policy if exists ghost on t;
drop policy p1 on t;
`)
	if len(cat.Policies) != 1 {
		t.Fatalf("expected one surviving policy, got %d", len(cat.Policies))
	}
	p := cat.Policies[0]
	if p.Name != "p2_renamed" || p.Using != "b = 2" {
		t.Fatalf("history mis-applied: %+v", p)
	}
	for _, note := range cat.Notes {
		if strings.Contains(note, "ghost") {
			t.Fatalf("DROP POLICY IF EXISTS must not produce a note: %v", cat.Notes)
		}
	}
}

func TestParseRLSFlags(t *testing.T) {
	cat := mustCatalog(t, `
alter table public.a enable row level security;
alter table only public.b force row level security;
alter table public.a disable row level security;
alter table public.b no force row level security;
alter table if exists public.c enable row level security;
`)
	if cat.Tables["public.a"].RLSEnabled {
		t.Fatal("a: later DISABLE must win")
	}
	if cat.Tables["public.b"].RLSForced {
		t.Fatal("b: later NO FORCE must win")
	}
	if !cat.Tables["public.c"].RLSEnabled {
		t.Fatal("c: IF EXISTS form must still parse")
	}
}

func TestParseColumnDefaultsReferencingAuth(t *testing.T) {
	cat := mustCatalog(t, `
create table public.profiles (
  id uuid primary key default auth.uid(),
  bio text default 'hello',
  created timestamptz not null default now(),
  constraint uniq unique (id)
);
alter table public.profiles add column if not exists owner uuid default auth.uid() not null;
alter table public.profiles alter column bio set default auth.jwt() ->> 'bio';
`)
	if len(cat.Defaults) != 3 {
		t.Fatalf("defaults: got %d, want 3: %+v", len(cat.Defaults), cat.Defaults)
	}
	if cat.Defaults[0].Column != "id" || cat.Defaults[0].Expr != "auth.uid()" {
		t.Fatalf("table default wrong: %+v", cat.Defaults[0])
	}
	if cat.Defaults[1].Column != "owner" || cat.Defaults[1].Expr != "auth.uid()" {
		t.Fatalf("add-column default wrong: %+v", cat.Defaults[1])
	}
	if cat.Defaults[2].Column != "bio" || cat.Defaults[2].Expr != "auth.jwt() ->> 'bio'" {
		t.Fatalf("set-default wrong: %+v", cat.Defaults[2])
	}
}

func TestParseRoutineReferencingAuth(t *testing.T) {
	cat := mustCatalog(t, `
create or replace function public.owned_count()
returns bigint language sql as $$
  select count(*) from todos where owner_id = auth.uid()
$$;
create function public.plain() returns int language sql as $$ select 1 $$;
`)
	if len(cat.Routines) != 1 || cat.Routines[0].Name.Key() != "public.owned_count" {
		t.Fatalf("routines: %+v", cat.Routines)
	}
}

func TestParseNotesOnViewReferencingAuth(t *testing.T) {
	cat := mustCatalog(t, `create view v as select * from todos where owner_id = auth.uid();`)
	if len(cat.Notes) != 1 || !strings.Contains(cat.Notes[0], "auth.*") {
		t.Fatalf("expected one out-of-scope note, got %v", cat.Notes)
	}
}

func TestParseQuotedIdentifiers(t *testing.T) {
	cat := mustCatalog(t, `create policy "My Policy" on "Weird Schema"."Weird Table" using (true);`)
	p := cat.Policies[0]
	if p.Table.Schema != "Weird Schema" || p.Table.Name != "Weird Table" {
		t.Fatalf("quoted qname wrong: %+v", p.Table)
	}
	if p.Table.String() != `"Weird Schema"."Weird Table"` {
		t.Fatalf("rendering wrong: %s", p.Table)
	}
}
