package live

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Set CAPYRLS_TEST_DATABASE_URL to a superuser connection to run this (see
// apply_live_test.go in the parent package); skipped otherwise.
func TestLoadReadsSecurityDefinerBodies(t *testing.T) {
	dsn := os.Getenv("CAPYRLS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CAPYRLS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	const name = "capyrls_live_loader"
	if _, err := admin.ExecContext(ctx, "drop database if exists "+name+" with (force)"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "create database "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.ExecContext(ctx, "drop database if exists "+name+" with (force)") }()

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `
create table public.t (id int);
alter table public.t enable row level security;
create function public.w() returns void language sql security definer as $$ insert into public.t values (1) $$;
create function public.w(x int) returns void language sql security definer as $$ delete from public.t where id = x $$;
create function public.r() returns void language sql as $$ insert into public.t values (2) $$;
`); err != nil {
		t.Fatal(err)
	}
	cat, err := Load(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Definers) != 1 {
		t.Fatalf("definers = %+v, want the overloaded public.w once", cat.Definers)
	}
	d := cat.Definers[0]
	if d.Name.Key() != "public.w" || len(d.Writes) != 1 || d.Writes[0].Key() != "public.t" {
		t.Errorf("definer = %+v, want public.w writing public.t", d)
	}
}
