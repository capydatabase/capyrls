package capyrls

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// These tests apply converted bundles to a real PostgreSQL as a role shaped like
// a CapyDB database role - it owns the database and its tables and has neither
// SUPERUSER, CREATEROLE nor BYPASSRLS - and check who can do what afterwards.
// The unit tests pin the SQL text; only a real server can say the text works.
//
// Set CAPYRLS_TEST_DATABASE_URL to a SUPERUSER connection (it creates and drops
// a throwaway role and databases), e.g.:
//
//	docker run -d --name capyrls-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55731:5432 postgres:18
//	CAPYRLS_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:55731/postgres?sslmode=disable' go test -run Live ./...
//
// Skipped when the variable is unset.

const liveSchema = `
create table public.todos (
  id bigint generated always as identity primary key,
  owner_id text not null,
  title text,
  locked boolean not null default false
);
alter table public.todos enable row level security;

create or replace function public.gift_todo(recipient text, what text)
returns void language plpgsql security definer as $$
begin
  insert into public.todos (owner_id, title) values (recipient, what);
end $$;
`

const liveSupabasePolicies = `
create policy todos_own on public.todos for all to authenticated
  using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
create policy todos_unlocked on public.todos as restrictive for update to authenticated
  using (not locked) with check (not locked);
create policy admin_all on public.todos for all to service_role using (true);
`

// liveContext is how each mode's application states the caller.
type liveContext struct {
	user    func(sub string) (name, value string)
	service [2]string
	// definerFix is gift_todo rewritten with the report's recipe.
	definerFix string
}

var liveContexts = map[Mode]liveContext{
	ModeVanilla: {
		user:    func(sub string) (string, string) { return "app.user_id", sub },
		service: [2]string{"app.role", "service"},
		definerFix: `
create or replace function public.gift_todo(recipient text, what text)
returns void language plpgsql security definer as $$
declare
  prev text := current_setting('app.role', true);
begin
  perform set_config('app.role', 'service', true);
  insert into public.todos (owner_id, title) values (recipient, what);
  perform set_config('app.role', coalesce(prev, ''), true);
end $$;`,
	},
	ModeCompat: {
		user: func(sub string) (string, string) {
			return "request.jwt.claims", fmt.Sprintf(`{"sub":%q,"role":"authenticated"}`, sub)
		},
		service: [2]string{"request.jwt.claims", `{"role":"service_role"}`},
		definerFix: `
create or replace function public.gift_todo(recipient text, what text)
returns void language plpgsql security definer as $$
declare
  prev text := current_setting('request.jwt.claims', true);
begin
  perform set_config('request.jwt.claims', (auth.jwt() || '{"role": "service_role"}')::text, true);
  insert into public.todos (owner_id, title) values (recipient, what);
  perform set_config('request.jwt.claims', coalesce(prev, ''), true);
end $$;`,
	},
}

func liveAdminDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("CAPYRLS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CAPYRLS_TEST_DATABASE_URL not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, dsn
}

// liveCustomerDB creates a CapyDB-shaped role and a database it owns, and
// returns a connection as that role.
func liveCustomerDB(t *testing.T, admin *sql.DB, adminDSN, name string) *sql.DB {
	t.Helper()
	ctx := context.Background()
	role := name + "_owner"
	for _, stmt := range []string{
		fmt.Sprintf("drop database if exists %s with (force)", name),
		fmt.Sprintf("drop role if exists %s", role),
		fmt.Sprintf("create role %s login password 'pw' nosuperuser nocreaterole nobypassrls", role),
		fmt.Sprintf("create database %s owner %s", name, role),
	} {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "pw")
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.ExecContext(ctx, fmt.Sprintf("drop database if exists %s with (force)", name))
		_, _ = admin.ExecContext(ctx, fmt.Sprintf("drop role if exists %s", role))
	})
	return db
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// inTx runs fn in a transaction that first sets the given GUCs
// transaction-locally, the way the context contract says to, and rolls back
// unless keep is set.
func inTx(t *testing.T, db *sql.DB, gucs [][2]string, keep bool, fn func(*sql.Tx) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gucs {
		if _, err := tx.ExecContext(ctx, "select set_config($1, $2, true)", g[0], g[1]); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	err = fn(tx)
	if err != nil || !keep {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func count(tx *sql.Tx, query string) (int, error) {
	var n int
	err := tx.QueryRow(query).Scan(&n)
	return n, err
}

func TestLiveSingleRoleServiceEscapeAndDefiners(t *testing.T) {
	admin, adminDSN := liveAdminDB(t)
	for _, mode := range []Mode{ModeVanilla, ModeCompat} {
		t.Run(mode.String(), func(t *testing.T) {
			lc := liveContexts[mode]
			db := liveCustomerDB(t, admin, adminDSN, "capyrls_live_"+strings.ReplaceAll(mode.String(), "-", "_"))

			res, err := Convert([]Source{
				{Name: "schema.sql", SQL: liveSchema},
				{Name: "policies.sql", SQL: liveSupabasePolicies},
			}, Options{Mode: mode, RoleModel: RoleSingle, UIDType: UIDText, Target: TargetCapyDB})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Report.DefinerWrites) != 1 || res.Report.DefinerWrites[0].Function != "public.gift_todo" {
				t.Fatalf("report definer writes = %+v, want public.gift_todo", res.Report.DefinerWrites)
			}

			// The whole bundle applies as the non-privileged owner: no step may
			// need SUPERUSER, CREATEROLE or BYPASSRLS.
			if _, err := db.Exec(liveSchema); err != nil {
				t.Fatalf("schema: %v", err)
			}
			for _, f := range res.Files {
				if _, err := db.Exec(f.SQL); err != nil {
					t.Fatalf("apply %s as a CapyDB-shaped role: %v", f.Name, err)
				}
			}

			alice := [][2]string{{}}
			alice[0][0], alice[0][1] = lc.user("user_alice")
			bob := [][2]string{{}}
			bob[0][0], bob[0][1] = lc.user("user_bob")
			service := [][2]string{lc.service}

			// Seed through the service path: it writes for anyone.
			err = inTx(t, db, service, true, func(tx *sql.Tx) error {
				_, err := tx.Exec(`insert into public.todos (owner_id, title, locked) values
					('user_alice', 'a1', false), ('user_alice', 'a-locked', true), ('user_bob', 'b1', false)`)
				return err
			})
			if err != nil {
				t.Fatalf("service insert for other users: %v", err)
			}

			check := func(label string, gucs [][2]string, query string, want int) {
				t.Helper()
				if err := inTx(t, db, gucs, false, func(tx *sql.Tx) error {
					got, err := count(tx, query)
					if err != nil {
						return err
					}
					if got != want {
						t.Errorf("%s: %s = %d, want %d", label, query, got, want)
					}
					return nil
				}); err != nil {
					t.Errorf("%s: %v", label, err)
				}
			}
			check("service sees every row", service, "select count(*) from public.todos", 3)
			check("alice sees her rows only", alice, "select count(*) from public.todos", 2)
			check("bob sees his rows only", bob, "select count(*) from public.todos", 1)
			check("no context sees nothing", nil, "select count(*) from public.todos", 0)

			// Confinement on writes.
			err = inTx(t, db, alice, false, func(tx *sql.Tx) error {
				_, err := tx.Exec(`insert into public.todos (owner_id, title) values ('user_bob', 'forged')`)
				return err
			})
			if sqlState(err) != "42501" {
				t.Errorf("alice inserting a row for bob: err = %v, want 42501", err)
			}
			// Restrictive policy: alice cannot touch her locked row, the service
			// path can - the escape is ORed into the restrictive policy.
			check("restrictive blocks alice", alice,
				"with u as (update public.todos set title = 'x' where title = 'a-locked' returning 1) select count(*) from u", 0)
			check("restrictive lets the service path through", service,
				"with u as (update public.todos set title = 'x' where title = 'a-locked' returning 1) select count(*) from u", 1)

			// The definer the report flagged: under FORCE it is filtered by the
			// caller's context and the cross-user write fails.
			err = inTx(t, db, alice, false, func(tx *sql.Tx) error {
				_, err := tx.Exec(`select public.gift_todo('user_bob', 'gift')`)
				return err
			})
			if sqlState(err) != "42501" {
				t.Fatalf("flagged definer before the fix: err = %v, want 42501 (the failure the report warns about)", err)
			}
			// The report's own fix, applied as the same unprivileged role.
			if !strings.Contains(res.Report.DefinerFix, "prev text := current_setting('"+lc.service[0]+"', true)") {
				t.Errorf("report fix does not carry the recipe this test applies:\n%s", res.Report.DefinerFix)
			}
			if _, err := db.Exec(lc.definerFix); err != nil {
				t.Fatalf("apply the definer fix: %v", err)
			}
			err = inTx(t, db, alice, false, func(tx *sql.Tx) error {
				if _, err := tx.Exec(`select public.gift_todo('user_bob', 'gift')`); err != nil {
					return err
				}
				// The escape is lowered again on the way out: alice is still
				// confined for the rest of her transaction.
				got, err := count(tx, "select count(*) from public.todos")
				if err != nil {
					return err
				}
				if got != 2 {
					t.Errorf("after the definer returned, alice sees %d rows, want 2 (escape leaked)", got)
				}
				return nil
			})
			if err != nil {
				t.Errorf("definer after the fix: %v", err)
			}
		})
	}
}

// The ALTER FUNCTION ... SET form the fix text rules out really is refused to a
// managed role - if a future Postgres relaxes this, the recipe can get simpler.
func TestLiveFunctionSetNeedsParameterPrivilege(t *testing.T) {
	admin, adminDSN := liveAdminDB(t)
	db := liveCustomerDB(t, admin, adminDSN, "capyrls_live_setparam")
	if _, err := db.Exec(liveSchema); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`alter function public.gift_todo set app.role = 'service'`)
	if sqlState(err) != "42501" {
		t.Errorf("alter function set app.role as a non-superuser: err = %v, want 42501", err)
	}
}
