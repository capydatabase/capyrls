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

// liveAnonPolicy is a public-read policy for callers with no token, so the
// split-on-CapyDB test carries both Supabase roles the bundle cannot create.
const liveAnonPolicy = `
create policy todos_public on public.todos for select to anon using (title = 'public');
`

// livePlatformAppRole creates CapyDB's runtime role the way the platform does
// for a project that enables it - the ensure SQL of the infrastructure
// template capydb-app-role.sh.j2, run as the superuser: a login that owns
// nothing and cannot bypass RLS, the owner a member of it WITH INHERIT FALSE,
// SET TRUE (it can SET ROLE to it but gains none of its privileges), CONNECT
// and TEMPORARY on the database, which is revoked from PUBLIC as
// instance-create does. The role is server-wide, so it is dropped first and
// after the test (register this before the database's cleanup runs, i.e.
// call it after liveCustomerDB).
func livePlatformAppRole(t *testing.T, admin *sql.DB, owner, dbName string) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		"drop role if exists app_user",
		"create role app_user",
		"alter role app_user login nosuperuser nocreatedb nocreaterole noreplication nobypassrls inherit password 'app-pw' valid until 'infinity'",
		fmt.Sprintf("grant app_user to %s with inherit false, set true", owner),
		fmt.Sprintf("revoke all on database %s from public", dbName),
		fmt.Sprintf("grant connect, temporary on database %s to app_user", dbName),
	} {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

// liveDSNAs is the admin DSN with another login and database.
func liveDSNAs(t *testing.T, adminDSN, user, password, dbName string) string {
	t.Helper()
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, password)
	u.Path = "/" + dbName
	return u.String()
}

// The split model on CapyDB: the bundle creates no roles and applies as the
// owner, RLS confines the platform's runtime role (with its own login, or the
// owner's credential after SET ROLE) and not the owner, which is the service
// path; the Supabase roles need not exist; and without the runtime role the
// bundle stops at a check that says how to enable it.
func TestLiveSplitOnCapyDB(t *testing.T) {
	admin, adminDSN := liveAdminDB(t)
	ctx := context.Background()
	var version int
	if err := admin.QueryRowContext(ctx, "select current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version < 160000 {
		t.Skipf("the platform's runtime role needs Postgres 16 or newer (server is %d)", version)
	}
	var supabaseRoles int
	if err := admin.QueryRowContext(ctx, "select count(*) from pg_roles where rolname in ('anon', 'authenticated', 'service_role')").Scan(&supabaseRoles); err != nil {
		t.Fatal(err)
	}
	if supabaseRoles != 0 {
		t.Fatal("the test server must not have the Supabase roles anon/authenticated/service_role: the test proves the bundle needs none")
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(ctx, "drop role if exists app_user") })

	t.Run("app_user missing", func(t *testing.T) {
		db := liveCustomerDB(t, admin, adminDSN, "capyrls_live_split_missing")
		if _, err := admin.ExecContext(ctx, "drop role if exists app_user"); err != nil {
			t.Fatal(err)
		}
		res, err := Convert([]Source{{Name: "schema.sql", SQL: liveSchema}, {Name: "policies.sql", SQL: liveSupabasePolicies}},
			Options{RoleModel: RoleSplit, Target: TargetCapyDB, UIDType: UIDText})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(liveSchema); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(findFile(t, res, "capyrls_01_prelude.sql")); err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(findFile(t, res, "capyrls_02_roles.sql"))
		if sqlState(err) != "P0001" || !strings.Contains(err.Error(), `role "app_user" does not exist: enable the runtime role for this project first`) {
			t.Fatalf("roles file without app_user: err = %v, want the presence check (P0001)", err)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && !strings.Contains(pgErr.Hint, "/roles/app") {
			t.Errorf("presence check hint = %q, want the enable endpoint", pgErr.Hint)
		}
	})

	for _, mode := range []Mode{ModeVanilla, ModeCompat} {
		t.Run(mode.String(), func(t *testing.T) {
			lc := liveContexts[mode]
			name := "capyrls_live_split_" + strings.ReplaceAll(mode.String(), "-", "_")
			owner := name + "_owner"
			db := liveCustomerDB(t, admin, adminDSN, name)
			livePlatformAppRole(t, admin, owner, name)

			res, err := Convert([]Source{
				{Name: "schema.sql", SQL: liveSchema},
				{Name: "policies.sql", SQL: liveSupabasePolicies + liveAnonPolicy},
			}, Options{Mode: mode, RoleModel: RoleSplit, UIDType: UIDText, Target: TargetCapyDB})
			if err != nil {
				t.Fatal(err)
			}
			// Nothing is FORCEd, so the definer keeps bypassing as the owner.
			if len(res.Report.DefinerWrites) != 0 {
				t.Errorf("definer writes = %+v, want none (no table is FORCEd)", res.Report.DefinerWrites)
			}

			// The whole bundle applies as the owner - no SUPERUSER, CREATEROLE or
			// BYPASSRLS - with no Supabase role in existence.
			if _, err := db.Exec(liveSchema); err != nil {
				t.Fatalf("schema: %v", err)
			}
			for _, f := range res.Files {
				if _, err := db.Exec(f.SQL); err != nil {
					t.Fatalf("apply %s as the CapyDB owner: %v", f.Name, err)
				}
			}
			// Re-applying is safe (a second deploy of the same bundle).
			for _, f := range res.Files {
				if _, err := db.Exec(f.SQL); err != nil {
					t.Fatalf("re-apply %s: %v", f.Name, err)
				}
			}

			// The owner is the service path: no context, no escape, every row.
			if _, err := db.Exec(`insert into public.todos (owner_id, title, locked) values
				('user_alice', 'a1', false), ('user_alice', 'a-locked', true),
				('user_bob', 'b1', false), ('user_bob', 'public', false)`); err != nil {
				t.Fatalf("owner inserting for other users: %v", err)
			}

			app, err := sql.Open("pgx", liveDSNAs(t, adminDSN, "app_user", "app-pw", name))
			if err != nil {
				t.Fatal(err)
			}
			app.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = app.Close() })

			alice := [][2]string{{}}
			alice[0][0], alice[0][1] = lc.user("user_alice")
			bob := [][2]string{{}}
			bob[0][0], bob[0][1] = lc.user("user_bob")

			// runs is fn as the runtime role: its own login, and the owner's
			// credential after SET LOCAL ROLE - both must behave the same.
			runs := func(label string, gucs [][2]string, fn func(*sql.Tx) error) {
				t.Helper()
				if err := inTx(t, app, gucs, false, fn); err != nil {
					t.Errorf("%s (app_user login): %v", label, err)
				}
				if err := inTx(t, db, gucs, false, func(tx *sql.Tx) error {
					if _, err := tx.Exec("set local role app_user"); err != nil {
						return err
					}
					return fn(tx)
				}); err != nil {
					t.Errorf("%s (owner, set role app_user): %v", label, err)
				}
			}
			check := func(label string, gucs [][2]string, query string, want int) {
				t.Helper()
				runs(label, gucs, func(tx *sql.Tx) error {
					got, err := count(tx, query)
					if err != nil {
						return err
					}
					if got != want {
						t.Errorf("%s: %s = %d, want %d", label, query, got, want)
					}
					return nil
				})
			}
			all := "select count(*) from public.todos"
			if err := inTx(t, db, nil, false, func(tx *sql.Tx) error {
				got, err := count(tx, all)
				if err == nil && got != 4 {
					t.Errorf("owner sees %d rows, want all 4 (owners bypass RLS on tables that are not FORCEd)", got)
				}
				return err
			}); err != nil {
				t.Error(err)
			}
			check("alice sees her rows only", alice, all, 2)
			check("bob sees his rows only", bob, all, 2)
			check("no token sees the anon rows only", nil, all, 1)
			check("restrictive policy confines alice", alice,
				"with u as (update public.todos set title = 'x' where title = 'a-locked' returning 1) select count(*) from u", 0)
			check("alice updates her unlocked row", alice,
				"with u as (update public.todos set title = 'x' where title = 'a1' returning 1) select count(*) from u", 1)

			runs("alice inserts her own row", alice, func(tx *sql.Tx) error {
				_, err := tx.Exec(`insert into public.todos (owner_id, title) values ('user_alice', 'mine')`)
				return err
			})
			runs("alice cannot insert for bob", alice, func(tx *sql.Tx) error {
				_, err := tx.Exec(`insert into public.todos (owner_id, title) values ('user_bob', 'forged')`)
				if sqlState(err) != "42501" {
					t.Errorf("alice inserting a row for bob: err = %v, want 42501", err)
				}
				return nil
			})
			// A SECURITY DEFINER function runs as the owner, which bypasses RLS
			// here, so the cross-user write it exists for still works.
			runs("the definer writes past the caller's policies", alice, func(tx *sql.Tx) error {
				_, err := tx.Exec(`select public.gift_todo('user_bob', 'gift')`)
				return err
			})
		})
	}
}
