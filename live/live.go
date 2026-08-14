// Package live builds a capyrls.Catalog by introspecting a running database
// instead of parsing SQL files. This is often the more faithful input: the
// server has already normalized every policy expression (pg_get_expr), and
// nothing depends on migration files being complete.
//
// It is driver-agnostic: pass any *sql.DB. The caller registers the driver
// (the capyrls CLI uses pgx's database/sql adapter).
package live

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	capyrls "github.com/capy-base/capyrls"
)

// authRefPattern matches expressions that call the Supabase auth helpers.
const authRefPattern = `auth\.(uid|jwt|role|email)\(`

// Load introspects the database and returns the RLS-relevant catalog.
func Load(ctx context.Context, db *sql.DB) (*capyrls.Catalog, error) {
	cat := capyrls.NewCatalog()

	if err := loadTables(ctx, db, cat); err != nil {
		return nil, fmt.Errorf("introspect row-security tables: %w", err)
	}
	if err := loadPolicies(ctx, db, cat); err != nil {
		return nil, fmt.Errorf("introspect policies: %w", err)
	}
	if err := loadDefaults(ctx, db, cat); err != nil {
		return nil, fmt.Errorf("introspect column defaults: %w", err)
	}
	if err := loadRoutines(ctx, db, cat); err != nil {
		return nil, fmt.Errorf("introspect functions: %w", err)
	}
	return cat, nil
}

func loadTables(ctx context.Context, db *sql.DB, cat *capyrls.Catalog) error {
	rows, err := db.QueryContext(ctx, `
		select n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
		from pg_catalog.pg_class c
		join pg_catalog.pg_namespace n on n.oid = c.relnamespace
		where c.relkind in ('r', 'p')
		  and (c.relrowsecurity or c.relforcerowsecurity)
		  and n.nspname not in ('pg_catalog', 'information_schema')
		order by n.nspname, c.relname`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var schema, name string
		var enabled, forced bool
		if err := rows.Scan(&schema, &name, &enabled, &forced); err != nil {
			return err
		}
		cat.SetTableRLS(capyrls.QName{Schema: schema, Name: name}, enabled, forced)
	}
	return rows.Err()
}

func loadPolicies(ctx context.Context, db *sql.DB, cat *capyrls.Catalog) error {
	rows, err := db.QueryContext(ctx, `
		select schemaname, tablename, policyname, permissive, cmd,
		       coalesce(array_to_string(roles, ','), ''),
		       coalesce(qual, ''), coalesce(with_check, '')
		from pg_catalog.pg_policies
		order by schemaname, tablename, policyname`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var schema, table, name, permissive, cmd, roles, qual, check string
		if err := rows.Scan(&schema, &table, &name, &permissive, &cmd, &roles, &qual, &check); err != nil {
			return err
		}
		policy := &capyrls.Policy{
			Name:       name,
			Table:      capyrls.QName{Schema: schema, Name: table},
			Permissive: !strings.EqualFold(permissive, "RESTRICTIVE"),
			Cmd:        parseCmd(cmd),
			Roles:      parseRoles(roles),
			Using:      qual,
			WithCheck:  check,
			Origin:     "database",
		}
		cat.AddPolicy(policy)
	}
	return rows.Err()
}

func parseCmd(cmd string) capyrls.PolicyCmd {
	switch strings.ToUpper(cmd) {
	case "SELECT":
		return capyrls.CmdSelect
	case "INSERT":
		return capyrls.CmdInsert
	case "UPDATE":
		return capyrls.CmdUpdate
	case "DELETE":
		return capyrls.CmdDelete
	default:
		return capyrls.CmdAll
	}
}

func parseRoles(joined string) []string {
	if joined == "" {
		return nil
	}
	var roles []string
	for role := range strings.SplitSeq(joined, ",") {
		role = strings.TrimSpace(role)
		if role == "" || role == "public" {
			continue
		}
		roles = append(roles, strings.ToLower(role))
	}
	return roles
}

func loadDefaults(ctx context.Context, db *sql.DB, cat *capyrls.Catalog) error {
	rows, err := db.QueryContext(ctx, `
		select n.nspname, c.relname, a.attname, pg_get_expr(d.adbin, d.adrelid)
		from pg_catalog.pg_attrdef d
		join pg_catalog.pg_class c on c.oid = d.adrelid
		join pg_catalog.pg_namespace n on n.oid = c.relnamespace
		join pg_catalog.pg_attribute a on a.attrelid = d.adrelid and a.attnum = d.adnum
		where n.nspname not in ('pg_catalog', 'information_schema')
		  and pg_get_expr(d.adbin, d.adrelid) ~ $1
		order by n.nspname, c.relname, a.attname`, authRefPattern)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var schema, table, column, expr string
		if err := rows.Scan(&schema, &table, &column, &expr); err != nil {
			return err
		}
		cat.AddDefault(capyrls.ColumnDefault{
			Table:  capyrls.QName{Schema: schema, Name: table},
			Column: column,
			Expr:   expr,
			Origin: "database",
		})
	}
	return rows.Err()
}

func loadRoutines(ctx context.Context, db *sql.DB, cat *capyrls.Catalog) error {
	rows, err := db.QueryContext(ctx, `
		select n.nspname, p.proname
		from pg_catalog.pg_proc p
		join pg_catalog.pg_namespace n on n.oid = p.pronamespace
		where p.prokind in ('f', 'p')
		  and n.nspname not in (
		    'pg_catalog', 'information_schema', 'auth', 'storage', 'realtime',
		    'vault', 'graphql', 'graphql_public', 'extensions', 'pgsodium',
		    'pgsodium_masks', 'supabase_functions', 'net', 'cron', 'pgbouncer'
		  )
		  and p.prosrc ~ $1
		order by n.nspname, p.proname`, authRefPattern)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var schema, name string
		if err := rows.Scan(&schema, &name); err != nil {
			return err
		}
		cat.AddRoutine(capyrls.Routine{
			Name:   capyrls.QName{Schema: schema, Name: name},
			Origin: "database",
		})
	}
	return rows.Err()
}
