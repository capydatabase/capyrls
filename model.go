package capyrls

import (
	"sort"
	"strings"
)

// QName is a possibly schema-qualified identifier. Schema is "" when the
// source SQL left the name unqualified; Key() folds that to "public", which
// matches how unqualified DDL resolves in the dumps this tool consumes.
type QName struct {
	Schema string
	Name   string
}

func (q QName) Key() string {
	s := q.Schema
	if s == "" {
		s = "public"
	}
	return s + "." + q.Name
}

func (q QName) EffectiveSchema() string {
	if q.Schema == "" {
		return "public"
	}
	return q.Schema
}

func (q QName) String() string {
	if q.Schema == "" {
		return QuoteIdent(q.Name)
	}
	return QuoteIdent(q.Schema) + "." + QuoteIdent(q.Name)
}

// PolicyCmd is the command class a policy applies to.
type PolicyCmd string

const (
	CmdAll    PolicyCmd = "ALL"
	CmdSelect PolicyCmd = "SELECT"
	CmdInsert PolicyCmd = "INSERT"
	CmdUpdate PolicyCmd = "UPDATE"
	CmdDelete PolicyCmd = "DELETE"
)

// Policy is one row-security policy in its final (post-ALTER) state.
type Policy struct {
	Name       string
	Table      QName
	Permissive bool
	Cmd        PolicyCmd
	Roles      []string // lower-cased role names; empty means PUBLIC
	Using      string   // raw expression SQL without the outer parens; "" if absent
	WithCheck  string
	Origin     string // "<file>:<line>" or "database"
}

// Table records row-security state for one relation.
type Table struct {
	Name       QName
	RLSEnabled bool
	RLSForced  bool
}

// ColumnDefault is a column default expression that references auth.*.
type ColumnDefault struct {
	Table  QName
	Column string
	Expr   string
	Origin string
}

// Routine is a function or procedure whose body references auth.*.
// Def carries the full CREATE definition when introspected live; it is ""
// when the reference was found while scanning SQL files.
type Routine struct {
	Name   QName
	Def    string
	Origin string
}

// Catalog is the RLS-relevant state extracted from SQL files or a live
// database: tables with row security, policies in final state, and the
// auth.*-referencing objects that need conversion or review.
type Catalog struct {
	Tables   map[string]*Table
	Policies []*Policy
	Defaults []ColumnDefault
	Routines []Routine
	Notes    []string
}

func NewCatalog() *Catalog {
	return &Catalog{Tables: map[string]*Table{}}
}

// SetTableRLS records a table's row-security flags. Used by external catalog
// builders such as the live subpackage.
func (c *Catalog) SetTableRLS(q QName, enabled, forced bool) {
	t := c.table(q)
	t.RLSEnabled = enabled
	t.RLSForced = forced
}

// AddPolicy inserts or replaces a policy by (name, table).
func (c *Catalog) AddPolicy(p *Policy) { c.upsertPolicy(p) }

// AddDefault records an auth-referencing column default.
func (c *Catalog) AddDefault(d ColumnDefault) { c.Defaults = append(c.Defaults, d) }

// AddRoutine records an auth-referencing function or procedure.
func (c *Catalog) AddRoutine(r Routine) { c.Routines = append(c.Routines, r) }

func (c *Catalog) table(q QName) *Table {
	key := q.Key()
	t := c.Tables[key]
	if t == nil {
		t = &Table{Name: q}
		c.Tables[key] = t
	}
	return t
}

func (c *Catalog) findPolicy(name string, table QName) *Policy {
	for _, p := range c.Policies {
		if p.Name == name && p.Table.Key() == table.Key() {
			return p
		}
	}
	return nil
}

func (c *Catalog) upsertPolicy(p *Policy) {
	if existing := c.findPolicy(p.Name, p.Table); existing != nil {
		*existing = *p
		return
	}
	c.Policies = append(c.Policies, p)
}

func (c *Catalog) dropPolicy(name string, table QName) bool {
	for i, p := range c.Policies {
		if p.Name == name && p.Table.Key() == table.Key() {
			c.Policies = append(c.Policies[:i], c.Policies[i+1:]...)
			return true
		}
	}
	return false
}

func (c *Catalog) note(msg string) {
	c.Notes = append(c.Notes, msg)
}

// sortedTables returns tables in deterministic key order.
func (c *Catalog) sortedTables() []*Table {
	keys := make([]string, 0, len(c.Tables))
	for k := range c.Tables {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*Table, 0, len(keys))
	for _, k := range keys {
		out = append(out, c.Tables[k])
	}
	return out
}

// reservedIdents is the set of PostgreSQL reserved (and type/function-name
// reserved) keywords that must be quoted when used as identifiers.
var reservedIdents = map[string]bool{
	"all": true, "analyse": true, "analyze": true, "and": true, "any": true,
	"array": true, "as": true, "asc": true, "asymmetric": true,
	"authorization": true, "binary": true, "both": true, "case": true,
	"cast": true, "check": true, "collate": true, "collation": true,
	"column": true, "concurrently": true, "constraint": true, "create": true,
	"cross": true, "current_catalog": true, "current_date": true,
	"current_role": true, "current_schema": true, "current_time": true,
	"current_timestamp": true, "current_user": true, "default": true,
	"deferrable": true, "desc": true, "distinct": true, "do": true,
	"else": true, "end": true, "except": true, "false": true, "fetch": true,
	"for": true, "foreign": true, "freeze": true, "from": true, "full": true,
	"grant": true, "group": true, "having": true, "ilike": true, "in": true,
	"initially": true, "inner": true, "intersect": true, "into": true,
	"is": true, "isnull": true, "join": true, "lateral": true,
	"leading": true, "left": true, "like": true, "limit": true,
	"localtime": true, "localtimestamp": true, "natural": true, "not": true,
	"notnull": true, "null": true, "offset": true, "on": true, "only": true,
	"or": true, "order": true, "outer": true, "overlaps": true,
	"placing": true, "primary": true, "references": true, "returning": true,
	"right": true, "select": true, "session_user": true, "similar": true,
	"some": true, "symmetric": true, "table": true, "tablesample": true,
	"then": true, "to": true, "trailing": true, "true": true, "union": true,
	"unique": true, "user": true, "using": true, "variadic": true,
	"verbose": true, "when": true, "where": true, "window": true, "with": true,
}

// QuoteIdent quotes a PostgreSQL identifier only when required.
func QuoteIdent(s string) string {
	if s == "" {
		return `""`
	}
	needQuote := reservedIdents[s]
	if !needQuote {
		for i, r := range s {
			if r >= 'a' && r <= 'z' || r == '_' {
				continue
			}
			if i > 0 && (r >= '0' && r <= '9' || r == '$') {
				continue
			}
			needQuote = true
			break
		}
	}
	if !needQuote {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
