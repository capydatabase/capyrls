package capyrls

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Under --uid-type text the user id is text, and Postgres has no implicit
// conversion between text and uuid. So anything still comparing it to a uuid
// column breaks - but loudly, at apply time, never silently. Verified on
// postgres:18:
//
//	policy     (select app.user_id()) = uuid_col       42883 operator does not exist: text = uuid
//	policy     app.user_id() in (select uuid_col ...)  42883, same
//	default    alter column uuid_col set default ...   42804 default expression is of type text
//	function   language sql body comparing to uuid    42883 at CREATE FUNCTION
//	function   language plpgsql body, same             42883 only when CALLED (late-bound)
//
// capyrls deliberately does not cast the column side (uuid_col::text = ...):
// that makes the predicate non-sargable, so every RLS-filtered scan loses its
// index, and a uuid column cannot hold a non-uuid subject anyway - the cast
// would turn a loud apply error into a policy that silently matches nothing.
// The fix belongs in the schema: the column becomes text.
//
// What this file adds is the early warning: the report names each uuid column
// the user id is compared to directly, so the operator changes it before
// applying the bundle rather than after the apply fails. Detection is
// deliberately bounded - references through a table alias are not resolved;
// Postgres rejects those at apply time instead.

// uuidColumnUse is one uuid column the user id meets.
type uuidColumnUse struct {
	table     QName
	column    string
	policies  []string
	asDefault bool
}

// uidTextCheck collects the uuid columns that --uid-type text breaks.
type uidTextCheck struct {
	cat  *Catalog
	uses map[string]*uuidColumnUse
}

func newUIDTextCheck(cat *Catalog) *uidTextCheck {
	return &uidTextCheck{cat: cat, uses: map[string]*uuidColumnUse{}}
}

func (c *uidTextCheck) use(table QName, column string) *uuidColumnUse {
	key := table.Key() + "." + column
	u := c.uses[key]
	if u == nil {
		u = &uuidColumnUse{table: table, column: column}
		c.uses[key] = u
	}
	return u
}

// policy records the uuid columns a policy compares the user id to and returns
// them as "schema.table.column" keys, for the policy's report detail.
func (c *uidTextCheck) policy(p *Policy) []string {
	var keys []string
	for _, expr := range []string{p.Using, p.WithCheck} {
		for _, ref := range uidComparedColumns(expr, p.Table) {
			if c.cat.columnType(ref.table, ref.column) != "uuid" {
				continue
			}
			u := c.use(ref.table, ref.column)
			if !slices.Contains(u.policies, p.Name) {
				u.policies = append(u.policies, p.Name)
			}
			key := ref.table.Key() + "." + ref.column
			if !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// policyNote is the report detail for a policy that compares the user id to a
// uuid column.
func policyNote(columns []string) string {
	return fmt.Sprintf("compares the user id to uuid column %s - fails to apply under --uid-type text (see Warnings)",
		strings.Join(columns, ", "))
}

// warnings returns one warning per broken uuid column (policies plus column
// defaults) and the general text-mode contract.
func (c *uidTextCheck) warnings(opts Options) []string {
	for _, d := range c.cat.Defaults {
		if supabaseManagedSchemas[d.Table.EffectiveSchema()] {
			continue
		}
		if c.cat.columnType(d.Table, d.Column) == "uuid" && exprCallsUID(d.Expr) {
			c.use(d.Table, d.Column).asDefault = true
		}
	}

	accessor := opts.Prefix + ".user_id()"
	if opts.Mode == ModeCompat {
		accessor = "auth.uid()"
	}
	general := fmt.Sprintf("--uid-type text: the user id (`%s`) is text, so every column and value it is compared to must be text too. Postgres has no implicit text-to-uuid conversion: policies, column defaults and SQL functions that compare it to a uuid fail when the bundle is applied, never silently", accessor)
	if len(c.cat.Routines) > 0 {
		general += "; plpgsql function bodies are only checked when called - review the functions listed under Functions to review"
	}
	out := []string{general}

	keys := make([]string, 0, len(c.uses))
	for key := range c.uses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		u := c.uses[key]
		var how []string
		if len(u.policies) > 0 {
			sort.Strings(u.policies)
			label := "policy"
			if len(u.policies) > 1 {
				label = "policies"
			}
			how = append(how, fmt.Sprintf("is compared to the user id by %s %s", label, strings.Join(u.policies, ", ")))
		}
		if u.asDefault {
			how = append(how, "takes the user id as its default")
		}
		col := QuoteIdent(u.column)
		out = append(out, fmt.Sprintf(
			"uuid column %s %s: under --uid-type text applying the bundle fails there - change the column to text first (`alter table %s alter column %s type text using %s::text`; a foreign key on it must change type on both sides)",
			key, strings.Join(how, " and "), u.table, col, col))
	}
	return out
}

// columnRef is a column reference resolved to a table.
type columnRef struct {
	table  QName
	column string
}

// uidComparedColumns returns the column references an expression compares
// auth.uid() to directly with =, <> or !=, on either side:
//
//	auth.uid() = owner_id
//	(select auth.uid()) = t.owner_id
//	owner_id = ( SELECT auth.uid() AS uid)   -- pg_get_expr's rendering
//
// An unqualified column, or one qualified by the policy table's own name,
// resolves to the policy table; table.column and schema.table.column resolve
// to that table. A cast on either side (owner_id::text) means the comparison is
// not text = uuid and is skipped.
func uidComparedColumns(expr string, table QName) []columnRef {
	var sig []token
	for _, t := range lexSQL(expr) {
		if t.significant() {
			sig = append(sig, t)
		}
	}
	var refs []columnRef
	for i := range sig {
		if !isUIDCall(sig, i) {
			continue
		}
		start, end := i, i+4
		// Widen over a scalar-subquery wrapper: ( select auth.uid() [as x] ).
		if start >= 2 && sig[start-1].isWord("select") && isOp(sig[start-2], "(") {
			e := end + 1
			if e < len(sig) && sig[e].isWord("as") {
				e += 2
			}
			if e < len(sig) && isOp(sig[e], ")") {
				start, end = start-2, e
			}
		}
		if start >= 2 && isComparison(sig[start-1]) {
			if parts, ok := identChainEndingAt(sig, start-2); ok {
				refs = appendRef(refs, parts, table)
			}
		}
		if end+2 < len(sig) && isComparison(sig[end+1]) {
			if parts, ok := identChainStartingAt(sig, end+2); ok {
				refs = appendRef(refs, parts, table)
			}
		}
	}
	return refs
}

// exprCallsUID reports whether an expression calls auth.uid().
func exprCallsUID(expr string) bool {
	var sig []token
	for _, t := range lexSQL(expr) {
		if t.significant() {
			sig = append(sig, t)
		}
	}
	for i := range sig {
		if isUIDCall(sig, i) {
			return true
		}
	}
	return false
}

// isUIDCall reports whether sig[i:i+5] is `auth . uid ( )` and not the tail of
// a longer qualified name.
func isUIDCall(sig []token, i int) bool {
	if i+4 >= len(sig) || !isIdentToken(sig[i]) || sig[i].Val != "auth" {
		return false
	}
	if i > 0 && isOp(sig[i-1], ".") {
		return false
	}
	return isOp(sig[i+1], ".") && sig[i+2].isWord("uid") && isOp(sig[i+3], "(") && isOp(sig[i+4], ")")
}

func appendRef(refs []columnRef, parts []string, table QName) []columnRef {
	switch len(parts) {
	case 1:
		return append(refs, columnRef{table: table, column: parts[0]})
	case 2:
		if parts[0] == table.Name {
			return append(refs, columnRef{table: table, column: parts[1]})
		}
		return append(refs, columnRef{table: QName{Name: parts[0]}, column: parts[1]})
	case 3:
		return append(refs, columnRef{table: QName{Schema: parts[0], Name: parts[1]}, column: parts[2]})
	}
	return refs
}

// identChainEndingAt reads a dotted identifier chain whose last token is at
// end, rejecting it when it is a cast target (::type) or part of a longer
// expression it does not own.
func identChainEndingAt(sig []token, end int) ([]string, bool) {
	if end < 0 || !isIdentToken(sig[end]) {
		return nil, false
	}
	parts := []string{sig[end].Val}
	i := end
	for i >= 2 && isOp(sig[i-1], ".") && isIdentToken(sig[i-2]) {
		parts = append([]string{sig[i-2].Val}, parts...)
		i -= 2
	}
	if i >= 1 && (isOp(sig[i-1], "::") || isOp(sig[i-1], ".")) {
		return nil, false
	}
	return parts, true
}

// identChainStartingAt reads a dotted identifier chain starting at start,
// rejecting it when it is followed by a call, a cast or a subscript.
func identChainStartingAt(sig []token, start int) ([]string, bool) {
	if start >= len(sig) || !isIdentToken(sig[start]) {
		return nil, false
	}
	parts := []string{sig[start].Val}
	i := start
	for i+2 < len(sig) && isOp(sig[i+1], ".") && isIdentToken(sig[i+2]) {
		parts = append(parts, sig[i+2].Val)
		i += 2
	}
	if i+1 < len(sig) && (isOp(sig[i+1], "(") || isOp(sig[i+1], "::") || isOp(sig[i+1], "[") || isOp(sig[i+1], ".")) {
		return nil, false
	}
	return parts, true
}

func isIdentToken(t token) bool { return t.Kind == tIdent || t.Kind == tQIdent }

func isOp(t token, op string) bool { return t.Kind == tOp && t.Text == op }

func isComparison(t token) bool {
	return isOp(t, "=") || isOp(t, "<>") || isOp(t, "!=")
}
