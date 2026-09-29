package capyrls

import (
	"fmt"
	"sort"
	"strings"
)

// SECURITY DEFINER functions and FORCE.
//
// A definer function runs as its owner, and on Supabase that owner bypassed row
// security - which is usually why the function is a definer at all: it writes
// rows the caller's own policies would not admit (an invitation accepted on
// someone else's behalf, a counter on a shared row). FORCE ROW LEVEL SECURITY
// applies policies to the owner too, so once a table is FORCEd the definer is
// filtered by the CALLER's context like any other query. Verified on
// postgres:18: the same cross-user insert that passes without FORCE fails with
// 42501 "new row violates row-level security policy" under it - or vanishes
// into a body's `exception when others` handler, which is the silent version.
//
// The report names every definer whose body writes a table that ends up
// FORCEd, with the fix for the configuration at hand. Detection reads the
// function body's own statements: writes through dynamic SQL (EXECUTE) or
// through another function are not seen.

// SecurityDefiner is a SECURITY DEFINER routine and the tables its body writes.
type SecurityDefiner struct {
	Name   QName
	Writes []QName // INSERT / UPDATE / DELETE / MERGE targets, in body order
	Origin string
}

// DefinerWrite is a report entry: a definer function that writes FORCEd tables.
type DefinerWrite struct {
	Function string   `json:"function"`
	Tables   []string `json:"tables"`
	Origin   string   `json:"origin"`
}

// AddSecurityDefiner records a SECURITY DEFINER routine from its body text,
// replacing an earlier definition of the same name. Used by the SQL parser and
// by external catalog builders such as the live subpackage.
func (c *Catalog) AddSecurityDefiner(name QName, body, origin string) {
	c.dropSecurityDefiner(name)
	c.Definers = append(c.Definers, SecurityDefiner{
		Name: name, Writes: writeTargets(lexSQL(body)), Origin: origin,
	})
}

func (c *Catalog) dropSecurityDefiner(name QName) {
	for i, d := range c.Definers {
		if d.Name.Key() == name.Key() {
			c.Definers = append(c.Definers[:i], c.Definers[i+1:]...)
			return
		}
	}
}

// isSecurityDefiner reports whether a CREATE FUNCTION statement's attributes
// say SECURITY DEFINER. The last SECURITY clause wins, as in Postgres; the
// body is a single string token, so words inside it never match here.
func isSecurityDefiner(toks []token) bool {
	definer := false
	for i := range toks {
		if !toks[i].isWord("security") {
			continue
		}
		j := nextSig(toks, i+1)
		if j == len(toks) {
			break
		}
		switch {
		case toks[j].isWord("definer"):
			definer = true
		case toks[j].isWord("invoker"):
			definer = false
		}
	}
	return definer
}

// routineBody returns the text a routine executes: its string-literal body
// (dollar-quoted or plain). Parameter DEFAULT strings are included, which is
// harmless - a string default cannot parse as a write statement.
func routineBody(toks []token) string {
	var b strings.Builder
	for _, t := range toks {
		if t.Kind == tString {
			b.WriteString(t.Val)
			b.WriteString("\n;\n")
		}
	}
	return b.String()
}

// Words that, placed before UPDATE, mean it is not an UPDATE statement:
// FOR [NO KEY] UPDATE locking, ON CONFLICT DO UPDATE (the target is the
// INSERT's), ON UPDATE referential actions, trigger event lists.
var notUpdateStatement = map[string]bool{
	"for": true, "key": true, "do": true, "on": true, "or": true,
	"before": true, "after": true, "of": true,
}

// writeTargets finds the tables a statement stream writes to:
// INSERT INTO t, UPDATE [ONLY] t [[AS] alias] SET, DELETE FROM [ONLY] t,
// MERGE INTO [ONLY] t.
func writeTargets(toks []token) []QName {
	var sig []token
	for _, t := range toks {
		if t.significant() {
			sig = append(sig, t)
		}
	}
	qnameAt := func(i int) (QName, int, bool) {
		if i < len(sig) && sig[i].isWord("only") {
			i++
		}
		if i >= len(sig) || sig[i].Kind != tIdent && sig[i].Kind != tQIdent {
			return QName{}, i, false
		}
		first := sig[i].Val
		if i+2 < len(sig) && sig[i+1].Kind == tOp && sig[i+1].Text == "." &&
			(sig[i+2].Kind == tIdent || sig[i+2].Kind == tQIdent) {
			return QName{Schema: first, Name: sig[i+2].Val}, i + 3, true
		}
		return QName{Name: first}, i + 1, true
	}

	seen := map[string]bool{}
	var out []QName
	add := func(q QName) {
		if !seen[q.Key()] {
			seen[q.Key()] = true
			out = append(out, q)
		}
	}
	for i := 0; i < len(sig); i++ {
		switch {
		case (sig[i].isWord("insert") || sig[i].isWord("merge")) && i+1 < len(sig) && sig[i+1].isWord("into"),
			sig[i].isWord("delete") && i+1 < len(sig) && sig[i+1].isWord("from"):
			if q, _, ok := qnameAt(i + 2); ok {
				add(q)
			}
		case sig[i].isWord("update"):
			if i > 0 && sig[i-1].Kind == tIdent && notUpdateStatement[sig[i-1].Val] {
				continue
			}
			q, next, ok := qnameAt(i + 1)
			if !ok {
				continue
			}
			// UPDATE t SET / UPDATE t alias SET / UPDATE t AS alias SET
			for k := next; k < len(sig) && k <= next+2; k++ {
				if sig[k].isWord("set") {
					add(q)
					break
				}
			}
		}
	}
	return out
}

// definerWrites matches every recorded definer against the tables that are
// FORCEd once the bundle is applied.
func definerWrites(cat *Catalog, forced map[string]QName) []DefinerWrite {
	byName := map[string][]QName{}
	for _, q := range forced {
		byName[q.Name] = append(byName[q.Name], q)
	}
	var out []DefinerWrite
	for _, d := range cat.Definers {
		if supabaseManagedSchemas[d.Name.EffectiveSchema()] {
			continue
		}
		var hits []string
		for _, w := range d.Writes {
			switch {
			case w.Schema != "":
				if q, ok := forced[w.Key()]; ok {
					hits = append(hits, q.Key())
				}
			default:
				// Unqualified: resolution depends on the function's search_path,
				// so any FORCEd table of that name is a candidate.
				for _, q := range byName[w.Name] {
					hits = append(hits, q.Key())
				}
			}
		}
		hits = dedupe(hits)
		if len(hits) == 0 {
			continue
		}
		sort.Strings(hits)
		out = append(out, DefinerWrite{Function: d.Name.Key(), Tables: hits, Origin: d.Origin})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Function < out[j].Function })
	return out
}

// definerFix is the remedy the report prints once above the list of definer
// functions, for the configuration at hand.
func definerFix(opts Options) string {
	const lead = "Each of these functions runs as the owner of your tables, and FORCE ROW LEVEL SECURITY " +
		"applies policies to the owner too - so a definer no longer bypasses row security. A write the " +
		"caller's own policies do not admit (the cross-user write that is usually why a function is " +
		"SECURITY DEFINER) now fails with 42501, or disappears into an `exception when others` handler."

	if opts.splitOnCapyDB() {
		return lead + " These tables were already FORCEd in your source. On CapyDB the owner is the split model's " +
			"service path, and no BYPASSRLS role exists or can be created to hand the functions to. Drop FORCE " +
			"on the tables they write to: the functions run as the owner, which bypasses row security on tables " +
			"that are not FORCEd, while " + opts.AppRole + " - which owns nothing - stays under the policies:\n\n" +
			"```sql\nalter table <schema>.<table> no force row level security;\n```\n\n" +
			"Keep FORCE only where the owner itself must be confined, and keep those functions' writes inside " +
			"what the caller's policies admit."
	}
	if opts.RoleModel == RoleSplit {
		return lead + fmt.Sprintf(" These tables were already FORCEd in your source. Hand the functions "+
			"to the BYPASSRLS service role the bundle creates, which skips policies as the old owner did:\n\n"+
			"```sql\nalter function <schema>.<function> owner to %s;\n```\n\n"+
			"Add the argument list if the name is overloaded.", QuoteIdent(opts.ServiceRole))
	}
	if !emitsServiceEscape(opts) {
		return lead + " This bundle has no service escape (--no-service-escape), so nothing lets these " +
			"writes past the policies: keep each function's writes inside what the caller's policies admit, " +
			"add a policy for the path it needs, or convert without --no-service-escape and raise the escape " +
			"inside the function."
	}

	var guc, raise, restore string
	if opts.Mode == ModeCompat {
		guc = "request.jwt.claims"
		raise = "perform set_config('request.jwt.claims', (auth.jwt() || '{\"role\": \"service_role\"}')::text, true);"
		restore = "perform set_config('request.jwt.claims', coalesce(prev, ''), true);"
	} else {
		guc = opts.Prefix + ".role"
		raise = fmt.Sprintf("perform set_config('%s.role', 'service', true);", opts.Prefix)
		restore = fmt.Sprintf("perform set_config('%s.role', coalesce(prev, ''), true);", opts.Prefix)
	}
	fix := lead + " If a function must write past the caller's policies, raise the service escape for the " +
		"length of its body and restore it before every RETURN (plpgsql - rewrite a `language sql` " +
		"function first):\n\n" +
		"```sql\ncreate or replace function <schema>.<function>(...) returns ... language plpgsql security definer\n" +
		"as $$\ndeclare\n  prev text := current_setting('" + guc + "', true);\nbegin\n  " + raise +
		"\n  -- the original body\n  " + restore + "\nend $$;\n```\n\n"
	if opts.Mode == ModeCompat {
		fix += "Merging into the claims keeps `sub`, so `auth.uid()` still names the caller inside the body. "
	}
	fix += "If the body raises, the rollback (of the transaction, or of the caller's savepoint) restores the " +
		"setting with it. `alter function ... set " + guc + " = ...` would be tidier, but setting a custom " +
		"parameter on a function needs SET privilege on that parameter, which a managed database role " +
		"(CapyDB's included) does not have - Postgres answers 42501 \"permission denied to set parameter\"."
	return fix
}
