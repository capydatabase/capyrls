package capyrls

import (
	"fmt"
	"strings"
)

// The parser consumes SQL sources (Supabase migration folders, pg_dump
// --schema-only output) and reduces them to a Catalog: the final state of
// every policy and row-security flag after CREATE/ALTER/DROP history is
// applied in order, plus every other object that references auth.*.

type statement struct {
	src    string
	toks   []token
	origin string
}

func (s statement) sliceText(fromPos, toPos int) string {
	return strings.TrimSpace(s.src[fromPos:toPos])
}

func splitStatements(src, name string) []statement {
	all := lexSQL(src)
	var stmts []statement
	var cur []token
	flush := func() {
		firstSig := nextSig(cur, 0)
		if firstSig == len(cur) {
			cur = nil
			return
		}
		stmts = append(stmts, statement{
			src:    src,
			toks:   cur,
			origin: fmt.Sprintf("%s:%d", name, cur[firstSig].Line),
		})
		cur = nil
	}
	for _, t := range all {
		if t.Kind == tOp && t.Text == ";" {
			flush()
			continue
		}
		cur = append(cur, t)
	}
	flush()
	return stmts
}

// cursor walks a statement's significant tokens.
type cursor struct {
	toks []token
	i    int
}

func (c *cursor) peek() token {
	j := nextSig(c.toks, c.i)
	if j == len(c.toks) {
		return token{Kind: tEOF}
	}
	return c.toks[j]
}

func (c *cursor) next() token {
	j := nextSig(c.toks, c.i)
	if j == len(c.toks) {
		c.i = j
		return token{Kind: tEOF}
	}
	c.i = j + 1
	return c.toks[j]
}

func (c *cursor) done() bool { return nextSig(c.toks, c.i) == len(c.toks) }

// matchWord consumes the given identifier words when they all appear next,
// in order; otherwise the cursor is unchanged.
func (c *cursor) matchWord(words ...string) bool {
	save := c.i
	for _, w := range words {
		t := c.next()
		if !t.isWord(w) {
			c.i = save
			return false
		}
	}
	return true
}

func (c *cursor) peekWord(w string) bool { return c.peek().isWord(w) }

func (c *cursor) matchOp(op string) bool {
	if t := c.peek(); t.Kind == tOp && t.Text == op {
		c.next()
		return true
	}
	return false
}

// identLike consumes an identifier (quoted or not) and returns its decoded
// name. Unquoted names fold to lower case, matching PostgreSQL.
func (c *cursor) identLike() (string, bool) {
	t := c.peek()
	switch t.Kind {
	case tIdent:
		c.next()
		return t.Val, true
	case tQIdent:
		c.next()
		return t.Val, true
	default:
		return "", false
	}
}

func (c *cursor) qname() (QName, bool) {
	first, ok := c.identLike()
	if !ok {
		return QName{}, false
	}
	if c.matchOp(".") {
		second, ok := c.identLike()
		if !ok {
			return QName{}, false
		}
		return QName{Schema: first, Name: second}, true
	}
	return QName{Name: first}, true
}

// parenExpr consumes a parenthesized expression and returns the raw source
// text between the outer parens.
func (c *cursor) parenExpr(s statement) (string, bool) {
	if !c.matchOp("(") {
		return "", false
	}
	startPos := -1
	depth := 1
	for {
		j := nextSig(c.toks, c.i)
		if j == len(c.toks) {
			return "", false // unterminated
		}
		t := c.toks[j]
		if startPos < 0 {
			startPos = t.Pos
		}
		if t.Kind == tOp {
			switch t.Text {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					c.i = j + 1
					if startPos == t.Pos { // empty parens
						return "", true
					}
					return s.sliceText(startPos, t.Pos), true
				}
			}
		}
		c.i = j + 1
	}
}

// ParseSQL builds a Catalog from SQL sources, applying statements in order.
func ParseSQL(sources []Source) (*Catalog, error) {
	cat := NewCatalog()
	for _, source := range sources {
		for _, stmt := range splitStatements(source.SQL, source.Name) {
			applyStatement(cat, stmt)
		}
	}
	return cat, nil
}

func applyStatement(cat *Catalog, stmt statement) {
	c := &cursor{toks: stmt.toks}
	switch {
	case c.matchWord("create"):
		c.matchWord("or", "replace")
		for c.peekWord("global") || c.peekWord("local") || c.peekWord("temporary") ||
			c.peekWord("temp") || c.peekWord("unlogged") {
			c.next()
		}
		switch {
		case c.matchWord("policy"):
			parseCreatePolicy(cat, c, stmt)
		case c.matchWord("table"):
			c.matchWord("if", "not", "exists")
			parseCreateTable(cat, c, stmt)
		case c.matchWord("function"), c.matchWord("procedure"):
			parseCreateRoutine(cat, c, stmt)
		default:
			noteAuthRefs(cat, stmt)
		}
	case c.matchWord("alter"):
		switch {
		case c.matchWord("policy"):
			parseAlterPolicy(cat, c, stmt)
		case c.matchWord("table"):
			c.matchWord("only")
			c.matchWord("if", "exists")
			parseAlterTable(cat, c, stmt)
		default:
			noteAuthRefs(cat, stmt)
		}
	case c.matchWord("drop"):
		if c.matchWord("policy") {
			parseDropPolicy(cat, c, stmt)
		}
	default:
		noteAuthRefs(cat, stmt)
	}
}

func parseCreatePolicy(cat *Catalog, c *cursor, stmt statement) {
	name, ok := c.identLike()
	if !ok || !c.matchWord("on") {
		cat.note(fmt.Sprintf("%s: could not parse CREATE POLICY statement", stmt.origin))
		return
	}
	table, ok := c.qname()
	if !ok {
		cat.note(fmt.Sprintf("%s: could not parse CREATE POLICY table name", stmt.origin))
		return
	}
	p := &Policy{Name: name, Table: table, Permissive: true, Cmd: CmdAll, Origin: stmt.origin}
	for !c.done() {
		switch {
		case c.matchWord("as"):
			if c.matchWord("restrictive") {
				p.Permissive = false
			} else {
				c.matchWord("permissive")
			}
		case c.matchWord("for"):
			switch {
			case c.matchWord("all"):
				p.Cmd = CmdAll
			case c.matchWord("select"):
				p.Cmd = CmdSelect
			case c.matchWord("insert"):
				p.Cmd = CmdInsert
			case c.matchWord("update"):
				p.Cmd = CmdUpdate
			case c.matchWord("delete"):
				p.Cmd = CmdDelete
			}
		case c.matchWord("to"):
			p.Roles = parseRoleList(c)
		case c.matchWord("using"):
			if expr, ok := c.parenExpr(stmt); ok {
				p.Using = expr
			}
		case c.matchWord("with"):
			c.matchWord("check")
			if expr, ok := c.parenExpr(stmt); ok {
				p.WithCheck = expr
			}
		default:
			cat.note(fmt.Sprintf("%s: unexpected token %q in CREATE POLICY %q", stmt.origin, c.peek().Text, name))
			return
		}
	}
	cat.upsertPolicy(p)
}

func parseRoleList(c *cursor) []string {
	var roles []string
	for {
		t := c.peek()
		var role string
		switch t.Kind {
		case tIdent:
			role = t.Val
		case tQIdent:
			role = t.Val
		default:
			return roles
		}
		c.next()
		roles = append(roles, role)
		if !c.matchOp(",") {
			return roles
		}
	}
}

func parseAlterPolicy(cat *Catalog, c *cursor, stmt statement) {
	name, ok := c.identLike()
	if !ok || !c.matchWord("on") {
		return
	}
	table, ok := c.qname()
	if !ok {
		return
	}
	p := cat.findPolicy(name, table)
	if p == nil {
		cat.note(fmt.Sprintf("%s: ALTER POLICY %q on %s has no matching CREATE POLICY in the scanned sources", stmt.origin, name, table.Key()))
		return
	}
	for !c.done() {
		switch {
		case c.matchWord("rename", "to"):
			if newName, ok := c.identLike(); ok {
				p.Name = newName
			}
		case c.matchWord("to"):
			p.Roles = parseRoleList(c)
		case c.matchWord("using"):
			if expr, ok := c.parenExpr(stmt); ok {
				p.Using = expr
			}
		case c.matchWord("with"):
			c.matchWord("check")
			if expr, ok := c.parenExpr(stmt); ok {
				p.WithCheck = expr
			}
		default:
			c.next()
		}
	}
}

func parseDropPolicy(cat *Catalog, c *cursor, stmt statement) {
	ifExists := c.matchWord("if", "exists")
	name, ok := c.identLike()
	if !ok || !c.matchWord("on") {
		return
	}
	table, ok := c.qname()
	if !ok {
		return
	}
	if !cat.dropPolicy(name, table) && !ifExists {
		cat.note(fmt.Sprintf("%s: DROP POLICY %q on %s has no matching CREATE POLICY in the scanned sources", stmt.origin, name, table.Key()))
	}
}

func parseAlterTable(cat *Catalog, c *cursor, stmt statement) {
	table, ok := c.qname()
	if !ok {
		return
	}
	for !c.done() {
		switch {
		case c.matchWord("enable", "row", "level", "security"):
			cat.table(table).RLSEnabled = true
		case c.matchWord("disable", "row", "level", "security"):
			cat.table(table).RLSEnabled = false
		case c.matchWord("no", "force", "row", "level", "security"):
			cat.table(table).RLSForced = false
		case c.matchWord("force", "row", "level", "security"):
			cat.table(table).RLSForced = true
		case c.matchWord("alter", "column"), c.matchWord("alter"):
			column, ok := c.identLike()
			if !ok {
				c.next()
				continue
			}
			if c.matchWord("set", "default") {
				expr := captureDefaultExpr(c, stmt)
				if exprReferencesAuth(expr) {
					cat.Defaults = append(cat.Defaults, ColumnDefault{
						Table: table, Column: column, Expr: expr, Origin: stmt.origin,
					})
				}
			}
		case c.matchWord("add", "column"), c.matchWord("add"):
			c.matchWord("if", "not", "exists")
			column, ok := c.identLike()
			if !ok {
				continue
			}
			element := captureUntilTopLevelComma(c)
			if expr := defaultExprIn(element, stmt); expr != "" && exprReferencesAuth(expr) {
				cat.Defaults = append(cat.Defaults, ColumnDefault{
					Table: table, Column: column, Expr: expr, Origin: stmt.origin,
				})
			}
		default:
			c.next()
		}
	}
}

// captureUntilTopLevelComma consumes and returns the significant tokens up to
// (but not past) the next comma outside parens.
func captureUntilTopLevelComma(c *cursor) []token {
	depth := 0
	var element []token
	for {
		j := nextSig(c.toks, c.i)
		if j == len(c.toks) {
			return element
		}
		t := c.toks[j]
		if t.Kind == tOp {
			switch t.Text {
			case "(":
				depth++
			case ")":
				depth--
			case ",":
				if depth == 0 {
					c.i = j + 1
					return element
				}
			}
		}
		element = append(element, t)
		c.i = j + 1
	}
}

// captureDefaultExpr consumes tokens up to the next top-level comma (the next
// ALTER TABLE action) and returns their source text.
func captureDefaultExpr(c *cursor, stmt statement) string {
	depth := 0
	startPos, endPos := -1, -1
	for {
		j := nextSig(c.toks, c.i)
		if j == len(c.toks) {
			break
		}
		t := c.toks[j]
		if t.Kind == tOp {
			switch t.Text {
			case "(":
				depth++
			case ")":
				depth--
			case ",":
				if depth == 0 {
					c.i = j + 1
					return stmt.sliceText(startPos, endPos)
				}
			}
		}
		if startPos < 0 {
			startPos = t.Pos
		}
		endPos = t.Pos + len(t.Text)
		c.i = j + 1
	}
	if startPos < 0 {
		return ""
	}
	return stmt.sliceText(startPos, endPos)
}

// Column-level keywords that terminate a DEFAULT expression inside a column
// definition, and element-leading keywords that mark table-level constraints.
var columnConstraintStops = map[string]bool{
	"not": true, "null": true, "check": true, "references": true,
	"primary": true, "unique": true, "constraint": true, "generated": true,
	"collate": true, "deferrable": true, "initially": true,
}

var tableConstraintLeads = map[string]bool{
	"constraint": true, "primary": true, "foreign": true, "unique": true,
	"check": true, "exclude": true, "like": true,
}

func parseCreateTable(cat *Catalog, c *cursor, stmt statement) {
	table, ok := c.qname()
	if !ok || !c.matchOp("(") {
		return
	}
	// Walk column definitions at depth 1, looking for DEFAULT expressions
	// that reference auth.*.
	depth := 1
	var element []token
	flushElement := func() {
		scanColumnDefault(cat, table, element, stmt)
		element = nil
	}
	for {
		j := nextSig(c.toks, c.i)
		if j == len(c.toks) {
			break
		}
		t := c.toks[j]
		c.i = j + 1
		if t.Kind == tOp {
			switch t.Text {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					flushElement()
					return
				}
			case ",":
				if depth == 1 {
					flushElement()
					continue
				}
			}
		}
		element = append(element, t)
	}
	flushElement()
}

func scanColumnDefault(cat *Catalog, table QName, element []token, stmt statement) {
	first := nextSig(element, 0)
	if first == len(element) {
		return
	}
	lead := element[first]
	if lead.Kind == tIdent && tableConstraintLeads[lead.Val] {
		return
	}
	column := lead.Val
	expr := defaultExprIn(element[first+1:], stmt)
	if expr != "" && exprReferencesAuth(expr) {
		cat.Defaults = append(cat.Defaults, ColumnDefault{
			Table: table, Column: column, Expr: expr, Origin: stmt.origin,
		})
	}
}

// defaultExprIn locates a depth-0 DEFAULT keyword inside a column-definition
// token run and returns its expression text, stopping at the next
// column-constraint keyword.
func defaultExprIn(element []token, stmt statement) string {
	depth := 0
	for i := 0; i < len(element); i++ {
		t := element[i]
		if t.Kind == tOp {
			switch t.Text {
			case "(":
				depth++
			case ")":
				depth--
			}
			continue
		}
		if depth != 0 || !t.isWord("default") {
			continue
		}
		startPos, endPos := -1, -1
		exprDepth := 0
		for j := i + 1; j < len(element); j++ {
			et := element[j]
			if !et.significant() {
				continue
			}
			if et.Kind == tOp {
				switch et.Text {
				case "(":
					exprDepth++
				case ")":
					exprDepth--
				}
			}
			if exprDepth == 0 && et.Kind == tIdent && columnConstraintStops[et.Val] && startPos >= 0 {
				break
			}
			if startPos < 0 {
				startPos = et.Pos
			}
			endPos = et.Pos + len(et.Text)
		}
		if startPos < 0 {
			return ""
		}
		return stmt.sliceText(startPos, endPos)
	}
	return ""
}

func parseCreateRoutine(cat *Catalog, c *cursor, stmt statement) {
	name, ok := c.qname()
	if !ok {
		return
	}
	// A routine body is a string token (dollar-quoted or plain); references
	// can also appear in DEFAULT parameter values or the SQL-standard body.
	for _, t := range stmt.toks {
		hit := false
		switch t.Kind {
		case tString:
			hit = strings.Contains(strings.ToLower(t.Val), "auth.")
		case tIdent:
			// covered by the expression scan below
		}
		if hit {
			cat.Routines = append(cat.Routines, Routine{Name: name, Origin: stmt.origin})
			return
		}
	}
	if tokensReferenceAuth(stmt.toks) {
		cat.Routines = append(cat.Routines, Routine{Name: name, Origin: stmt.origin})
	}
}

// noteAuthRefs records a warning when an otherwise-unhandled statement
// references auth.* (views, triggers, grants, ...).
func noteAuthRefs(cat *Catalog, stmt statement) {
	if tokensReferenceAuth(stmt.toks) {
		firstSig := nextSig(stmt.toks, 0)
		head := ""
		for k, j := 0, firstSig; k < 3 && j < len(stmt.toks); k++ {
			head += stmt.toks[j].Text + " "
			j = nextSig(stmt.toks, j+1)
		}
		cat.note(fmt.Sprintf("%s: statement %q references auth.* and is outside the converter's scope - review manually", stmt.origin, strings.TrimSpace(head)+" ..."))
	}
}

// tokensReferenceAuth reports whether a token stream contains a reference to
// the auth schema (auth.<anything>).
func tokensReferenceAuth(toks []token) bool {
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		isAuth := t.Kind == tIdent && t.Val == "auth" || t.Kind == tQIdent && t.Val == "auth"
		if !isAuth {
			continue
		}
		if p := prevSig(toks, i); p >= 0 && toks[p].Kind == tOp && toks[p].Text == "." {
			continue // x.auth - not the auth schema
		}
		j := nextSig(toks, i+1)
		if j < len(toks) && toks[j].Kind == tOp && toks[j].Text == "." {
			return true
		}
	}
	return false
}

func exprReferencesAuth(expr string) bool {
	return tokensReferenceAuth(lexSQL(expr))
}
