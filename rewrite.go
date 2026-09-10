package capyrls

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// The rewriter translates Supabase auth helpers inside SQL expressions into
// the target convention. It works on token streams, preserving every byte it
// does not deliberately change (whitespace, comments, casts, casing).
//
// Vanilla dialect mapping:
//
//	auth.uid()                 -> (select app.user_id())
//	auth.role()                -> (select app.role())
//	auth.email()               -> (select app.email())
//	auth.jwt() ->> 'sub'       -> (select app.user_id())::text
//	auth.jwt() ->> '<claim>'   -> (select app.<claim>())       [promoted claim]
//	auth.jwt() <anything else> -> (select app.claims()) ...    [blob fallback]
//
// Compat dialect keeps auth.* calls verbatim (the shim schema provides them)
// and only adds the scalar-subquery wrapper so the planner caches the call.
//
// Anything referencing auth.<not-a-helper> (most importantly auth.users) is a
// blocker: the surrounding policy cannot port mechanically and is surfaced in
// the report instead of being silently mistranslated.

type dialectKind int

const (
	dialectVanilla dialectKind = iota
	dialectCompat
)

// Claim accessor names reserved by the prelude itself.
var reservedAccessors = map[string]bool{
	"user_id": true, "role": true, "email": true, "claims": true, "is_service": true,
}

type rewriter struct {
	dialect  dialectKind
	prefix   string
	claims   map[string]string // accessor name -> original JWT claim
	usedBlob bool
	usedUser bool
	usedRole bool
	usedMail bool
	warnings []string
}

func newRewriter(d dialectKind, prefix string) *rewriter {
	return &rewriter{dialect: d, prefix: prefix, claims: map[string]string{}}
}

func (rw *rewriter) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if slices.Contains(rw.warnings, msg) {
		return
	}
	rw.warnings = append(rw.warnings, msg)
}

func (rw *rewriter) sortedClaims() []ClaimMapping {
	names := make([]string, 0, len(rw.claims))
	for name := range rw.claims {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ClaimMapping, 0, len(names))
	for _, name := range names {
		out = append(out, ClaimMapping{
			Claim:    rw.claims[name],
			Accessor: rw.prefix + "." + name + "()",
			GUC:      rw.prefix + "." + name,
		})
	}
	return out
}

type exprOutcome struct {
	SQL      string
	Blockers []string
}

// rewriteExpr rewrites one SQL expression. allowSubquery controls the
// (select ...) initplan wrapper: it must be off inside contexts that forbid
// subqueries, such as column DEFAULT expressions.
func (rw *rewriter) rewriteExpr(expr string, allowSubquery bool) exprOutcome {
	toks := lexSQL(expr)
	var out strings.Builder
	var blockers []string

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		isAuth := (t.Kind == tIdent || t.Kind == tQIdent) && t.Val == "auth"
		if isAuth {
			if p := prevSig(toks, i); p >= 0 && toks[p].Kind == tOp && toks[p].Text == "." {
				isAuth = false // x.auth - not the auth schema
			}
		}
		if !isAuth {
			if t.Kind == tIdent && t.Val == "current_setting" {
				if arg := firstStringArg(toks, i); strings.HasPrefix(arg, "request.jwt") {
					rw.warn("expression reads current_setting('%s') directly; the converted context uses %s.* GUCs - review this expression manually", arg, rw.prefix)
				}
			}
			out.WriteString(t.Text)
			continue
		}

		dot := nextSig(toks, i+1)
		if dot == len(toks) || toks[dot].Kind != tOp || toks[dot].Text != "." {
			out.WriteString(t.Text)
			continue
		}
		memberIdx := nextSig(toks, dot+1)
		if memberIdx == len(toks) {
			out.WriteString(t.Text)
			continue
		}
		member := toks[memberIdx]
		open := nextSig(toks, memberIdx+1)
		isCall := member.Kind == tIdent && open < len(toks) && toks[open].Kind == tOp && toks[open].Text == "("
		var closeIdx int
		if isCall {
			closeIdx = nextSig(toks, open+1)
			if closeIdx == len(toks) || toks[closeIdx].Kind != tOp || toks[closeIdx].Text != ")" {
				isCall = false // auth.something(args...) - not a known zero-arg helper
			}
		}
		if !isCall || !isAuthHelper(member.Val) {
			blockers = append(blockers, fmt.Sprintf("references auth.%s", member.Val))
			out.WriteString(t.Text)
			continue
		}

		wrapped := allowSubquery && !insideScalarSubquery(toks, i)
		replacement, consumedThrough := rw.replaceHelper(toks, member.Val, closeIdx, wrapped)
		out.WriteString(replacement)
		// Skip everything the replacement covered, then continue with the
		// remaining raw tokens.
		i = consumedThrough
	}
	return exprOutcome{SQL: out.String(), Blockers: blockers}
}

func isAuthHelper(name string) bool {
	switch name {
	case "uid", "jwt", "role", "email":
		return true
	}
	return false
}

// replaceHelper renders the replacement text for one auth helper call and
// returns the last token index it consumed.
func (rw *rewriter) replaceHelper(toks []token, helper string, closeIdx int, wrap bool) (string, int) {
	if rw.dialect == dialectCompat {
		// Deliberately ignores `wrap`. Compat is the fidelity mode - the call is
		// emitted as written. Wrapping it as `(select auth.uid())` sets the
		// policy's hasSubLinks flag, and Postgres's static recursion check then
		// rejects any policy that reaches this table through it; the common case
		// is an INSERT whose WITH CHECK looks for a prior row, which fails with
		// "infinite recursion detected in policy". Verified on postgres:17, both
		// for this call site and for the role predicate in emit.go. A source
		// policy that wanted the initplan already spells it that way, and that
		// text is preserved verbatim.
		return "auth." + helper + "()", closeIdx
	}

	p := rw.prefix
	switch helper {
	case "uid":
		rw.usedUser = true
		return wrapCall(p+".user_id()", wrap), closeIdx
	case "role":
		rw.usedRole = true
		return wrapCall(p+".role()", wrap), closeIdx
	case "email":
		rw.usedMail = true
		return wrapCall(p+".email()", wrap), closeIdx
	}

	// auth.jwt(): look at what the caller does with the blob.
	opIdx := nextSig(toks, closeIdx+1)
	if opIdx < len(toks) && toks[opIdx].Kind == tOp && toks[opIdx].Text == "->>" {
		litIdx := nextSig(toks, opIdx+1)
		if litIdx < len(toks) && toks[litIdx].Kind == tString {
			claim := toks[litIdx].Val
			switch claim {
			case "sub":
				rw.usedUser = true
				return wrapCall(p+".user_id()", wrap) + "::text", litIdx
			case "role":
				rw.usedRole = true
				return wrapCall(p+".role()", wrap), litIdx
			case "email":
				rw.usedMail = true
				return wrapCall(p+".email()", wrap), litIdx
			}
			if accessor, ok := rw.promoteClaim(claim); ok {
				return wrapCall(p+"."+accessor+"()", wrap), litIdx
			}
		}
	}

	// Deep JSON paths, existence operators, or a bare blob: fall back to the
	// full claims accessor and keep the rest of the expression as written.
	rw.usedBlob = true
	rw.warn("auth.jwt() used beyond a top-level ->> claim; the app must set the full %s.claims JSON for those expressions", p)
	return wrapCall(p+".claims()", wrap), closeIdx
}

// promoteClaim maps a JWT claim to a dedicated accessor/GUC name. It returns
// ok=false when the claim cannot become a clean identifier or collides.
func (rw *rewriter) promoteClaim(claim string) (string, bool) {
	name := sanitizeClaimName(claim)
	if name == "" || reservedAccessors[name] {
		rw.usedBlob = true
		rw.warn("JWT claim %q cannot be promoted to a dedicated GUC; it stays in the %s.claims JSON blob", claim, rw.prefix)
		return "", false
	}
	if existing, ok := rw.claims[name]; ok && existing != claim {
		rw.usedBlob = true
		rw.warn("JWT claims %q and %q both map to %s.%s; %q stays in the %s.claims JSON blob", existing, claim, rw.prefix, name, claim, rw.prefix)
		return "", false
	}
	rw.claims[name] = claim
	return name, true
}

func sanitizeClaimName(claim string) string {
	lower := strings.ToLower(claim)
	var b strings.Builder
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" || len(name) > 48 {
		return ""
	}
	if name[0] < 'a' || name[0] > 'z' {
		return ""
	}
	return name
}

func wrapCall(core string, wrap bool) string {
	if wrap {
		return "(select " + core + ")"
	}
	return core
}

// insideScalarSubquery reports whether the token at idx is already the body
// of a scalar subquery - pg_get_expr renders policies as
// ( SELECT auth.uid() AS uid), and double-wrapping would be noise.
func insideScalarSubquery(toks []token, idx int) bool {
	p := prevSig(toks, idx)
	return p >= 0 && toks[p].isWord("select")
}

// firstStringArg returns the first string literal argument of a call whose
// function name token is at idx, or "".
func firstStringArg(toks []token, idx int) string {
	open := nextSig(toks, idx+1)
	if open == len(toks) || toks[open].Kind != tOp || toks[open].Text != "(" {
		return ""
	}
	lit := nextSig(toks, open+1)
	if lit < len(toks) && toks[lit].Kind == tString {
		return toks[lit].Val
	}
	return ""
}

// rewriteSQLFile rewrites auth helper calls across a whole SQL file while
// leaving everything else byte-identical. Used by Rewrite (in-place mode),
// where migration history must stay shaped as the user wrote it.
func (rw *rewriter) rewriteSQLFile(src string) (string, []string) {
	outcome := rw.rewriteExpr(src, false)
	return outcome.SQL, outcome.Blockers
}
