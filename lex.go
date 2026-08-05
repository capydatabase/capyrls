package capyrls

import "strings"

// A hand-rolled PostgreSQL lexer. It exists so the converter can walk real
// token streams instead of regexing SQL: dollar-quoted bodies, nested block
// comments, escaped strings, and quoted identifiers all tokenize correctly,
// which is the difference between a converter and a foot-gun.

type tokKind int

const (
	tEOF tokKind = iota
	tWS
	tComment
	tIdent  // unquoted identifier or keyword; Val holds the lower-cased form
	tQIdent // "quoted" identifier; Val holds the decoded name
	tString // any string literal; Val holds the decoded content (best effort)
	tNumber
	tOp    // operator or punctuation
	tParam // positional parameter such as $1
)

type token struct {
	Kind tokKind
	Text string // raw source slice
	Val  string // decoded/folded value (see kind comments)
	Pos  int    // byte offset of Text in the source
	Line int    // 1-based line of the token start
}

func (t token) isWord(w string) bool { return t.Kind == tIdent && t.Val == w }

// significant reports whether the token carries syntax (not trivia).
func (t token) significant() bool {
	return t.Kind != tWS && t.Kind != tComment && t.Kind != tEOF
}

// Multi-character operators, longest first so prefixes never shadow them.
var multiOps = []string{
	"->>", "#>>", "!~*",
	"::", ":=", "=>", "->", "#>", "||", "!=", "<>", "<=", ">=",
	"?|", "?&", "@>", "<@", "#-", "!~", "~*",
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || c == '$' || c >= '0' && c <= '9'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func lexSQL(src string) []token {
	var toks []token
	line := 1
	i := 0
	n := len(src)

	emit := func(kind tokKind, start int, val string) {
		text := src[start:i]
		toks = append(toks, token{Kind: kind, Text: text, Val: val, Pos: start, Line: line})
		line += strings.Count(text, "\n")
	}

	for i < n {
		start := i
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f':
			for i < n {
				c := src[i]
				if c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != '\v' && c != '\f' {
					break
				}
				i++
			}
			emit(tWS, start, "")

		case c == '-' && i+1 < n && src[i+1] == '-':
			for i < n && src[i] != '\n' {
				i++
			}
			emit(tComment, start, "")

		case c == '/' && i+1 < n && src[i+1] == '*':
			depth := 1
			i += 2
			for i < n && depth > 0 {
				switch {
				case src[i] == '/' && i+1 < n && src[i+1] == '*':
					depth++
					i += 2
				case src[i] == '*' && i+1 < n && src[i+1] == '/':
					depth--
					i += 2
				default:
					i++
				}
			}
			emit(tComment, start, "")

		case c == '\'':
			i = scanString(src, i, false)
			emit(tString, start, decodeString(src[start:i], false))

		case (c == 'e' || c == 'E') && i+1 < n && src[i+1] == '\'':
			i = scanString(src, i+1, true)
			emit(tString, start, decodeString(src[start+1:i], true))

		case (c == 'b' || c == 'B' || c == 'x' || c == 'X') && i+1 < n && src[i+1] == '\'':
			i = scanString(src, i+1, false)
			emit(tString, start, decodeString(src[start+1:i], false))

		case c == '"':
			i++
			for i < n {
				if src[i] == '"' {
					if i+1 < n && src[i+1] == '"' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			raw := src[start:i]
			val := raw
			if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
				val = strings.ReplaceAll(raw[1:len(raw)-1], `""`, `"`)
			}
			emit(tQIdent, start, val)

		case c == '$':
			// Dollar-quoted string ($tag$ ... $tag$), positional param ($1),
			// or a lone $ operator.
			j := i + 1
			for j < n && (isIdentStart(src[j]) || j > i+1 && isDigit(src[j])) {
				j++
			}
			if j < n && src[j] == '$' {
				delim := src[i : j+1]
				closeIdx := strings.Index(src[j+1:], delim)
				if closeIdx < 0 {
					i = n // unterminated: consume the rest
				} else {
					i = j + 1 + closeIdx + len(delim)
				}
				body := ""
				if closeIdx >= 0 {
					body = src[j+1 : j+1+closeIdx]
				}
				emit(tString, start, body)
			} else if i+1 < n && isDigit(src[i+1]) {
				i++
				for i < n && isDigit(src[i]) {
					i++
				}
				emit(tParam, start, src[start:i])
			} else {
				i++
				emit(tOp, start, "$")
			}

		case isIdentStart(c):
			for i < n && isIdentCont(src[i]) {
				i++
			}
			emit(tIdent, start, strings.ToLower(src[start:i]))

		case isDigit(c) || c == '.' && i+1 < n && isDigit(src[i+1]):
			if c == '0' && i+1 < n && (src[i+1] == 'x' || src[i+1] == 'X') {
				i += 2
				for i < n && (isDigit(src[i]) || src[i] >= 'a' && src[i] <= 'f' || src[i] >= 'A' && src[i] <= 'F' || src[i] == '_') {
					i++
				}
			} else {
				for i < n && (isDigit(src[i]) || src[i] == '_') {
					i++
				}
				if i < n && src[i] == '.' {
					i++
					for i < n && (isDigit(src[i]) || src[i] == '_') {
						i++
					}
				}
				if i < n && (src[i] == 'e' || src[i] == 'E') {
					j := i + 1
					if j < n && (src[j] == '+' || src[j] == '-') {
						j++
					}
					if j < n && isDigit(src[j]) {
						i = j
						for i < n && isDigit(src[i]) {
							i++
						}
					}
				}
			}
			emit(tNumber, start, src[start:i])

		default:
			matched := false
			for _, op := range multiOps {
				if strings.HasPrefix(src[i:], op) {
					i += len(op)
					emit(tOp, start, op)
					matched = true
					break
				}
			}
			if !matched {
				i++
				emit(tOp, start, src[start:i])
			}
		}
	}
	return toks
}

// scanString scans a single-quoted string starting at the opening quote and
// returns the index just past the closing quote. backslash toggles E-string
// escape handling; ” doubling is always honored.
func scanString(src string, i int, backslash bool) int {
	n := len(src)
	i++ // opening quote
	for i < n {
		switch {
		case backslash && src[i] == '\\':
			i += 2
		case src[i] == '\'':
			if i+1 < n && src[i+1] == '\'' {
				i += 2
				continue
			}
			return i + 1
		default:
			i++
		}
	}
	return n
}

// decodeString extracts the literal content of a quoted string token.
// Escape decoding is best effort: it covers what claim names in policy
// expressions realistically contain.
func decodeString(raw string, backslash bool) string {
	if len(raw) < 2 || raw[0] != '\'' {
		return raw
	}
	body := raw[1:]
	if body[len(body)-1] == '\'' {
		body = body[:len(body)-1]
	}
	body = strings.ReplaceAll(body, "''", "'")
	if backslash {
		body = strings.ReplaceAll(body, `\'`, "'")
		body = strings.ReplaceAll(body, `\\`, `\`)
	}
	return body
}

// nextSig returns the index of the first significant token at or after i,
// or len(toks) when none remain.
func nextSig(toks []token, i int) int {
	for ; i < len(toks); i++ {
		if toks[i].significant() {
			return i
		}
	}
	return len(toks)
}

// prevSig returns the index of the last significant token before i, or -1.
func prevSig(toks []token, i int) int {
	for i--; i >= 0; i-- {
		if toks[i].significant() {
			return i
		}
	}
	return -1
}
