package capyrls

import "testing"

func kinds(toks []token) []tokKind {
	var out []tokKind
	for _, t := range toks {
		if t.significant() {
			out = append(out, t.Kind)
		}
	}
	return out
}

func TestLexDollarQuoting(t *testing.T) {
	toks := lexSQL(`create function f() as $body$ select 'x'; -- not a comment $ $body$ language sql`)
	var strTok *token
	for i := range toks {
		if toks[i].Kind == tString {
			strTok = &toks[i]
			break
		}
	}
	if strTok == nil {
		t.Fatal("no dollar-quoted string token found")
	}
	if strTok.Val != ` select 'x'; -- not a comment $ ` {
		t.Fatalf("dollar body decoded wrong: %q", strTok.Val)
	}
	// The semicolon inside the body must not have leaked out as an operator.
	for _, tok := range toks {
		if tok.Kind == tOp && tok.Text == ";" {
			t.Fatal("semicolon inside dollar-quoted body leaked as an operator token")
		}
	}
}

func TestLexNestedBlockComment(t *testing.T) {
	toks := lexSQL(`a /* outer /* inner */ still outer */ b`)
	sig := kinds(toks)
	if len(sig) != 2 || sig[0] != tIdent || sig[1] != tIdent {
		t.Fatalf("expected exactly two identifiers around the nested comment, got %v", sig)
	}
}

func TestLexEscapedStrings(t *testing.T) {
	toks := lexSQL(`select E'it\'s', 'double''d'`)
	var vals []string
	for _, tok := range toks {
		if tok.Kind == tString {
			vals = append(vals, tok.Val)
		}
	}
	if len(vals) != 2 || vals[0] != "it's" || vals[1] != "double'd" {
		t.Fatalf("string decoding wrong: %#v", vals)
	}
}

func TestLexQuotedIdent(t *testing.T) {
	toks := lexSQL(`"Weird""Name"`)
	if len(toks) != 1 || toks[0].Kind != tQIdent || toks[0].Val != `Weird"Name` {
		t.Fatalf("quoted ident decoded wrong: %#v", toks)
	}
}

func TestLexJSONOperators(t *testing.T) {
	toks := lexSQL(`j ->> 'a' -> 'b' #>> '{c}' :: text`)
	var ops []string
	for _, tok := range toks {
		if tok.Kind == tOp {
			ops = append(ops, tok.Text)
		}
	}
	want := []string{"->>", "->", "#>>", "::"}
	if len(ops) != len(want) {
		t.Fatalf("operators: got %v want %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("operators: got %v want %v", ops, want)
		}
	}
}

func TestLexLineNumbers(t *testing.T) {
	toks := lexSQL("select 1;\n\ncreate policy p")
	for _, tok := range toks {
		if tok.isWord("create") && tok.Line != 3 {
			t.Fatalf("create is on line 3, lexer says %d", tok.Line)
		}
	}
}

func TestLexParams(t *testing.T) {
	toks := lexSQL(`$1 $tag$x$tag$ $2`)
	var params, strs int
	for _, tok := range toks {
		switch tok.Kind {
		case tParam:
			params++
		case tString:
			strs++
		}
	}
	if params != 2 || strs != 1 {
		t.Fatalf("params=%d strings=%d, want 2 and 1", params, strs)
	}
}
