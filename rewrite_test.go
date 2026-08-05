package capyrls

import (
	"strings"
	"testing"
)

func TestRewriteVanillaExpressions(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"uid wrap", `auth.uid() = user_id`, `(select app.user_id()) = user_id`},
		{"already wrapped", `( SELECT auth.uid() AS uid) = user_id`, `( SELECT app.user_id() AS uid) = user_id`},
		{"role", `auth.role() = 'authenticated'`, `(select app.role()) = 'authenticated'`},
		{"email", `auth.email() = email`, `(select app.email()) = email`},
		{"jwt sub keeps text typing", `(auth.jwt() ->> 'sub')::uuid = id`, `((select app.user_id())::text)::uuid = id`},
		{"jwt role", `auth.jwt() ->> 'role' = 'admin'`, `(select app.role()) = 'admin'`},
		{"claim promotion", `org_id::text = auth.jwt() ->> 'org_id'`, `org_id::text = (select app.org_id())`},
		{"deep path falls back to blob", `(auth.jwt() -> 'app_metadata' ->> 'tier') = 'pro'`, `((select app.claims()) -> 'app_metadata' ->> 'tier') = 'pro'`},
		{"bare jwt blob", `auth.jwt() ? 'admin'`, `(select app.claims()) ? 'admin'`},
		{"spacing preserved", `owner_id =  auth.uid()  and true`, `owner_id =  (select app.user_id())  and true`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rw := newRewriter(dialectVanilla, "app")
			out := rw.rewriteExpr(tc.in, true)
			if len(out.Blockers) != 0 {
				t.Fatalf("unexpected blockers: %v", out.Blockers)
			}
			if out.SQL != tc.want {
				t.Fatalf("got  %q\nwant %q", out.SQL, tc.want)
			}
		})
	}
}

func TestRewriteNoSubqueryContext(t *testing.T) {
	rw := newRewriter(dialectVanilla, "app")
	out := rw.rewriteExpr(`auth.uid()`, false)
	if out.SQL != `app.user_id()` {
		t.Fatalf("DEFAULT-context rewrite must not use a subquery, got %q", out.SQL)
	}
}

func TestRewriteAuthUsersIsBlocker(t *testing.T) {
	rw := newRewriter(dialectVanilla, "app")
	out := rw.rewriteExpr(`exists (select 1 from auth.users u where u.id = auth.uid())`, true)
	if len(out.Blockers) != 1 || !strings.Contains(out.Blockers[0], "auth.users") {
		t.Fatalf("expected an auth.users blocker, got %v", out.Blockers)
	}
}

func TestRewriteCompatKeepsAuthCalls(t *testing.T) {
	rw := newRewriter(dialectCompat, "app")
	out := rw.rewriteExpr(`auth.uid() = user_id`, true)
	if out.SQL != `(select auth.uid()) = user_id` {
		t.Fatalf("compat should keep auth.uid() and only wrap it, got %q", out.SQL)
	}
}

func TestRewriteClaimCollisionFallsBack(t *testing.T) {
	rw := newRewriter(dialectVanilla, "app")
	first := rw.rewriteExpr(`auth.jwt() ->> 'org_id'`, true)
	if first.SQL != `(select app.org_id())` {
		t.Fatalf("first claim should promote, got %q", first.SQL)
	}
	second := rw.rewriteExpr(`auth.jwt() ->> 'Org-Id'`, true)
	if !strings.Contains(second.SQL, "app.claims()") {
		t.Fatalf("colliding claim should fall back to the blob, got %q", second.SQL)
	}
	if !rw.usedBlob {
		t.Fatal("collision must mark the blob accessor as used")
	}
	foundWarning := false
	for _, w := range rw.warnings {
		if strings.Contains(w, "Org-Id") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("collision must warn, warnings: %v", rw.warnings)
	}
}

func TestRewriteReservedClaimNameFallsBack(t *testing.T) {
	rw := newRewriter(dialectVanilla, "app")
	out := rw.rewriteExpr(`auth.jwt() ->> 'claims'`, true)
	if !strings.Contains(out.SQL, "app.claims()") {
		t.Fatalf("reserved accessor name must fall back to the blob, got %q", out.SQL)
	}
}

func TestRewriteQualifiedNonAuthUntouched(t *testing.T) {
	rw := newRewriter(dialectVanilla, "app")
	in := `myschema.auth.uid() = x` // x.auth - not the auth schema
	out := rw.rewriteExpr(in, true)
	if out.SQL != in {
		t.Fatalf("schema-qualified non-auth reference must stay untouched, got %q", out.SQL)
	}
}

func TestRewriteWarnsOnDirectRequestJWT(t *testing.T) {
	rw := newRewriter(dialectVanilla, "app")
	rw.rewriteExpr(`current_setting('request.jwt.claims', true)::json ->> 'sub' = 'x'`, true)
	if len(rw.warnings) == 0 || !strings.Contains(rw.warnings[0], "request.jwt") {
		t.Fatalf("expected a request.jwt warning, got %v", rw.warnings)
	}
}
