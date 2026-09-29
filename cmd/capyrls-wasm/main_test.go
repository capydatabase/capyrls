//go:build js && wasm

package main

import (
	"strings"
	"testing"
)

// Run with: PATH="$(go env GOROOT)/lib/wasm:$PATH" GOOS=js GOARCH=wasm go test ./cmd/capyrls-wasm
func TestConvertMirrorsTheCLIOptions(t *testing.T) {
	sources := `[{"name":"a.sql","sql":"create table public.t (id int, owner_id uuid); alter table public.t enable row level security; create policy own on public.t for all to authenticated using (auth.uid() = owner_id); create policy svc on public.t for all to service_role using (true);"}]`

	res := convert(sources, `{"mode":"supabase-compat","role_model":"single","uid_type":"text","target":"capydb"}`)
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if len(res.Files) != 3 || res.Report == nil || res.Report.Mode != "supabase-compat" || res.Report.UIDType != "text" {
		t.Fatalf("unexpected result: files=%d report=%+v", len(res.Files), res.Report)
	}
	if !strings.Contains(res.Files[1].SQL, "auth.role() = 'service_role'") {
		t.Error("compat single bundle lacks the service escape")
	}
	if !strings.Contains(res.ReportMarkdown, "# capyrls conversion report") {
		t.Error("markdown report missing")
	}

	if res := convert(sources, `{"role_model":"split","target":"capydb"}`); !strings.Contains(res.Error, "split role model cannot be applied on CapyDB") {
		t.Errorf("split on capydb: error = %q", res.Error)
	}
	if res := convert(sources, `{"mode":"nope"}`); !strings.Contains(res.Error, "unknown mode") {
		t.Errorf("bad mode: error = %q", res.Error)
	}
	if res := convert(`not json`, ``); !strings.HasPrefix(res.Error, "sources:") {
		t.Errorf("bad sources: error = %q", res.Error)
	}
	// Defaults match the standalone CLI: vanilla, split.
	if res := convert(sources, ``); res.Error != "" || res.Report.Mode != "vanilla" || res.Report.RoleModel != "split" {
		t.Errorf("defaults: %+v %q", res.Report, res.Error)
	}
}
