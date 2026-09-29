//go:build js && wasm

// capyrls-wasm exposes the converter to a browser: it registers one global,
// capyrlsConvert(sourcesJSON, optionsJSON), and then blocks forever so the Go
// runtime stays alive to serve calls. Nothing leaves the page - the converter
// is pure computation over the SQL it is handed.
//
// Build (from the module root):
//
//	GOOS=js GOARCH=wasm go build -trimpath -ldflags='-s -w' -o capyrls.wasm ./cmd/capyrls-wasm
//
// and load it with the wasm_exec.js that ships with the same Go toolchain
// ($(go env GOROOT)/lib/wasm/wasm_exec.js).
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	capyrls "github.com/capydatabase/capyrls"
)

// request mirrors the capyrls CLI flags, by the same names and values.
type request struct {
	Mode            string `json:"mode"`       // vanilla | supabase-compat
	RoleModel       string `json:"role_model"` // split | single
	UIDType         string `json:"uid_type"`   // uuid | text
	Target          string `json:"target"`     // postgres | capydb
	KeepForAll      bool   `json:"keep_for_all"`
	NoServiceEscape bool   `json:"no_service_escape"`
	Prefix          string `json:"prefix"`
}

type response struct {
	Version        string            `json:"version"`
	Files          []capyrls.OutFile `json:"files,omitempty"`
	Report         *capyrls.Report   `json:"report,omitempty"`
	ReportMarkdown string            `json:"report_markdown,omitempty"`
	Error          string            `json:"error,omitempty"`
}

func options(r request) (capyrls.Options, error) {
	opts := capyrls.Options{NoSplitAll: r.KeepForAll, NoServiceEscape: r.NoServiceEscape, Prefix: r.Prefix}
	switch r.Mode {
	case "", "vanilla":
		opts.Mode = capyrls.ModeVanilla
	case "supabase-compat", "compat":
		opts.Mode = capyrls.ModeCompat
	default:
		return opts, fmt.Errorf("unknown mode %q (vanilla or supabase-compat)", r.Mode)
	}
	switch r.RoleModel {
	case "", "split":
		opts.RoleModel = capyrls.RoleSplit
	case "single":
		opts.RoleModel = capyrls.RoleSingle
	default:
		return opts, fmt.Errorf("unknown role model %q (split or single)", r.RoleModel)
	}
	switch r.UIDType {
	case "", "uuid":
		opts.UIDType = capyrls.UIDUUID
	case "text":
		opts.UIDType = capyrls.UIDText
	default:
		return opts, fmt.Errorf("unknown uid type %q (uuid or text)", r.UIDType)
	}
	switch r.Target {
	case "", "postgres":
		opts.Target = capyrls.TargetPostgres
	case "capydb":
		opts.Target = capyrls.TargetCapyDB
	default:
		return opts, fmt.Errorf("unknown target %q (postgres or capydb)", r.Target)
	}
	return opts, nil
}

func convert(sourcesJSON, optionsJSON string) response {
	res := response{Version: capyrls.Version}
	var sources []capyrls.Source
	if err := json.Unmarshal([]byte(sourcesJSON), &sources); err != nil {
		res.Error = "sources: " + err.Error()
		return res
	}
	var req request
	if optionsJSON != "" {
		if err := json.Unmarshal([]byte(optionsJSON), &req); err != nil {
			res.Error = "options: " + err.Error()
			return res
		}
	}
	opts, err := options(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	out, err := capyrls.Convert(sources, opts)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Files = out.Files
	res.Report = &out.Report
	res.ReportMarkdown = out.Report.Markdown()
	return res
}

func main() {
	js.Global().Set("capyrlsConvert", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var res response
		if len(args) < 1 || args[0].Type() != js.TypeString {
			res = response{Version: capyrls.Version, Error: "capyrlsConvert(sourcesJSON, optionsJSON?) takes a JSON string of [{name, sql}]"}
		} else {
			optionsJSON := ""
			if len(args) > 1 && args[1].Type() == js.TypeString {
				optionsJSON = args[1].String()
			}
			res = convert(args[0].String(), optionsJSON)
		}
		encoded, err := json.Marshal(res)
		if err != nil {
			return `{"error":"encode result: ` + err.Error() + `"}`
		}
		return string(encoded)
	}))
	select {}
}
