// capyrls converts Supabase row-level-security policies to portable, vanilla
// PostgreSQL. See https://github.com/capy-base/capyrls.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	capyrls "github.com/capy-base/capyrls"
	"github.com/capy-base/capyrls/live"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for --db
)

const usage = `capyrls - convert Supabase RLS policies to vanilla PostgreSQL

Usage:
  capyrls convert [flags] [path ...]   Build a fresh SQL bundle from SQL files,
                                       a directory (e.g. supabase/migrations),
                                       "-" for stdin, or --db for a live database.
  capyrls rewrite [flags] path ...     Rewrite auth.* calls inside existing SQL
                                       files, keeping your migration history.
  capyrls version                      Print the version.

Common flags:
  --mode vanilla|supabase-compat   Output convention (default vanilla)
  --role-model split|single        split: app_user/app_service roles
                                   single: FORCE RLS, app connects as owner
  --keep-for-all                   Do not split FOR ALL policies per command
  --no-service-escape              single role model: no GUC-gated bypass policies
  --prefix NAME                    Schema/GUC namespace (default app)
  --out DIR                        Output directory (default capyrls_out)
  --stdout                         Print SQL to stdout instead of writing files
  --json                           Also emit capyrls_report.json
  --strict                         Exit 1 if any policy needs manual attention

convert only:
  --db DSN                         Introspect a live database (postgres://...)
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "capyrls: %v\n", err)
		os.Exit(1)
	}
}

type commonFlags struct {
	mode            string
	roleModel       string
	keepForAll      bool
	noServiceEscape bool
	prefix          string
	appRole         string
	serviceRole     string
	out             string
	stdout          bool
	jsonOut         bool
	strict          bool
}

func (cf *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&cf.mode, "mode", "vanilla", "output convention: vanilla or supabase-compat")
	fs.StringVar(&cf.roleModel, "role-model", "split", "role model: split or single")
	fs.BoolVar(&cf.keepForAll, "keep-for-all", false, "keep FOR ALL policies instead of splitting per command")
	fs.BoolVar(&cf.noServiceEscape, "no-service-escape", false, "single role model: skip the GUC-gated service bypass policies")
	fs.StringVar(&cf.prefix, "prefix", "app", "schema and GUC namespace")
	fs.StringVar(&cf.appRole, "app-role", "app_user", "runtime role name (split role model)")
	fs.StringVar(&cf.serviceRole, "service-role", "app_service", "service role name (split role model)")
	fs.StringVar(&cf.out, "out", "capyrls_out", "output directory")
	fs.BoolVar(&cf.stdout, "stdout", false, "print SQL to stdout instead of writing files")
	fs.BoolVar(&cf.jsonOut, "json", false, "also emit capyrls_report.json")
	fs.BoolVar(&cf.strict, "strict", false, "exit non-zero when policies need manual attention")
}

func (cf *commonFlags) options() (capyrls.Options, error) {
	opts := capyrls.Options{
		NoSplitAll:      cf.keepForAll,
		NoServiceEscape: cf.noServiceEscape,
		Prefix:          cf.prefix,
		AppRole:         cf.appRole,
		ServiceRole:     cf.serviceRole,
	}
	switch cf.mode {
	case "vanilla":
		opts.Mode = capyrls.ModeVanilla
	case "supabase-compat", "compat":
		opts.Mode = capyrls.ModeCompat
	default:
		return opts, fmt.Errorf("unknown --mode %q (vanilla or supabase-compat)", cf.mode)
	}
	switch cf.roleModel {
	case "split":
		opts.RoleModel = capyrls.RoleSplit
	case "single":
		opts.RoleModel = capyrls.RoleSingle
	default:
		return opts, fmt.Errorf("unknown --role-model %q (split or single)", cf.roleModel)
	}
	return opts, nil
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("no command given")
	}
	switch args[0] {
	case "convert":
		return runConvert(args[1:])
	case "rewrite":
		return runRewrite(args[1:])
	case "version":
		fmt.Println("capyrls v" + capyrls.Version)
		return nil
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runConvert(args []string) error {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	db := fs.String("db", "", "introspect a live database (postgres://...)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts, err := cf.options()
	if err != nil {
		return err
	}

	var result *capyrls.Result
	switch {
	case *db != "":
		if fs.NArg() > 0 {
			return fmt.Errorf("--db and file arguments are mutually exclusive")
		}
		cat, err := introspect(*db)
		if err != nil {
			return err
		}
		result, err = capyrls.ConvertCatalog(cat, opts)
		if err != nil {
			return err
		}
	default:
		sources, err := readSources(fs.Args())
		if err != nil {
			return err
		}
		result, err = capyrls.Convert(sources, opts)
		if err != nil {
			return err
		}
	}
	return emit(result, &cf)
}

func runRewrite(args []string) error {
	fs := flag.NewFlagSet("rewrite", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("rewrite needs at least one file or directory")
	}
	opts, err := cf.options()
	if err != nil {
		return err
	}
	sources, err := readSources(fs.Args())
	if err != nil {
		return err
	}
	result, err := capyrls.Rewrite(sources, opts)
	if err != nil {
		return err
	}
	return emit(result, &cf)
}

func introspect(dsn string) (*capyrls.Catalog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return live.Load(ctx, db)
}

// readSources expands the given paths: files are read as-is, directories are
// walked for *.sql (sorted, so migration ordering holds), "-" reads stdin.
func readSources(paths []string) ([]capyrls.Source, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no input: pass SQL files, a migrations directory, \"-\" for stdin, or --db")
	}
	var sources []capyrls.Source
	for _, path := range paths {
		if path == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("read stdin: %w", err)
			}
			sources = append(sources, capyrls.Source{Name: "stdin", SQL: string(data)})
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			sources = append(sources, capyrls.Source{Name: filepath.Base(path), SQL: string(data)})
			continue
		}
		var files []string
		walkErr := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(strings.ToLower(d.Name()), ".sql") {
				files = append(files, p)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
		sort.Strings(files)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(path, f)
			if err != nil {
				rel = filepath.Base(f)
			}
			sources = append(sources, capyrls.Source{Name: rel, SQL: string(data)})
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no .sql files found under %s", strings.Join(paths, ", "))
	}
	return sources, nil
}

func emit(result *capyrls.Result, cf *commonFlags) error {
	blocked := 0
	for _, p := range result.Report.Policies {
		if p.Status == "blocked" {
			blocked++
		}
	}

	if cf.stdout {
		for _, f := range result.Files {
			fmt.Printf("-- >>> %s\n%s\n", f.Name, f.SQL)
		}
		fmt.Fprint(os.Stderr, summaryLine(result, blocked))
	} else {
		if err := os.MkdirAll(cf.out, 0o755); err != nil {
			return err
		}
		for _, f := range result.Files {
			target := filepath.Join(cf.out, filepath.FromSlash(f.Name))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(target, []byte(f.SQL), 0o644); err != nil {
				return err
			}
		}
		reportPath := filepath.Join(cf.out, "capyrls_report.md")
		if err := os.WriteFile(reportPath, []byte(result.Report.Markdown()), 0o644); err != nil {
			return err
		}
		if cf.jsonOut {
			data, err := json.MarshalIndent(result.Report, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(cf.out, "capyrls_report.json"), append(data, '\n'), 0o644); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "wrote %d files to %s\n", len(result.Files)+1, cf.out)
		fmt.Fprint(os.Stderr, summaryLine(result, blocked))
	}

	if cf.strict && blocked > 0 {
		return fmt.Errorf("%d policies need manual attention (see the report)", blocked)
	}
	return nil
}

func summaryLine(result *capyrls.Result, blocked int) string {
	converted, skipped := 0, 0
	for _, p := range result.Report.Policies {
		switch p.Status {
		case "converted":
			converted++
		case "skipped":
			skipped++
		}
	}
	return fmt.Sprintf("policies: %d converted, %d skipped, %d need attention; warnings: %d\n",
		converted, skipped, blocked, len(result.Report.Warnings))
}
