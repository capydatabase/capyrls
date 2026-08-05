package capyrls

import (
	"fmt"
	"sort"
	"strings"
)

// The report is the second half of the product: the SQL bundle says what to
// run, the report says what the application now owes the database (the GUC
// contract), what ported cleanly, and what needs a human.

type PolicyOutcome struct {
	Policy string `json:"policy"`
	Table  string `json:"table"`
	Status string `json:"status"` // converted | skipped | blocked
	Detail string `json:"detail,omitempty"`
}

type ClaimMapping struct {
	Claim    string `json:"claim"`
	Accessor string `json:"accessor"`
	GUC      string `json:"guc"`
}

type GUCSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type Report struct {
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Mode      string          `json:"mode"`
	RoleModel string          `json:"role_model"`
	Policies  []PolicyOutcome `json:"policies"`
	Claims    []ClaimMapping  `json:"claims"`
	GUCs      []GUCSpec       `json:"gucs"`
	Defaults  []string        `json:"column_defaults"`
	Routines  []string        `json:"routines_to_review"`
	Warnings  []string        `json:"warnings"`
	Notes     []string        `json:"notes"`
}

func (r *Report) counts() (converted, skipped, blocked int) {
	for _, p := range r.Policies {
		switch p.Status {
		case "converted":
			converted++
		case "skipped":
			skipped++
		case "blocked":
			blocked++
		}
	}
	return
}

// Markdown renders the human-facing report.
func (r *Report) Markdown() string {
	var b strings.Builder
	converted, skipped, blocked := r.counts()

	fmt.Fprintf(&b, "# capyrls conversion report\n\n")
	fmt.Fprintf(&b, "- mode: `%s`\n- role model: `%s`\n", r.Mode, r.RoleModel)
	fmt.Fprintf(&b, "- policies: %d converted, %d skipped, %d need attention\n\n", converted, skipped, blocked)

	if len(r.GUCs) > 0 {
		b.WriteString("## The context contract\n\n")
		b.WriteString("Your application authenticates the caller, then sets these transaction-local\nGUCs before running queries. Unset values read as NULL, so policies fail closed.\n\n")
		b.WriteString("| GUC | type | meaning |\n|---|---|---|\n")
		for _, g := range r.GUCs {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", g.Name, g.Type, g.Description)
		}
		b.WriteString("\nSet them inside a transaction (`true` = transaction-local, safe behind\ntransaction pooling):\n\n")
		b.WriteString("```sql\nbegin;\n")
		for _, g := range r.GUCs {
			fmt.Fprintf(&b, "select set_config('%s', $1, true);\n", g.Name)
		}
		b.WriteString("-- your queries run under RLS here\ncommit;\n```\n\n")
		b.WriteString("With node-postgres or any driver, issue the `set_config` calls as the first\nstatement of each transaction. With drizzle on CapyDB, `@capydb/drizzle`\nexposes `withAuthContext(db, context, callback)` which does exactly this.\n\n")
	}

	if len(r.Claims) > 0 {
		b.WriteString("## Promoted JWT claims\n\n")
		b.WriteString("These claims were read from `auth.jwt()` in your policies and are now\nfirst-class context values:\n\n")
		b.WriteString("| JWT claim | accessor | GUC to set |\n|---|---|---|\n")
		for _, c := range r.Claims {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` |\n", c.Claim, c.Accessor, c.GUC)
		}
		b.WriteString("\n")
	}

	writeOutcomeSection := func(title, status, blurb string) {
		var rows []PolicyOutcome
		for _, p := range r.Policies {
			if p.Status == status {
				rows = append(rows, p)
			}
		}
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", title, blurb)
		for _, p := range rows {
			if p.Detail != "" {
				fmt.Fprintf(&b, "- `%s` on `%s` - %s\n", p.Policy, p.Table, p.Detail)
			} else {
				fmt.Fprintf(&b, "- `%s` on `%s`\n", p.Policy, p.Table)
			}
		}
		b.WriteString("\n")
	}

	writeOutcomeSection("Needs attention", "blocked",
		"These policies reference things that do not exist outside Supabase (most\ncommonly the `auth.users` table). They are emitted commented out; port the\nreferenced data into your own schema and rewrite them by hand.")
	writeOutcomeSection("Skipped", "skipped",
		"Not portable or not needed on vanilla Postgres:")
	writeOutcomeSection("Converted", "converted", "Ported cleanly:")

	if len(r.Defaults) > 0 {
		b.WriteString("## Column defaults\n\n")
		for _, d := range r.Defaults {
			fmt.Fprintf(&b, "- %s\n", d)
		}
		b.WriteString("\n")
	}

	if len(r.Routines) > 0 {
		b.WriteString("## Functions to review\n\n")
		b.WriteString("These functions reference `auth.*` in their bodies. Function bodies are not\nrewritten automatically - apply the same substitutions by hand:\n\n")
		for _, f := range r.Routines {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		b.WriteString("\n")
	}

	if len(r.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		b.WriteString("\n")
	}

	if len(r.Notes) > 0 {
		b.WriteString("## Parse notes\n\n")
		for _, note := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func sortOutcomes(outcomes []PolicyOutcome) {
	sort.Slice(outcomes, func(i, j int) bool {
		if outcomes[i].Table != outcomes[j].Table {
			return outcomes[i].Table < outcomes[j].Table
		}
		return outcomes[i].Policy < outcomes[j].Policy
	})
}
