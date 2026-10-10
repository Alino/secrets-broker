package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/vaultcore/secrets-broker/internal/provision"
)

// profilesCmd lists the provisioning profiles available: builtins plus any
// from SB_PROFILES_FILE. A profile shapes an item's fields for a specific tool
// (env vars and/or a secret file the tool is pointed at).
func profilesCmd(args []string) error {
	reg, err := provision.LoadRegistry(os.Getenv("SB_PROFILES_FILE"))
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tITEM FIELDS\tGIVES THE TOOL")
	for _, name := range reg.Names() {
		p, _ := reg.Get(name)
		var gives []string
		for e := range p.Env {
			gives = append(gives, "$"+e)
		}
		for _, f := range p.Files {
			gives = append(gives, "file "+f.Path)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", name, strings.Join(p.Fields, ", "), strings.Join(gives, ", "))
	}
	w.Flush()
	fmt.Fprintln(os.Stderr, "\nuse: exec_with_secret with profile=<name> profile_item=sec://<adapter>/<item>")
	return nil
}
