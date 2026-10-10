package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	keepassadapter "github.com/vaultcore/secrets-broker/internal/adapters/keepass"
	opvaultadapter "github.com/vaultcore/secrets-broker/internal/adapters/opvault"
)

// itemsCmd lists the item titles in a vault so a human can write policy for
// them. It prompts for the master password on the terminal and prints titles
// only — never field values.
//
// There is deliberately no MCP tool for this: enumerating the vault is not
// something the agent needs in order to use a secret, and an inventory of
// what exists is itself worth withholding.
func itemsCmd(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: sb items <adapter> <vault-path>\n" +
			"  e.g. sb items opvault /path/to/agent.opvault")
	}
	adapter, path := args[0], args[1]

	pw, err := readPassword("master password for " + adapter + ":" + path + ": ")
	if err != nil {
		return err
	}
	if pw == "" {
		return fmt.Errorf("empty password")
	}
	pwFn := func() (string, error) { return pw, nil }

	var titles []string
	switch adapter {
	case "opvault":
		titles, err = (&opvaultadapter.Adapter{Dir: path, PasswordFn: pwFn}).List()
	case "keepass":
		titles, err = (&keepassadapter.Adapter{DBPath: path, PasswordFn: pwFn}).List()
	default:
		return fmt.Errorf("adapter must be opvault or keepass")
	}
	if err != nil {
		return err
	}
	sort.Slice(titles, func(i, j int) bool {
		return strings.ToLower(titles[i]) < strings.ToLower(titles[j])
	})
	for _, t := range titles {
		fmt.Printf("  %-40s sec://%s/%s/password\n", t, adapter, t)
	}
	fmt.Fprintf(os.Stderr, "\n%d items. Allow one with:\n  sudo sb allow <ref> <exec> --approve -- <args>\n", len(titles))
	return nil
}
