package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vaultcore/secrets-broker/internal/importer"
)

// importCmd discovers credentials already on the system and, on `apply`, vaults
// them through the daemon. `scan` is read-only and prints no values.
//
//	sb import scan [file.env ...]
//	sb import apply [--adapter keepass] [--group Imported] [file.env ...]
func importCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sb import scan [file.env ...] | sb import apply [--adapter <a>] [--group <g>] [file.env ...]")
	}
	sub := args[0]
	adapter, group := "keepass", "Imported"
	var files []string
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--adapter" && i+1 < len(args):
			i++
			adapter = args[i]
		case args[i] == "--group" && i+1 < len(args):
			i++
			group = args[i]
		default:
			files = append(files, args[i])
		}
	}

	home, _ := os.UserHomeDir()
	cands := importer.ScanAll(home)
	for _, f := range files {
		cands = append(cands, importer.ScanEnvFile(f)...)
	}

	switch sub {
	case "scan":
		if len(cands) == 0 {
			fmt.Println("no importable credentials found (looked in ~/.aws/credentials, ~/.netrc" +
				func() string {
					if len(files) > 0 {
						return ", " + strings.Join(files, ", ")
					}
					return ""
				}() + ")")
			return nil
		}
		fmt.Printf("found %d importable credential(s) — values not shown:\n", len(cands))
		for _, c := range cands {
			fmt.Println("  " + c.Redacted())
		}
		fmt.Fprintln(os.Stderr, "\nvault them with: sb import apply   (needs: sb write-allow "+adapter+" create)")
		return nil

	case "apply":
		if len(cands) == 0 {
			return fmt.Errorf("nothing to import")
		}
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return fmt.Errorf("cannot reach the broker at %s: %w", socketPath, err)
		}
		defer conn.Close()
		rpc := &mcpConn{conn: conn, r: bufio.NewReader(conn)}
		if err := rpc.initialize(); err != nil {
			return err
		}
		var ok, failed int
		for _, c := range cands {
			out, err := rpc.call("save_secret", map[string]any{
				"adapter": adapter, "group": group, "title": c.Suggest, "fields": c.Fields,
			})
			if err != nil || !strings.Contains(out, `"stored":true`) {
				failed++
				msg := strings.TrimSpace(out)
				if err != nil {
					msg = err.Error()
				}
				fmt.Fprintf(os.Stderr, "  %-24s FAILED: %s\n", c.Suggest, msg)
				continue
			}
			ok++
			fmt.Printf("  %-24s -> sec://%s/%s/%s/*\n", c.Suggest, adapter, group, c.Suggest)
		}
		fmt.Printf("\nimported %d, failed %d\n", ok, failed)
		if failed > 0 {
			os.Exit(1)
		}
		return nil
	}
	return fmt.Errorf("unknown subcommand %q (scan|apply)", sub)
}
