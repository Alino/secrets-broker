// sb-browser-proxy is the native messaging host Chrome launches for the
// KeePassXC-Browser extension. It is deliberately a pipe and nothing else:
// it copies length-prefixed frames between the browser and the broker's
// socket, parses no JSON, and holds no keys. Every decision — association,
// origin scoping, which credential — belongs to the daemon, which runs as its
// own uid; this process runs as whoever the browser runs as.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

func main() {
	socket := flag.String("socket", "", "broker browser-protocol socket")
	flag.Parse()

	path := resolveSocket(*socket)
	conn, err := net.Dial("unix", path)
	if err != nil {
		// Chrome surfaces nothing useful, so make the reason findable.
		fmt.Fprintf(os.Stderr, "sb-browser-proxy: cannot reach the broker at %s: %v\n", path, err)
		os.Exit(1)
	}
	defer conn.Close()

	done := make(chan struct{}, 2)
	go func() { pipe(conn, os.Stdin); done <- struct{}{} }()
	go func() { pipe(os.Stdout, conn); done <- struct{}{} }()
	<-done
}

// resolveSocket finds the broker's browser socket.
//
// A native-messaging manifest carries only a "path" — Chrome launches the host
// with no arguments and does not pass the browser's environment through, so
// neither a flag nor an inherited env var can be relied on here. The
// single-uid fallback is therefore a well-known per-user path, written by
// `sb browser install-host`.
//
// Order: explicit flag (manual runs, tests) → SB_BROWSER_SOCKET (when the
// launcher does set it) → per-user socket → system-wide isolated-mode socket.
func resolveSocket(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("SB_BROWSER_SOCKET"); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil {
		userSock := filepath.Join(home, ".secrets-broker", "browser.sock")
		if _, err := os.Stat(userSock); err == nil {
			return userSock
		}
	}
	return systemBrowserSocket
}

// systemBrowserSocket is the isolated-mode location, owned by the broker's
// service account.
const systemBrowserSocket = "/usr/local/var/secrets-broker/run/browser.sock"

// pipe copies whole frames so a partial write never desynchronises the
// stream: both hops use the same uint32 length prefix.
func pipe(dst io.Writer, src io.Reader) {
	for {
		var n uint32
		if err := binary.Read(src, binary.LittleEndian, &n); err != nil {
			return
		}
		if n > 64*1024*1024 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(src, buf); err != nil {
			return
		}
		if err := binary.Write(dst, binary.LittleEndian, n); err != nil {
			return
		}
		if _, err := dst.Write(buf); err != nil {
			return
		}
	}
}
