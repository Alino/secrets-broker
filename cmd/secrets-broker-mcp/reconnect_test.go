package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// fakeDaemon is a minimal MCP-ish server on a unix socket that can be stopped
// and restarted on the same path, tagging replies with a generation so the
// test can tell which daemon answered.
type fakeDaemon struct {
	path  string
	gen   int
	mu    sync.Mutex
	ln    net.Listener
	conns []net.Conn
}

func (d *fakeDaemon) start(t *testing.T) {
	ln, err := net.Listen("unix", d.path)
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.ln = ln
	gen := d.gen
	d.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns = append(d.conns, c)
			d.mu.Unlock()
			go d.serve(c, gen)
		}
	}()
}

func (d *fakeDaemon) serve(c net.Conn, gen int) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Method == "" {
			continue
		}
		if len(m.ID) == 0 { // a notification: no reply
			continue
		}
		resp, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": json.RawMessage(m.ID),
			"result": map[string]any{"gen": gen, "method": m.Method},
		})
		c.Write(append(resp, '\n'))
	}
}

func (d *fakeDaemon) restart(t *testing.T) {
	d.mu.Lock()
	d.ln.Close()
	for _, c := range d.conns { // a real daemon exit closes its sockets → proxy sees EOF
		c.Close()
	}
	d.conns = nil
	d.gen++
	d.mu.Unlock()
	// brief gap so the socket file is free
	time.Sleep(100 * time.Millisecond)
	d.start(t)
}

// The proxy must survive a daemon restart: it replays initialize to the fresh
// daemon and the client's later calls still get answered.
func TestProxyReconnectsAcrossDaemonRestart(t *testing.T) {
	// short path: macOS unix sockets cap at 104 bytes, t.TempDir() is too long
	f, _ := os.CreateTemp("/tmp", "sbrc-*.sock")
	sock := f.Name()
	f.Close()
	os.Remove(sock)
	t.Cleanup(func() { os.Remove(sock) })
	d := &fakeDaemon{path: sock, gen: 1}
	d.start(t)

	inClient, inServer := net.Pipe()   // test writes inClient -> proxy reads inServer
	outServer, outClient := net.Pipe() // proxy writes outServer -> test reads outClient
	done := make(chan error, 1)
	go func() {
		done <- proxyReconnecting(inServer, outServer, func() (net.Conn, error) { return net.Dial("unix", sock) })
	}()
	replies := bufio.NewReader(outClient)

	send := func(line string) { inClient.Write([]byte(line + "\n")) }
	readGen := func() int {
		type r struct {
			Result struct {
				Gen    int    `json:"gen"`
				Method string `json:"method"`
			} `json:"result"`
		}
		outClient.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := replies.ReadBytes('\n')
		if err != nil {
			t.Fatalf("no reply: %v", err)
		}
		var v r
		json.Unmarshal(line, &v)
		return v.Result.Gen
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if g := readGen(); g != 1 {
		t.Fatalf("initialize answered by gen %d, want 1", g)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`)
	if g := readGen(); g != 1 {
		t.Fatalf("first call answered by gen %d, want 1", g)
	}

	d.restart(t)

	// This call must be answered by gen 2 — proving the proxy reconnected and
	// replayed initialize (the new daemon had never seen this client otherwise).
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`)
	if g := readGen(); g != 2 {
		t.Fatalf("post-restart call answered by gen %d, want 2 (reconnect/replay failed)", g)
	}

	inClient.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}
