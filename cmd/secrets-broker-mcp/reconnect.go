package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
)

// proxyReconnecting bridges an MCP stdio client (Claude Code) to the daemon's
// unix socket, and survives daemon restarts. MCP is a stateful session — the
// client sends `initialize` once and never again — so when the daemon drops,
// this redials, replays the captured initialize handshake to the fresh daemon
// (swallowing its duplicate initialize response), and resumes. Without this a
// daemon restart kills the client's session and the user must restart the app.
//
// dial returns a fresh connection to the daemon. redialBackoff bounds retries.
func proxyReconnecting(in io.Reader, out io.Writer, dial func() (net.Conn, error)) error {
	p := &reconnProxy{dial: dial, out: out}
	if err := p.connect(); err != nil {
		return err
	}
	// client -> daemon: capture the handshake, forward every line, reconnect on write failure
	clientLines := bufio.NewScanner(in)
	clientLines.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for clientLines.Scan() {
		line := append(clientLines.Bytes(), '\n')
		p.remember(line)
		if err := p.send(line); err != nil {
			return err
		}
	}
	// client closed stdin: end the session
	p.closeWrite()
	return clientLines.Err()
}

type reconnProxy struct {
	dial func() (net.Conn, error)
	out  io.Writer

	mu       sync.Mutex
	conn     net.Conn
	initReq  []byte // the client's initialize request line
	initNote []byte // the notifications/initialized line
}

// remember captures the two frames needed to re-establish a session.
func (p *reconnProxy) remember(line []byte) {
	var m struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(line, &m) != nil {
		return
	}
	switch m.Method {
	case "initialize":
		p.mu.Lock()
		p.initReq = append([]byte(nil), line...)
		p.mu.Unlock()
	case "notifications/initialized":
		p.mu.Lock()
		p.initNote = append([]byte(nil), line...)
		p.mu.Unlock()
	}
}

// connect dials, replays the handshake if we have one, and starts pumping the
// daemon's replies to the client. Called for the first connection and on every
// reconnect.
func (p *reconnProxy) connect() error {
	c, err := p.dial()
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.conn = c
	initReq, initNote := p.initReq, p.initNote
	p.mu.Unlock()

	br := bufio.NewReader(c)
	if initReq != nil {
		// Re-establish the session on the fresh daemon and swallow its
		// duplicate initialize response — the client already got one.
		if _, err := c.Write(initReq); err != nil {
			return err
		}
		if _, err := br.ReadBytes('\n'); err != nil {
			return err
		}
		if initNote != nil {
			if _, err := c.Write(initNote); err != nil {
				return err
			}
		}
	}
	go p.pump(c, br)
	return nil
}

// pump forwards daemon -> client. On daemon EOF it reconnects (with backoff)
// and returns; the new connection's own pump takes over.
func (p *reconnProxy) pump(c net.Conn, br *bufio.Reader) {
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			p.mu.Lock()
			_, werr := p.out.Write(line)
			p.mu.Unlock()
			if werr != nil {
				return
			}
		}
		if err != nil {
			// daemon closed (restart?) — try to bring the session back
			if p.reconnect(c) {
				return // connect() started a fresh pump
			}
			return
		}
	}
}

// reconnect redials with backoff, but only if c is still the current conn (so
// two pumps don't both reconnect). Returns true if a new connection is up.
func (p *reconnProxy) reconnect(stale net.Conn) bool {
	p.mu.Lock()
	if p.conn != stale {
		p.mu.Unlock()
		return false // someone else already reconnected
	}
	p.mu.Unlock()
	for i := 0; i < 30; i++ {
		time.Sleep(200 * time.Millisecond)
		if err := p.connect(); err == nil {
			return true
		}
	}
	return false
}

func (p *reconnProxy) send(line []byte) error {
	p.mu.Lock()
	c := p.conn
	p.mu.Unlock()
	if c == nil {
		return io.ErrClosedPipe
	}
	if _, err := c.Write(line); err == nil {
		return nil
	}
	// write failed: the daemon may have just restarted; reconnect and retry once
	if !p.reconnect(c) {
		return io.ErrClosedPipe
	}
	p.mu.Lock()
	c = p.conn
	p.mu.Unlock()
	_, err := c.Write(line)
	return err
}

func (p *reconnProxy) closeWrite() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.conn.(*net.UnixConn); ok {
		_ = u.CloseWrite()
	}
}
