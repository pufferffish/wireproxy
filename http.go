package wireproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/sourcegraph/conc"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

type HTTPServer struct {
	config *HTTPConfig

	auth CredentialValidator
	dial func(network, address string) (net.Conn, error)

	authRequired bool
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}

	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return http.StatusProxyAuthRequired, fmt.Errorf(http.StatusText(http.StatusProxyAuthRequired))
	}

	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}
	if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
		return 0, nil
	}
	return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
}

// handleConn sets up tunneling for CONNECT requests.
func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		return nil, err
	}

	return peer, nil
}

// handle handles standard HTTP methods.
func (s *HTTPServer) handle(req *http.Request) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "80"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	err = req.Write(peer)
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("conn write failed: %w", err)
	}

	return peer, nil
}

// serve handles one connection from the listener.
func (s *HTTPServer) serve(conn net.Conn) {
	var rd = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		log.Printf("read request failed: %s\n", err)
		conn.Close() // ensure StatsConn closes
		return
	}

	code, authErr := s.authenticate(req)
	if authErr != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		log.Println(authErr)
		conn.Close() // ensure StatsConn closes
		return
	}

	var peer net.Conn
	switch req.Method {
	case http.MethodConnect:
		peer, err = s.handleConn(req, conn)
	case http.MethodGet:
		peer, err = s.handle(req)
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		log.Printf("unsupported protocol: %s\n", req.Method)
		conn.Close() // ensure StatsConn closes
		return
	}

	if err != nil {
		log.Printf("dial proxy failed: %s\n", err)
		conn.Close() // ensure StatsConn closes
		return
	}
	if peer == nil {
		log.Println("dial proxy failed: peer nil")
		conn.Close() // ensure StatsConn closes
		return
	}
	go func() {
		wg := conc.NewWaitGroup()
		wg.Go(func() {
			_, _ = io.Copy(conn, peer)
			conn.Close()
		})
		wg.Go(func() {
			_, _ = io.Copy(peer, conn)
			_ = peer.Close()
		})
		wg.Wait()
	}()
}

// Serve runs an accept loop on the given listener.
func (s *HTTPServer) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept request failed: %w", err)
		}
		go s.serve(conn)
	}
}
