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
	if auth != "" {
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

	return http.StatusProxyAuthRequired, fmt.Errorf(http.StatusText(http.StatusProxyAuthRequired))
}

func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		peer.Close()
		peer = nil
	}

	return
}

func (s *HTTPServer) handle(req *http.Request) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "80"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	err = req.Write(peer)
	if err != nil {
		peer.Close()
		peer = nil
		return peer, fmt.Errorf("conn write failed: %w", err)
	}

	return
}

func (s *HTTPServer) serve(conn net.Conn) error {
	defer conn.Close()

	var rd io.Reader = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd.(*bufio.Reader))
	if err != nil {
		return fmt.Errorf("read request failed: %w", err)
	}

	code, err := s.authenticate(req)
	if err != nil {
		_ = responseWith(req, code).Write(conn)
		return err
	}

	var peer net.Conn
	switch req.Method {
	case http.MethodConnect:
		peer, err = s.handleConn(req, conn)
	case http.MethodGet:
		peer, err = s.handle(req)
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		return fmt.Errorf("unsupported protocol: %s", req.Method)
	}
	if err != nil {
		return fmt.Errorf("dial proxy failed: %w", err)
	}
	if peer == nil {
		return fmt.Errorf("dial proxy failed: peer nil")
	}
	defer peer.Close()

	go func() {
		defer peer.Close()
		defer conn.Close()
		_, _ = io.Copy(conn, peer)
	}()
	_, err = io.Copy(peer, conn)

	return err
}

// ListenAndServe is used to create a listener and serve on it
func (s *HTTPServer) ListenAndServe(network, addr string) error {
	server, err := net.Listen("tcp", s.config.BindAddress)
	if err != nil {
		return fmt.Errorf("listen tcp failed: %w", err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			return fmt.Errorf("accept request failed: %w", err)
		}
		go func(conn net.Conn) {
			err = s.serve(conn)
			if err != nil {
				log.Println(err)
			}
		}(conn)
	}
}
