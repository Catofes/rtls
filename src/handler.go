package rtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// idleConn resets the read deadline before every Read so that connections
// idle for longer than the given duration are automatically closed.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

type rule struct {
	pattern *regexp.Regexp
	target  *url.URL
}

type tlsServer struct {
	config
	cm        *certManager
	log       zerolog.Logger
	rules     []rule
	tlsConfig *tls.Config
	ca        *x509.CertPool
}

func (s *tlsServer) init(ctx context.Context) *tlsServer {
	s.cm = (&certManager{config: s.config}).init(ctx)
	s.log = s.config.logger.With().Str("module", "handler").Logger()
	s.rules = make([]rule, 0)
	s.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	if s.config.Fallback != "" {
		u, err := url.Parse(s.config.Fallback)
		if err != nil {
			s.log.Fatal().Err(err).Msg("Parse server url failed.")
		}
		s.rules = append(s.rules, rule{pattern: regexp.MustCompile("^fallback$"), target: u})
	}
	for _, ruleSet := range s.config.Rules {
		for reg, value := range ruleSet {
			u, err := url.Parse(value)
			if err != nil {
				s.log.Fatal().Err(err).Msg("Parse server url failed.")
			}
			r, err := regexp.Compile(reg)
			if err != nil {
				s.log.Fatal().Err(err).Str("regex", reg).Msg("Compile rule regex failed.")
			}
			s.rules = append(s.rules, rule{pattern: r, target: u})
		}
	}
	if s.CAPath != "" {
		data, err := ioutil.ReadFile(s.CAPath)
		if err != nil {
			s.log.Fatal().Err(err).Msg("Read client ca cert failed.")
		}
		certDERBlock, _ := pem.Decode(data)
		if certDERBlock == nil || certDERBlock.Bytes == nil {
			s.log.Fatal().Msg("Parse client ca failed.")
		}
		cert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			s.log.Fatal().Err(err).Msg("Parse client ca cert failed.")
		}
		s.ca = x509.NewCertPool()
		s.ca.AddCert(cert)
	}
	return s
}

func (s *tlsServer) listen(ctx context.Context) {
	wg := &sync.WaitGroup{}
	l := func(addr string) {
		defer wg.Done()
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			s.log.Fatal().Err(err).Send()
		}
		s.log.Info().Str("Listen", addr).Send()
		go func() {
			<-ctx.Done()
			s.log.Info().Str("addr", addr).Msg("Shutting down listener.")
			listener.Close()
		}()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				s.log.Warn().Err(err).Msg("Accept error.")
				continue
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(30 * time.Second)
			}
			go s.handle(conn)
		}
	}
	if len(s.config.Listens) > 0 {
		for _, v := range s.config.Listens {
			wg.Add(1)
			go l(v)
		}
	} else {
		wg.Add(1)
		go l(s.config.Listen)
	}
	wg.Wait()
	s.log.Info().Msg("All listeners stopped.")
}

func (s *tlsServer) handle(c net.Conn) {
	log := s.log.With().Str("client", c.RemoteAddr().String()).Logger()
	cc := (&conn{}).init(c, log)
	log = cc.log
	defer cc.Close()

	host, err := cc.parseSNI()
	if err != nil {
		s.log.Warn().Err(err).Msg("ParseSNI error.")
		if s.config.Fallback == "" {
			return
		} else {
			host = "fallback"
		}
	}
	if u := s.getConfig(host); u != nil {
		log.Info().Str("sni", host).Str("dst", u.Hostname()).Msg("Start dial.")
		var lc, rc net.Conn
		var h2 bool
		if u.Query().Get("h2") == "true" && u.Scheme == "tls" {
			tc, err := s.dail(u, host, true)
			if err != nil {
				log.Warn().Str("sni", host).Str("dst", u.Hostname()).Err(err).Msg("Dial error.")
				return
			}
			defer tc.Close()
			if tc.(*tls.Conn).ConnectionState().NegotiatedProtocol == "h2" {
				h2 = true
				log.Debug().Str("sni", host).Str("dst", u.Hostname()).Msg("h2 upstream connected.")
				rc = tc
			}
		}
		switch u.Scheme {
		case "direct":
			lc = cc
		case "tcp", "tls":
			config := s.cm.get(u.User.Username())
			if config == nil {
				log.Warn().Msg("Missing cert config.")
				return
			}
			c := &tls.Config{
				Certificates: config.Certificates,
			}
			var tc *tls.Conn
			if u.Query().Get("CheckClientCert") == "true" {
				c.ClientAuth = tls.RequireAndVerifyClientCert
				c.ClientCAs = s.ca
			}
			if h2 {
				c.NextProtos = []string{"h2"}
			}
			log.Info().Str("sni", host).Str("dst", u.Hostname()).Msg("TLS handshake with client.")
			tc = tls.Server(cc, c)
			cc.SetDeadline(time.Now().Add(15 * time.Second))
			err := tc.Handshake()
			cc.SetDeadline(time.Time{})
			//defer tc.Close()
			if err != nil {
				log.Warn().Err(err).Msg("TLS handshake error.")
				return
			}
			if tc.ConnectionState().NegotiatedProtocol == "h2" {
				log.Debug().Str("sni", host).Str("dst", u.Hostname()).Msg("h2 negotiated with client.")
				h2 = true
			} else {
				h2 = false
			}
			lc = tc
		}
		if !h2 {
			if u.Query().Get("h2") == "true" {
				log.Debug().Str("sni", host).Str("dst", u.Hostname()).Msg("h2 not negotiated, falling back to http/1.1.")
			}
			if rc, err = s.dail(u, host, false); err != nil {
				log.Warn().Str("sni", host).Str("dst", u.Hostname()).Err(err).Msg("Dial error.")
				return
			}
			defer rc.Close()
		}
		log.Info().Str("sni", host).Str("dst", u.Hostname()).Msg("Tunnel established.")
		s.pipe(lc, rc, cc.log)
	}
}

func (s *tlsServer) dail(u *url.URL, requestSNI string, h2 bool) (net.Conn, error) {
	switch u.Scheme {
	case "direct", "tcp":
		return net.DialTimeout("tcp", u.Host, 5*time.Second)
	case "tls":
		c := tls.Config{InsecureSkipVerify: true}
		if u.Query().Get("ForceSNI") != "" {
			c.ServerName = u.Query().Get("ForceSNI")
		}
		if u.Query().Get("BypassSNI") == "true" {
			c.ServerName = requestSNI
		}
		if h2 {
			c.NextProtos = []string{"h2"}
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		return tls.DialWithDialer(dialer, "tcp", u.Host, &c)
	}
	return nil, errors.New("dail failed, unknow host type")
}

func (s *tlsServer) getConfig(sni string) *url.URL {
	for _, r := range s.rules {
		if r.pattern.MatchString(sni) {
			return r.target
		}
	}
	return nil
}

func (s *tlsServer) pipe(a, b net.Conn, log zerolog.Logger) error {
	done := make(chan error, 2)
	wrapReader := func(c net.Conn) io.Reader {
		if s.config.IdleTimeout > 0 {
			return &idleConn{Conn: c, timeout: time.Duration(s.config.IdleTimeout) * time.Second}
		}
		return c
	}
	cp := func(r, w net.Conn, l zerolog.Logger) {
		n, err := io.Copy(w, wrapReader(r))
		if err != nil {
			l.Debug().Int64("bytes", n).Err(err).Msg("Copy error, closing.")
			w.Close()
			r.Close()
		} else {
			switch w := w.(type) {
			case *net.TCPConn:
				w.CloseWrite()
			case *tls.Conn:
				w.CloseWrite()
			}
			switch r := r.(type) {
			case *net.TCPConn:
				r.CloseRead()
			}
			l.Debug().Int64("bytes", n).Msg("Half close.")
		}
		done <- err
	}
	log.Debug().Str("a", a.RemoteAddr().String()).Str("b", b.RemoteAddr().String()).Msg("Piping connections.")
	go cp(a, b, log.With().Str("dir", "upstream").Logger())
	go cp(b, a, log.With().Str("dir", "downstream").Logger())
	<-done
	<-done
	a.Close()
	b.Close()
	log.Debug().Msg("Tunnel closed.")
	return nil
}
