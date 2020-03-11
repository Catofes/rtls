package rtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"time"

	"github.com/rs/zerolog"
)

type tlsServer struct {
	config
	cm        *certManager
	log       zerolog.Logger
	rules     []map[string]*url.URL
	tlsConfig *tls.Config
	ca        *x509.CertPool
}

//todo
func (s *tlsServer) init() *tlsServer {
	s.cm = (&certManager{config: s.config}).init()
	s.log = s.config.logger.With().Str("module", "handler").Logger()
	s.rules = make([]map[string]*url.URL, 0)
	s.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	if s.config.Fallback != "" {
		t := make(map[string]*url.URL)
		u, err := url.Parse(s.config.Fallback)
		if err != nil {
			s.log.Fatal().Err(err).Msg("Parse server url failed.")
		}
		t["fallback"] = u
		s.rules = append(s.rules, t)
	}
	for _, ruleSet := range s.config.Rules {
		t := make(map[string]*url.URL)
		for reg, value := range ruleSet {
			u, err := url.Parse(value)
			if err != nil {
				s.log.Fatal().Err(err).Msg("Parse server url failed.")
			}
			t[reg] = u
		}
		s.rules = append(s.rules, t)
	}
	if s.CAPath != "" {
		data, err := ioutil.ReadFile(s.CAPath)
		if err != nil {
			s.log.Fatal().Err(err).Msg("Read client ca cert failed.")
		}
		certDERBlock, _ := pem.Decode(data)
		if certDERBlock == nil {
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

func (s *tlsServer) listen() {
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		s.log.Fatal().Err(err).Send()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.log.Warn().Err(err).Msg("Accept error.")
			continue
		}
		go s.handle(conn)
	}
}

func (s *tlsServer) handle(c net.Conn) {
	log := s.log.With().Str("from", c.RemoteAddr().String()).Logger()
	cc := (&conn{}).init(c, s.log)
	//log.Debug().Msg("Handle conn.")
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
		var lc net.Conn
		switch u.Scheme {
		case "direct":
			lc = cc
		case "tcp":
		case "tls":
			config := s.cm.get(u.User.Username())
			if config == nil {
				log.Warn().Err(err).Msg("Missing cert config.")
				return
			}
			var tc *tls.Conn
			if u.Query().Get("CheckClientCert") == "true" {
				cconfig := &tls.Config{
					Certificates: config.Certificates,
					ClientCAs:    s.ca,
				}
				tc = tls.Server(cc, cconfig)
			} else {
				tc = tls.Server(cc, config)
			}
			err := tc.Handshake()
			if err != nil {
				log.Warn().Err(err).Msg("HandShake error.")
				return
			}
			defer tc.Close()
			lc = tc
		}
		log.Debug().Str("To", host).Str("Dail", u.Hostname()).Msg("Dail.")
		rc, err := s.dail(u, host)
		if err != nil {
			log.Warn().Str("To", host).Str("Dail", u.Hostname()).Err(err).Msg("Dial error.")
			return
		}
		defer rc.Close()
		err = s.pipe(lc, rc)
		if err != nil {
			log.Debug().Err(err).Msg("Pipe return error.")
		}
	}
}

func (s *tlsServer) dail(u *url.URL, requestSNI string) (net.Conn, error) {
	switch u.Scheme {
	case "direct":
	case "tcp":
		return net.DialTimeout("tcp", u.Host, 5*time.Second)
	case "tls":
		if u.Query().Get("ForceSNI") != "" {
			return tls.Dial("tcp", u.Host, &tls.Config{ServerName: u.Query().Get("ForceSNI"), InsecureSkipVerify: true})
		}
		if u.Query().Get("BypassSNI") == "true" {
			return tls.Dial("tcp", u.Host, &tls.Config{ServerName: requestSNI, InsecureSkipVerify: true})
		}
		return tls.Dial("tcp", u.Host, s.tlsConfig)
	}
	return nil, errors.New("dail failed, unknow host type")
}

func (s *tlsServer) getConfig(sni string) *url.URL {
	for _, ruleSet := range s.rules {
		for reg, value := range ruleSet {
			if ok, _ := regexp.MatchString(reg, sni); ok {
				return value
			}
		}
	}
	return nil
}

func (s *tlsServer) pipe(a, b net.Conn) error {
	done := make(chan error, 1)
	cp := func(r, w net.Conn) {
		_, err := io.Copy(w, r)
		switch w.(type) {
		case *net.TCPConn:
			w.(*net.TCPConn).CloseWrite()
		case *tls.Conn:
			w.(*tls.Conn).CloseWrite()
		}
		switch r.(type) {
		case *net.TCPConn:
			r.(*net.TCPConn).CloseRead()
		}
		done <- err
	}
	go cp(a, b)
	go cp(b, a)
	err1 := <-done
	err2 := <-done
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}
