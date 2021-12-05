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
	"sync"
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
	l := func(addr string) {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			s.log.Fatal().Err(err).Send()
		}
		s.log.Info().Str("Listen", addr).Send()
		for {
			conn, err := listener.Accept()
			if err != nil {
				s.log.Warn().Err(err).Msg("Accept error.")
				continue
			}
			go s.handle(conn)
		}
	}
	wg := &sync.WaitGroup{}
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
		log.Debug().Str("To", host).Str("Dail", u.Hostname()).Msg("Start dail.")
		var lc, rc net.Conn
		var h2 bool
		if u.Query().Get("h2") == "true" && u.Scheme == "tls" {
			tc, err := s.dail(u, host, true)
			if err != nil {
				log.Warn().Str("To", host).Str("Dail", u.Hostname()).Err(err).Msg("Dial error.")
				return
			}
			defer tc.Close()
			if tc.(*tls.Conn).ConnectionState().NegotiatedProtocol == "h2" {
				h2 = true
				log.Debug().Str("To", host).Str("Dail", u.Hostname()).Err(err).Msg("h2 half connect.")
				rc = tc
			}
		}
		switch u.Scheme {
		case "direct":
			lc = cc
		case "tcp", "tls":
			config := s.cm.get(u.User.Username())
			if config == nil {
				log.Warn().Err(err).Msg("Missing cert config.")
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
			tc = tls.Server(cc, c)
			err := tc.Handshake()
			//defer tc.Close()
			if err != nil {
				log.Warn().Err(err).Msg("HandShake error.")
				return
			}
			if tc.ConnectionState().NegotiatedProtocol == "h2" {
				log.Debug().Str("To", host).Str("Dail", u.Hostname()).Msg("h2 connect success.")
				h2 = true
			} else {
				h2 = false
			}
			lc = tc
		}
		if !h2 {
			if u.Query().Get("h2") == "true" {
				log.Debug().Str("To", host).Str("Dail", u.Hostname()).Err(err).Msg("h2 connect failed.")
			}
			if rc, err = s.dail(u, host, false); err != nil {
				log.Warn().Str("To", host).Str("Dail", u.Hostname()).Err(err).Msg("Dial error.")
				return
			}
			defer rc.Close()
		}
		err = s.pipe(lc, rc)
		if err != nil {
			log.Debug().Err(err).Msg("Pipe return error.")
		}
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
		return tls.Dial("tcp", u.Host, &c)
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
		// switch w.(type) {
		// case *net.TCPConn:
		// 	w.(*net.TCPConn).CloseWrite()
		// case *tls.Conn:
		// 	w.(*tls.Conn).CloseWrite()
		// }
		// switch r.(type) {
		// case *net.TCPConn:
		// 	r.(*net.TCPConn).CloseRead()
		// }
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
