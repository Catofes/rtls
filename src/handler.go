package rtls

import (
	"crypto/tls"
	"errors"
	"io"
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
}

//todo
func (s *tlsServer) init() {
	s.cm = (&certManager{}).init()
	s.log = s.config.logger.With().Str("module", "handler").Logger()
	s.rules = make([]map[string]*url.URL, 0)
	s.tlsConfig = &tls.Config{InsecureSkipVerify: true}
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
	log.Debug().Msg("Handle conn.")
	defer cc.Close()

	host, err := cc.parseSNI()
	if err != nil {
		s.log.Warn().Err(err).Msg("ParseSNI error.")
		return
	}

	if u := s.getConfig(host); u != nil {
		var lc net.Conn
		if u.Scheme == "direct" {
			lc = cc
		} else if u.Scheme == "tcp" || u.Scheme == "tls" {
			lc = tls.Server(cc, s.cm.get(u.User.Username()))
		}
		log.Debug().Str("To", host).Msg("Dail.")
		rc, err := s.dail(u)
		if err != nil {
			log.Warn().Str("To", host).Err(err).Msg("Dial error.")
			return
		}
		defer rc.Close()
		err = s.pipe(lc, rc)
		if err != nil {
			log.Debug().Err(err).Msg("Pipe return error.")
		}
	}
}

func (s *tlsServer) dail(u *url.URL) (net.Conn, error) {
	if u.Scheme == "direct" || u.Scheme == "tcp" {
		return net.DialTimeout("tcp", u.Host, 5*time.Second)
	} else if u.Scheme == "tls" {
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
		w.(*net.TCPConn).CloseWrite()
		r.(*net.TCPConn).CloseRead()
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
