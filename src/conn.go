package rtls

import (
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
)

type conn struct {
	c   net.Conn
	b   []byte
	log zerolog.Logger
	t   int64
}

func (s *conn) init(c net.Conn, l zerolog.Logger) *conn {
	s.c = c
	s.b = make([]byte, 16392)
	s.t = time.Now().UnixNano() / 1000
	s.log = l.With().Int64("I", s.t).Logger()
	return s
}

func (s *conn) fetchHeader() (int, error) {
	n, err := s.c.Read(s.b)
	if err != nil {
		return n, err
	}
	if s.b[0] != 22 {
		return n, fmt.Errorf("first package seems not TLS handshake")
	}
	packageLength := int(s.b[3])<<8 + int(s.b[4])
	if n < packageLength+5 {
		s.log.Debug().Msg("First package not long enough.")
		s.c.SetReadDeadline(time.Now().Add(1 * time.Second))
		count := 0
		for (n < packageLength+5) && (count <= 5) {
			nn, err := s.c.Read(s.b[n:])
			s.log.Debug().Msgf("Reread %d bytes.", nn)
			if err != nil {
				s.log.Debug().Msgf("err: %s.", err.Error())
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return n + nn, fmt.Errorf("read timeout")
				} else {
					return n + nn, err
				}
			}
			n = n + nn
			count = count + 1
		}
		s.c.SetReadDeadline(time.Time{})
	}
	return n, nil
}

func (s *conn) parseSNI() (string, error) {
	//n, err := s.c.Read(s.b)
	n, err := s.fetchHeader()
	if err != nil {
		s.log.Warn().Err(err).Msg("Read error.")
		return "", err
	}
	s.b = s.b[:n]
	host, err := GetHostname(s.b[:])
	if err != nil {
		s.log.Warn().Err(err).Msg("ParseSNI error.")
		return "", err
	}
	s.log.Debug().Str("S", host).Msg("Parse SNI success.")
	return host, nil
}

func (s *conn) Read(b []byte) (int, error) {
	if len(s.b) > 0 {
		n := copy(b, s.b)
		s.b = s.b[n:]
		return n, nil
	}
	return s.c.Read(b)
}

func (s *conn) Write(b []byte) (int, error) {
	return s.c.Write(b)
}

func (s *conn) Close() error {
	return s.c.Close()
}

func (s *conn) LocalAddr() net.Addr {
	return s.c.LocalAddr()
}

func (s *conn) RemoteAddr() net.Addr {
	return s.c.RemoteAddr()
}

func (s *conn) SetDeadline(t time.Time) error {
	return s.c.SetDeadline(t)
}

func (s *conn) SetReadDeadline(t time.Time) error {
	return s.c.SetReadDeadline(t)
}

func (s *conn) SetWriteDeadline(t time.Time) error {
	return s.c.SetWriteDeadline(t)
}
