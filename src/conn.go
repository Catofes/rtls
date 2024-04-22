package rtls

import (
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
	s.b = make([]byte, 16384)
	s.t = time.Now().UnixNano() / 1000
	s.log = l.With().Int64("I", s.t).Logger()
	return s
}

func (s *conn) parseSNI() (string, error) {
	n, err := s.c.Read(s.b)
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
