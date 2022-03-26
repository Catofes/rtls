package rtls

import (
	"crypto/tls"

	"github.com/rs/zerolog"
)

type certManager struct {
	config
	certs map[string]*cert
	log   zerolog.Logger
}

//todo
func (s *certManager) init() *certManager {
	s.log = s.config.logger.With().Str("M", "cm").Logger()
	s.certs = make(map[string]*cert)
	for k, v := range s.config.Certs {
		c := &cert{
			config: s.config,
			uuid:   v.UUID,
		}
		c = c.init(k, s.log)
		s.certs[k] = c
	}
	return s
}

func (s *certManager) get(name string) *tls.Config {
	v, ok := s.certs[name]
	if !ok {
		s.log.Warn().Str("request", name).Msg("no such cert")
		return nil
	}
	c := v.getTLSConfig()
	if c == nil {
		s.log.Warn().Str("request", name).Msg("cert is not ready")
		return nil
	}
	return c
}
