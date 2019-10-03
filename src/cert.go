package rtls

import (
	"crypto/x509"
	"sync"
	"time"
	"io/ioutil"
	"github.com/rs/zerolog/log"
)

type cert struct {
	domain     string
	uuid       string
	chain      []x509.Certificate
	data       string
	mutex      sync.Mutex
	lastUpdate time.Time
	log zerolog.Logger
}

func (s *cert) init(domain string) *cert {
	s.domain = domain
	s.chain = make([]x509.Certificate, 0)
	s.log := log.With().Str("domain":s.domain).Logger()
	return s
}

func (s *cert) loadFromFile(path string) {
	data, err := ioutil.ReadFile(path)
	if err!=nil{
	}
	s.data = string(data)
}
