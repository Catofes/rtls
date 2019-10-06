package rtls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/go-resty/resty"
	"github.com/rs/zerolog"
)

type cert struct {
	config
	domain     string
	uuid       string
	chain      []x509.Certificate
	cert       *x509.Certificate
	data       string
	mutex      sync.Mutex
	lastUpdate time.Time
	log        zerolog.Logger
}

func (s *cert) init(domain string) *cert {
	s.domain = domain
	s.chain = make([]x509.Certificate, 0)
	s.log = s.logger.With().Str("domain", s.domain).Logger()
	return s
}

func (s *cert) loadFromFile() error {
	path := fmt.Sprintf("%s/%s.crt", s.config.CertsPath, s.domain)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		s.log.Debug().Str("option", "load from file").Err(err).Send()
		return err
	}
	s.data = string(data)
	s.loadFromPEM()
	return nil
}

func (s *cert) loadFromWeb() error {
	url := fmt.Sprintf("%s/%s/watch", s.config.CertGateway, s.uuid)
	resty.New().R()
}

func (s *cert) loadFromPEM() error {
	var err error
	s.chain, err = s.parseCert(s.data)
	if err != nil {
		s.log.Debug().Str("option", "load from PEM").Err(err).Send()
		return err
	}
	for _, cert := range s.chain {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			s.cert = &cert
		}
	}
	if s.cert == nil {
		err = errors.New("can not find final cert")
		s.log.Debug().Str("option", "load from PEM").Err(err).Send()
		return err
	}
	return nil
}

func (s *cert) parseCert(data string) ([]x509.Certificate, error) {
	if data == "" {
		return nil, fmt.Errorf("empty cert data")
	}
	restPEMBlock := []byte(data)
	var certDERBlock *pem.Block
	chain := make([]x509.Certificate, 0)
	for {
		certDERBlock, restPEMBlock = pem.Decode(restPEMBlock)
		if certDERBlock == nil {
			break
		}
		cert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			s.log.Debug().Str("option", "parse cert").Err(err).Send()
			continue
		}
		chain = append(chain, *cert)
	}
	if len(chain) <= 0 {
		return chain, errors.New("empty chain")
	}
	return chain, nil
}
