package rtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
)

type cert struct {
	config
	domain     string
	uuid       string
	chain      []x509.Certificate
	cert       *x509.Certificate
	chainRaw   []byte
	data       string
	key        interface{}
	keyRaw     []byte
	mutex      sync.Mutex
	lastUpdate time.Time
	log        zerolog.Logger
	tlsConfig  *tls.Config
}

func (s *cert) init(domain string, l zerolog.Logger) *cert {
	s.domain = domain
	s.chain = make([]x509.Certificate, 0)
	s.log = l.With().Str("domain", s.domain).Logger()
	s.loadFromFile()
	go s.loop()
	return s
}

func (s *cert) loadKey() error {
	var err error
	defer func() {
		if err != nil {
			s.log.Fatal().Str("option", "load key").Err(err).Send()
		}
	}()
	path := fmt.Sprintf("%s/%s.crt", s.config.CertsPath, s.domain)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		err = errors.New("parse pem block failed")
		return err
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	s.key = pub
	s.keyRaw = block.Bytes
	return nil
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

func (s *cert) saveToFile() error {
	path := fmt.Sprintf("%s/%s.crt", s.config.CertsPath, s.domain)
	err := ioutil.WriteFile(path, []byte(s.data), 644)
	if err != nil {
		s.log.Debug().Str("option", "save to file").Err(err).Send()
		return err
	}
	return nil
}

func (s *cert) loadFromWeb() error {
	var id string
	if s.cert == nil {
		id = "null"
	} else {
		id = s.cert.SerialNumber.String()
	}
	url := fmt.Sprintf("%s/%s/watch/%s", s.config.CertGateway, s.uuid, id)
	resp, err := resty.New().R().Post(url)
	if err != nil {
		s.log.Debug().Str("option", "download cert").Err(err).Send()
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		s.log.Debug().Str("option", "download cert").Msg("not 2xx response")
		return fmt.Errorf("bad request [%d]", resp.StatusCode())
	}
	if resp.StatusCode() == 204 {
		return nil
	}
	s.data = string(resp.Body())
	s.loadFromPEM()
	s.saveToFile()
	return nil
}

func (s *cert) loop() {
	if s.uuid != "" {
		for {
			s.loadFromWeb()
			time.Sleep(10 * time.Second)
		}
	}
}

func (s *cert) loadFromPEM() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var err error
	s.chain, err = s.parseCert(s.data)
	if err != nil {
		s.log.Debug().Str("option", "load from PEM").Err(err).Send()
		return err
	}
	for _, cert := range s.chain {
		//if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		if !cert.IsCA {
			s.cert = &cert
		}
	}
	if s.cert == nil {
		err = errors.New("can not find final cert")
		s.log.Debug().Str("option", "load from PEM").Err(err).Send()
		return err
	}
	s.chainRaw = []byte(s.data)
	keyPair, err := tls.X509KeyPair(s.chainRaw, s.keyRaw)
	if err != nil {
		s.log.Debug().Str("option", "prepair key pair").Err(err).Send()
		return err
	}
	certs := make([]tls.Certificate, 0)
	s.tlsConfig = &tls.Config{
		Certificates: append(certs, keyPair),
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

func (s *cert) getTLSConfig() *tls.Config {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.tlsConfig
}
