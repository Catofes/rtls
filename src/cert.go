package rtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
)

type cert struct {
	config
	domain   string
	uuid     string
	chain    []x509.Certificate
	cert     *x509.Certificate
	chainRaw []byte
	data     string
	key      interface{}
	keyRaw   []byte
	mutex    sync.Mutex
	//lastUpdate time.Time
	log       zerolog.Logger
	tlsConfig *tls.Config
}

type certState struct {
	data      string
	chain     []x509.Certificate
	cert      *x509.Certificate
	chainRaw  []byte
	tlsConfig *tls.Config
}

func (s *cert) init(ctx context.Context, domain string, l zerolog.Logger) *cert {
	s.domain = domain
	s.chain = make([]x509.Certificate, 0)
	s.log = l.With().Str("domain", s.domain).Logger()
	s.loadKey()
	s.loadFromFile()
	go s.loop(ctx)
	return s
}

func (s *cert) loadKey() error {
	var err error
	defer func() {
		if err != nil {
			s.log.Fatal().Str("option", "load key").Err(err).Send()
		}
	}()
	path := fmt.Sprintf("%s/%s.key", s.config.CertsPath, s.domain)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		err = errors.New("parse pem block failed")
		return err
	}
	pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	s.key = pub
	s.keyRaw = data
	return nil
}

func (s *cert) loadFromFile() error {
	path := fmt.Sprintf("%s/%s.crt", s.config.CertsPath, s.domain)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		s.log.Debug().Str("option", "load from file").Err(err).Send()
		return err
	}
	return s.loadFromPEM(string(data))
}

func (s *cert) saveToFile(data string) error {
	path := fmt.Sprintf("%s/%s.crt", s.config.CertsPath, s.domain)
	tmp, err := os.CreateTemp(s.config.CertsPath, fmt.Sprintf(".%s.crt-*", s.domain))
	if err != nil {
		s.log.Debug().Str("option", "save to file").Err(err).Send()
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		s.log.Debug().Str("option", "save to file").Err(err).Send()
		return err
	}
	return nil
}

func (s *cert) loadFromWeb() error {
	id := s.currentSerial()
	url := fmt.Sprintf("%s/%s/wait/%s", s.config.CertGateway, s.uuid, id)
	resp, err := resty.New().R().Get(url)
	if err != nil {
		s.log.Debug().Str("option", "download cert").Err(err).Send()
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		s.log.Debug().Str("option", "download cert").Msg("not 2xx response")
		return fmt.Errorf("bad request [%d]", resp.StatusCode())
	}
	if resp.StatusCode() == 204 {
		return nil
	}
	data := string(resp.Body())
	state, err := s.prepareState(data)
	if err != nil {
		return err
	}
	if err := s.saveToFile(data); err != nil {
		return err
	}
	s.applyState(state)
	return nil
}

func (s *cert) loop(ctx context.Context) {
	if s.uuid == "" {
		return
	}
	const (
		initialBackoff = 10 * time.Second
		maxBackoff     = 5 * time.Minute
	)
	backoff := initialBackoff
	for {
		err := s.loadFromWeb()
		if err != nil {
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			sleep := backoff + jitter
			s.log.Warn().Err(err).Dur("retry_in", sleep).Msg("Cert fetch failed, retrying.")
			select {
			case <-ctx.Done():
				s.log.Debug().Msg("Cert loop stopped.")
				return
			case <-time.After(sleep):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = initialBackoff
			select {
			case <-ctx.Done():
				s.log.Debug().Msg("Cert loop stopped.")
				return
			case <-time.After(10 * time.Second):
			}
		}
	}
}

func (s *cert) loadFromPEM(data string) error {
	state, err := s.prepareState(data)
	if err != nil {
		return err
	}
	s.applyState(state)
	return nil
}

func (s *cert) prepareState(data string) (*certState, error) {
	l := s.log.With().Str("option", "load from PEM").Logger()
	chain, err := s.parseCert(data)
	if err != nil {
		l.Err(err).Send()
		return nil, err
	}
	var cert *x509.Certificate
	for k, c := range chain {
		//if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		if !c.IsCA {
			cert = &chain[k]
		}
	}
	if cert == nil {
		err = errors.New("can not find final cert")
		l.Err(err).Send()
		return nil, err
	}

	chainRaw := []byte(data)
	keyPair, err := tls.X509KeyPair(chainRaw, s.keyRaw)
	if err != nil {
		s.log.Debug().Str("option", "prepare key pair").Err(err).Send()
		return nil, err
	}
	return &certState{
		data:     data,
		chain:    chain,
		cert:     cert,
		chainRaw: chainRaw,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{keyPair},
		},
	}, nil
}

func (s *cert) applyState(state *certState) {
	l := s.log.With().Str("option", "load from PEM").Logger()

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.cert != nil && state.cert.SerialNumber.String() == s.cert.SerialNumber.String() {
		l.Debug().Str("serial", state.cert.SerialNumber.String()).Msg("Same cert, ignore.")
		return
	}
	l.Debug().Str("serial", state.cert.SerialNumber.String()).Msg("New cert, update.")
	s.data = state.data
	s.chain = state.chain
	s.cert = state.cert
	s.chainRaw = state.chainRaw
	s.tlsConfig = state.tlsConfig
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

func (s *cert) currentSerial() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.cert == nil {
		return "null"
	}
	return s.cert.SerialNumber.String()
}
