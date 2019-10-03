package rtls

import (
	"github.com/rs/zerolog"
	"encoding/json"
	"io/ioutil"
	"log"
)

type config struct {
	Listen      string
	CertGateway string
	CertsPath   string
	Debug bool
}

func (s *config) load(path string) *config {
	s.Listen = "0.0.0.0:443"
	s.CertGateway = "https://cert.catofes.com/"
	d, e := ioutil.ReadFile(path)
	if e != nil {
		log.Fatal(e)
	}
	e = json.Unmarshal(d, s)
	if e != nil {
		log.Fatal(e)
	}
	if s.Debug{
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	return s
}
