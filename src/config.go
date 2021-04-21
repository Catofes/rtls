package rtls

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/rs/zerolog"
)

type certConfig struct {
	UUID string
}

type config struct {
	Listen       string
	Listens      []string
	CertGateway  string
	CertsPath    string
	Debug        bool
	LogBufferLen int
	Fallback     string
	Rules        []map[string]string
	Certs        map[string]certConfig
	CAPath       string
	logBuffer    *logBuffer
	logger       zerolog.Logger
}

func (s *config) load(path string) *config {
	s.Listen = "[::]:443"
	s.Listens = make([]string, 0)
	s.CertGateway = "https://cert.catofes.com/"
	s.LogBufferLen = 10000

	d, e := ioutil.ReadFile(path)
	if e != nil {
		log.Fatal(e)
	}
	e = json.Unmarshal(d, s)
	if e != nil {
		log.Fatal(e)
	}

	s.logBuffer = (&logBuffer{}).init(s.LogBufferLen)
	s.logger = zerolog.New(io.MultiWriter(os.Stdout, s.logBuffer))

	if s.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	return s
}
