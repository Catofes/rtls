package rtls

import "sync"

type storge struct {
	config
	mutex sync.Mutex
	data  map[string]interface{}
}

func (s *storge) load() *storge {
	return s
}
