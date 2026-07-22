package rtls

import "sync"

type logBuffer struct {
	data  []string
	in    chan []byte
	len   int
	mutex sync.RWMutex
}

func (s *logBuffer) init(len int) *logBuffer {
	s.data = make([]string, 0)
	s.in = make(chan []byte, 256)
	s.len = len
	go s.loop()
	return s
}

func (s *logBuffer) loop() {
	for {
		v := <-s.in
		s.mutex.Lock()
		if s.len <= 0 {
			s.mutex.Unlock()
			continue
		}
		if len(s.data) < s.len {
			s.data = append(s.data, string(v))
		} else {
			s.data = s.data[1:]
			s.data = append(s.data, string(v))
		}
		s.mutex.Unlock()
	}
}

func (s *logBuffer) getAll() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	result := make([]string, len(s.data))
	copy(result, s.data)
	return result
}

func (s *logBuffer) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	_ = copy(buf, p)
	s.in <- buf
	return len(p), nil
}
