package rtls

type logBuffer struct {
	data []string
	in   chan []byte
	len  int
}

func (s *logBuffer) init(len int) *logBuffer {
	s.data = make([]string, 0)
	s.in = make(chan []byte)
	s.len = len
	go s.loop()
	return s
}

func (s *logBuffer) loop() {
	for {
		v := <-s.in
		if len(s.data) < s.len {
			s.data = append(s.data, string(v))
		} else {
			s.data = s.data[1:]
			s.data = append(s.data, string(v))
		}
	}
}

// func (s *logBuffer) getAll() []string {
// 	return s.data
// }

func (s *logBuffer) Write(p []byte) (n int, err error) {
	s.in <- p
	return len(p), nil
}
