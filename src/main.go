package rtls

import "flag"

//Run function is the entry of this program
func Run() {
	path := flag.String("config", "./config.json", "config path")
	flag.Parse()
	c := (&config{}).load(*path)
	s := (&tlsServer{config: *c}).init()
	s.listen()
}
