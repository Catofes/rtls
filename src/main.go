package rtls

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
)

// Run function is the entry of this program
func Run() {
	path := flag.String("c", "./config.json", "config path")
	flag.Parse()
	c := (&config{}).load(*path)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	s := (&tlsServer{config: *c}).init(ctx)
	go (&webServer{config: *c}).init().serve(ctx)
	s.listen(ctx)
}
