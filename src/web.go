package rtls

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type webServer struct {
	config
	log zerolog.Logger
}

func (s *webServer) init() *webServer {
	s.log = s.config.logger.With().Str("module", "web").Logger()
	return s
}

func (s *webServer) serve(ctx context.Context) {
	if s.config.WebListen == "" {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/logs", s.handleLogs)
	mux.HandleFunc("/healthz", s.handleHealthz)

	srv := &http.Server{
		Addr:    s.config.WebListen,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		s.log.Info().Msg("Shutting down web server.")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.log.Warn().Err(err).Msg("Web server shutdown timed out; closing connections.")
			if err := srv.Close(); err != nil && err != http.ErrServerClosed {
				s.log.Warn().Err(err).Msg("Force-close web server failed.")
			}
		}
	}()

	s.log.Info().Str("addr", s.config.WebListen).Msg("Web server started.")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.log.Error().Err(err).Msg("Web server error.")
	}
}

// handleLogs returns buffered log lines as JSON.
// Supports optional query params:
//
//	?n=100   return last N lines (default: all)
//	?q=text  filter lines containing text (case-insensitive)
func (s *webServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	lines := s.config.logBuffer.getAll()

	if q := r.URL.Query().Get("q"); q != "" {
		q = strings.ToLower(q)
		filtered := lines[:0]
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), q) {
				filtered = append(filtered, l)
			}
		}
		lines = filtered
	}

	if n := r.URL.Query().Get("n"); n != "" {
		if count, err := strconv.Atoi(n); err == nil && count > 0 && count < len(lines) {
			lines = lines[len(lines)-count:]
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lines)
}

func (s *webServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}
