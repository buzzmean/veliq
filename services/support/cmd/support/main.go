// The support service has its own database and does not modify control-plane state.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/buzzmean/neexitlag/services/support"
	"github.com/jackc/pgx/v5/pgxpool"
)

func secret(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		log.Fatal("cannot read credential file")
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		log.Fatal("empty credential file")
	}
	return v
}
func main() {
	listen := flag.String("listen", "127.0.0.1:8091", "loopback HTTP behind HTTPS nginx")
	origin := flag.String("origin", "https://veliqapp.ru", "exact public HTTPS origin")
	dbFile := flag.String("database-url-file", "", "support-only PostgreSQL credential file")
	tokenFile := flag.String("telegram-token-file", "", "optional bot token file; absent means read-only/unavailable")
	chat := flag.Int64("telegram-chat-id", 0, "private support group ID")
	operators := flag.String("telegram-operators", "", "comma-separated numeric operator IDs")
	migrate := flag.Bool("migrate", false, "apply support schema and exit")
	flag.Parse()
	host, _, e := net.SplitHostPort(*listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("listen must be a loopback IP")
	}
	u, e := url.Parse(*origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		log.Fatal("origin must be an HTTPS origin without a path")
	}
	if *dbFile == "" {
		log.Fatal("database-url-file required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, e := pgxpool.ParseConfig(secret(*dbFile))
	if e != nil {
		log.Fatal("invalid database configuration")
	}
	cfg.MaxConns = 12
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		log.Fatal("database unavailable")
	}
	defer db.Close()
	if e = db.Ping(ctx); e != nil {
		log.Fatal("database unavailable")
	}
	store := &support.Store{DB: db}
	if *migrate {
		if e = store.Migrate(ctx); e != nil {
			log.Fatal("support migration failed")
		}
		log.Print("support schema ready")
		return
	}
	enabled := *tokenFile != ""
	if enabled {
		ids, e := support.ParseOperators(*operators)
		if e != nil || *chat >= 0 {
			log.Fatal("negative group ID and operator IDs required")
		}
		token := secret(*tokenFile)
		parts := strings.Split(token, ":")
		if len(parts) != 2 || len(parts[1]) < 20 {
			log.Fatal("invalid bot token format")
		}
		if _, e = strconv.ParseInt(parts[0], 10, 64); e != nil {
			log.Fatal("invalid bot token format")
		}
		tg := &support.Telegram{Store: store, Token: token, ChatID: *chat, Operators: ids}
		go func() {
			if e := tg.Run(ctx, func(code string) { log.Print(code) }); e != nil && ctx.Err() == nil {
				log.Print("support worker stopped")
				stop()
			}
		}()
	}
	srv := &http.Server{Addr: *listen, Handler: &support.Server{Store: store, Origin: *origin, Enabled: enabled, TrustProxy: true}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	log.Printf("support started; telegram configured=%t", enabled)
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal("support listener failed")
	}
}
