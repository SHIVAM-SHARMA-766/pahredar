// Command pahredar runs the Pahredar backend: HTTP API, sync scheduler, and
// maintenance subcommands.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/alerts"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/api"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/assets"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/auth"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/config"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/incidents"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/jobs"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/cvelist"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/detection"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/exploits"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/nvd"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

const usage = `usage: pahredar <command>

commands:
  serve                           apply migrations, run the HTTP API and the sync scheduler
  migrate                         apply pending migrations and exit
  sync <source> [--bootstrap]     run one sync in the foreground and exit
                                  sources: cvelist, nvd, kev, epss, exploitdb, metasploit, nuclei, github, trickest,
                                  sigma, suricata, nmap, splunk, elastic, snort, yara, greenbone, euvd, debian, attack, capec, vulncheck, cwe, feeds, stats
                                  --bootstrap (cvelist, nvd) re-imports everything
  rederive                        rewrite every CVE's derived fields from stored raw records, then refresh stats
                                  (run after changing derivation logic; downloads nothing)
  recheck-articles                re-read the article pages of page-checked feeds and replace their CVE IDs
                                  (run after changing how article pages are read)
  healthcheck                     exit 0 if the local API reports healthy (for container health checks)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "serve":
		err = withConfig(ctx, serve)
	case "migrate":
		err = withConfig(ctx, func(ctx context.Context, cfg config.Config) error {
			return db.Migrate(ctx, cfg.DatabaseURL)
		})
	case "sync":
		err = withConfig(ctx, func(ctx context.Context, cfg config.Config) error {
			return syncOnce(ctx, cfg, os.Args[2:])
		})
	case "rederive":
		err = withConfig(ctx, rederive)
	case "recheck-articles":
		err = withConfig(ctx, recheckArticles)
	case "healthcheck":
		err = healthcheck()
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("fatal", "command", os.Args[1], "err", err)
		os.Exit(1)
	}
}

// nucleiRunner enables active scanning only when configured.
func nucleiRunner(cfg config.Config) *scan.Nuclei {
	if !cfg.ScanActiveEnabled {
		return nil
	}
	return scan.NewNuclei(cfg.NucleiPath, cfg.NucleiTemplatesDir, cfg.DataDir)
}

func withConfig(ctx context.Context, fn func(context.Context, config.Config) error) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})))
	return fn(ctx, cfg)
}

// openStore applies migrations and returns a store; the caller closes it.
func openStore(ctx context.Context, cfg config.Config) (*db.Store, func(), error) {
	if err := db.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return nil, nil, err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return db.NewStore(pool), pool.Close, nil
}

// syncTasks builds every source's task and the runner they share. bootstrap
// forces a full re-import for the sources that support it; serve always
// passes false.
func syncTasks(cfg config.Config, store *db.Store, bootstrap bool) ([]syncer.Task, *syncer.Runner) {
	runner := syncer.NewRunner(store)
	list := syncer.NewCVEList(cvelist.New(cfg.GitHubToken, cfg.DataDir), store, runner)
	nvdJob := syncer.NewNVD(nvd.New(cfg.NVDAPIKey), store, runner)
	enrich := syncer.NewEnrichment(fetch.NewClient(), store, runner)

	tasks := []syncer.Task{
		{Name: syncer.SourceCVEList, Interval: cfg.Intervals.CVEList, Fn: func(ctx context.Context) error { return list.Sync(ctx, bootstrap) }},
		{Name: syncer.SourceNVD, Interval: cfg.Intervals.NVD, Fn: func(ctx context.Context) error { return nvdJob.Sync(ctx, bootstrap) }},
		{Name: syncer.SourceKEV, Interval: cfg.Intervals.KEV, Fn: enrich.SyncKEV},
		{Name: syncer.SourceEPSS, Interval: cfg.Intervals.EPSS, Fn: enrich.SyncEPSS},
	}
	for _, src := range []string{exploits.SourceExploitDB, exploits.SourceMetasploit, exploits.SourceNuclei, exploits.SourceGitHub, exploits.SourceTrickest} {
		tasks = append(tasks, syncer.Task{Name: src, Interval: cfg.Intervals.Exploits,
			Fn: func(ctx context.Context) error { return enrich.SyncExploits(ctx, src) }})
	}
	for _, src := range []string{detection.SourceSigma, detection.SourceSuricata, detection.SourceNmap,
		detection.SourceSplunk, detection.SourceElastic, detection.SourceSnort, detection.SourceYARA} {
		tasks = append(tasks, syncer.Task{Name: src, Interval: cfg.Intervals.Detection,
			Fn: func(ctx context.Context) error { return enrich.SyncDetection(ctx, src) }})
	}
	tasks = append(tasks, syncer.Task{Name: detection.SourceGreenbone, Interval: cfg.Intervals.Greenbone,
		Fn: func(ctx context.Context) error { return enrich.SyncDetection(ctx, detection.SourceGreenbone) }})
	tasks = append(tasks,
		syncer.Task{Name: syncer.SourceEUVD, Interval: cfg.Intervals.Context, Fn: enrich.SyncEUVD},
		syncer.Task{Name: syncer.SourceDebian, Interval: cfg.Intervals.Context, Fn: enrich.SyncDebian},
		syncer.Task{Name: syncer.SourceAttack, Interval: 7 * cfg.Intervals.Context, Fn: enrich.SyncAttack},
		syncer.Task{Name: syncer.SourceCAPEC, Interval: 7 * cfg.Intervals.Context, Fn: enrich.SyncCAPEC},
	)
	if cfg.VulnCheckToken != "" {
		tasks = append(tasks, syncer.Task{Name: syncer.SourceVulnCheck, Interval: cfg.Intervals.Context,
			Fn: func(ctx context.Context) error { return enrich.SyncVulnCheck(ctx, cfg.VulnCheckToken) }})
	}
	tasks = append(tasks,
		syncer.Task{Name: syncer.SourceCWE, Interval: cfg.Intervals.CWE, Fn: enrich.SyncCWE},
		syncer.Task{Name: syncer.SourceFeeds, Interval: cfg.Intervals.Feeds, Fn: enrich.SyncFeeds},
		syncer.Task{Name: syncer.SourceStats, Interval: cfg.Intervals.Stats, Fn: enrich.RefreshStats},
	)
	return tasks, runner
}

func syncOnce(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return errors.New("missing source; see usage")
	}
	fs := flag.NewFlagSet("sync "+args[0], flag.ContinueOnError)
	bootstrap := fs.Bool("bootstrap", false, "re-import everything even if a cursor exists (cvelist, nvd)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if cfg.NVDAPIKey == "" && args[0] == syncer.SourceNVD {
		slog.Warn("NVD_API_KEY is not set; NVD sync will be about 10x slower")
	}
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()
	tasks, _ := syncTasks(cfg, store, *bootstrap)
	var names []string
	for _, t := range tasks {
		if t.Name == args[0] {
			return t.Fn(ctx)
		}
		names = append(names, t.Name)
	}
	return fmt.Errorf("unknown source %q; available: %s", args[0], strings.Join(names, ", "))
}

func recheckArticles(ctx context.Context, cfg config.Config) error {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()
	return syncer.NewEnrichment(fetch.NewClient(), store, syncer.NewRunner(store)).RecheckArticlePages(ctx)
}

func rederive(ctx context.Context, cfg config.Config) error {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()
	runner := syncer.NewRunner(store)
	if err := syncer.Rederive(ctx, store, runner); err != nil {
		return err
	}
	return syncer.NewEnrichment(fetch.NewClient(), store, runner).RefreshStats(ctx)
}

func serve(ctx context.Context, cfg config.Config) error {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	// Seed the first admin from ADMIN_EMAIL/ADMIN_PASSWORD when no users exist.
	if err := bootstrapAdmin(ctx, store, cfg); err != nil {
		return err
	}

	// Durable task queue + worker pool (survives restarts; see docs P2).
	queue := jobs.New(store, slog.Default())
	jobsCtx, stopJobs := context.WithCancel(ctx)
	jobsDone := make(chan struct{})
	go func() { defer close(jobsDone); queue.Work(jobsCtx, 2) }()

	// Auto re-scan tracked assets on a schedule (0 disables).
	if cfg.AssetRescanInterval > 0 {
		go assetRescanLoop(jobsCtx, store, queue, cfg.AssetRescanInterval)
	}

	// Raise alerts for assets matched by known-exploited CVEs, roll them up into
	// per-asset incidents, and deliver new/updated incidents to the configured
	// channels (Phase 4B).
	notifier := alerts.NewNotifier(cfg.AlertWebhookURL, alerts.Mail{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword, From: cfg.SMTPFrom, To: cfg.AlertEmailTo,
	}, slog.Default())
	go incidentCheckLoop(jobsCtx, store, notifier, cfg.AlertEPSSThreshold)

	syncCtx, stopSync := context.WithCancel(ctx)
	syncDone := make(chan struct{})
	var sched *syncer.Scheduler
	if cfg.SyncEnabled {
		if cfg.NVDAPIKey == "" {
			slog.Warn("NVD_API_KEY is not set; NVD sync will be about 10x slower")
		}
		tasks, runner := syncTasks(cfg, store, false)
		sched = syncer.NewScheduler(tasks...)
		runner.OnChange(func(source string) {
			if slices.Contains(syncer.StatsInputs, source) {
				sched.Trigger(syncer.SourceStats)
			}
		})
		go func() {
			defer close(syncDone)
			sched.Run(syncCtx)
		}()
	} else {
		slog.Info("sync scheduler disabled")
		close(syncDone)
	}

	plat := &platform.Platform{Store: store, Log: slog.Default(), Jobs: queue}
	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: api.New(plat, sched, reports.New(fetch.NewClient(), reports.Keys{
			NVD: cfg.NVDAPIKey, GitHub: cfg.GitHubToken, OTX: cfg.OTXKey, AbuseCH: cfg.AbuseCHKey,
			BlueskyHandle: cfg.BlueskyHandle, BlueskyPassword: cfg.BlueskyAppPassword,
		}), cfg.ScanAllowPrivate, nucleiRunner(cfg), auth.Options{
			CookieSecure: cfg.AuthCookieSecure,
			SessionTTL:   cfg.AuthSessionTTL,
			APIKeys:      cfg.APIKeys,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	var serveErr error
	select {
	case serveErr = <-errCh:
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	stopSync()
	stopJobs()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if serveErr == nil {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	}
	select {
	case <-syncDone:
	case <-shutdownCtx.Done():
		slog.Warn("sync did not stop within the shutdown timeout")
	}
	select {
	case <-jobsDone:
	case <-shutdownCtx.Done():
		slog.Warn("job queue did not stop within the shutdown timeout")
	}
	return serveErr
}

// assetRescanLoop enqueues due asset re-scans every interval.
func assetRescanLoop(ctx context.Context, store *db.Store, queue *jobs.Queue, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			n, err := assets.RescanDue(rctx, store, queue, interval)
			cancel()
			if err != nil {
				slog.Warn("asset rescan failed", "err", err)
			} else if n > 0 {
				slog.Info("asset rescans enqueued", "count", n)
			}
		}
	}
}

// bootstrapAdmin seeds the first admin from ADMIN_EMAIL/ADMIN_PASSWORD when the
// user table is empty, so a fresh install has a way in. With users already
// present it is a no-op; with no env set it only warns.
func bootstrapAdmin(ctx context.Context, store *db.Store, cfg config.Config) error {
	n, err := store.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		return nil
	}
	if cfg.AdminEmail == "" || cfg.AdminPassword == "" {
		slog.Warn("no accounts exist; set ADMIN_EMAIL and ADMIN_PASSWORD to seed the first admin (automation can still use API_KEY)")
		return nil
	}
	hash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	u, err := store.CreateUser(ctx, cfg.AdminEmail, hash, string(platform.RoleAdmin))
	if err != nil {
		return fmt.Errorf("create first admin: %w", err)
	}
	slog.Info("seeded first admin account", "user_id", u.ID, "email", u.Email)
	return nil
}

// incidentCheckLoop runs the detectors, rolls alerts up into per-asset
// incidents, and delivers undelivered incidents, shortly after startup and
// periodically.
func incidentCheckLoop(ctx context.Context, store *db.Store, notifier *alerts.Notifier, epssThreshold float64) {
	run := func() {
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := incidents.Check(rctx, store, epssThreshold); err != nil {
			slog.Warn("incident check failed", "err", err)
		}
		// Deliver undelivered incidents, each routed to its client's channels
		// (plus global ones); the env webhook/email is a fallback when no DB
		// channel applies. An incident is marked delivered when at least one
		// target succeeds, or when there is nothing to send; failures leave it
		// pending for the next tick.
		pending, perr := store.PendingIncidents(rctx, 100)
		if perr != nil {
			slog.Warn("pending incidents query failed", "err", perr)
		} else {
			deliverPending(rctx, store, notifier, pending)
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
		run()
	}
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// deliverPending routes each pending incident to its client's channels (plus
// global channels); when none apply it falls back to the env webhook/email. An
// incident is marked delivered on the first successful target, or when there is
// nothing to send to.
func deliverPending(ctx context.Context, store *db.Store, notifier *alerts.Notifier, pending []db.Incident) {
	delivered := []int64{}
	for _, inc := range pending {
		chans, err := store.ChannelsForClient(ctx, inc.ClientID)
		if err != nil {
			slog.Warn("channels lookup failed", "err", err)
			continue
		}
		targets := make([]alerts.Target, 0, len(chans))
		for _, c := range chans {
			targets = append(targets, alerts.Target{Type: c.Type, Target: c.Target})
		}
		if len(targets) == 0 {
			targets = notifier.EnvTargets() // fallback to env config
		}
		if len(targets) == 0 {
			delivered = append(delivered, inc.ID) // nothing configured; in-app only
			continue
		}
		ok := false
		for _, t := range targets {
			if derr := notifier.DeliverIncidentTo(ctx, t.Type, t.Target, inc); derr != nil {
				slog.Warn("incident channel delivery failed", "type", t.Type, "err", derr)
			} else {
				ok = true
			}
		}
		if ok {
			delivered = append(delivered, inc.ID)
		}
	}
	if len(delivered) > 0 {
		if err := store.MarkIncidentsDelivered(ctx, delivered); err != nil {
			slog.Warn("mark delivered failed", "err", err)
		} else {
			slog.Info("incidents delivered", "count", len(delivered))
		}
	}
}

func healthcheck() error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8080/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
