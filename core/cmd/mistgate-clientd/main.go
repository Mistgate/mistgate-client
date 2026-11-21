package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/ipc"
	"github.com/mistgate/mistgate-client/core/internal/probereport"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/proxy"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
	"github.com/mistgate/mistgate-client/core/internal/users"
)

func main() {
	usage := func() {
		fmt.Fprintln(os.Stderr, "usage: mistgate-clientd run [-fake] [-data <dir>] [-verify host:port] | allow <SID> | install [run flags] | uninstall")
		os.Exit(2)
	}
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "allow":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: mistgate-clientd allow <SID>")
			os.Exit(2)
		}
		if err := allowAccount(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "install", "uninstall":
		var err error
		if os.Args[1] == "install" {
			err = install(os.Args[2:])
		} else {
			err = uninstall()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "run":
	default:
		usage()
	}
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	fake := flags.Bool("fake", false, "use the in-process fake engine")
	dataDir := flags.String("data", defaultDataDir(), "subscription data directory")
	verify := flags.String("verify", "", "override the tunnel verification target (development only)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	start := func(ctx context.Context, powerEvents <-chan time.Duration) error {
		return run(ctx, *fake, *dataDir, *verify, powerEvents)
	}
	if asService, err := runAsService(start); asService {
		if err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := start(ctx, nil); err != nil {
		os.Exit(1)
	}
}

func shouldConnectAtStart(configured settings.Settings) bool {
	return configured.LastServer != "" && (configured.Autoconnect || configured.Restore && configured.LastOn)
}

// shouldResumeAtStart: the tunnel was up when the service stopped without being told to disconnect (last_up stays set
// through a crash, a reboot and a service stop), and the kill switch promises the network is not open without it. The
// service then holds the network and reconnects whatever restore and autoconnect say; with the kill switch off there is
// nothing to hold and the two settings decide as before. A connect that never came up leaves the network open, before
// a restart and after it.
func shouldResumeAtStart(configured settings.Settings) bool {
	return configured.LastServer != "" && configured.LastUp && configured.KillSwitch != "off"
}

// savedServerGone: the server the service would connect to is no longer in any subscription (removed, or the list
// replaced). A resume holds the network for a tunnel it cannot bring up, so it does not start. When the profiles cannot
// be read the engine decides, as it does for any connect.
func savedServerGone(configured settings.Settings, profiles func() ([]profile.Profile, error)) bool {
	list, err := profiles()
	if err != nil {
		return false
	}
	_, found := profile.PickForSettings(list, configured.LastServer, "auto", configured.LastSub, configured.Protocol, configured.Game)
	return !found
}

// keepLastUp writes last_up from the session's own states: connected sets it, a session that ended in an error (the
// network is open then) clears it. "off" is left alone: the service says it when it stops too, and a disconnect the
// person asked for clears the flag where it is handled. "blocked" keeps it: the network is held, as it will be again.
func keepLastUp(statuses <-chan session.Event, store *settings.Store) {
	for event := range statuses {
		status, ok := event.Data.(session.Status)
		if !ok || status.State != "connected" && status.State != "error" {
			continue
		}
		if up := status.State == "connected"; store.Get().LastUp != up {
			_, _ = store.Set(map[string]json.RawMessage{"last_up": json.RawMessage(strconv.FormatBool(up))})
		}
	}
}

// A panel that issued a new key leaves a connected client with auth_rejected until its next scheduled sync, and the
// session would give up first. One sync of that subscription fetches the new profiles for the next attempt. The panel
// allows 30 requests an hour per device: one in this window is at most 6.
const refreshAfterRejection = 10 * time.Minute

// subscriptionOf is the subscription of the server a status names; the one the person connected through when the status
// names none (a first connect that failed).
func subscriptionOf(list []subs.Subscription, serverID, lastSub string) string {
	for _, sub := range list {
		if serverID != "" && slices.ContainsFunc(sub.Servers, func(server subs.Server) bool { return server.ID == serverID }) {
			return sub.ID
		}
	}
	return lastSub
}

// refreshOnRejection asks for a refresh of the subscription when a connect or reconnect is refused for its key, at most
// once per window for each subscription. refresh must not wait for the network: this loop drains the session's events.
func refreshOnRejection(statuses <-chan session.Event, subOf func(serverID string) string, refresh func(sub string), now func() time.Time) {
	last := make(map[string]time.Time)
	for event := range statuses {
		status, ok := event.Data.(session.Status)
		if !ok || status.Error != "auth_rejected" || status.State != "reconnecting" && status.State != "error" {
			continue
		}
		sub := subOf(status.ServerID)
		if at, asked := last[sub]; sub == "" || asked && now().Sub(at) < refreshAfterRejection {
			continue
		}
		last[sub] = now()
		refresh(sub)
	}
}

// keepCrashOutput: a service has no console, so what the runtime says when it dies (the panic and the goroutines'
// stacks) goes to crash.log in the data directory. The file is started again once it is over 256 KiB.
func keepCrashOutput(dataDir string) {
	path := filepath.Join(dataDir, "crash.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(path); err == nil && info.Size() > 256<<10 {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	if file, err := os.OpenFile(path, flags, 0600); err == nil {
		_ = debug.SetCrashOutput(file, debug.CrashOptions{})
		serviceStderrTo(file)
	}
}

func defaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.TempDir()
		if runtime.GOOS == "windows" {
			base = `C:\ProgramData`
		}
	}
	return filepath.Join(base, "Mistgate")
}

// run owns the lifecycle; the context ends it (Ctrl+C in a console, a stop request as a Windows service).
func run(ctx context.Context, useFake bool, dataDir, verify string, powerEvents <-chan time.Duration) error {
	// before anything is written there: a folder planted by another user is not used. When the name is held by a
	// program that cannot be moved aside, the service takes a directory beside it; everything below uses that one.
	dataDir, err := subs.ClaimDirectory(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "the data directory could not be secured")
		return err
	}
	var callerAccess *ipc.CallerAccess
	allowListReadFailed := false
	if isLocalSystemProcess() {
		allowedSIDs, err := users.Read(dataDir)
		if err != nil {
			allowedSIDs = nil
			allowListReadFailed = true
		}
		callerAccess = ipc.NewCallerAccess(allowedSIDs, func(sids []string) error {
			return users.Write(dataDir, sids)
		})
	}
	keepCrashOutput(dataDir)
	var eventMu sync.RWMutex
	var eventHub *session.Hub
	logs := ipc.NewLogStore()
	logger := ipc.NewEventLogger(func(data any) {
		eventMu.RLock()
		hub := eventHub
		eventMu.RUnlock()
		if hub != nil {
			hub.Publish("log", data)
		}
	}, logs)
	slog.SetDefault(logger.With("src", "subs"))
	if allowListReadFailed {
		logger.Warn("IPC allow-list read failed", "code", "read_failed")
	}
	store, err := subs.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open the data directory:", err)
		return err
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open settings:", err)
		return err
	}
	geoStore, err := geo.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open geo cache:", err)
		return err
	}
	slog.SetDefault(logger.With("src", "engine"))
	go store.Run(ctx)
	var eng engine.Engine
	var routeState session.RouteState
	var routes func() geo.Routes
	var check func(string) geo.Check
	var dialVPN func(context.Context, string, uint16) (net.Conn, error)
	var homeAddr func() string
	// the list's numbers: a round trip, not a session (VLESS and TrustTunnel: one TCP connect)
	ping := ipc.PingFunc(diag.Latency)
	if useFake {
		fake := engine.NewFake(engine.FakeConfig{StepDelay: 300 * time.Millisecond})
		eng = fake
		dialVPN = fake.DialVPN
		homeAddr = func() string { return "" }
		routeState.Effective = func(settings.Settings) string { return "all" }
		routes = func() geo.Routes {
			configured := settingsStore.Get()
			return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
		}
		ping = func(_ context.Context, p profile.Profile, _ time.Duration) (time.Duration, error) {
			return time.Duration(20+crc32.ChecksumIEEE([]byte(p.ID))%180) * time.Millisecond, nil // plausible, stable per server
		}
		check = func(name string) geo.Check {
			configured := settingsStore.Get()
			region := ""
			if geo.ValidRegion(configured.RouteRegion) {
				region = configured.RouteRegion
			}
			return geoStore.CheckName(configured.RouteMode, region, name, false)
		}
	} else {
		real := engine.NewReal(store.Profiles, settingsStore.Get, geoStore, verify)
		eng = real
		real.AllowDest = proxy.AllowedAddr
		dialVPN = real.DialVPN
		homeAddr = real.HomeAddr
		routeState.Effective = real.EffectiveRoute
		routeState.Path = real.RoutePath
		routeState.Refresh = real.RefreshAutoRegion
		routes = func() geo.Routes { return real.Routes(settingsStore.Get()) }
		check = func(name string) geo.Check { return real.CheckSite(settingsStore.Get(), name) }
	}
	routeState.Snapshot = func() geo.Routes { return routes() }
	// the programs the rules already name stay in the window's list even when they are not running
	apps := func() []engine.AppInfo {
		rules := geoStore.GetRules()
		return engine.ListApps(slices.Concat(rules.Direct.Apps, rules.VPN.Apps))
	}
	manager := session.NewManager(eng, settingsStore.Get, routeState)
	defer manager.Close()
	if powerEvents != nil {
		go func() {
			for {
				select {
				case asleep, ok := <-powerEvents:
					if !ok {
						return
					}
					manager.NetworkChanged("resume", asleep)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	eventMu.Lock()
	eventHub = manager.Events()
	eventMu.Unlock()
	if statuses, err := manager.Events().Subscribe([]string{"status"}); err == nil {
		go keepLastUp(statuses.C, settingsStore) // ends when the manager closes its hub
	}
	if statuses, err := manager.Events().Subscribe([]string{"status"}); err == nil {
		go refreshOnRejection(statuses.C, func(serverID string) string {
			return subscriptionOf(store.List(), serverID, settingsStore.Get().LastSub)
		}, func(sub string) {
			go store.Refresh(ctx, sub) // the store tells the session when the profiles changed
		}, time.Now)
	}
	if configured := settingsStore.Get(); shouldResumeAtStart(configured) || shouldConnectAtStart(configured) {
		target := engine.Target{Server: configured.LastServer, Protocol: "auto", Sub: configured.LastSub}
		resume := shouldResumeAtStart(configured)
		if resume && savedServerGone(configured, store.Profiles) {
			// nothing to hold the network for; and the flag must not bring the hold back at every start
			_, _ = settingsStore.Set(map[string]json.RawMessage{"last_up": json.RawMessage("false")})
			resume = false
		}
		if resume {
			_, _ = manager.Resume(ctx, target)
		} else if shouldConnectAtStart(configured) {
			_, _ = manager.ConnectAtStart(ctx, target)
		}
	}
	reporter := &probereport.Reporter{Subs: store, Log: logger.With("src", "report")}
	diagnostics := diag.NewRunner(diag.Config{Profiles: store.Profiles, Tunnel: func() bool {
		status, err := manager.Status(ctx)
		return err == nil && status.State == "connected"
	}, Connected: func() string {
		// the status carries the profile's name (its id when it has no name), not the id
		if status, err := manager.Status(ctx); err == nil && status.State == "connected" {
			return status.Server
		}
		return ""
	}, Logger: logger.With("src", "diag")}, func(state diag.State) {
		manager.Events().Publish("diag", state)
		if state.State == "done" { // a finished check goes to the panel when the person has the switch on
			go reporter.Auto(context.Background(), state.Result)
		}
	})
	localProxy := proxy.New(proxy.Config{
		Dir: dataDir, Settings: settingsStore.Get, Dial: dialVPN, Host: homeAddr,
		Firewall: proxy.FirewallRule, Logger: logger.With("src", "proxy"),
	})
	defer localProxy.Close()
	localProxy.Reload()
	if err := ipc.Run(ctx, manager, logger, store, settingsStore, diagnostics, logs, geoStore, routes, check, apps, ping, localProxy, callerAccess); err != nil {
		logger.With("src", "ipc").Error("service stopped", "error", err)
		return err
	}
	return nil
}
