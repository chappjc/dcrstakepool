package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/context"

	"github.com/decred/dcrrpcclient"
	"github.com/decred/dcrstakepool/controllers"
	"github.com/decred/dcrstakepool/system"

	"github.com/zenazn/goji/bind"
	"github.com/zenazn/goji/graceful"
	"github.com/zenazn/goji/web"
	"github.com/zenazn/goji/web/middleware"
)

var (
	cfg *config
)

func init() {
	bind.WithFlag()
}

func main() {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		os.Exit(1)
	}
	cfg = loadedCfg
	dcrstakepoolLog.Infof("Version: %s", version())
	dcrstakepoolLog.Infof("Network: %s", activeNetParams.Params.Name)

	// Until flag import is removed along with glog, this will allow go-flags
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	filename := flag.String("config", "config.toml", "Path to configuration file")

	flag.Parse()

	fmt.Println(bind.Default().Addr().String())

	application := system.NewApplication(filename, dcrstakepoolLog)
	if err = application.LoadTemplates(); err != nil {
		dcrstakepoolLog.Criticalf("Failed to load templates: %v", err)
		os.Exit(1)
	}

	// Set up signal handler
	// SIGUSR1 = Reload html templates (On nix systems)
	system.ReloadTemplatesSig(application)

	dcrrpcclient.UseLogger(dcrstakepoolLog)

	// Setup static files
	static := web.New()
	publicPath := application.Config.Get("general.public_path").(string)
	static.Get("/assets/*", http.StripPrefix("/assets/",
		http.FileServer(http.Dir(publicPath))))

	http.Handle("/assets/", static)

	// Apply middleware
	app := web.New()
	app.Use(middleware.RequestID)
	app.Use(middleware.Logger) // TODO: reimplement to use our logger
	app.Use(middleware.Recoverer)

	app.Use(application.ApplyTemplates)
	app.Use(application.ApplySessions)
	app.Use(application.ApplyDbMap)
	app.Use(application.ApplyAuth)
	app.Use(application.ApplyIsXhr)
	app.Use(application.ApplyCsrfProtection)
	app.Use(context.ClearHandler)

	controller, err := controllers.NewMainController(activeNetParams.Params,
		cfg.AdminIPs, cfg.BaseURL, cfg.ClosePool, cfg.ClosePoolMsg,
		cfg.ColdWalletExtPub, cfg.PoolEmail, cfg.PoolFees, cfg.PoolLink,
		cfg.RecaptchaSecret, cfg.RecaptchaSitekey, cfg.SMTPFrom, cfg.SMTPHost,
		cfg.SMTPUsername, cfg.SMTPPassword, cfg.Version,
		cfg.WalletHosts, cfg.WalletCerts, cfg.WalletUsers, cfg.WalletPasswords,
		cfg.MinServers)
	if err != nil {
		application.Close()
		dcrstakepoolLog.Errorf("Failed to initialize the main controller: %v",
			err)
		fmt.Fprintf(os.Stderr, "Fatal error in controller init: %v",
			err)
		os.Exit(1)
	}

	err = controller.RPCSync(application.DbMap, cfg.SkipVoteBitsSync)
	if err != nil {
		application.Close()
		dcrstakepoolLog.Errorf("Failed to sync the wallets: %v",
			err)
		fmt.Fprintf(os.Stderr, "Fatal error in rpc sync: %v",
			err)
		os.Exit(1)
	}

	controller.RPCStart()

	// Couple of files - in the real world you would use nginx to serve them.
	app.Get("/robots.txt", http.FileServer(http.Dir(publicPath)))
	app.Get("/favicon.ico", http.FileServer(http.Dir(publicPath+"/images")))

	// Home page
	app.Get("/", application.Route(controller, "Index"))

	// Address form
	app.Get("/address", application.Route(controller, "Address"))
	app.Post("/address", application.Route(controller, "AddressPost"))

	// API
	app.Handle("/api/*", application.Route(controller, "API"))

	// Email change/update confirmation
	app.Get("/emailupdate", application.Route(controller, "EmailUpdate"))

	// Email verification
	app.Get("/emailverify", application.Route(controller, "EmailVerify"))

	// Error page
	app.Get("/error", application.Route(controller, "Error"))

	// Password Reset routes
	app.Get("/passwordreset", application.Route(controller, "PasswordReset"))
	app.Post("/passwordreset", application.Route(controller, "PasswordResetPost"))

	// Password Update routes
	app.Get("/passwordupdate", application.Route(controller, "PasswordUpdate"))
	app.Post("/passwordupdate", application.Route(controller, "PasswordUpdatePost"))

	// Settings routes
	app.Get("/settings", application.Route(controller, "Settings"))
	app.Post("/settings", application.Route(controller, "SettingsPost"))

	// Sign In routes
	app.Get("/signin", application.Route(controller, "SignIn"))
	app.Post("/signin", application.Route(controller, "SignInPost"))

	// Sign Up routes
	app.Get("/signup", application.Route(controller, "SignUp"))
	app.Post("/signup", application.Route(controller, "SignUpPost"))

	// Stats
	app.Get("/stats", application.Route(controller, "Stats"))

	// Status
	app.Get("/status", application.Route(controller, "Status"))

	// Tickets routes
	app.Get("/tickets", application.Route(controller, "Tickets"))
	app.Post("/tickets", application.Route(controller, "TicketsPost"))

	// KTHXBYE
	app.Get("/logout", application.Route(controller, "Logout"))

	graceful.PostHook(func() {
		controller.RPCStop()
		application.Close()
	})
	app.Abandon(middleware.Logger)
	app.Compile()

	server := &http.Server{Handler: app}
	listener := bind.Default()
	//listener := net.Listen("tcp", addr)
	server.Serve(listener)
	//http.Serve(listener, app)
}
