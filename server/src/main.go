package main
import (
	"log/slog"
	"os"
)


func main() {

	// Check for DEBUG environment variable to drop the log level to Debug
	if os.Getenv("DEBUG") != "" {
		// Can be replaced with `slog.SetLogLoggerLevel(slog.LevelDebug)` in golang 1.22
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	port := os.Getenv("PORT")
	if port == "" {
		slog.Error("Environment variable `PORT` not set")
		os.Exit(2)
	}

	loganne := Loganne{
		endpoint: os.Getenv("LOGANNE_ENDPOINT"),
		source: "lucos_creds",
		ui_domain: os.Getenv("UI_DOMAIN"),
	}
	done, _ := startSftpServer(
		port,
		getCreateSshSigner("/var/lib/creds_store/server_key"),
		initDatastore("/var/lib/creds_store/creds.sqlite", "/var/lib/creds_store/data_key", loganne),
		parseAuthorizedKeys("authorized_keys"),
		parseUserPermissions(),
	)
	<- done()
}
