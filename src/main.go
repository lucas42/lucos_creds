package main
import (
	"log/slog"
	"os"
	"strings"
	"golang.org/x/crypto/ssh"
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
	startSftpServer(port, getCreatePrivateKey(), parseAuthorizedKeys(), map[string]ssh.Permissions{})

}

func parseAuthorizedKeys() (map[string]ssh.PublicKey) {
	keyMap := map[string]ssh.PublicKey{}
	fileBytes, err := os.ReadFile("authorized_keys")
	if err != nil {
		slog.Error("Failed to read authorized_keys", slog.Any("error", err))
		os.Exit(6)
	}
	fileLines := strings.Split(string(fileBytes), "\n")
	for _, line := range fileLines {
		if line == "" {
			continue
		}
		parsedKey, user, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			slog.Error("Failed to parse key", "input", line, slog.Any("error", err))
			os.Exit(6)
		}
		keyMap[user] = parsedKey
	}
	slog.Debug("parse authorized keys", "keyMap", keyMap)
	return keyMap
}