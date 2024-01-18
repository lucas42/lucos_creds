package main
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"golang.org/x/crypto/ssh"
)

/**
 * Attempts to get a private RSA key from the mounted docker volume
 * If that fails, a new public/private key pair is generated and saved to the volume
 *
 * @returns ssh.Singer
 * (No errors are returned - instead any failures log and then exit.  Nothing else in the programme is gonna work without a private key)
 */
func getCreatePrivateKey() (ssh.Signer) {
	privateKeyPath := "/var/lib/creds_store/id_rsa"
	publicKeyPath := "/var/lib/creds_store/id_rsa.pub"
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		slog.Warn("Failed to load private key, generating a new one")
		bitSize := 4096
		key, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			slog.Error("Failed to generate RSA keypair", slog.Any("error", err))
			os.Exit(4)
		}

		// Encode private key
		privateKeyBytes = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			},
		)

		// Write private key to file
		err = os.WriteFile(privateKeyPath, privateKeyBytes, 0700)
		if err != nil {
			slog.Error("Failed to write private key to filesystem", slog.Any("error", err))
			os.Exit(4)
		}

		// Encode public key
		publicKeyBytes := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(key.Public().(*rsa.PublicKey)),
			},
		)

		// Write public key to file.
		err = os.WriteFile(publicKeyPath, publicKeyBytes, 0755)
		if err != nil {
			slog.Error("Failed to write public key to filesystem", slog.Any("error", err))
			os.Exit(4)
		}
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		slog.Error("Failed to parse private key", slog.Any("error", err))
		os.Exit(5)
	}

	return privateKey
}

func acceptSshConnection(socket net.Listener, config *ssh.ServerConfig) {
	slog.Debug("Accepting new connection from socket")
	connection, err := socket.Accept()
	if err != nil {
		slog.Warn("Failed to accept connection from socket", slog.Any("error", err))
		return
	}

	sshConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		slog.Warn("Failed to create a new server connection", slog.Any("error", err))
		return
	}
	slog.Debug("Login", "user", sshConnection.User())

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		slog.Debug("Incoming channel", "channelType", newChannel.ChannelType())
		// TODO: actually do some stuff here
	}
}

func main() {

	// Check for DEBUG environment variable to drop the log level to Debug
	if os.Getenv("DEBUG") != "" {
		// Can be replaced with `slog.SetLogLoggerLevel(slog.LevelDebug)` in golang 1.22
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true,  // TODO: Implement some client authentication
	}

	config.AddHostKey(getCreatePrivateKey())

	port := os.Getenv("PORT")
	if port == "" {
		slog.Error("Environment variable `PORT` not set")
		os.Exit(2)
	}

	socket, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("Failed to listen for connection", slog.Any("error", err))
		os.Exit(3)
	}
	slog.Info("Listening for connections", "address", socket.Addr())

	for {
		// Handle each incoming connection in its own goroutine
		go acceptSshConnection(socket, config)
	}
}