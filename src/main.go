package main
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"golang.org/x/crypto/ssh"
)

/**
 * Attempts to get a private RSA key from the mounted docker volume
 * If that fails, a new public/private key pair is generated and saved to the volume
 *
 * @returns ssh.Singer
 * (No errors are return, the function just panics.  Nothing else in the programme is gonna work without a private key)
 */
func getCreatePrivateKey() (ssh.Signer) {
	privateKeyPath := "/var/lib/creds_store/id_rsa"
	publicKeyPath := "/var/lib/creds_store/id_rsa.pub"
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Println("Failed to load private key, generating a new one")
		bitSize := 4096
		key, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			panic(err)
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
			panic(err)
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
			panic(err)
		}
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		panic(err)
	}

	return privateKey
}

func acceptSshConnection(socket net.Listener, config *ssh.ServerConfig, logger *log.Logger, warn *log.Logger) {
		connection, err := socket.Accept()
		if err != nil {
			warn.Println(err)
			return
		}

		sshConnection, channels, requests, err := ssh.NewServerConn(connection, config)
		if err != nil {
			warn.Println(err)
			return
		}
		logger.Println("Login from user: ", sshConnection.User())

		go ssh.DiscardRequests(requests)

		for newChannel := range channels {
			logger.Println("Incoming channel: ", newChannel.ChannelType())
			// TODO: actually do some stuff here
		}
}

func main() {
	logger := log.New(os.Stdout, "LOG:", log.Ldate|log.Ltime|log.Lshortfile)
	warn := log.New(os.Stderr, "WARN:", log.Ldate|log.Ltime|log.Lshortfile)
	config := &ssh.ServerConfig{
		NoClientAuth: true,  // TODO: Implement some client authentication
	}

	config.AddHostKey(getCreatePrivateKey())

	port := os.Getenv("PORT")
	if port == "" {
		warn.Fatal("Environment variable `PORT` not set")
	}

	socket, err := net.Listen("tcp", ":"+port)
	if err != nil {
		warn.Fatal("Failed to listen for connection", err)
	}
	fmt.Printf("Listening on %v\n", socket.Addr())

	for {
		// Handle each incoming connection in its own goroutine
		go acceptSshConnection(socket, config, logger, warn)
	}
}