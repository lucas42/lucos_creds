package main
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
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

func handleSshConnection(connection net.Conn, config *ssh.ServerConfig) {
	slog.Debug("New connection received")
	sshConnection, channels, globalRequests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		slog.Warn("Failed to create a new server connection", slog.Any("error", err))
		return
	}
	slog.Debug("Login", "user", sshConnection.User())

	go ssh.DiscardRequests(globalRequests) // Discard Keep Alive requests

	for newChannel := range channels {

		// Only the session channel is relevant to SFTP.  Reject any other channel types
		if newChannel.ChannelType() != "session" {
			slog.Warn("Rejecting Unknown Channel Type", "channelType", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "Unknown Channel Type")
			continue
		}
		slog.Debug("Incoming channel", "channelType", newChannel.ChannelType(), "extraData", newChannel.ExtraData())

		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			slog.Warn("Failed to Accept Channel", slog.Any("error", err))
			continue
		}
		go func(reqs <-chan *ssh.Request) {
			for req := range reqs {
				if !req.WantReply {
					continue
				}
				if (req.Type == "subsystem" && string(req.Payload[4:]) == "sftp") {
					slog.Debug("Accepting request for subsystem sftp", "RequestType", req.Type, "Payload", req.Payload[4:])
					err = initSftpSubsystem(req, channel)
					if err == nil {
						req.Reply(true, nil) // payload is ignored for replies to channel-specific requests, so just pass nil
					} else {
						slog.Warn("Failed to initialise SFTP subsystem.  Rejecting request.", slog.Any("error", err))
						req.Reply(false, nil)
					}
				} else {
					slog.Warn("Rejecting request for non-sftp", "RequestType", req.Type, "Payload", req.Payload)
					req.Reply(false, nil)
				}
			}
		}(channelRequests)
	}
}

/**
 * Reads a single SFTP packet from an SSH channel
 */
func readPacket(channel ssh.Channel)(command byte, data []byte, err error) {

	// First 4 bytes are a unsigned integer giving the length of the rest of the packet
	lengthBytes := make([]byte, 4)
	_, err = channel.Read(lengthBytes)
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lengthBytes)

	// The next byte is the command being sent by the client
	commandBytes := make([]byte, 1)
	_, err = channel.Read(commandBytes)
	if err != nil {
		return
	}
	command = commandBytes[0]

	// The remaining bytes are data for the command (subtract one from length as that's already been used for command)
	data = make([]byte, length - 1)
	_, err = channel.Read(data)
	if err != nil {
		return
	}

	slog.Debug("Packet Parsed", "length", length, "command", command, "data", data)
	return
}

/**
 * Writes a single SFTP packet to an SSH Channel
 */
func writePacket(channel ssh.Channel, command byte, data []byte) (err error) {
	length := len(data) + 1
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(length))
	packetBytes := append(append(lengthBytes, command), data...)
	_, err = channel.Write(packetBytes)
	return
}

/**
 * Recieves the INIT command from the client and checks for compatibility
 * Replies with the VERSION command
 */
func initSftpSubsystem(request *ssh.Request, channel ssh.Channel) (err error) {

	command, data, err := readPacket(channel)
	if err != nil {
		return
	}
	if command != 1 { // SSH_FXP_INIT should come first
		err = errors.New("SSH_FXP_INIT wasn't first command received")
		return
	}
	versionBytes := data[:4]
	version := binary.BigEndian.Uint32(versionBytes)

	if version != 3 { // Only supporting version 3 as that seems to be most common
		err = errors.New(fmt.Sprintf("Server doesn't support SFTP version %d", version))
		return
	}

	err = writePacket(channel, 2, versionBytes) // SSH_FXP_VERSION
	return
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
		slog.Debug("Awating new connection from socket")
		connection, err := socket.Accept()
		if err != nil {
			slog.Warn("Failed to accept connection from socket", slog.Any("error", err))
			continue
		}
		// Once a connection is received, handle it in its own goroutine
		go handleSshConnection(connection, config)
	}
}