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
					err = initSftpSubsystem(channel)
					if err == nil {
						req.Reply(true, nil) // payload is ignored for replies to channel-specific requests, so just pass nil
						handlePackets(channel, sshConnection.User())
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
 * (Doesn't handle request IDs, so can be used for SSH_FXP_VERSION)
 */
func writeRawPacket(channel ssh.Channel, command byte, data []byte) (err error) {
	packetBytes := ssh.Marshal(struct {
			data []byte
		} {
			append([]byte{command}, data...),
		},
	)
	slog.Debug("Write packet", "command", command, "data", data)
	_, err = channel.Write(packetBytes)
	return
}
/**
 * Writes a single SFTP packet to an SSH Channel, adding the requestId to the start of the data
 */
func writePacket(channel ssh.Channel, requestId uint32, command byte, data []byte) (err error) {
	requestIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(requestIdBytes, requestId)
	data = append(requestIdBytes, data...)
	slog.Debug("Add requestID to packet", "requestId", requestId, "requestIdBytes", requestIdBytes)
	err = writeRawPacket(channel, command, data)
	return
}

/**
 * Recieves the INIT command from the client and checks for compatibility
 * Replies with the VERSION command
 */
func initSftpSubsystem(channel ssh.Channel) (err error) {

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

	err = writeRawPacket(channel, 2, versionBytes) // SSH_FXP_VERSION
	return
}

/**
 * Reads incoming SFTP packets from the client and responds appropriately
 */
func handlePackets(channel ssh.Channel, user string) (err error) {
	for {
		var command byte
		var data []byte
		command, data, err = readPacket(channel)
		if err != nil {
			return
		}
		switch command {
		case 3: // SSH_FXP_OPEN
			var request struct{
				Id uint32
				Path string
				Pflags uint32
				Attrs []byte
			}
			err = ssh.Unmarshal(data, &request)
			if err != nil {
				break
			}
			slog.Debug("OPEN command", "request", request)
			if request.Pflags != 0x00000001 { // Permission error if any pflag other than SSH_FXF_READ is set
				err = errorAndCloseChannel(channel, request.Id, 3, "Permission Denied") // SSH_FX_PERMISSION_DENIED
				break
			}

			found, handle, handleErr := getHandle(user, request.Path)
			if handleErr != nil {
				err = handleErr
				break
			}
			if !found {
				err = errorAndCloseChannel(channel, request.Id, 2, "No Such File") // SSH_FX_NO_SUCH_FILE
				break
			}
			handleBytes := ssh.Marshal(struct {handle string}{handle})
			err = writePacket(channel, request.Id, 102, handleBytes) // SSH_FXP_HANDLE
		case 4: // SSH_FXP_CLOSE
			var request struct{
				Id uint32
				Handle string
			}
			err = ssh.Unmarshal(data, &request)
			if err != nil {
				break
			}
			slog.Debug("CLOSE command", "requestId", request.Id, "handle", request.Handle)
			// No need to actually close anything.  Just return a success message
			err = writeStatusPacket(channel, request.Id, 0, "") // SSH_FX_OK
			if err != nil {
				return
			}


			_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct { exitCode uint32 } { 0 }))
			if err != nil {
				return
			}
			channel.Close()
		case 5: // SSH_FXP_READ
			var request struct{
				Id uint32
				Handle string
				Offset uint64
				MaxLength uint32
			}
			err = ssh.Unmarshal(data, &request)
			if err != nil {
				break
			}
			slog.Debug("READ command", "request", request, slog.Any("error", err))
			found, contents, readErr := readFileByHandle(user, request.Handle)
			if readErr != nil {
				err = readErr
				break
			}
			if !found {
				err = errorAndCloseChannel(channel, request.Id, 2, "No Such Handle") // SSH_FX_NO_SUCH_FILE
				break
			}
			if (int(request.Offset) >= len(contents)) {
				err = writeStatusPacket(channel, request.Id, 1, "End Of File") // SSH_FX_EOF
				break
			}
			if (int(request.Offset) != 0 || int(request.MaxLength) < len(contents)) {
				slog.Warn("requested subset of file - not implemented", "maxLength", request.MaxLength, "offset", request.Offset, "contentsLength", len(contents))
				err = errors.New("Reading subset of file not implemented")
				break
			}
			contentsBytes := ssh.Marshal(struct {contents string}{contents})
			err = writePacket(channel, request.Id, 103, contentsBytes) // SSH_FXP_DATA
		case 7: // SSH_FXP_LSTAT
			fallthrough // No need to differentiate between STAT and LSTAT as symbolic links aren't relevant here
		case 17: // SSH_FXP_STAT
			var request struct{
				Id uint32
				Path string
			}
			err = ssh.Unmarshal(data, &request)
			if err != nil {
				break
			}
			slog.Debug("STAT command", "requestId", request.Id, "path", request.Path)
			found, _, handleErr := getHandle(user, request.Path)
			if handleErr != nil {
				err = handleErr
				break
			}
			if !found {
				err = errorAndCloseChannel(channel, request.Id, 2, "No Such File") // SSH_FX_NO_SUCH_FILE
				break
			}
			attrBytes := ssh.Marshal(struct { exitCode uint32 } { 0x00000000 })
			err = writePacket(channel, request.Id, 105, attrBytes)// SSH_FXP_ATTRS
		default:
			slog.Warn("Unknown command", "command", command)
			err = errors.New(fmt.Sprintf("Can't handle command %d", command))
		}

		if err != nil {
			slog.Warn("Error handling packet", slog.Any("error", err))
			requestId := binary.BigEndian.Uint32(data[:4])
			errorAndCloseChannel(channel, requestId, 4, "Internal Server Error") // SSH_FX_FAILURE
			return
		}
	}
}

/**
 * Writes a STATUS Packet back to the client
 * (Assumes errorMessage is in English)
 */
func writeStatusPacket(channel ssh.Channel, requestId uint32, statusCode uint32, errorMessage string) (err error){
	statusCodeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(statusCodeBytes, statusCode)
	languageTag := "en"

	var data []byte
	data = append(data, statusCodeBytes...)
	data = append(data, []byte(errorMessage)...)
	data = append(data, []byte(languageTag)...)

	slog.Debug("Write Status Packed", "requestId", requestId, "statusCode", statusCode, "errorMessage", errorMessage)
	err = writePacket(channel, requestId, 101, data) // SSH_FXP_STATUS
	return
}

/**
 * Writes a STATUS packet to the client and then closes the channel
 */
func errorAndCloseChannel(channel ssh.Channel, requestId uint32, statusCode uint32, errorMessage string) (err error) {
	err = writeStatusPacket(channel, requestId, statusCode, errorMessage)
	if err != nil {
		return
	}
	slog.Debug("Closing Channel", "requestId", requestId)
	err = channel.Close()
	return
}

/**
 * Parses encoded File Attributes
 * (Ignores extended attrs)
 */
func parseFileAttributes(attrs []byte) (size uint64, uid uint32, gid uint32, permissions uint32, atime uint32, mtime uint32) {
	flags := binary.BigEndian.Uint32(attrs[:4])
	attrs = attrs[4:]
	if flags & 0x00000001 != 0 {
		size = binary.BigEndian.Uint64(attrs[:8])
		attrs = attrs[8:]
	}
	if flags & 0x00000002 != 0 {
		uid = binary.BigEndian.Uint32(attrs[:4])
		gid = binary.BigEndian.Uint32(attrs[4:8])
		attrs = attrs[8:]
	}
	if flags & 0x00000004 != 0 {
		permissions = binary.BigEndian.Uint32(attrs[:4])
		attrs = attrs[4:]
	}
	if flags & 0x00000008 != 0 {
		atime = binary.BigEndian.Uint32(attrs[:4])
		mtime = binary.BigEndian.Uint32(attrs[4:8])
		attrs = attrs[8:]
	}
	slog.Debug("File Attributes", "size", size, "uid", uid, "gid", gid, "permissions", permissions, "atime", atime, "mtime", mtime)
	return
}

func startSftpServer(port string, serverPrivateKey ssh.Signer) {

	config := &ssh.ServerConfig{
		NoClientAuth: true,  // TODO: Implement some client authentication
	}

	config.AddHostKey(serverPrivateKey)

	socket, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("Failed to listen for connection", slog.Any("error", err))
		os.Exit(3)
	}
	slog.Info("Listening for connections", "address", socket.Addr())

	for {
		slog.Debug("Awaiting new connection from socket")
		connection, err := socket.Accept()
		if err != nil {
			slog.Warn("Failed to accept connection from socket", slog.Any("error", err))
			continue
		}
		// Once a connection is received, handle it in its own goroutine
		go handleSshConnection(connection, config)
	}
}