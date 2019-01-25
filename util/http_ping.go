package util

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// HTTPPing try connect to a http server with domain though the http addr

func HTTPPing(tcpAddr, domain string, timeout time.Duration) <-chan error {
	errCh := make(chan error)
	go func() {
		errCh <- httpPing(tcpAddr, domain, timeout)
	}()
	return errCh
}

func httpPing(tcpAddr, domain string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", tcpAddr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	idx := strings.Index(tcpAddr, ":")
	if idx <= 0 {
		return errors.New("tcp address port is needed")
	}

	var msg []byte
	switch tcpAddr[idx:] {
	case ":80":
		msg = []byte("TRACE / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n")
	case ":443":
		msg = NewClientHelloSNIMsg(domain)
	}

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(msg); err != nil {
		return err
	}

	// err -> nil:		read something succ
	// err -> io.EOF:	no such domain or connection refused
	// err -> timeout:	tcp package has been dropped
	_, err = conn.Read(make([]byte, 1))
	if err == io.EOF {
		if tcpAddr[:idx] == domain {
			return nil
		}
	}
	return err
}

type clientHelloSNI struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	handshakeProtocol
}
type handshakeProtocol struct {
	HandshakeType            uint8
	LengthExpand             uint8
	Length                   uint16
	Version                  uint16
	Random                   [32]byte
	SessionIDLength          uint8
	CipherSuitesLength       uint16
	CipherSuite              uint16
	CompressionMethodsLength uint8
	CompressionMethod        uint8
	ExtensionsLength         uint16
	extensionServerName
}
type extensionServerName struct {
	Type   uint16
	Length uint16
	serverNameIndicationExtension
}
type serverNameIndicationExtension struct {
	ServerNameListlength uint16
	ServerNameType       uint8
	ServerNamelength     uint16
	// ServerName        []byte // Disable for fix length
}

func NewClientHelloSNIMsg(domain string) []byte {
	length := uint16(len(domain))
	msg := &clientHelloSNI{
		ContentType: 0x16,   // Content Type: Handshake (22)
		Version:     0x0301, // Version: TLS 1.0 (0x0301)
		Length:      length + 56,
		handshakeProtocol: handshakeProtocol{
			HandshakeType:            0x01, // Handshake Type: Client Hello (1)
			Length:                   length + 52,
			Version:                  0x0303,     // Version: TLS 1.2 (0x0303)
			Random:                   [32]byte{}, // [32]byte{},
			SessionIDLength:          0x0,        // Session ID Length: 0
			CipherSuitesLength:       2,          // Cipher Suites Length: 84
			CipherSuite:              tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CompressionMethodsLength: 1,    // Compression Methods Length: 1
			CompressionMethod:        0x00, // Compression null
			ExtensionsLength:         length + 9,
			extensionServerName: extensionServerName{
				Type:   0x0000, // Type: server_name (0)
				Length: length + 5,
				serverNameIndicationExtension: serverNameIndicationExtension{
					ServerNameListlength: length + 3,
					ServerNameType:       0x00, // Server Name Type: host_name (0)
					ServerNamelength:     length,
				},
			},
		},
	}

	buf := bytes.NewBuffer(make([]byte, 0, length+71))
	binary.Write(buf, binary.BigEndian, msg)
	buf.WriteString(domain)
	return buf.Bytes()
}
