package transport

import (
	"crypto/md5"
	"crypto/tls"
	"io"
	"net"
)

// checksum(>=0x80) + target_length + target + data
// data(HTTP ONLY)
type proxyConn struct {
	net.Conn
}

func ToProxyConn(conn net.Conn, password []byte) (net.Conn, string) {
	teeConn := &TeeConn{Conn: conn}
	defer teeConn.Stop()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(teeConn, buf); err != nil {
		return teeConn, ""
	}
	checksum := buf[0]

	buf = make([]byte, int(buf[1]))
	if _, err := io.ReadFull(teeConn, buf); err != nil {
		return teeConn, ""
	}

	if checksum != sumChecksum(buf, password) {
		return teeConn, ""
	}

	teeConn.Reset()
	return teeConn, string(buf)
}

func DialTlsProxyConn(address, target string, password []byte) (net.Conn, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{})
	if err != nil {
		return nil, err
	}

	header := append([]byte{
		sumChecksum([]byte(target), password),
		byte(len(target))},
		[]byte(target)...)
	for n, nn := 0, 0; nn < len(target)+2; nn += n {
		if n, err = conn.Write(header); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func sumChecksum(target, password []byte) byte {
	return md5.Sum(append(target, password...))[0] | 0x80
}
