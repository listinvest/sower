package transport

import (
	"net"
)

func Dial(address, target string, password []byte) (net.Conn, error) {
	if addr, ok := IsSocks5Schema(address); ok {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		if conn, err = ToSocks5(conn, target); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}

	return DialTlsProxyConn(address, target, password)
}
