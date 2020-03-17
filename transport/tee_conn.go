package transport

import (
	"net"
)

type TeeConn struct {
	net.Conn
	buf    []byte
	offset int
	stop   bool // read
}

func (t *TeeConn) Reread() {
	t.offset = 0
}
func (t *TeeConn) Reset() {
	t.buf = []byte{}
	t.offset = 0
}
func (t *TeeConn) Stop() {
	t.offset = 0
	t.stop = true
}

func (t *TeeConn) Read(b []byte) (n int, err error) {
	length := len(t.buf) - t.offset
	if length > 0 {
		n = copy(b, t.buf[t.offset:])
		t.offset += n
		return
	}

	n, err = t.Conn.Read(b)
	if !t.stop {
		t.buf = append(t.buf, b[:n]...)
		t.offset += n
	}
	return n, err
}
