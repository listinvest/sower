package router

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wweir/sower/transport"
	"github.com/wweir/utils/log"
	"github.com/wweir/utils/mem"
)

type detector struct {
	port         Port
	timeout      time.Duration
	detectLevel  int
	passwordData []byte
	persistFn    func(string)
}

var (
	cache   = mem.New(4 * time.Hour)
	detect  *detector
	address string

	directRule  *Node
	proxyRule   *Node
	dynamicRule *Node
)

func Init(addr, password, timeout string, detectLevel int,
	directs, proxys, dynamics []string, persistFn func(string)) (err error) {

	address = addr

	directRule = NewNodeFromRules(directs...)
	proxyRule = NewNodeFromRules(proxys...)
	dynamicRule = NewNodeFromRules(dynamics...)

	detect = &detector{
		detectLevel:  detectLevel,
		passwordData: []byte(password),
	}

	detect.timeout, err = time.ParseDuration(timeout)
	return err
}

// ShouldProxy check if the domain shoule request though proxy
func ShouldProxy(domain string) bool {
	// break deadlook, for wildcard
	if strings.Count(domain, ".") > 4 {
		return false
	}
	domain = strings.TrimSuffix(domain, ".")

	if domain == address {
		return false
	}
	if directRule.Match(domain) {
		return false
	}
	if proxyRule.Match(domain) {
		return true
	}

	cache.Remember(detect, domain)
	return dynamicRule.Match(domain)
}

func (d *detector) Get(key interface{}) (err error) {
	domain := key.(string)

	if d.detect(domain) > d.detectLevel {
		dynamicRule.Add(domain)
		d.persistFn(domain)
	}
	return nil
}

// detect and caculate direct connection and proxy connection score
func (d *detector) detect(domain string) int {
	wg := sync.WaitGroup{}
	httpScore, httpsScore := new(int32), new(int32)
	for _, ping := range [...]detector{{port: HTTP}, {port: HTTPS}} {
		wg.Add(1)
		go func(ping detector) {
			defer wg.Done()

			if err := ping.port.Ping(domain, d.timeout); err != nil {
				return
			}

			switch ping.port {
			case HTTP:
				if !atomic.CompareAndSwapInt32(httpScore, 0, -2) {
					atomic.AddInt32(httpScore, -1)
				}
			case HTTPS:
				if !atomic.CompareAndSwapInt32(httpsScore, 0, -2) {
					atomic.AddInt32(httpScore, -1)
				}
			}
		}(ping)
	}
	for _, ping := range [...]detector{{port: HTTP}, {port: HTTPS}} {
		wg.Add(1)
		go func(ping detector) {
			defer wg.Done()

			target := net.JoinHostPort(domain, ping.port.String())
			conn, err := transport.Dial(address, target, d.passwordData)
			if err != nil {
				log.Errorw("sower dial", "addr", address, "err", err)
				return
			}

			if err := ping.port.PingWithConn(domain, conn, d.timeout); err != nil {
				return
			}

			switch ping.port {
			case HTTP:
				if !atomic.CompareAndSwapInt32(httpScore, 0, 2) {
					atomic.AddInt32(httpScore, 1)
				}
			case HTTPS:
				if !atomic.CompareAndSwapInt32(httpsScore, 0, 2) {
					atomic.AddInt32(httpScore, 1)
				}
			}
		}(ping)
	}

	wg.Wait()
	return int(*httpScore + *httpsScore)
}
