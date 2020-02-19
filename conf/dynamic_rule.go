package conf

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wweir/sower/internal/http"
	"github.com/wweir/sower/internal/socks5"
	"github.com/wweir/utils/log"
	"github.com/wweir/utils/mem"
)

type dynamic struct {
	port http.Port
}

var cache = mem.New(4 * time.Hour)
var detect = &dynamic{}
var passwordData []byte
var timeout time.Duration
var dynamicCache sync.Map
var dynamicMu = sync.Mutex{}

// ShouldProxy check if the domain shoule request though proxy
func ShouldProxy(domain string) bool {
	// break deadlook, for wildcard
	if strings.Count(domain, ".") > 4 {
		return false
	}
	domain = strings.TrimSuffix(domain, ".")

	if domain == Client.Address {
		return false
	}
	if Client.Router.directRules.Match(domain) {
		return false
	}
	if Client.Router.proxyRules.Match(domain) {
		return true
	}

	cache.Remember(detect, domain)
	val, _ := dynamicCache.Load(domain)
	return val.(int) >= Client.Router.DetectLevel
}

func (d *dynamic) Get(key interface{}) (err error) {
	domain := key.(string)
	domainUnderscore := strings.ReplaceAll(domain, ".", "_")
	var score int

	defer func() {
		dynamicCache.Store(domain, score)

		if score < conf.Client.Router.DetectLevel {
			delete(Client.Router.DynamicList, domainUnderscore)
		} else {
			Client.Router.DynamicList[domainUnderscore] = score

			// persist when add new domain
			select {
			case flushCh <- struct{}{}:
			default:
			}
			log.Infow("persist rule", "domain", domain, "score", score)
		}
	}()

	if val, ok := dynamicCache.Load(domain); ok {
		score = val.(int)
	} else {
		dynamicMu.Lock()
		score = Client.Router.DynamicList[domainUnderscore]
		dynamicMu.Unlock()
	}

	// detect range: [0,conf.Client.Router.DetectLevel)
	switch {
	case score < -1:
		score++
	case score == -1:
		score++
		score += d.detect(domain)
	case score > conf.Client.Router.DetectLevel:
		score--
	case score == conf.Client.Router.DetectLevel:
		score--
		score += d.detect(domain)
	}

	return nil
}

// detect and caculate direct connection and proxy connection score
func (d *dynamic) detect(domain string) int {
	wg := sync.WaitGroup{}
	httpScore, httpsScore := new(int32), new(int32)
	for _, ping := range [...]dynamic{{port: http.HTTP}, {port: http.HTTPS}} {
		wg.Add(1)
		go func(ping dynamic) {
			defer wg.Done()

			if err := ping.port.Ping(domain, timeout); err != nil {
				return
			}

			switch ping.port {
			case http.HTTP:
				if !atomic.CompareAndSwapInt32(httpScore, 0, -2) {
					atomic.AddInt32(httpScore, -1)
				}
			case http.HTTPS:
				if !atomic.CompareAndSwapInt32(httpsScore, 0, -2) {
					atomic.AddInt32(httpScore, -1)
				}
			}
		}(ping)
	}
	for _, ping := range [...]dynamic{{port: http.HTTP}, {port: http.HTTPS}} {
		wg.Add(1)
		go func(ping dynamic) {
			defer wg.Done()

			var conn net.Conn
			var err error
			if addr, ok := socks5.IsSocks5Schema(Client.Address); ok {
				conn, err = net.Dial("tcp", addr)
				conn = socks5.ToSocks5(conn, domain, uint16(ping.port))

			} else {
				conn, err = tls.Dial("tcp", net.JoinHostPort(Client.Address, "443"), &tls.Config{})
				if ping.port == http.HTTP {
					conn = http.NewTgtConn(conn, passwordData, http.TGT_HTTP, "", 80)
				} else {
					conn = http.NewTgtConn(conn, passwordData, http.TGT_HTTPS, "", 443)
				}
			}
			if err != nil {
				log.Errorw("sower dial", "addr", Client.Address, "err", err)
				return
			}

			if err := ping.port.PingWithConn(domain, conn, timeout); err != nil {
				return
			}

			switch ping.port {
			case http.HTTP:
				if !atomic.CompareAndSwapInt32(httpScore, 0, 2) {
					atomic.AddInt32(httpScore, 1)
				}
			case http.HTTPS:
				if !atomic.CompareAndSwapInt32(httpsScore, 0, 2) {
					atomic.AddInt32(httpScore, 1)
				}
			}
		}(ping)
	}

	wg.Wait()
	return int(*httpScore + *httpsScore)
}
