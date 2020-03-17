package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"

	"github.com/wweir/sower/transport"
	"github.com/wweir/utils/log"
	"golang.org/x/crypto/acme/autocert"
)

func StartClient(serverAddr, password, httpProxy string, forwards map[string]string) {
	passwordData := []byte(password)
	if httpProxy != "" {
		go startHTTPProxy(httpProxy, serverAddr, passwordData)
	}

	relayToRemote := func(lnAddr, target string) {
		ln, err := net.Listen("tcp", lnAddr)
		if err != nil {
			log.Fatalw("tcp listen", "port", lnAddr, "err", err)
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Errorw("tcp accept", "port", lnAddr, "err", err)
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()

				rc, err := transport.Dial(serverAddr, target, passwordData)
				if err != nil {
					log.Errorw("dial", "addr", serverAddr, "err", err)
					return
				}
				defer rc.Close()

				relay(conn, rc)
			}(conn)
		}
	}

	for from, to := range forwards {
		go func(from, to string) {
			relayToRemote(from, to)
		}(from, to)
	}

	select {}
}

func StartServer(relayTarget, password, certFile, keyFile, email string) {
	certManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  email,
	}
	if dir, err := os.UserCacheDir(); err != nil {
		certManager.Cache = autocert.DirCache(dir)
	}

	tlsConf := &tls.Config{
		GetCertificate: certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1", "h2"},
	}
	if certFile != "" && keyFile != "" {
		if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			log.Fatalw("load certificate", "cert", certFile, "key", keyFile, "err", err)
		} else {
			tlsConf.GetCertificate = nil
			tlsConf.Certificates = []tls.Certificate{cert}
		}
	}

	// Try to redirect 80 to 443
	go http.ListenAndServe(":80", certManager.HTTPHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if host, _, err := net.SplitHostPort(r.Host); err != nil {
				r.URL.Host = r.Host
			} else {
				r.URL.Host = host
			}
			r.URL.Scheme = "https"
			http.Redirect(w, r, r.URL.String(), 301)
		})))

	ln, err := tls.Listen("tcp", ":443", tlsConf)
	if err != nil {
		log.Fatalw("tcp listen", "err", err)
	}

	passwordData := []byte(password)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Errorw("tcp accept", "err", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			conn, target := transport.ToProxyConn(conn, passwordData)
			if target == "" {
				target = relayTarget
			}

			rc, err := net.Dial("tcp", target)
			if err != nil {
				log.Errorw("tcp dial", "addr", target, "err", err)
				return
			}
			defer rc.Close()

			relay(conn, rc)
		}(conn)
	}
}
