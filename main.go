package main

import (
	"flag"
	"fmt"

	"github.com/wweir/sower/conf"
	"github.com/wweir/sower/proxy"
	"github.com/wweir/sower/router"
)

func main() {
	if conf.Server.Upstream != "" {
		proxy.StartServer(conf.Server.Upstream, conf.Conf.Password,
			conf.Server.CertFile, conf.Server.KeyFile, conf.Server.CertEmail)
	}

	if conf.Client.Address != "" {
		router.Init(conf.Client.Address, conf.Conf.Password,
			conf.Client.Router.DetectTimeout,
			conf.Client.Router.DetectLevel,
			conf.Client.Router.DirectList,
			conf.Client.Router.ProxyList,
			conf.Client.Router.DynamicList,
			conf.PersistRule,
		)

		proxy.StartClient(conf.Client.Address, conf.Conf.Password,
			conf.Client.HTTPProxy,
			conf.Client.Router.PortMapping)
	}

	if conf.Server.Upstream == "" && conf.Client.Address == "" {
		fmt.Println()
		flag.Usage()
	}
}
