package userserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/klog/v2"

	addonutils "open-cluster-management.io/addon-framework/pkg/utils"
	"open-cluster-management.io/cluster-proxy/pkg/constant"
	clusterproxyutil "open-cluster-management.io/cluster-proxy/pkg/util"
	"open-cluster-management.io/cluster-proxy/pkg/utils"
	konnectivity "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/util"

	addonclient "open-cluster-management.io/api/client/addon/clientset/versioned"
	addoninformers "open-cluster-management.io/api/client/addon/informers/externalversions"
	addonlisterv1alpha1 "open-cluster-management.io/api/client/addon/listers/addon/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
)

func NewUserServerCommand() *cobra.Command {
	userServer := newUserServer()

	cmd := &cobra.Command{
		Use:   "user-server",
		Short: "user-server",
		Long:  `A http proxy server running on the hub cluster, receives http requests from users and forwards to the ANP proxy-server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return userServer.Run(cmd.Context())
		},
	}

	userServer.AddFlags(cmd)
	return cmd
}

var (
	serviceProxyRootCA *x509.CertPool
)

type userServer struct {
	getTunnel       func(context.Context) (konnectivity.Tunnel, error)
	proxyServerHost string
	proxyServerPort int

	proxyCACertPath, proxyCertPath, proxyKeyPath string

	serverCert, serverKey string
	serverPort            int

	serviceProxyCACertPath string
	agentInstallNamespace  string

	maxConnsPerHost     int
	maxIdleConnsPerHost int
	idleConnTimeout     time.Duration

	addonLister addonlisterv1alpha1.ManagedClusterAddOnLister

	// transports caches one http.Transport per managed cluster name.
	// Each transport maintains a connection pool to the cluster's service-proxy,
	// allowing tunnel reuse across sequential HTTP requests and eliminating the
	// tunnel-per-request churn that saturates the ANP proxy-server under load.
	// Key: cluster name (string), Value: *http.Transport
	transports sync.Map
}

func (k *userServer) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.StringVar(&k.proxyServerHost, "host", k.proxyServerHost, "The host of the ANP proxy-server")
	flags.IntVar(&k.proxyServerPort, "port", k.proxyServerPort, "The port of the ANP proxy-server")

	flags.StringVar(&k.proxyCACertPath, "proxy-ca-cert", k.proxyCACertPath, "The path to the CA certificate of the ANP proxy-server")
	flags.StringVar(&k.proxyCertPath, "proxy-cert", k.proxyCertPath, "The path to the certificate of the ANP proxy-server")
	flags.StringVar(&k.proxyKeyPath, "proxy-key", k.proxyKeyPath, "The path to the key of the ANP proxy-server")

	flags.StringVar(&k.serverCert, "server-cert", k.serverCert, "Secure communication with this cert")
	flags.StringVar(&k.serverKey, "server-key", k.serverKey, "Secure communication with this key")
	flags.IntVar(&k.serverPort, "server-port", k.serverPort, "handle user request using this port")

	flags.StringVar(&k.serviceProxyCACertPath, "service-proxy-ca-cert", k.serviceProxyCACertPath, "The path to the CA certificate of the service proxy server")

	flags.StringVar(&k.agentInstallNamespace, "agent-install-namespace", k.agentInstallNamespace, "The namespace of the agent install")

	flags.IntVar(&k.maxConnsPerHost, "max-conns-per-host", k.maxConnsPerHost,
		"Maximum total (active + idle) connections per managed cluster. "+
			"When reached, additional requests queue until a connection frees up. "+
			"Defaults to max-idle-conns-per-host if not set. "+
			"Can also be set via MAX_CONNS_PER_HOST env var.")
	flags.IntVar(&k.maxIdleConnsPerHost, "max-idle-conns-per-host", k.maxIdleConnsPerHost,
		"Maximum idle connections per managed cluster in the transport pool. "+
			"Can also be set via MAX_IDLE_CONNS_PER_HOST env var.")
	flags.DurationVar(&k.idleConnTimeout, "idle-conn-timeout", k.idleConnTimeout,
		"How long idle connections are kept in the transport pool before closing. "+
			"Can also be set via IDLE_CONN_TIMEOUT env var.")
}

func (k *userServer) Validate() error {
	if k.serverCert == "" {
		return fmt.Errorf("The server-cert is required")
	}

	if k.serverKey == "" {
		return fmt.Errorf("The server-key is required")
	}

	if k.serverPort == 0 {
		return fmt.Errorf("The server-port is required")
	}

	if k.serviceProxyCACertPath == "" {
		return fmt.Errorf("The serviceproxy-ca-cert is required")
	}

	return nil
}

// defaultMaxIdleConnsPerHost returns the value of MAX_IDLE_CONNS_PER_HOST env var
// if set and valid, otherwise returns 10. This follows the same pattern as ANP's
// PROXY_SERVER_ID: the env var sets the default, the CLI flag overrides it.
func defaultMaxIdleConnsPerHost() int {
	if v := os.Getenv("MAX_IDLE_CONNS_PER_HOST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 10 // Default value
}

// defaultMaxConnsPerHost returns the value of MAX_CONNS_PER_HOST env var
// if set and valid, otherwise returns 0 (sentinel meaning "use maxIdleConnsPerHost").
func defaultMaxConnsPerHost() int {
	if v := os.Getenv("MAX_CONNS_PER_HOST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// defaultIdleConnTimeout returns the value of IDLE_CONN_TIMEOUT env var
// if set and valid, otherwise returns 90s. Accepts any duration string
// parseable by time.ParseDuration (e.g. "30s", "2m").
func defaultIdleConnTimeout() time.Duration {
	if v := os.Getenv("IDLE_CONN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 90 * time.Second // Default value
}

func newUserServer() *userServer {
	maxConns := defaultMaxConnsPerHost()
	maxIdle := defaultMaxIdleConnsPerHost()
	if maxConns == 0 {
		maxConns = maxIdle
	}
	return &userServer{
		maxConnsPerHost:     maxConns,
		maxIdleConnsPerHost: maxIdle,
		idleConnTimeout:     defaultIdleConnTimeout(),
	}
}

func (k *userServer) init(ctx context.Context) error {
	proxyTLSCfg, err := util.GetClientTLSConfig(k.proxyCACertPath, k.proxyCertPath, k.proxyKeyPath, k.proxyServerHost, nil)
	if err != nil {
		return err
	}

	// prepare ca for sevice proxy server
	serviceProxyCaCert, err := os.ReadFile(k.serviceProxyCACertPath)
	if err != nil {
		return err
	}
	serviceProxyRootCA = x509.NewCertPool()
	if ok := serviceProxyRootCA.AppendCertsFromPEM(serviceProxyCaCert); !ok {
		return fmt.Errorf("failed to parse service proxy ca cert")
	}

	k.getTunnel = func(tunnelCtx context.Context) (konnectivity.Tunnel, error) {
		// instantiate a gprc proxy dialer
		tunnel, err := konnectivity.CreateSingleUseGrpcTunnelWithContext(
			ctx,
			tunnelCtx,
			net.JoinHostPort(k.proxyServerHost, strconv.Itoa(k.proxyServerPort)),
			grpc.WithTransportCredentials(grpccredentials.NewTLS(proxyTLSCfg)),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time: time.Minute * 10,
			}),
		)
		if err != nil {
			return nil, err
		}
		return tunnel, nil
	}

	addonClient, err := addonclient.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		return err
	}
	addonInformerFactory := addoninformers.NewSharedInformerFactory(addonClient, 30*time.Minute)
	k.addonLister = addonInformerFactory.Addon().V1alpha1().ManagedClusterAddOns().Lister()
	addonInformerFactory.Start(ctx.Done())

	klog.Infof("transport pool config: maxConnsPerHost=%d maxIdleConnsPerHost=%d idleConnTimeout=%v http2=enabled (not applicable to upgrade/SPDY requests)",
		k.maxConnsPerHost, k.maxIdleConnsPerHost, k.idleConnTimeout)

	return nil
}

// getOrCreateTransport returns a cached *http.Transport for the given cluster,
// creating one if it does not already exist.
//
// The key mechanism is Go's http.Transport connection pooling. After a request
// completes, the transport retains the underlying net.Conn in its idle pool
// rather than closing it. Because the net.Conn IS the konnectivity tunnel (the
// connection established by DialContext through the ANP proxy-server), keeping
// the connection alive keeps the tunnel -- and the Proxy() gRPC stream on the
// proxy-server -- alive between requests. Subsequent requests to the same
// cluster reuse the idle connection without invoking DialContext at all: no new
// tunnel, no new gRPC stream, no additional Proxy() handler on the proxy-server.
//
// DialContext is therefore only called on a pool miss: the first request to a
// cluster, after IdleConnTimeout elapses with no activity, or when concurrent
// requests exhaust the pool (up to MaxIdleConnsPerHost connections are retained).
// Both values are configurable via CLI flags or environment variables.
// At high request rates, multiple connections may exist simultaneously, but each
// is reused by subsequent requests rather than torn down after a single use.
//
// Without this caching, every HTTP request creates a new gRPC tunnel (full
// TCP+TLS+HTTP/2 negotiation) regardless of whether an existing tunnel is idle.
// Under load this saturates the ANP proxy-server with concurrent short-lived
// Proxy() handlers, causing lock contention on shared state and channel
// backpressure errors.
func (k *userServer) getOrCreateTransport(clusterName string) *http.Transport {
	if t, ok := k.transports.Load(clusterName); ok {
		return t.(*http.Transport)
	}

	transport := &http.Transport{
		MaxConnsPerHost:     k.maxConnsPerHost,
		MaxIdleConns:        k.maxIdleConnsPerHost, // same as MaxIdleConnsPerHost since this transport serves a single host (one managed cluster)
		MaxIdleConnsPerHost: k.maxIdleConnsPerHost,
		IdleConnTimeout:     k.idleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		// Not using our global TLSConfig for outbound will rely on server settings
		TLSClientConfig: &tls.Config{
			RootCAs:    serviceProxyRootCA,
			MinVersion: tls.VersionTLS12,
		},
		// Enable HTTP/2 on the cached transport. HTTP/2 multiplexes concurrent
		// requests over a single connection via streams, so all concurrent REST
		// API calls to the same cluster share one tunnel (one Proxy() handler on
		// the proxy-server) instead of each needing their own. The service-proxy
		// accepts HTTP/2 by default -- Go's http.Server enables it automatically
		// when serving TLS with ListenAndServeTLS.
		//
		// SPDY upgrade requests (kubectl exec, VM console sessions) bypass this
		// cached transport and use a dedicated HTTP/1.1 transport, so SPDY
		// compatibility is not affected by enabling HTTP/2 here.
		//
		// If HTTP/2 negotiation fails (e.g. TLS profile incompatibility), the
		// transport falls back to HTTP/1.1 automatically, in which case
		// MaxConnsPerHost limits concurrent tunnels as a safety net.
		ForceAttemptHTTP2:     true,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			klog.V(4).Infof("creating tunnel for cluster %s (transport pool miss)", clusterName)
			tunnel, err := k.getTunnel(ctx)
			if err != nil {
				return nil, err
			}
			return tunnel.DialContext(ctx, network, addr)
		},
	}

	// LoadOrStore handles the race where two goroutines concurrently create
	// a transport for the same cluster -- the loser's transport is discarded
	// (it has no active connections so there is no resource leak).
	actual, _ := k.transports.LoadOrStore(clusterName, transport)
	return actual.(*http.Transport)
}

func (k *userServer) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	if klog.V(4).Enabled() {
		dump, err := httputil.DumpRequest(req, true)
		if err != nil {
			http.Error(wr, err.Error(), http.StatusBadRequest)
			return
		}
		klog.V(4).Infof("request:\n%s", string(dump))
	}

	var tsc utils.TargetServiceConfig
	var err error

	switch utils.GetProxyType(req.RequestURI) {
	case utils.ProxyTypeService:
		tsc, err = utils.GetTargetServiceConfig(req.RequestURI)
	case utils.ProxyTypeKubeAPIServer:
		tsc, err = utils.GetTargetServiceConfigForKubeAPIServer(req.RequestURI)
	}
	if err != nil {
		http.Error(wr, err.Error(), http.StatusBadRequest)
		return
	}

	targetURL, err := url.Parse(serviceProxyURL(tsc.Cluster))
	if err != nil {
		http.Error(wr, err.Error(), http.StatusBadRequest)
		return
	}

	// Upgrade requests (SPDY/WebSocket, e.g. kubectl exec terminal sessions) are
	// long-lived and need a dedicated tunnel for their duration. They bypass the
	// shared transport cache and get the current single-use tunnel behavior.
	//
	// REST API requests use the cached transport. Go's http.Transport retains
	// the net.Conn (the konnectivity tunnel) in its idle pool after each request
	// completes, so DialContext -- which creates a new gRPC tunnel -- is only
	// called on a pool miss. Sequential requests to the same cluster reuse the
	// idle connection and the existing Proxy() stream on the proxy-server,
	// avoiding the per-request tunnel churn that causes proxy-server saturation.
	var transport http.RoundTripper
	if httpstream.IsUpgradeRequest(req) {
		klog.V(4).Infof("upgrade request for cluster %s, using dedicated tunnel", tsc.Cluster)
		tunnel, err := k.getTunnel(req.Context())
		if err != nil {
			http.Error(wr, err.Error(), http.StatusBadRequest)
			return
		}
		transport = &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Not using our global TLSConfig for outbound will rely on server settings
			TLSClientConfig: &tls.Config{
				RootCAs:    serviceProxyRootCA,
				MinVersion: tls.VersionTLS12,
			},
			// golang http pkg automatically upgrade http connection to http2 connection, but http2 can not upgrade to SPDY which used in "kubectl exec".
			// set ForceAttemptHTTP2 = false to prevent auto http2 upgration
			ForceAttemptHTTP2: false,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				klog.V(4).Infof("proxy dial to %s (upgrade request)", addr)
				return tunnel.DialContext(ctx, network, addr)
			},
		}
	} else {
		transport = k.getOrCreateTransport(tsc.Cluster)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = transport

	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, e error) {
		http.Error(rw, fmt.Sprintf("proxy to anp-proxy-server failed because %v", e), http.StatusBadGateway)
		klog.Errorf("proxy to anp-proxy-server failed because %v", e)
	}

	klog.V(4).Infof("request scheme:%s; rawQuery:%s; path:%s", req.URL.Scheme, req.URL.RawQuery, req.URL.Path)

	proxy.ServeHTTP(wr, utils.UpdateRequest(tsc, req))
}

func (k *userServer) Run(ctx context.Context) error {
	var err error

	klog.Info("begin to run user server")

	if err = k.Validate(); err != nil {
		klog.Fatal(err)
	}

	if err = k.init(ctx); err != nil {
		klog.Fatal(err)
	}

	cc, err := addonutils.NewConfigChecker("user-server", k.proxyCACertPath, k.proxyCertPath, k.proxyKeyPath, k.serverCert, k.serverKey, k.serviceProxyCACertPath)
	if err != nil {
		klog.Fatal(err)
	}

	go func() {
		if err = utils.ServeHealthProbes(":8000", cc.Check); err != nil {
			klog.Fatal(err)
		}
	}()

	klog.Infof("start https server on %d", k.serverPort)

	s := &http.Server{
		Addr:      fmt.Sprintf(":%d", k.serverPort),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		Handler:   k,
	}

	err = s.ListenAndServeTLS(k.serverCert, k.serverKey)
	if err != nil {
		klog.Fatalf("failed to start user proxy server: %v", err)
	}

	return nil
}

// serviceProxyURL is used to generate the URL of the service proxy server.
func serviceProxyURL(clusterName string) string {
	serviceProxyHost := clusterproxyutil.GenerateServiceProxyHost(clusterName)
	return fmt.Sprintf("https://%s:%d", serviceProxyHost, constant.ServiceProxyPort)
}
