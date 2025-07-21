// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/services"
	"github.com/jzelinskie/cobrautil"
	"github.com/jzelinskie/stringz"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	run()
}
func run() {

	rootCmd := &cobra.Command{
		Use:     "prom-keycloak-proxy",
		Short:   "Proxy that protects Prometheus queries with Keycloak fine-grained resource permissions",
		PreRunE: cobrautil.SyncViperPreRunE("prom-keycloak-proxy"),
		RunE: cobrautil.CommandStack(
			cobrautil.ZeroLogRunE("log", zerolog.InfoLevel),
			cobrautil.OpenTelemetryRunE("otel", zerolog.InfoLevel),
			rootRunE,
		),
	}

	flags := rootCmd.Flags()
	cobrautil.RegisterZeroLogFlags(flags, "log")
	cobrautil.RegisterOpenTelemetryFlags(flags, "otel", "prom-keycloak-proxy")
	cobrautil.RegisterHTTPServerFlags(flags, "metrics", "metrics", ":9091", true)

	cobrautil.RegisterHTTPServerFlags(flags, "proxy", "proxy", ":8080", true)
	flags.StringSlice("proxy-cors-allowed-origins", []string{"*"}, "allowed origins for CORS requests")

	flags.String("proxy-auth-tenant", "", "Keycloak auth tenant")
	viper.BindPFlag("proxy-auth-tenant", flags.Lookup("proxy-auth-tenant"))
	viper.BindEnv("proxy-auth-tenant", "PROXY_AUTH_TENANT")

	flags.String("proxy-auth-client-id", "", "Keycloak auth client ID")
	viper.BindPFlag("proxy-auth-client-id", flags.Lookup("proxy-auth-client-id"))
	viper.BindEnv("proxy-auth-client-id", "PROXY_AUTH_CLIENT_ID")

	flags.String("proxy-auth-client-secret", "", "Keycloak auth client secret")
	viper.BindPFlag("proxy-auth-client-secret", flags.Lookup("proxy-auth-client-secret"))
	viper.BindEnv("proxy-auth-client-secret", "PROXY_AUTH_CLIENT_SECRET")

	flags.String("proxy-auth-realm", "", "Keycloak auth realm")
	viper.BindPFlag("proxy-auth-realm", flags.Lookup("proxy-auth-realm"))
	viper.BindEnv("proxy-auth-realm", "PROXY_AUTH_REALM")

	flags.String("proxy-auth-base-url", "", "Keycloak base URL")
	viper.BindPFlag("proxy-auth-base-url", flags.Lookup("proxy-auth-base-url"))
	viper.BindEnv("proxy-auth-base-url", "PROXY_AUTH_BASE_URL")

	flags.Bool("proxy-auth-tls-verify", true, "connect to keycloak and verify valid TLS")
	viper.BindPFlag("proxy-auth-tls-verify", flags.Lookup("proxy-auth-tls-verify"))
	viper.BindEnv("proxy-auth-tls-verify", "PROXY_AUTH_TLS_VERIFY")

	flags.Bool("proxy-prometheus-insecure", true, "connect to prometheus and verify valid TLS")
	viper.BindPFlag("proxy-prometheus-insecure", flags.Lookup("proxy-prometheus-tls-verify"))
	viper.BindEnv("proxy-prometheus-insecure", "PROXY_PROMETHEUS_TLS_VERIFY")

	flags.String("proxy-prometheus-base-url", "", "address of the prometheus to use for checking")
	viper.BindPFlag("proxy-prometheus-base-url", flags.Lookup("proxy-prometheus-base-url"))
	viper.BindEnv("proxy-prometheus-base-url", "PROXY_PROMETHEUS_BASE_URL")

	flags.String("proxy-prometheus-tls-crt", "", "path at which to find a certificate for prometheus TLS")
	viper.BindPFlag("proxy-prometheus-tls-crt", flags.Lookup("proxy-prometheus-tls-crt"))
	viper.BindEnv("proxy-prometheus-tls-crt", "PROXY_PROMETHEUS_TLS_CRT")

	flags.String("proxy-prometheus-tls-key", "", "path at which to find a private key for prometheus TLS")
	viper.BindPFlag("proxy-prometheus-tls-key", flags.Lookup("proxy-prometheus-tls-key"))
	viper.BindEnv("proxy-prometheus-tls-key", "PROXY_PROMETHEUS_TLS_KEY")

	flags.String("proxy-prometheus-ca-crt", "", "path at which to find a ca certificate for prometheus TLS")
	viper.BindPFlag("proxy-prometheus-ca-crt", flags.Lookup("proxy-prometheus-ca-crt"))
	viper.BindEnv("proxy-prometheus-ca-crt", "PROXY_PROMETHEUS_CA_CRT")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

//func metricsHandler() http.Handler {
//	mux := http.NewServeMux()
//	mux.Handle("/metrics", promhttp.Handler())
//	return mux
//}

func rootRunE(cmd *cobra.Command, args []string) error {

	proxyPrometheusBaseUrl, err := url.Parse(viper.GetString("proxy-prometheus-base-url"))
	if err != nil {
		return fmt.Errorf("failed to build parse upstream URL: %w", err)
	}
	if !stringz.SliceContains([]string{"http", "https"}, proxyPrometheusBaseUrl.Scheme) {
		return errors.New("only 'http' and 'https' schemes are supported for the upstream prometheus URL")
	}

	proxyAuthTenant := viper.GetString("proxy-auth-tenant")
	if proxyAuthTenant == "" {
		return fmt.Errorf("the PROXY_AUTH_TENANT environment variable cannot be empty")
	}

	authBaseUrl := viper.GetString("proxy-auth-base-url")
	authRealm := viper.GetString("proxy-auth-realm")
	authClientId := viper.GetString("proxy-auth-client-id")
	authClientSecret := viper.GetString("proxy-auth-client-secret")
	authTlsVerify := viper.GetBool("proxy-auth-tls-verify")
	gocloakClient := services.InitializeOauthServer(authBaseUrl, authTlsVerify)

	prometheusBaseUrl := viper.GetString("proxy-prometheus-base-url")
	prometheusTlsCertPath := viper.GetString("proxy-prometheus-tls-crt")
	prometheusTlsKeyPath := viper.GetString("proxy-prometheus-tls-key")
	prometheusCaCertPath := viper.GetString("proxy-prometheus-ca-crt")
	const proxyPrefix = "proxy"
	proxySrv := cobrautil.HTTPServerFromFlags(cmd, proxyPrefix)
	proxySrv.Handler = logHandler(cors.New(cors.Options{
		AllowedOrigins:   cobrautil.MustGetStringSlice(cmd, "proxy-cors-allowed-origins"),
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
		Debug:            log.Debug().Enabled(),
	}).Handler(
		services.Protect(
			gocloakClient,
			authRealm,
			authClientId,
			authClientSecret,
			proxyAuthTenant,
			services.PromQueryHandler(
				gocloakClient,
				authRealm,
				authClientId,
				prometheusBaseUrl,
				prometheusTlsCertPath,
				prometheusTlsKeyPath,
				prometheusCaCertPath))))
	go func() {
		if err := cobrautil.HTTPListenFromFlags(cmd, proxyPrefix, proxySrv, zerolog.InfoLevel); err != nil {
			log.Fatal().Err(err).Msg("failed while serving proxy")
		}
	}()
	defer proxySrv.Close()

	signalctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-signalctx.Done() // Block until we've received a signal.
	log.Info().Msg("received interrupt signal, exiting gracefully")
	return nil
}
