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
	"strings"
	"syscall"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/services"
	"github.com/jzelinskie/cobrautil"
	"github.com/jzelinskie/stringz"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func bindFlagToViper(flags *pflag.FlagSet, name string) {
	envVar := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	must(viper.BindPFlag(name, flags.Lookup(name)))
	must(viper.BindEnv(name, envVar))
}

func registerStringFlag(flags *pflag.FlagSet, name, defaultValue, usage string) { //nolint:unparam
	flags.String(name, defaultValue, usage)
	bindFlagToViper(flags, name)
}

func registerBoolFlag(flags *pflag.FlagSet, name string, defaultValue bool, usage string) {
	flags.Bool(name, defaultValue, usage)
	bindFlagToViper(flags, name)
}

func main() {
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

	registerStringFlag(flags, "proxy-auth-tenant", "", "Keycloak auth tenant")
	registerStringFlag(flags, "proxy-auth-client-id", "", "Keycloak auth client ID")
	registerStringFlag(flags, "proxy-auth-client-secret", "", "Keycloak auth client secret")
	registerStringFlag(flags, "proxy-auth-realm", "", "Keycloak auth realm")
	registerStringFlag(flags, "proxy-auth-base-url", "", "Keycloak base URL")
	registerBoolFlag(flags, "proxy-auth-tls-verify", true, "connect to keycloak and verify valid TLS")
	registerStringFlag(flags, "proxy-prometheus-base-url", "", "address of the prometheus to use for checking")
	registerStringFlag(flags, "proxy-prometheus-tls-crt", "", "path at which to find a certificate for prometheus TLS")
	registerStringFlag(flags, "proxy-prometheus-tls-key", "", "path at which to find a private key for prometheus TLS")
	registerStringFlag(flags, "proxy-prometheus-ca-crt", "", "path at which to find a ca certificate for prometheus TLS")

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
	defer proxySrv.Close() //nolint:errcheck

	signalctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-signalctx.Done() // Block until we've received a signal.
	log.Info().Msg("received interrupt signal, exiting gracefully")
	return nil
}
