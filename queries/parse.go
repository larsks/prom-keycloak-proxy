package queries

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	QueryParam    = "query"
	MatchersParam = "match[]"
)

func ParseQuery(query string) (ms []*labels.Matcher, err error) {
	m, err := parser.ParseMetricSelector(query)
	return m, err
}

func LabelValuesToRegexpString(labelValues []string) string {
	lvs := make([]string, len(labelValues))
	for i := range labelValues {
		lvs[i] = regexp.QuoteMeta(labelValues[i])
	}

	return strings.Join(lvs, "|")
}
func MatchersToString(ms ...*labels.Matcher) string {
	var el []string
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}

func InjectMatcher(q url.Values, matcher *labels.Matcher) error {
	matchers := q[QueryParam]
	if len(matchers) == 0 {
		q.Set(QueryParam, MatchersToString(matcher))
		return nil
	}

	// Inject label into existing matchers.
	for i, m := range matchers {
		ms, err := parser.ParseMetricSelector(m)
		if err != nil {
			return err
		}

		matchers[i] = MatchersToString(append(ms, matcher)...)
	}
	q[QueryParam] = matchers

	return nil
}

func AppendMatcher(queryValues url.Values, queryValuesForAuth url.Values, key string, authKey string, defaultValue string) (string, string, error) {
	value := defaultValue
	matchers := queryValues[QueryParam]
	for _, matcher := range matchers {
		matcherSelector, _ := parser.ParseMetricSelector(matcher)

		for _, matcherSelector := range matcherSelector {
			if matcherSelector.Name == key {
				value = matcherSelector.Value
			}
		}
	}
	if value != "" {
		matcher := &labels.Matcher{
			Name:  authKey,
			Type:  labels.MatchRegexp,
			Value: LabelValuesToRegexpString([]string{value}),
		}
		err := InjectMatcher(queryValuesForAuth, matcher)
		return authKey, value, err
	} else {
		return authKey, value, nil
	}
}

func ParseAuthorizations(tenant string, queryValues url.Values) (url.Values, []string, []string) {
	queryValuesForAuth := make(url.Values)

	var authResourceNames []string
	var authScopeNames []string
	tenant_key := "Tenant"
	cluster_key := "AiCluster"
	project_key := "AiProject"

	authResourceNames = append(authResourceNames, tenant_key)
	authScopeNames = append(authScopeNames, "GET")

	authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s", tenant_key, tenant))
	authScopeNames = append(authScopeNames, "GET")

	_, cluster, _ := AppendMatcher(queryValues, queryValuesForAuth, "cluster", fmt.Sprintf("%s-%s-%s", tenant_key, tenant, "AiCluster"), "")

	if cluster != "" {
		authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s-%s-%s", tenant_key, tenant, cluster_key, cluster))
		authScopeNames = append(authScopeNames, "GET")

		_, exported_namespace, _ := AppendMatcher(queryValues, queryValuesForAuth, "exported_namespace", fmt.Sprintf("%s-%s-%s-%s-%s", tenant_key, tenant, "AiCluster", cluster, "AiProject"), "")
		_, namespace, _ := AppendMatcher(queryValues, queryValuesForAuth, "namespace", fmt.Sprintf("%s-%s-%s-%s-%s", tenant_key, tenant, "AiCluster", cluster, "AiProject"), exported_namespace)

		if exported_namespace != "" && cluster != "" {
			if cluster != "" {
				authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s-%s-%s-%s-%s", tenant_key, tenant, cluster_key, cluster, project_key, exported_namespace))
				authScopeNames = append(authScopeNames, "GET")
			}
		}

		if namespace != "" {
			if cluster != "" {
				authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s-%s-%s-%s-%s", tenant_key, tenant, cluster_key, cluster, project_key, namespace))
				authScopeNames = append(authScopeNames, "GET")
			}
		}
	}

	return queryValuesForAuth, authResourceNames, authScopeNames
}

func QueryPrometheus(prometheusTlsCertPath string, prometheusTlsKeyPath string,
	prometheusCaCertPath string, prometheusUrl string) (interface{}, error) {
	prometheusCaCert, err := os.ReadFile(prometheusCaCertPath)
	if err != nil {
		log.Panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(prometheusCaCert)
	cert, err := tls.LoadX509KeyPair(prometheusTlsCertPath, prometheusTlsKeyPath)
	if err != nil {
		log.Panic(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	response, err := client.Get(prometheusUrl)
	if err == nil {
		defer response.Body.Close() //nolint:errcheck
		var data interface{}
		err := json.NewDecoder(response.Body).Decode(&data)
		return data, err
	} else {
		return nil, err
	}
}
