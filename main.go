package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	// Change these constants if you want to filter on a different label.
	filterLabelKey   = "hidden"
	filterLabelValue = "true"
)

// KubeConfig represents the parts of the kubeconfig we care about.
type KubeConfig struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Users          []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// ClusterInfo holds the information needed to contact the API server.
type ClusterInfo struct {
	Server     string
	CACertPool *x509.CertPool
	ClientCert *tls.Certificate // nil if not available
	Token      string
}

// getKindClusterInfo loads the kubeconfig, selects the current context for a kind cluster,
// and returns the server URL, CA pool, and credentials.
func getKindClusterInfo() (*ClusterInfo, error) {
	// Locate kubeconfig.
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = os.ExpandEnv("$HOME/.kube/config")
	}
	data, err := ioutil.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, err
	}

	var config KubeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	currentContextName := config.CurrentContext
	if currentContextName == "" {
		return nil, errors.New("current-context not set in kubeconfig")
	}

	var contextCluster, contextUser string
	for _, ctx := range config.Contexts {
		if ctx.Name == currentContextName {
			contextCluster = ctx.Context.Cluster
			contextUser = ctx.Context.User
			break
		}
	}
	if contextCluster == "" || contextUser == "" {
		return nil, errors.New("failed to find current context details")
	}

	// Find the cluster whose name matches the current context and contains "kind".
	var server, caDataB64 string
	for _, cl := range config.Clusters {
		if cl.Name == contextCluster && strings.Contains(strings.ToLower(cl.Name), "kind") {
			server = cl.Cluster.Server
			caDataB64 = cl.Cluster.CertificateAuthorityData
			break
		}
	}
	if server == "" {
		return nil, errors.New("kind cluster not found in kubeconfig")
	}

	// Decode CA data.
	caData, err := base64.StdEncoding.DecodeString(caDataB64)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caData); !ok {
		return nil, errors.New("failed to append CA certs")
	}

	// Get user credentials.
	var token, clientCertData, clientKeyData string
	for _, u := range config.Users {
		if u.Name == contextUser {
			token = u.User.Token
			clientCertData = u.User.ClientCertificateData
			clientKeyData = u.User.ClientKeyData
			break
		}
	}

	var clientCert *tls.Certificate = nil
	if clientCertData != "" && clientKeyData != "" {
		certBytes, err := base64.StdEncoding.DecodeString(clientCertData)
		if err != nil {
			return nil, err
		}
		keyBytes, err := base64.StdEncoding.DecodeString(clientKeyData)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, err
		}
		clientCert = &cert
	}

	return &ClusterInfo{
		Server:     server,
		CACertPool: caCertPool,
		ClientCert: clientCert,
		Token:      token,
	}, nil
}

// proxyHandler forwards incoming requests to the API server of the kind cluster.
// For GET requests, it appends a labelSelector to filter out resources that match the unwanted label.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	clusterInfo, err := getKindClusterInfo()
	if err != nil {
		http.Error(w, "failed to get cluster info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the cluster's server URL.
	serverURL, err := url.Parse(clusterInfo.Server)
	if err != nil {
		http.Error(w, "invalid server URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Rebuild the target URL using the server URL and the incoming request's URI.
	targetURL := serverURL.ResolveReference(&url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery})

	// For GET requests, add a labelSelector filter.
	if r.Method == "GET" {
		// Create a filter that excludes resources with filterLabelKey=filterLabelValue.
		newFilter := filterLabelKey + "!=" + filterLabelValue
		q := targetURL.Query()
		existing := q.Get("labelSelector")
		if existing != "" {
			// Append the filter if not already present.
			if !strings.Contains(existing, filterLabelKey) {
				q.Set("labelSelector", existing+","+newFilter)
			}
		} else {
			q.Set("labelSelector", newFilter)
		}
		targetURL.RawQuery = q.Encode()
	}

	tlsConfig := &tls.Config{
		RootCAs: clusterInfo.CACertPool,
	}
	if clusterInfo.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clusterInfo.ClientCert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()
	// Set the Host header so that the API server recognizes the request correctly.
	req.Host = serverURL.Host

	if clusterInfo.Token != "" {
		req.Header.Set("Authorization", "Bearer "+clusterInfo.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Forward the response from the API server.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/", proxyHandler)
	log.Println("Proxy started on :8001")
	log.Fatal(http.ListenAndServe(":8001", nil))
}
