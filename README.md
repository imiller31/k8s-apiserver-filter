# k8s-apiserver-filter
a naive way to filter things like nodes from kubectl

## Usage
1. create a kind cluster with the provided kind-config `kind create cluster --config kind-config.yaml`
2. run the proxy with `go run main.go`
3. query your proxy with something like `kubectl --server=http://localhost:8001 get nodes`
4. label the control-plane node with `kubectl label node kind-control-plane hidden=true`
5. query your proxy again with `kubectl --server=http://localhost:8001 get nodes`
6. see that the control-plane node is not listed

This is 100% vibe-coded and shouldn't be used by anyone, anywhere for anything besides proving it's possible to filter nodes partially from kubectl.

All that o3-mini-high could come up with is stealing the auth from the local kubeconfig file, then appending a selector to the request. 
This is a naive way to partially filter things from k8s like nodes.