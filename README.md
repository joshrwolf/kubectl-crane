# `kubectl-crane`

A simple `kubectl` plugin that replicates some of the logic of `crane` to do
Kubernetes things in the context of a `kubectl` plugin.

Currently all this supports is a subset of commands to simplify setting up
registry credentials as pull secrets, and optionally pairing them with service
accounts.

## Installation

This operates like any other `kubectl` plugin ([ref](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/)).

```bash
go install github.com/joshrwolf/kubectl-crane

# Use it
kubectl crane --repo cgr.dev
```

## Usage

```bash
Create a secret with registry credentials

Usage:
  crane [repository] [flags]

Examples:

Create a secret appropriate for pulling "cgr.dev/chainguard/chainguard-base:latest"

        kubectl crane --ref cgr.dev/chainguard/chainguard-base:latest

Create a secret appropriate for pulling all images from "cgr.dev" and "gcr.io"

        kubectl crane --repo cgr.dev --ref gcr.io/foo/bar

Create a secret in the "foo" namespace that all the default service accounts in the "foo" namespace can pull images from "cgr.dev"

        kubectl crane --repo cgr.dev --sa default --namespace foo

Flags:
      --as string                      Username to impersonate for the operation. User could be a regular user or a service account in a namespace.
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --as-uid string                  UID to impersonate for the operation.
      --cache-dir string               Default cache directory (default "/Users/wolf/.kube/cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
      --disable-compression            If true, opt-out of response compression for all requests to the server
  -h, --help                           help for crane
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
      --name string                    The name of the registry credentials secret to create/update. (default "kc")
  -n, --namespace string               If present, the namespace scope for this CLI request
      --ref strings                    The image reference to create the secret for. The repository will be inferred.
  -r, --repo strings                   The repository to create the secret for
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
      --sa strings                     The service account to patch.
  -s, --server string                  The address and port of the Kubernetes API server
      --tls-server-name string         Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
```
