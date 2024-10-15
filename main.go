package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/chainguard-dev/clog"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
)

type copts struct {
	refs            []string
	repos           []string
	serviceaccounts []string
	name            string

	flags *genericclioptions.ConfigFlags
	genericiooptions.IOStreams
}

func NewCmdCrane(streams genericiooptions.IOStreams) *cobra.Command {
	o := copts{
		flags:     genericclioptions.NewConfigFlags(true),
		IOStreams: streams,
	}

	cmd := &cobra.Command{
		Use:   "crane [repository]",
		Short: "Create a secret with registry credentials",
		Example: `
Create a secret appropriate for pulling "cgr.dev/chainguard/chainguard-base:latest"

	kubectl crane --ref cgr.dev/chainguard/chainguard-base:latest

Create a secret appropriate for pulling all images from "cgr.dev" and "gcr.io"

	kubectl crane --repo cgr.dev --ref gcr.io/foo/bar

Create a secret in the "foo" namespace that all the default service accounts in the "foo" namespace can pull images from "cgr.dev"

	kubectl crane --repo cgr.dev --sa default --namespace foo`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd)
		},
	}

	o.flags.AddFlags(cmd.Flags())
	cmd.Flags().StringVar(&o.name, "name", "kc", "The name of the registry credentials secret to create/update.")
	cmd.Flags().StringSliceVar(&o.refs, "ref", []string{}, "The image reference to create the secret for. The repository will be inferred.")
	cmd.Flags().StringSliceVarP(&o.repos, "repo", "r", []string{}, "The repository to create the secret for")
	cmd.Flags().StringSliceVar(&o.serviceaccounts, "sa", []string{}, "The service account to patch.")

	return cmd
}

func (o *copts) Run(cmd *cobra.Command) error {
	ctx := cmd.Context()
	log := clog.FromContext(ctx)

	repos := make(map[string]name.Registry)

	for _, repo := range o.repos {
		r, err := name.NewRegistry(repo)
		if err != nil {
			return fmt.Errorf("parsing repository: %w", err)
		}
		log.Infof("registering repo %s", r.RegistryStr())
		repos[r.RegistryStr()] = r
	}

	for _, ref := range o.refs {
		r, err := name.ParseReference(ref)
		if err != nil {
			return fmt.Errorf("parsing repository: %w", err)
		}
		log.Infof("registering repo %s inferred from reference %s", r.Context().RegistryStr(), r.String())
		repos[r.Context().RegistryStr()] = r.Context().Registry
	}

	dcfg := configfile.ConfigFile{
		AuthConfigs: map[string]types.AuthConfig{},
	}

	for name, repo := range repos {
		a, err := authn.DefaultKeychain.Resolve(repo)
		if err != nil {
			return err
		}

		cfg, err := a.Authorization()
		if err != nil {
			return err
		}

		dcfg.AuthConfigs[name] = types.AuthConfig{
			Username: cfg.Username,
			Password: cfg.Password,
			Auth:     cfg.Auth,
		}
	}

	secret, err := o.secret(dcfg)
	if err != nil {
		return fmt.Errorf("creating secret: %w", err)
	}

	log.Infof("creating secret '%s/%s'", secret.Name, secret.Namespace)

	rcfg, err := o.flags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("getting REST config: %w", err)
	}

	kcli, err := kubernetes.NewForConfig(rcfg)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	var sobj *corev1.Secret

	sobj, err = kcli.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, v1.GetOptions{})
	if err == nil {
		// update it
		sobj, err = kcli.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating secret: %w", err)
		}
		log.Infof("updated secret '%s/%s'", secret.Name, secret.Namespace)

	} else if errors.IsNotFound(err) {
		// create it
		sobj, err = kcli.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating secret: %w", err)
		}
		log.Infof("created secret '%s/%s'", secret.Name, secret.Namespace)

	} else {
		return fmt.Errorf("checking for existing secret: %w", err)
	}

	// for each service account, patch it with the imagePullSecret
	for _, sa := range o.serviceaccounts {
		obj, err := kcli.CoreV1().ServiceAccounts(secret.Namespace).Get(ctx, sa, v1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				// Create the service account if it doesn't exist
				newSA := &corev1.ServiceAccount{
					ObjectMeta: v1.ObjectMeta{
						Name:      sa,
						Namespace: secret.Namespace,
					},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: sobj.Name}},
				}
				_, err = kcli.CoreV1().ServiceAccounts(secret.Namespace).Create(ctx, newSA, v1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("creating service account '%s': %w", sa, err)
				}
				log.Infof("created service account '%s'", sa)
				continue
			}
			return fmt.Errorf("getting service account '%s': %w", sa, err)
		}

		// Check if the imagePullSecret is already in the service account
		found := false
		for _, ips := range obj.ImagePullSecrets {
			if ips.Name == secret.Name {
				found = true
				break
			}
		}
		if !found {
			obj.ImagePullSecrets = append(obj.ImagePullSecrets, corev1.LocalObjectReference{Name: sobj.Name})
			_, err = kcli.CoreV1().ServiceAccounts(secret.Namespace).Update(ctx, obj, v1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("updating service account '%s': %w", sa, err)
			}
			log.Infof("patched service account '%s' with imagePullSecret '%s'", sa, secret.Name)
		}
	}

	return nil
}

func main() {
	flags := pflag.NewFlagSet("kubectl-crane", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := NewCmdCrane(genericiooptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	})

	ctx := context.Background()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})))

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func (o *copts) secret(dockerconfig configfile.ConfigFile) (*corev1.Secret, error) {
	dockerConfigJSON, err := json.Marshal(dockerconfig)
	if err != nil {
		return nil, fmt.Errorf("marshaling docker config: %w", err)
	}

	ns := "default"
	if *o.flags.Namespace != "" {
		ns = *o.flags.Namespace
	}

	return &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "kc",
			Namespace: ns,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": dockerConfigJSON,
		},
	}, nil
}
