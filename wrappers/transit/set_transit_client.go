package transit

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	vault "github.com/hashicorp/vault/api"
	k8sAuth "github.com/hashicorp/vault/api/auth/kubernetes"
	"os"
	"strconv"
)

const (
	envTransitWrapperMountPath   = "TRANSIT_WRAPPER_MOUNT_PATH"
	envVaultTransitSealMountPath = "VAULT_TRANSIT_SEAL_MOUNT_PATH"

	envTransitWrapperKeyName   = "TRANSIT_WRAPPER_KEY_NAME"
	envVaultTransitSealKeyName = "VAULT_TRANSIT_SEAL_KEY_NAME"

	envTransitWrapperDisableRenewal   = "TRANSIT_WRAPPER_DISABLE_RENEWAL"
	envVaultTransitSealDisableRenewal = "VAULT_TRANSIT_SEAL_DISABLE_RENEWAL"

	envVaultRoleName = "VAULT_ROLE_NAME"
)

func getTransitClient(logger hclog.Logger, opts *options) (*TransitClient, error) {
	var err error
	var mountPath, keyName string

	if mountPath, err = getMountPath(opts); err != nil {
		return nil, err
	}
	if keyName, err = getKeyName(opts); err != nil {
		return nil, err
	}

	var apiConfig *vault.Config
	if apiConfig, err = getApiConfig(opts); err != nil {
		return nil, err
	}

	vaultClient, err := vault.NewClient(apiConfig)
	if err != nil {
		return nil, err
	}
	if opts.withToken != "" {
		vaultClient.SetToken(opts.withToken)
	}

	if vaultClient.Token() == "" {
		if logger != nil {
			logger.Info("no token provided to transit auto-seal")
		}
	}

	client := &TransitClient{
		vaultClient: vaultClient,
		mountPath:   mountPath,
		keyName:     keyName,
	}

	return client, nil
}

func newWrapConfig(transitClient *TransitClient, namespace string) *wrapping.WrapperConfig {
	var wrapConfig = new(wrapping.WrapperConfig)

	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["address"] = transitClient.vaultClient.Address()
	wrapConfig.Metadata["mount_path"] = transitClient.mountPath
	wrapConfig.Metadata["key_name"] = transitClient.keyName

	if namespace != "" {
		wrapConfig.Metadata["namespace"] = namespace
	}

	return wrapConfig
}

func getApiConfig(opts *options) (*vault.Config, error) {
	var apiConfig = vault.DefaultConfig()

	if opts.withAddress != "" {
		apiConfig.Address = opts.withAddress
	}
	if opts.withTlsCaCert != "" ||
		opts.withTlsCaPath != "" ||
		opts.withTlsClientCert != "" ||
		opts.withTlsClientKey != "" ||
		opts.withTlsServerName != "" ||
		opts.withTlsSkipVerify {

		tlsConfig := &vault.TLSConfig{
			CACert:        opts.withTlsCaCert,
			CAPath:        opts.withTlsCaPath,
			ClientCert:    opts.withTlsClientCert,
			ClientKey:     opts.withTlsClientKey,
			TLSServerName: opts.withTlsServerName,
			Insecure:      opts.withTlsSkipVerify,
		}
		if err := apiConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, err
		}
	}

	return apiConfig, nil
}

func getNamespace(opts *options) string {
	var namespace string

	switch {
	case os.Getenv("VAULT_NAMESPACE") != "" && !opts.Options.WithDisallowEnvVars:
		namespace = os.Getenv("VAULT_NAMESPACE")
	case opts.withNamespace != "":
		namespace = opts.withNamespace
	}

	return namespace
}

func getDisableRenewal(opts *options) (bool, error) {
	var err error
	var disableRenewal bool
	var disableRenewalRaw string

	switch {
	case os.Getenv(envTransitWrapperDisableRenewal) != "" && !opts.Options.WithDisallowEnvVars:
		disableRenewalRaw = os.Getenv(envTransitWrapperDisableRenewal)
	case os.Getenv(envVaultTransitSealDisableRenewal) != "" && !opts.Options.WithDisallowEnvVars:
		disableRenewalRaw = os.Getenv(envVaultTransitSealDisableRenewal)
	case opts.withDisableRenewal != "":
		disableRenewalRaw = opts.withDisableRenewal
	}
	if disableRenewalRaw != "" {
		disableRenewal, err = strconv.ParseBool(disableRenewalRaw)
		if err != nil {
			return false, err
		}
	}

	return disableRenewal, nil
}

func getKeyName(opts *options) (string, error) {
	var keyName string

	switch {
	case os.Getenv(envTransitWrapperKeyName) != "" && !opts.Options.WithDisallowEnvVars:
		keyName = os.Getenv(envTransitWrapperKeyName)
	case os.Getenv(envVaultTransitSealKeyName) != "" && !opts.Options.WithDisallowEnvVars:
		keyName = os.Getenv(envVaultTransitSealKeyName)
	case opts.withKeyName != "":
		keyName = opts.withKeyName
	default:
		return "", fmt.Errorf("key_name is required")
	}

	return keyName, nil
}

func getMountPath(opts *options) (string, error) {
	var mountPath string

	switch {
	case os.Getenv(envTransitWrapperMountPath) != "" && !opts.Options.WithDisallowEnvVars:
		mountPath = os.Getenv(envTransitWrapperMountPath)
	case os.Getenv(envVaultTransitSealMountPath) != "" && !opts.Options.WithDisallowEnvVars:
		mountPath = os.Getenv(envVaultTransitSealMountPath)
	case opts.withMountPath != "":
		mountPath = opts.withMountPath
	default:
		return "", fmt.Errorf("mount_path is required")
	}

	return mountPath, nil
}

func getVaultRoleName(opts *options) string {
	switch {
	case os.Getenv(envVaultRoleName) != "" && !opts.Options.WithDisallowEnvVars:
		return os.Getenv(envVaultRoleName)
	case opts.withRoleName != "":
		return opts.withRoleName
	default:
		return ""
	}
}

func getServiceAccountTokenPath(opts *options) string {
	switch {
	case opts.withServiceAccountTokenPath != "":
		return opts.withServiceAccountTokenPath
	default:
		return ""
	}
}

func getServiceAccountTokenEnv(opts *options) string {
	switch {
	case opts.withServiceAccountTokenEnv != "":
		return opts.withServiceAccountTokenEnv
	default:
		return ""
	}
}

func getKubernetesMountPath(opts *options) string {
	switch {
	case opts.withKubernetesMountPath != "":
		return opts.withKubernetesMountPath
	default:
		return ""
	}
}

func getKubernetesLoginOptions(opts *options) []k8sAuth.LoginOption {
	var tokenPath = getServiceAccountTokenPath(opts)
	var tokenEnv = getServiceAccountTokenEnv(opts)
	var kubernetesMountPath = getKubernetesMountPath(opts)
	var loginOption []k8sAuth.LoginOption

	switch {
	case tokenPath != "":
		loginOption = append(loginOption, k8sAuth.WithServiceAccountTokenPath(tokenPath))
	case tokenEnv != "":
		loginOption = append(loginOption, k8sAuth.WithServiceAccountTokenEnv(tokenEnv))
	case kubernetesMountPath != "":
		loginOption = append(loginOption, k8sAuth.WithMountPath(kubernetesMountPath))
	default:
		loginOption = nil
	}

	return loginOption
}

func tokenRenew(transitClient *TransitClient, logger hclog.Logger) error {
	// Renew the token immediately to get a secret to pass to lifetime watcher
	secret, err := transitClient.vaultClient.Auth().Token().RenewTokenAsSelf(transitClient.vaultClient.Token(), 0)
	// If we don't get an error renewing, set up a lifetime watcher.  The token
	// may not be renewable or not have permission to renew-self.
	if err != nil {
		if logger != nil {
			logger.Info("unable to renew token, disabling renewal", "err", err)
		}
		return nil
	}

	if err = setUpLifetimeWatcher(transitClient, secret, logger); err != nil {
		return err
	}

	return nil
}

func setUpLifetimeWatcher(transitClient *TransitClient, secret *vault.Secret, logger hclog.Logger) error {
	var err error
	var lifetimeWatcher *vault.LifetimeWatcher

	if lifetimeWatcher, err = transitClient.vaultClient.
		NewLifetimeWatcher(&vault.LifetimeWatcherInput{Secret: secret}); err != nil {
		return err
	}

	transitClient.lifetimeWatcher = lifetimeWatcher
	go monitorLifetimeWatcher(lifetimeWatcher, logger)
	go lifetimeWatcher.Start()

	return nil
}

func monitorLifetimeWatcher(lifetimeWatcher *vault.LifetimeWatcher, logger hclog.Logger) {
	for {
		select {
		case err := <-lifetimeWatcher.DoneCh():
			if logger != nil {
				logger.Info("shutting down token renewal")
			}
			if err != nil {
				if logger != nil {
					logger.Error("error renewing token", "error", err)
				}
			}
			return
		case <-lifetimeWatcher.RenewCh():
			if logger != nil {
				logger.Trace("successfully renewed token")
			}
		}
	}
}

func performK8sAuthentication(transitClient *TransitClient, roleName string, opts *options, logger hclog.Logger) error {
	var err error
	var auth *k8sAuth.KubernetesAuth

	var loginOptions = getKubernetesLoginOptions(opts)
	if loginOptions != nil {
		auth, err = k8sAuth.NewKubernetesAuth(roleName, loginOptions...)
	} else {
		auth, err = k8sAuth.NewKubernetesAuth(roleName)
	}

	if err != nil {
		if logger != nil {
			logger.Error("error creating new kubernetes auth", "error", err)
		}
		return err
	}

	secret, err := transitClient.vaultClient.Auth().Login(context.Background(), auth)
	if err != nil {
		if logger != nil {
			logger.Error("error authenticating with kubernetes auth", "error", err)
		}
		return err
	}

	if err = setUpLifetimeWatcher(transitClient, secret, logger); err != nil {
		return err
	}

	return err
}
