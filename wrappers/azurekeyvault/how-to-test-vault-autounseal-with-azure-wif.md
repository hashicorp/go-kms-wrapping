# How to test Vault Auto-Unseal with Azure Workload Identity Federation

This document describes the steps needed to validate Vault auto unsealing
against Azure's Workload Identity Federation.

## Prerequisites

* A Vault linux amd64 docker image
* An Azure subscription
  - If internal, you can use HashiCorp's `doormat` to create a temporary subscription
* `azure-cli`
* `kubectl`

## Test Setup

### Azure

``` shell
az login --tenant <tenant_id>

export LOCATION="eastus"
export SUBSCRIPTION="$(az account show --query id --output tsv)"

export RESOURCE_GROUP="test-resource-group"
export USER_ASSIGNED_IDENTITY_NAME="test-identity"
export FEDERATED_IDENTITY_CREDENTIAL_NAME="test-federated-identity-credential"
export KEYVAULT_NAME="test-keyvault"
export KEY_NAME="test-key"
export REGISTRY_NAME="testregistry"
export AKS_NAME="test-aks"
export SERVICE_ACCOUNT_NAME="vault-service-account"
```

Create an Azure Resource Group (high-level grouping/container for all other Azure
resources)

```shell
# Create a Resource Group
az group create --name ${RESOURCE_GROUP} --location ${LOCATION}
```

Create a docker container registry in Azure and add the vault docker image. This
is so that we can use the docker image we created above in an Azure instance

```shell
# Create Azure Docker Container Registry
az acr create --resource-group ${RESOURCE_GROUP} --name ${REGISTRY_NAME} --sku Basic
export ACR_SERVER=$(az acr show -n ${REGISTRY_NAME} --query "loginServer" -otsv)

# Log in to Registry
az acr login --name ${REGISTRY_NAME}

# Tag desired image with an azure tag
# Example:
# docker tag docker.io/hashicorp/vault:1.15.0-beta1 \
#   testmichaelliregistry.azurecr.io/vault:v1
docker tag docker.io/hashicorp/vault:<tag> ${ACR_SERVER}/vault:v1

# Push to registry
docker push ${ACR_SERVER}/vault:v1

# Remove local copy of image
# Example:
# docker rmi testmichaelliregistry.azurecr.io/vault:v1
docker rmi ${ACR_SERVER}/vault:v1

# Check registry
az acr repository list --name ${REGISTRY_NAME} --output table
az acr repository show-tags --name ${REGISTRY_NAME} --repository vault --output table
```

Create Azure Kubernetes Service (AKS) cluster (instance that can run Kubernetes)

```shell
# Create an AKS cluster
# Note: I also had to add in --generate-ssh-keys the first time
az aks create -g ${RESOURCE_GROUP} -n ${AKS_NAME} --node-count 1 --enable-oidc-issuer --enable-workload-identity

# Get Credentials for AKS
# These credentials will be stored and used by kubectl
az aks get-credentials --admin --name ${AKS_NAME} --resource-group ${RESOURCE_GROUP}

# Attach Container Registry to AKS
az aks update -n ${AKS_NAME} -g ${RESOURCE_GROUP} --attach-acr ${REGISTRY_NAME}
```

Enable Workload Identity Federation (WIF) for your AKS cluster

```shell
# Enable WIF for your subscription
az feature register --namespace "Microsoft.ContainerService" --name "EnableWorkloadIdentityPreview"

# Wait until the following shows "Registered" (it could take a few minutes)
az feature show --namespace "Microsoft.ContainerService" --name "EnableWorkloadIdentityPreview"

# When registered, run the following
az provider register --namespace Microsoft.ContainerService

# Enable WIF for your cluster
az aks update -g ${RESOURCE_GROUP} -n ${AKS_NAME} --enable-workload-identity
```

Create an Azure Identity for Auto Unseal authentication

```shell
# Create an Azure Identity
az identity create --name ${USER_ASSIGNED_IDENTITY_NAME} --resource-group ${RESOURCE_GROUP} --subscription ${SUBSCRIPTION}

# Note the client_id for the identity
export USER_ASSIGNED_CLIENT_ID="$(az identity show --resource-group ${RESOURCE_GROUP} --name ${USER_ASSIGNED_IDENTITY_NAME} --query 'clientId' -otsv)"
```

Create a federated credential

```shell
# Create an OIDC issuer for your AKS cluster (this might take a while)
az aks update -g ${RESOURCE_GROUP} -n ${AKS_NAME} --enable-oidc-issuer

# Get the URL for your OIDC issue and save it for later
export AKS_OIDC_ISSUER="$(az aks show -n ${AKS_NAME} -g "${RESOURCE_GROUP}" --query "oidcIssuerProfile.issuerUrl" -otsv)"

# Establish federated identity credential trust (using the OIDC issue from the last step)
az identity federated-credential create --name ${FEDERATED_IDENTITY_CREDENTIAL_NAME} --identity-name ${USER_ASSIGNED_IDENTITY_NAME} --resource-group ${RESOURCE_GROUP} --issuer ${AKS_OIDC_ISSUER} --subject system:serviceaccount:default:${SERVICE_ACCOUNT_NAME} --audience api://AzureADTokenExchange
```

Create Azure Key Vault (stores key used for auto unseal)

```shell
# Create key vault
az keyvault create --resource-group ${RESOURCE_GROUP} --location ${LOCATION} --name ${KEYVAULT_NAME}

# Create secret in key vault using the application secret created earlier
az keyvault key create --vault-name ${KEYVAULT_NAME} --name ${KEY_NAME} --ops wrapKey unwrapKey --size 2048 --kty RSA

# Define policy so that identity can access this secret
az keyvault set-policy --name ${KEYVAULT_NAME} --key-permissions get unwrapKey wrapKey --spn "${USER_ASSIGNED_CLIENT_ID}"
```

### Kubernetes

Set up a Kubernetes Service Account

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
	azure.workload.identity/client-id: ${USER_ASSIGNED_CLIENT_ID}
  name: ${SERVICE_ACCOUNT_NAME}
EOF
```

Set up a Kubernetes Config Map (config file for vault)

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
data:
  vault-config.hcl: |
	ui = true
	disable_mlock = true

	api_addr = "http://0.0.0.0:8200"
	cluster_addr = "http://0.0.0.0:8201"

	storage "file" {
  	path = "/opt/vault/data"
	}

	listener "tcp" {
  	address     	= "0.0.0.0:8200"
  	cluster_address = "0.0.0.0:8201"
  	tls_disable 	= 1
  	telemetry {
    	unauthenticated_metrics_access = true
  	}
	}

	telemetry {
  	disable_hostname = true
  	prometheus_retention_time = "24h"
	}

	# enable auto-unseal using the azure key vault.
	seal "azurekeyvault" {
  	vault_name 	= "${KEYVAULT_NAME}"
  	key_name   	= "${KEY_NAME}"
	}
EOF
```

Set up a Kubernetes Pod that runs a vault instance

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: vault
  labels:
	app.kubernetes.io/name: vault
	azure.workload.identity/use: "true"
spec:
  serviceAccountName: ${SERVICE_ACCOUNT_NAME}
  containers:
  - name: vault
	image: ${REGISTRY_NAME}.azurecr.io/vault:v1
	args:
	- server
	- -config=/etc/config/vault-config.hcl
	ports:
  	- containerPort: 8200
    	name: vault-port
	volumeMounts:
	- name: config-volume
  	mountPath: /etc/config
	- name: vault-volume
  	mountPath: /opt/vault
	securityContext:
  	capabilities:
    	add:
    	- IPC_LOCK
  restartPolicy: Always
  volumes:
  - name: config-volume
	configMap:
  	name: vault-config
  - name: vault-volume
	emptyDir:
  	sizeLimit: 500Mi
EOF
```

## Test

```shell
# Confirm that vault is unable to unseal
kubectl logs pods/vault

# Initialize vault
kubectl exec -it pods/vault -- /bin/sh
export VAULT_ADDR=http://0.0.0.0:8200
# confirm there is an azurekeyvault seal type and that "sealed" is true
vault status
vault operator init
# confirm that "sealed" is false
vault status

# Find the process id for vault server
top
kill <process_id>

# Confirm that Vault is still unsealed
kubectl logs pods/vault
kubectl exec -it pods/vault -- /bin/sh
export VAULT_ADDR=http://0.0.0.0:8200
vault status
exit
```

## Cleanup
```shell
kubectl delete pod vault
kubectl delete sa ${SERVICE_ACCOUNT_NAME}
kubectl delete configMap vault-config

az group delete --name ${RESOURCE_GROUP}
az keyvault purge --name ${KEYVAULT_NAME} --location ${LOCATION}
```
