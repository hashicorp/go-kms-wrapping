FROM ubuntu:latest

COPY . /go-kms-wrapping


# Set up SoftHSM, generate a key, and run tests.
#
# uses BAO_HSM_TOKEN_LABEL.
RUN true && \
	apt update && \
	DEBIAN_FRONTEND="noninteractive" apt install -y softhsm2 libsofthsm2 golang-go opensc ca-certificates && \
	mkdir /softhsm && \
	export SOFTHSM2_CONF=/go-kms-wrapping/wrappers/pkcs11/softhsm2.conf && \
	softhsm2-util --init-token --slot 0 --label "OpenBao g-k-w" --so-pin 1234 --pin 4321 && \
	softhsm2-util --show-slots && \
	export BAO_HSM_TOKEN_LABEL="OpenBao g-k-w" && \
	export BAO_HSM_PIN=4321 && \
	export BAO_HSM_LIB=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so && \
	export BAO_HSM_KEY_LABEL=bao-root-key-aes && \
    pkcs11-tool --module "$BAO_HSM_LIB" --token-label "$BAO_HSM_TOKEN_LABEL" --so-pin 1234 --pin 4321 --keygen --key-type aes:32 --label "$BAO_HSM_KEY_LABEL" && \
	pkcs11-tool --module "$BAO_HSM_LIB" --token-label "$BAO_HSM_TOKEN_LABEL" --so-pin 1234 --pin 4321 --show-info && \
	cd /go-kms-wrapping/wrappers/pkcs11 && \
	export VAULT_ACC=true && \
	go test -v ./... && \
	export BAO_HSM_KEY_LABEL=bao-root-key-rsa && \
	export BAO_HSM_RSA_OAEP_HASH="SHA1" && \
	pkcs11-tool --module "$BAO_HSM_LIB" --token-label "$BAO_HSM_TOKEN_LABEL" --so-pin 1234 --pin 4321 --keypairgen --key-type rsa:4096 --label "$BAO_HSM_KEY_LABEL" && \
	go test -v ./... && \
	true

# Set up SoftHSM, generate a key, and run tests.
#
# Uses a new BAO_HSM_SLOT.
RUN true && \
	rm -rf /softhsm && \
	mkdir /softhsm && \
	export SOFTHSM2_CONF=/go-kms-wrapping/wrappers/pkcs11/softhsm2.conf && \
	softhsm2-util --init-token --slot 0 --label "OpenBao g-k-w" --so-pin 1234 --pin 4321 && \
	softhsm2-util --show-slots && \
	export BAO_HSM_SLOT="$(softhsm2-util --show-slots | grep '^Slot [0-9]*$' | awk '{print $2 }' | sort -n | tail -n 1)" && \
	export BAO_HSM_PIN=4321 && \
	export BAO_HSM_LIB=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so && \
	export BAO_HSM_KEY_LABEL=bao-root-key-aes && \
    pkcs11-tool --module "$BAO_HSM_LIB" --slot "$BAO_HSM_SLOT" --so-pin 1234 --pin 4321 --keygen --key-type aes:32 --label "$BAO_HSM_KEY_LABEL" && \
	pkcs11-tool --module "$BAO_HSM_LIB" --slot "$BAO_HSM_SLOT" --so-pin 1234 --pin 4321 --show-info && \
	cd /go-kms-wrapping/wrappers/pkcs11 && \
	export VAULT_ACC=true && \
	go test -v ./... && \
	export BAO_HSM_KEY_LABEL=bao-root-key-rsa && \
	export BAO_HSM_RSA_OAEP_HASH="SHA1" && \
	pkcs11-tool --module "$BAO_HSM_LIB" --slot "$BAO_HSM_SLOT" --so-pin 1234 --pin 4321 --keypairgen --key-type rsa:4096 --label "$BAO_HSM_KEY_LABEL" && \
	go test -v ./... && \
	true
