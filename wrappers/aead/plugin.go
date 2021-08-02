package aead

import "github.com/hashicorp/go-plugin"

var PluginHandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKMS_AEAD_PLUGIN",
	MagicCookieValue: "Hi there!",
}
