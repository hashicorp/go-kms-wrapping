package wrapping

import (
	"os"
	"strconv"
)

type ConfigurationTool struct {
	config map[string]string
	allowEnv bool
}

func NewConfigurationTool(config map[string]string) (*ConfigurationTool, error) {
	allowEnv := true
	if val, ok := config["disallow_env_vars"]; ok {
		disallowEnvVars, err := strconv.ParseBool(val)
		if err != nil {
			return nil, err
		}
		allowEnv = !disallowEnvVars
	}

	return &ConfigurationTool{
		config: config,
		allowEnv: allowEnv,
	}, nil
}

func (t *ConfigurationTool) GetParam(key string, envVars ...string) string {
	if t.allowEnv {
		for _, envVar := range envVars {
			envVarValue := os.Getenv(envVar)
			if envVarValue != "" {
				return envVarValue
			}
		}
	}
	return t.config[key]
}

func (t *ConfigurationTool) GetParamWithDefault(defaultValue, key string, envVars ...string) string {
	v := t.GetParam(key, envVars...)
	if v != "" {
		return v
	}

	return defaultValue
}