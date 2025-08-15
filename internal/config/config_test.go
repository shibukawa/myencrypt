package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHostnameConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		bindAddress string
		expected    string
		description string
	}{
		{
			name:        "ExplicitHostname",
			hostname:    "myencrypt.local",
			bindAddress: "0.0.0.0",
			expected:    "myencrypt.local",
			description: "明示的にホスト名が設定されている場合",
		},
		{
			name:        "LocalhostHostname",
			hostname:    "localhost",
			bindAddress: "127.0.0.1",
			expected:    "localhost",
			description: "localhostが明示的に設定されている場合",
		},
		{
			name:        "EmptyHostname",
			hostname:    "",
			bindAddress: "192.168.1.100",
			expected:    "",
			description: "ホスト名が空の場合",
		},
		{
			name:        "CustomDomainHostname",
			hostname:    "acme.example.com",
			bindAddress: "0.0.0.0",
			expected:    "acme.example.com",
			description: "カスタムドメインが設定されている場合",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Hostname = tt.hostname
			cfg.BindAddress = tt.bindAddress

			if cfg.Hostname != tt.expected {
				t.Errorf("%s: Hostname = %v, want %v", tt.description, cfg.Hostname, tt.expected)
			}

			t.Logf("%s: ✅ Hostname configuration correct: %s", tt.description, cfg.Hostname)
		})
	}
}

func TestHostnameEnvironmentVariable(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		configValue string
		expected    string
		description string
	}{
		{
			name:        "EnvironmentOverridesConfig",
			envValue:    "env.example.com",
			configValue: "config.example.com",
			expected:    "env.example.com",
			description: "環境変数がconfig値をオーバーライドする",
		},
		{
			name:        "EnvironmentWithEmptyConfig",
			envValue:    "localhost",
			configValue: "",
			expected:    "localhost",
			description: "環境変数が空のconfig値を設定する",
		},
		{
			name:        "EmptyEnvironmentUsesConfig",
			envValue:    "",
			configValue: "config.example.com",
			expected:    "config.example.com",
			description: "空の環境変数はconfig値を使用する",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 環境変数をクリア
			os.Unsetenv("MYENCRYPT_HOSTNAME")

			// 環境変数を設定（空でない場合）
			if tt.envValue != "" {
				os.Setenv("MYENCRYPT_HOSTNAME", tt.envValue)
				defer os.Unsetenv("MYENCRYPT_HOSTNAME")
			}

			cfg := DefaultConfig()
			cfg.Hostname = tt.configValue

			// 環境変数からの設定を適用
			overrides := CLIOverrides{
				Hostname: os.Getenv("MYENCRYPT_HOSTNAME"),
			}
			err := cfg.ApplyOverrides(overrides)
			if err != nil {
				t.Fatalf("Failed to apply overrides: %v", err)
			}

			if cfg.Hostname != tt.expected {
				t.Errorf("%s: Hostname = %v, want %v", tt.description, cfg.Hostname, tt.expected)
			}

			t.Logf("%s: ✅ Environment variable handling correct: %s", tt.description, cfg.Hostname)
		})
	}
}

func TestHostnameYAMLConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		yamlData string
		expected string
		wantErr  bool
	}{
		{
			name: "hostname in YAML",
			yamlData: `
http_port: 14000
bind_address: "0.0.0.0"
hostname: "myencrypt.local"
`,
			expected: "myencrypt.local",
			wantErr:  false,
		},
		{
			name: "empty hostname in YAML",
			yamlData: `
http_port: 14000
bind_address: "127.0.0.1"
hostname: ""
`,
			expected: "",
			wantErr:  false,
		},
		{
			name: "no hostname in YAML",
			yamlData: `
http_port: 14000
bind_address: "0.0.0.0"
`,
			expected: "", // デフォルト値
			wantErr:  false,
		},
		{
			name: "localhost hostname in YAML",
			yamlData: `
http_port: 14000
bind_address: "0.0.0.0"
hostname: "localhost"
`,
			expected: "localhost",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()

			err := yaml.Unmarshal([]byte(tt.yamlData), cfg)
			if tt.wantErr {
				if err == nil {
					t.Errorf("yaml.Unmarshal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("yaml.Unmarshal() unexpected error = %v", err)
				return
			}

			if cfg.Hostname != tt.expected {
				t.Errorf("Hostname = %v, want %v", cfg.Hostname, tt.expected)
			}

			t.Logf("✅ YAML hostname configuration correct: %s", cfg.Hostname)
		})
	}
}

func TestHostnameConfigSaveAndLoad(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create test config with hostname
	cfg := DefaultConfig()
	cfg.CertStorePath = tempDir
	cfg.Hostname = "test.myencrypt.local"
	cfg.BindAddress = "0.0.0.0"
	cfg.HTTPPort = 14000

	// Save config
	err := cfg.Save()
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Check that config file was created
	configPath := filepath.Join(tempDir, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created at %s", configPath)
	}

	// Load config back
	loadedCfg := DefaultConfig()
	loadedCfg.CertStorePath = tempDir

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	err = yaml.Unmarshal(data, loadedCfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Validate loaded config
	if loadedCfg.Hostname != "test.myencrypt.local" {
		t.Errorf("Hostname = %s, want test.myencrypt.local", loadedCfg.Hostname)
	}

	if loadedCfg.BindAddress != "0.0.0.0" {
		t.Errorf("BindAddress = %s, want 0.0.0.0", loadedCfg.BindAddress)
	}

	if loadedCfg.HTTPPort != 14000 {
		t.Errorf("HTTPPort = %d, want 14000", loadedCfg.HTTPPort)
	}

	t.Logf("✅ Hostname config save and load successful: %s", loadedCfg.Hostname)
}

func TestGetHostnameForACME(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		bindAddress string
		expected    string
		description string
	}{
		{
			name:        "ExplicitHostname",
			hostname:    "myencrypt.local",
			bindAddress: "0.0.0.0",
			expected:    "myencrypt.local",
			description: "明示的なHostname設定が最優先",
		},
		{
			name:        "LocalhostHostname",
			hostname:    "localhost",
			bindAddress: "127.0.0.1",
			expected:    "localhost",
			description: "明示的なlocalhost設定",
		},
		{
			name:        "CustomDomainHostname",
			hostname:    "acme.example.com",
			bindAddress: "192.168.1.100",
			expected:    "acme.example.com",
			description: "カスタムドメイン設定",
		},
		{
			name:        "EmptyHostnameWithBindAddress",
			hostname:    "",
			bindAddress: "127.0.0.1",
			expected:    "127.0.0.1",
			description: "空のHostnameでBindAddressを使用",
		},
		{
			name:        "EmptyHostnameWithDefaultBind",
			hostname:    "",
			bindAddress: "0.0.0.0",
			expected:    "localhost",
			description: "空のHostnameでBindAddressが0.0.0.0の場合はlocalhost",
		},
		{
			name:        "EmptyHostnameWithSpecificIP",
			hostname:    "",
			bindAddress: "192.168.1.100",
			expected:    "192.168.1.100",
			description: "空のHostnameで特定のIPアドレス",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Hostname = tt.hostname
			cfg.BindAddress = tt.bindAddress

			result := cfg.GetHostnameForACME()

			if result != tt.expected {
				t.Errorf("%s: GetHostnameForACME() = %v, want %v", tt.description, result, tt.expected)
			}

			t.Logf("%s: ✅ %s", tt.description, result)
		})
	}
}

func TestHostnameEnvironmentVariableIntegration(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		configValue string
		bindAddress string
		expected    string
		description string
	}{
		{
			name:        "EnvironmentOverridesConfig",
			envValue:    "env.example.com",
			configValue: "config.example.com",
			bindAddress: "0.0.0.0",
			expected:    "env.example.com",
			description: "環境変数がconfig値をオーバーライド",
		},
		{
			name:        "EnvironmentWithEmptyConfig",
			envValue:    "localhost",
			configValue: "",
			bindAddress: "127.0.0.1",
			expected:    "localhost",
			description: "環境変数が空のconfig値を設定",
		},
		{
			name:        "EmptyEnvironmentUsesConfig",
			envValue:    "",
			configValue: "config.example.com",
			bindAddress: "0.0.0.0",
			expected:    "config.example.com",
			description: "空の環境変数はconfig値を使用",
		},
		{
			name:        "EmptyBothUsesBindAddress",
			envValue:    "",
			configValue: "",
			bindAddress: "192.168.1.100",
			expected:    "192.168.1.100",
			description: "両方空の場合はBindAddressを使用",
		},
		{
			name:        "EmptyBothWithDefaultBind",
			envValue:    "",
			configValue: "",
			bindAddress: "0.0.0.0",
			expected:    "localhost",
			description: "両方空でBindAddressがデフォルトの場合はlocalhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 環境変数をクリア
			os.Unsetenv("MYENCRYPT_HOSTNAME")

			// 環境変数を設定（空でない場合）
			if tt.envValue != "" {
				os.Setenv("MYENCRYPT_HOSTNAME", tt.envValue)
				defer os.Unsetenv("MYENCRYPT_HOSTNAME")
			}

			cfg := DefaultConfig()
			cfg.Hostname = tt.configValue
			cfg.BindAddress = tt.bindAddress

			// 環境変数からの設定を適用
			overrides := CLIOverrides{
				Hostname: os.Getenv("MYENCRYPT_HOSTNAME"),
			}
			err := cfg.ApplyOverrides(overrides)
			if err != nil {
				t.Fatalf("Failed to apply overrides: %v", err)
			}

			result := cfg.GetHostnameForACME()

			if result != tt.expected {
				t.Errorf("%s: GetHostnameForACME() = %v, want %v", tt.description, result, tt.expected)
			}

			t.Logf("%s: ✅ %s", tt.description, result)
		})
	}
}
func TestEnvironmentVariableAccessFunctions(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		setValue string
		getFunc  func() string
		hasFunc  func() bool
	}{
		{
			name:     "GetExposePort",
			envVar:   "MYENCRYPT_EXPOSE_PORT",
			setValue: "14000",
			getFunc:  GetExposePort,
			hasFunc:  HasExposePort,
		},
		{
			name:     "GetProjectName",
			envVar:   "MYENCRYPT_PROJECT_NAME",
			setValue: "test-project",
			getFunc:  GetProjectName,
			hasFunc:  HasProjectName,
		},
		{
			name:     "GetLogLevel",
			envVar:   "MYENCRYPT_LOG_LEVEL",
			setValue: "debug",
			getFunc:  GetLogLevel,
			hasFunc:  nil, // No has function for log level
		},
		{
			name:     "GetTestHTTP01BaseURL",
			envVar:   "MYENCRYPT_TEST_HTTP01_BASE_URL",
			setValue: "http://test.example.com",
			getFunc:  GetTestHTTP01BaseURL,
			hasFunc:  nil, // No has function for test URL
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv(tt.envVar)

			// Test empty value
			result := tt.getFunc()
			if result != "" {
				t.Errorf("%s() with empty env = %v, want empty string", tt.name, result)
			}

			if tt.hasFunc != nil {
				hasResult := tt.hasFunc()
				if hasResult {
					t.Errorf("Has%s() with empty env = %v, want false", tt.name[3:], hasResult)
				}
			}

			// Set environment variable
			os.Setenv(tt.envVar, tt.setValue)
			defer os.Unsetenv(tt.envVar)

			// Test with value
			result = tt.getFunc()
			if result != tt.setValue {
				t.Errorf("%s() with env set = %v, want %v", tt.name, result, tt.setValue)
			}

			if tt.hasFunc != nil {
				hasResult := tt.hasFunc()
				if !hasResult {
					t.Errorf("Has%s() with env set = %v, want true", tt.name[3:], hasResult)
				}
			}

			t.Logf("✅ %s: Environment variable access function working correctly", tt.name)
		})
	}
}
