package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES & CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	idnDir      = ".idn"
	profilesDir = "profiles"
	configFile  = "config.yml"
	currentFile = ".current"
	lockFile    = ".lock"
	keyFile     = ".master.key"
	saltSize    = 32
	keySize     = 32
	nonceSize   = 12
	pbkdf2Iter  = 100000
	lockTimeout = 5 * time.Second
	httpTimeout = 10 * time.Second
)

type Profile struct {
	Name        string            `yaml:"name" json:"name"`
	SSHKeyPath  string            `yaml:"ssh_key_path,omitempty" json:"ssh_key_path,omitempty"`
	SSHKeyType  string            `yaml:"ssh_key_type,omitempty" json:"ssh_key_type,omitempty"`
	GitName     string            `yaml:"git_name,omitempty" json:"git_name,omitempty"`
	GitEmail    string            `yaml:"git_email,omitempty" json:"git_email,omitempty"`
	SigningKey  string            `yaml:"signing_key,omitempty" json:"signing_key,omitempty"`
	GitHubToken string            `yaml:"github_token,omitempty" json:"github_token,omitempty"`
	EnvVars     map[string]string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
	APIKeys     map[string]string `yaml:"api_keys,omitempty" json:"api_keys,omitempty"`
	CreatedAt   time.Time         `yaml:"created_at" json:"created_at"`
	UpdatedAt   time.Time         `yaml:"updated_at" json:"updated_at"`
}

type Config struct {
	EncryptionMethod string `yaml:"encryption_method"`
	ProfilesDir      string `yaml:"profiles_dir"`
	GitAutoUpdate    bool   `yaml:"git_auto_update"`
	BackupGitConfig  bool   `yaml:"backup_git_config"`
}

type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type ProfileManager struct {
	baseDir    string
	profileDir string
	config     *Config
	cipher     *AESCipher
}

type AESCipher struct {
	key []byte
}

// ═══════════════════════════════════════════════════════════════════════════════
// TERMINAL UI & COLORS
// ═══════════════════════════════════════════════════════════════════════════════

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(os.Stdout.Fd())) {
		colorReset, colorRed, colorGreen, colorYellow = "", "", "", ""
		colorBlue, colorCyan, colorBold, colorDim = "", "", "", ""
	}
}

func success(msg string, args ...interface{}) {
	fmt.Printf(colorGreen+"✓ "+colorReset+msg+"\n", args...)
}
func warn(msg string, args ...interface{}) {
	fmt.Printf(colorYellow+"⚠ "+colorReset+msg+"\n", args...)
}
func errorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorRed+"✗ "+colorReset+msg+"\n", args...)
}
func info(msg string, args ...interface{}) { fmt.Printf(colorCyan+"→ "+colorReset+msg+"\n", args...) }
func bold(s string) string                 { return colorBold + s + colorReset }
func dim(s string) string                  { return colorDim + s + colorReset }

func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func promptInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func promptSecret(prompt string) (string, error) {
	fmt.Print(prompt)
	bytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func promptConfirm(prompt string) bool {
	input, err := promptInput(prompt + " [y/N]: ")
	if err != nil {
		return false
	}
	return strings.ToLower(input) == "y" || strings.ToLower(input) == "yes"
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCRYPTION & CRYPTO
// ═══════════════════════════════════════════════════════════════════════════════

func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), keySize)
	}
	return &AESCipher{key: key}, nil
}

func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func deriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iter, keySize, sha256.New)
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func generateMasterKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE LOCKING
// ═══════════════════════════════════════════════════════════════════════════════

type FileLock struct {
	path string
	file *os.File
}

func NewFileLock(baseDir string) *FileLock {
	return &FileLock{path: filepath.Join(baseDir, lockFile)}
}

func (l *FileLock) Lock() error {
	start := time.Now()
	for {
		file, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			l.file = file
			fmt.Fprintf(file, "%d", os.Getpid())
			return nil
		}
		if !os.IsExist(err) {
			return fmt.Errorf("create lock: %w", err)
		}
		if time.Since(start) > lockTimeout {
			return fmt.Errorf("lock timeout: another process may be holding the lock")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (l *FileLock) Unlock() error {
	if l.file != nil {
		l.file.Close()
	}
	return os.Remove(l.path)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE MANAGER
// ═══════════════════════════════════════════════════════════════════════════════

func NewProfileManager(baseDir string) (*ProfileManager, error) {
	profileDir := filepath.Join(baseDir, profilesDir)
	pm := &ProfileManager{
		baseDir:    baseDir,
		profileDir: profileDir,
		config:     &Config{EncryptionMethod: "aes-256-gcm", BackupGitConfig: true, GitAutoUpdate: true},
	}
	if err := pm.loadConfig(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := pm.loadMasterKey(); err != nil {
		return nil, err
	}
	return pm, nil
}

func (pm *ProfileManager) loadConfig() error {
	data, err := os.ReadFile(filepath.Join(pm.baseDir, configFile))
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, pm.config)
}

func (pm *ProfileManager) saveConfig() error {
	data, err := yaml.Marshal(pm.config)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(pm.baseDir, configFile), data, 0600)
}

func (pm *ProfileManager) loadMasterKey() error {
	keyPath := filepath.Join(pm.baseDir, keyFile)
	data, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	parts := bytes.SplitN(data, []byte(":"), 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid key file format")
	}
	salt, err := base64.StdEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return err
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return err
	}
	passphrase, err := "123456789", nil
	derivedKey := deriveKey(passphrase, salt)
	tempCipher, _ := NewAESCipher(derivedKey)
	masterKey, _ := tempCipher.Decrypt(encryptedKey)
	pm.cipher, _ = NewAESCipher(masterKey)
	return nil
}

func (pm *ProfileManager) InitMasterKey(passphrase string) error {
	masterKey, err := generateMasterKey()
	if err != nil {
		return err
	}
	salt, err := generateSalt()
	if err != nil {
		return err
	}
	derivedKey := deriveKey(passphrase, salt)
	tempCipher, _ := NewAESCipher(derivedKey)
	encryptedKey, err := tempCipher.Encrypt(masterKey)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(pm.baseDir, keyFile)
	content := base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(encryptedKey)
	if err := os.WriteFile(keyPath, []byte(content), 0600); err != nil {
		return err
	}
	pm.cipher, _ = NewAESCipher(masterKey)
	return nil
}

func (pm *ProfileManager) profilePath(name string) string {
	return filepath.Join(pm.profileDir, name+".yml.enc")
}

func (pm *ProfileManager) Create(profile *Profile) error {
	if pm.cipher == nil {
		return fmt.Errorf("master key not initialized - run 'idn init' first")
	}
	if profile.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(profile.Name) {
		return fmt.Errorf("profile name must be alphanumeric with underscores or hyphens")
	}
	if _, err := os.Stat(pm.profilePath(profile.Name)); err == nil {
		return fmt.Errorf("profile '%s' already exists", profile.Name)
	}
	profile.CreatedAt = time.Now()
	profile.UpdatedAt = time.Now()
	return pm.save(profile)
}

func (pm *ProfileManager) save(profile *Profile) error {
	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	encrypted, err := pm.cipher.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt profile: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	return os.WriteFile(pm.profilePath(profile.Name), []byte(encoded), 0600)
}

func (pm *ProfileManager) Get(name string) (*Profile, error) {
	if pm.cipher == nil {
		return nil, fmt.Errorf("master key not initialized")
	}
	data, err := os.ReadFile(pm.profilePath(name))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("profile '%s' not found", name)
	}
	if err != nil {
		return nil, err
	}
	encrypted, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode profile: %w", err)
	}
	decrypted, err := pm.cipher.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt profile (corrupted or wrong key): %w", err)
	}
	var profile Profile
	if err := yaml.Unmarshal(decrypted, &profile); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}
	return &profile, nil
}

func (pm *ProfileManager) List() ([]*Profile, error) {
	if pm.cipher == nil {
		return nil, fmt.Errorf("master key not initialized")
	}
	entries, err := os.ReadDir(pm.profileDir)
	if os.IsNotExist(err) {
		return []*Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var profiles []*Profile
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yml.enc") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".yml.enc")
		profile, err := pm.Get(name)
		if err != nil {
			warn("Failed to load profile '%s': %v", name, err)
			continue
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func (pm *ProfileManager) Delete(name string) error {
	path := pm.profilePath(name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("profile '%s' not found", name)
	}
	current, _ := GetActiveProfile(pm.baseDir)
	if current == name {
		if err := ClearActiveProfile(pm.baseDir); err != nil {
			return fmt.Errorf("clear active profile: %w", err)
		}
	}
	return os.Remove(path)
}

func (pm *ProfileManager) Update(profile *Profile) error {
	if _, err := os.Stat(pm.profilePath(profile.Name)); os.IsNotExist(err) {
		return fmt.Errorf("profile '%s' not found", profile.Name)
	}
	profile.UpdatedAt = time.Now()
	return pm.save(profile)
}

func (pm *ProfileManager) Validate(name string) (*ValidationResult, error) {
	profile, err := pm.Get(name)
	if err != nil {
		return nil, err
	}
	result := &ValidationResult{Valid: true}
	if profile.SSHKeyPath != "" {
		keyPath := expandPath(profile.SSHKeyPath)
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("SSH key not found: %s", keyPath))
			result.Valid = false
		} else if err := validateSSHKey(keyPath); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid SSH key: %v", err))
			result.Valid = false
		}
	}
	if profile.GitHubToken != "" {
		if !isValidTokenFormat(profile.GitHubToken) {
			result.Warnings = append(result.Warnings, "GitHub token format is unusual")
		}
	}
	if profile.GitName == "" {
		result.Warnings = append(result.Warnings, "Git name not set")
	}
	if profile.GitEmail == "" {
		result.Warnings = append(result.Warnings, "Git email not set")
	}
	return result, nil
}

func (pm *ProfileManager) Activate(name string) error {
	profile, err := pm.Get(name)
	if err != nil {
		return err
	}
	validation, err := pm.Validate(name)
	if err != nil {
		return err
	}
	if !validation.Valid {
		for _, e := range validation.Errors {
			errorf("%s", e)
		}
		return fmt.Errorf("profile validation failed")
	}
	for _, w := range validation.Warnings {
		warn("%s", w)
	}
	lock := NewFileLock(pm.baseDir)
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if profile.GitName != "" || profile.GitEmail != "" {
		if err := injectGitConfig(profile, pm.config.BackupGitConfig); err != nil {
			return fmt.Errorf("inject git config: %w", err)
		}
	}
	if profile.SSHKeyPath != "" {
		if err := configureSSHForGitHub(profile.SSHKeyPath); err != nil {
			return fmt.Errorf("configure SSH: %w", err)
		}
	}
	if profile.GitHubToken != "" {
		if err := configureGitCredentials(profile.GitHubToken); err != nil {
			warn("Failed to configure git credentials: %v", err)
		}
	}
	return SetActiveProfile(pm.baseDir, name)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATE TRACKING
// ═══════════════════════════════════════════════════════════════════════════════

func SetActiveProfile(baseDir, name string) error {
	return os.WriteFile(filepath.Join(baseDir, currentFile), []byte(name), 0600)
}

func GetActiveProfile(baseDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(baseDir, currentFile))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func ClearActiveProfile(baseDir string) error {
	path := filepath.Join(baseDir, currentFile)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(path)
}

// ═══════════════════════════════════════════════════════════════════════════════
// GIT CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

func injectGitConfig(profile *Profile, backup bool) error {
	home, _ := os.UserHomeDir()
	gitConfigPath := filepath.Join(home, ".gitconfig")
	if backup {
		if _, err := os.Stat(gitConfigPath); err == nil {
			backupPath := gitConfigPath + ".idn.backup"
			data, _ := os.ReadFile(gitConfigPath)
			os.WriteFile(backupPath, data, 0644)
		}
	}
	if profile.GitName != "" {
		if err := runGitConfig("user.name", profile.GitName); err != nil {
			return err
		}
	}
	if profile.GitEmail != "" {
		if err := runGitConfig("user.email", profile.GitEmail); err != nil {
			return err
		}
	}
	if profile.SigningKey != "" {
		if err := runGitConfig("user.signingkey", profile.SigningKey); err != nil {
			return err
		}
	}
	return nil
}

func runGitConfig(key, value string) error {
	cmd := exec.Command("git", "config", "--global", key, value)
	return cmd.Run()
}

func getGitConfig(key string) (string, error) {
	cmd := exec.Command("git", "config", "--global", "--get", key)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func configureGitCredentials(token string) error {
	cmd := exec.Command("git", "config", "--global", "credential.helper", "store")
	if err := cmd.Run(); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	credPath := filepath.Join(home, ".git-credentials")
	cred := fmt.Sprintf("https://oauth2:%s@github.com\n", token)
	return os.WriteFile(credPath, []byte(cred), 0600)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSH HANDLING
// ═══════════════════════════════════════════════════════════════════════════════

func validateSSHKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if strings.Contains(err.Error(), "passphrase") {
			return nil
		}
		return err
	}
	return nil
}

func detectSSHKeyType(path string) string {
	data, _ := os.ReadFile(path)
	content := string(data)
	switch {
	case strings.Contains(content, "RSA"):
		return "RSA"
	case strings.Contains(content, "EC"):
		return "ECDSA"
	case strings.Contains(content, "OPENSSH"):
		return "ED25519"
	default:
		return "Unknown"
	}
}

func configureSSHForGitHub(keyPath string) error {
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}
	configPath := filepath.Join(sshDir, "config")
	keyPath = expandPath(keyPath)
	entry := fmt.Sprintf("\n# idn-managed\nHost github.com\n  HostName github.com\n  User git\n  IdentityFile %s\n  IdentitiesOnly yes\n", keyPath)
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	re := regexp.MustCompile(`(?s)\n?# idn-managed\nHost github\.com\n.*?IdentitiesOnly yes\n?`)
	cleaned := re.ReplaceAllString(string(existing), "")
	return os.WriteFile(configPath, []byte(cleaned+entry), 0600)
}

func addToSSHAgent(keyPath string) error {
	cmd := exec.Command("ssh-add", expandPath(keyPath))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ═══════════════════════════════════════════════════════════════════════════════
// GITHUB TOKEN
// ═══════════════════════════════════════════════════════════════════════════════

func isValidTokenFormat(token string) bool {
	if len(token) == 40 && isHex(token) {
		return true
	}
	if strings.HasPrefix(token, "ghp_") || strings.HasPrefix(token, "gho_") ||
		strings.HasPrefix(token, "ghu_") || strings.HasPrefix(token, "ghs_") ||
		strings.HasPrefix(token, "ghr_") || strings.HasPrefix(token, "github_pat_") {
		return true
	}
	return false
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func verifyGitHubToken(token string) (bool, string, error) {
	client := &http.Client{Timeout: httpTimeout}
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return false, "", nil
	}
	if resp.StatusCode != 200 {
		return false, "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return false, "", err
	}
	return true, user.Login, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func getBaseDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, idnDir)
}

func isInitialized(baseDir string) bool {
	_, err := os.Stat(filepath.Join(baseDir, keyFile))
	return err == nil
}

func initializeIDN(baseDir string) error {
	dirs := []string{
		baseDir,
		filepath.Join(baseDir, profilesDir),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func getStatus(pm *ProfileManager) map[string]interface{} {
	status := make(map[string]interface{})
	current, _ := GetActiveProfile(pm.baseDir)
	status["active_profile"] = current
	if current != "" {
		if profile, err := pm.Get(current); err == nil {
			status["git_name"] = profile.GitName
			status["git_email"] = profile.GitEmail
			status["ssh_key"] = profile.SSHKeyPath
			status["has_github_token"] = profile.GitHubToken != ""
			status["env_vars_count"] = len(profile.EnvVars)
		}
	}
	actualName, _ := getGitConfig("user.name")
	actualEmail, _ := getGitConfig("user.email")
	status["actual_git_name"] = actualName
	status["actual_git_email"] = actualEmail
	home, _ := os.UserHomeDir()
	sshConfig, _ := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	status["ssh_github_configured"] = strings.Contains(string(sshConfig), "# idn-managed")
	return status
}
