package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var jsonOutput bool

func main() {
	rootCmd := &cobra.Command{
		Use:   "idn",
		Short: "Identity profile manager for SSH keys, GitHub tokens, and API credentials",
		Long: `idn - Production-grade CLI for managing multiple developer identities.

Manage SSH keys, GitHub tokens, git configs, and environment variables
with instant context switching across projects and accounts.

Examples:
  idn init                    Initialize idn and create master key
  idn profile create work     Create a new profile interactively
  idn switch work             Activate the 'work' profile
  idn current                 Show currently active profile
  idn status                  Show diagnostic information`,
	}

	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(profileCmd())
	rootCmd.AddCommand(switchCmd())
	rootCmd.AddCommand(currentCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(validateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INIT COMMAND
// ═══════════════════════════════════════════════════════════════════════════════

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize idn configuration and master key",
		RunE: func(cmd *cobra.Command, args []string) error {
			baseDir := getBaseDir()
			if isInitialized(baseDir) {
				warn("idn is already initialized at %s", baseDir)
				return nil
			}
			if err := initializeIDN(baseDir); err != nil {
				return fmt.Errorf("failed to create directories: %w", err)
			}
			info("Setting up master encryption key...")
			passphrase, err := promptSecret("Enter master passphrase: ")
			if err != nil {
				return err
			}
			if len(passphrase) < 8 {
				return fmt.Errorf("passphrase must be at least 8 characters")
			}
			confirm, err := promptSecret("Confirm passphrase: ")
			if err != nil {
				return err
			}
			if passphrase != confirm {
				return fmt.Errorf("passphrases do not match")
			}
			pm := &ProfileManager{baseDir: baseDir, profileDir: baseDir + "/profiles"}
			if err := pm.InitMasterKey(passphrase); err != nil {
				return err
			}
			cfg := &Config{EncryptionMethod: "aes-256-gcm", BackupGitConfig: true, GitAutoUpdate: true}
			pm.config = cfg
			if err := pm.saveConfig(); err != nil {
				return err
			}
			if jsonOutput {
				out := map[string]interface{}{"status": "initialized", "path": baseDir}
				enc, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(enc))
			} else {
				success("Initialized idn at %s", baseDir)
				info("Create your first profile with: idn profile create <name>")
			}
			return nil
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

func profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage identity profiles",
	}
	cmd.AddCommand(profileCreateCmd())
	cmd.AddCommand(profileListCmd())
	cmd.AddCommand(profileShowCmd())
	cmd.AddCommand(profileDeleteCmd())
	cmd.AddCommand(profileUpdateCmd())
	return cmd
}

func profileCreateCmd() *cobra.Command {
	var (
		sshKey         string
		gitName        string
		gitEmail       string
		githubToken    string
		signingKey     string
		envVars        []string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new identity profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			profile := &Profile{Name: name, EnvVars: make(map[string]string)}

			if nonInteractive {
				profile.SSHKeyPath = sshKey
				profile.GitName = gitName
				profile.GitEmail = gitEmail
				profile.GitHubToken = githubToken
				profile.SigningKey = signingKey
				for _, ev := range envVars {
					parts := strings.SplitN(ev, "=", 2)
					if len(parts) == 2 {
						profile.EnvVars[parts[0]] = parts[1]
					}
				}
			} else {
				fmt.Printf("\n%s\n\n", bold("Creating profile: "+name))
				if v, _ := promptInput("SSH key path (e.g., ~/.ssh/id_ed25519): "); v != "" {
					profile.SSHKeyPath = v
					profile.SSHKeyType = detectSSHKeyType(expandPath(v))
				}
				if v, _ := promptInput("Git user name: "); v != "" {
					profile.GitName = v
				}
				if v, _ := promptInput("Git user email: "); v != "" {
					profile.GitEmail = v
				}
				if v, _ := promptSecret("GitHub token (optional): "); v != "" {
					profile.GitHubToken = v
				}
				if v, _ := promptInput("GPG signing key ID (optional): "); v != "" {
					profile.SigningKey = v
				}
				fmt.Println(dim("\nAdd environment variables (key=value), empty line to finish:"))
				for {
					v, _ := promptInput("  ")
					if v == "" {
						break
					}
					parts := strings.SplitN(v, "=", 2)
					if len(parts) == 2 {
						profile.EnvVars[parts[0]] = parts[1]
					}
				}
			}

			if err := pm.Create(profile); err != nil {
				return err
			}

			if jsonOutput {
				enc, _ := json.MarshalIndent(map[string]string{"status": "created", "name": name}, "", "  ")
				fmt.Println(string(enc))
			} else {
				success("Profile '%s' created successfully", name)
				info("Activate with: idn switch %s", name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH key path")
	cmd.Flags().StringVar(&gitName, "git-name", "", "Git user name")
	cmd.Flags().StringVar(&gitEmail, "git-email", "", "Git user email")
	cmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub token")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "GPG signing key")
	cmd.Flags().StringArrayVar(&envVars, "env", nil, "Environment variables (KEY=VALUE)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Disable prompts")

	return cmd
}

func profileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			profiles, err := pm.List()
			if err != nil {
				return err
			}
			current, _ := GetActiveProfile(pm.baseDir)

			if jsonOutput {
				out := make([]map[string]interface{}, len(profiles))
				for i, p := range profiles {
					out[i] = map[string]interface{}{
						"name":      p.Name,
						"git_name":  p.GitName,
						"git_email": p.GitEmail,
						"ssh_key":   p.SSHKeyPath,
						"has_token": p.GitHubToken != "",
						"active":    p.Name == current,
					}
				}
				enc, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(enc))
				return nil
			}

			if len(profiles) == 0 {
				info("No profiles found. Create one with: idn profile create <name>")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tGIT USER\tSSH KEY\tTOKEN\tSTATUS")
			fmt.Fprintln(w, "────\t────────\t───────\t─────\t──────")
			for _, p := range profiles {
				status := ""
				if p.Name == current {
					status = colorGreen + "● active" + colorReset
				}
				token := dim("no")
				if p.GitHubToken != "" {
					token = colorGreen + "yes" + colorReset
				}
				sshKey := dim("none")
				if p.SSHKeyPath != "" {
					sshKey = p.SSHKeyPath
				}
				fmt.Fprintf(w, "%s\t%s <%s>\t%s\t%s\t%s\n",
					bold(p.Name), p.GitName, p.GitEmail, sshKey, token, status)
			}
			w.Flush()
			return nil
		},
	}
}

func profileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show profile details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			profile, err := pm.Get(args[0])
			if err != nil {
				return err
			}
			current, _ := GetActiveProfile(pm.baseDir)

			if jsonOutput {
				out := map[string]interface{}{
					"name":         profile.Name,
					"git_name":     profile.GitName,
					"git_email":    profile.GitEmail,
					"ssh_key_path": profile.SSHKeyPath,
					"ssh_key_type": profile.SSHKeyType,
					"signing_key":  profile.SigningKey,
					"github_token": maskSecret(profile.GitHubToken),
					"env_vars":     len(profile.EnvVars),
					"created_at":   profile.CreatedAt,
					"updated_at":   profile.UpdatedAt,
					"active":       profile.Name == current,
				}
				enc, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(enc))
				return nil
			}

			fmt.Printf("\n%s", bold("Profile: "+profile.Name))
			if profile.Name == current {
				fmt.Printf(" %s", colorGreen+"(active)"+colorReset)
			}
			fmt.Println("\n")

			fmt.Printf("  %-16s %s\n", dim("Git Name:"), profile.GitName)
			fmt.Printf("  %-16s %s\n", dim("Git Email:"), profile.GitEmail)
			fmt.Printf("  %-16s %s\n", dim("SSH Key:"), profile.SSHKeyPath)
			if profile.SSHKeyType != "" {
				fmt.Printf("  %-16s %s\n", dim("Key Type:"), profile.SSHKeyType)
			}
			if profile.SigningKey != "" {
				fmt.Printf("  %-16s %s\n", dim("Signing Key:"), profile.SigningKey)
			}
			if profile.GitHubToken != "" {
				fmt.Printf("  %-16s %s\n", dim("GitHub Token:"), maskSecret(profile.GitHubToken))
			}
			if len(profile.EnvVars) > 0 {
				fmt.Printf("  %-16s\n", dim("Env Variables:"))
				for k, v := range profile.EnvVars {
					fmt.Printf("    %s=%s\n", k, maskSecret(v))
				}
			}
			fmt.Printf("\n  %-16s %s\n", dim("Created:"), profile.CreatedAt.Format(time.RFC3339))
			fmt.Printf("  %-16s %s\n\n", dim("Updated:"), profile.UpdatedAt.Format(time.RFC3339))
			return nil
		},
	}
}

func profileDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "delete <name>",
		Aliases: []string{"rm"},
		Short:   "Delete a profile",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			if _, err := pm.Get(name); err != nil {
				return err
			}
			if !force {
				if !promptConfirm(fmt.Sprintf("Delete profile '%s'?", name)) {
					info("Cancelled")
					return nil
				}
			}
			if err := pm.Delete(name); err != nil {
				return err
			}
			if jsonOutput {
				enc, _ := json.MarshalIndent(map[string]string{"status": "deleted", "name": name}, "", "  ")
				fmt.Println(string(enc))
			} else {
				success("Profile '%s' deleted", name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")
	return cmd
}

func profileUpdateCmd() *cobra.Command {
	var (
		sshKey      string
		gitName     string
		gitEmail    string
		githubToken string
		signingKey  string
		addEnv      []string
		removeEnv   []string
	)

	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update an existing profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			profile, err := pm.Get(name)
			if err != nil {
				return err
			}

			if cmd.Flags().Changed("ssh-key") {
				profile.SSHKeyPath = sshKey
				profile.SSHKeyType = detectSSHKeyType(expandPath(sshKey))
			}
			if cmd.Flags().Changed("git-name") {
				profile.GitName = gitName
			}
			if cmd.Flags().Changed("git-email") {
				profile.GitEmail = gitEmail
			}
			if cmd.Flags().Changed("github-token") {
				profile.GitHubToken = githubToken
			}
			if cmd.Flags().Changed("signing-key") {
				profile.SigningKey = signingKey
			}
			for _, ev := range addEnv {
				parts := strings.SplitN(ev, "=", 2)
				if len(parts) == 2 {
					if profile.EnvVars == nil {
						profile.EnvVars = make(map[string]string)
					}
					profile.EnvVars[parts[0]] = parts[1]
				}
			}
			for _, key := range removeEnv {
				delete(profile.EnvVars, key)
			}

			if err := pm.Update(profile); err != nil {
				return err
			}

			current, _ := GetActiveProfile(pm.baseDir)
			if current == name {
				if err := pm.Activate(name); err != nil {
					warn("Profile updated but failed to reactivate: %v", err)
				}
			}

			if jsonOutput {
				enc, _ := json.MarshalIndent(map[string]string{"status": "updated", "name": name}, "", "  ")
				fmt.Println(string(enc))
			} else {
				success("Profile '%s' updated", name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH key path")
	cmd.Flags().StringVar(&gitName, "git-name", "", "Git user name")
	cmd.Flags().StringVar(&gitEmail, "git-email", "", "Git user email")
	cmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub token")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "GPG signing key")
	cmd.Flags().StringArrayVar(&addEnv, "add-env", nil, "Add environment variable (KEY=VALUE)")
	cmd.Flags().StringArrayVar(&removeEnv, "remove-env", nil, "Remove environment variable by key")

	return cmd
}

// ═══════════════════════════════════════════════════════════════════════════════
// SWITCH COMMAND
// ═══════════════════════════════════════════════════════════════════════════════

func switchCmd() *cobra.Command {
	var skipSSHAgent bool
	cmd := &cobra.Command{
		Use:   "switch <name>",
		Short: "Activate a profile and inject credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			profile, err := pm.Get(name)
			if err != nil {
				return err
			}

			current, _ := GetActiveProfile(pm.baseDir)
			if current != "" && current != name {
				info("Switching from '%s' to '%s'", current, name)
			}

			if err := pm.Activate(name); err != nil {
				return err
			}

			if !skipSSHAgent && profile.SSHKeyPath != "" {
				if err := addToSSHAgent(profile.SSHKeyPath); err != nil {
					warn("Failed to add key to ssh-agent: %v", err)
				}
			}

			if jsonOutput {
				enc, _ := json.MarshalIndent(map[string]string{"status": "switched", "profile": name}, "", "  ")
				fmt.Println(string(enc))
			} else {
				success("Switched to profile '%s'", name)
				if profile.GitName != "" {
					fmt.Printf("  %s %s <%s>\n", dim("Git:"), profile.GitName, profile.GitEmail)
				}
				if profile.SSHKeyPath != "" {
					fmt.Printf("  %s %s\n", dim("SSH:"), profile.SSHKeyPath)
				}
				if profile.GitHubToken != "" {
					fmt.Printf("  %s configured\n", dim("GitHub Token:"))
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&skipSSHAgent, "skip-ssh-agent", false, "Don't add key to ssh-agent")
	return cmd
}

// ═══════════════════════════════════════════════════════════════════════════════
// CURRENT COMMAND
// ═══════════════════════════════════════════════════════════════════════════════

func currentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the currently active profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			current, err := GetActiveProfile(pm.baseDir)
			if err != nil {
				return err
			}

			if current == "" {
				if jsonOutput {
					fmt.Println(`{"active": null}`)
				} else {
					info("No profile currently active")
				}
				return nil
			}

			profile, err := pm.Get(current)
			if err != nil {
				if jsonOutput {
					fmt.Printf(`{"active": "%s", "error": "profile not found"}`+"\n", current)
				} else {
					warn("Active profile '%s' not found (may have been deleted)", current)
				}
				return nil
			}

			if jsonOutput {
				out := map[string]interface{}{
					"active":    current,
					"git_name":  profile.GitName,
					"git_email": profile.GitEmail,
					"ssh_key":   profile.SSHKeyPath,
				}
				enc, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(enc))
			} else {
				fmt.Printf("%s %s\n", bold("Active:"), current)
				if profile.GitName != "" {
					fmt.Printf("  %s %s <%s>\n", dim("Git:"), profile.GitName, profile.GitEmail)
				}
			}
			return nil
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATUS COMMAND
// ═══════════════════════════════════════════════════════════════════════════════

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show diagnostic information about current state",
		RunE: func(cmd *cobra.Command, args []string) error {
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			status := getStatus(pm)

			if jsonOutput {
				enc, _ := json.MarshalIndent(status, "", "  ")
				fmt.Println(string(enc))
				return nil
			}

			fmt.Printf("\n%s\n\n", bold("idn Status"))

			active := status["active_profile"]
			if active == nil || active == "" {
				fmt.Printf("  %-20s %s\n", dim("Active Profile:"), dim("none"))
			} else {
				fmt.Printf("  %-20s %s\n", dim("Active Profile:"), colorGreen+active.(string)+colorReset)
			}

			fmt.Printf("\n  %s\n", bold("Git Configuration:"))
			fmt.Printf("    %-18s %s\n", dim("Configured Name:"), strOrNone(status["git_name"]))
			fmt.Printf("    %-18s %s\n", dim("Configured Email:"), strOrNone(status["git_email"]))
			fmt.Printf("    %-18s %s\n", dim("Actual Name:"), strOrNone(status["actual_git_name"]))
			fmt.Printf("    %-18s %s\n", dim("Actual Email:"), strOrNone(status["actual_git_email"]))

			if status["git_name"] != status["actual_git_name"] || status["git_email"] != status["actual_git_email"] {
				warn("Git config differs from active profile!")
			}

			fmt.Printf("\n  %s\n", bold("SSH Configuration:"))
			fmt.Printf("    %-18s %s\n", dim("Key Path:"), strOrNone(status["ssh_key"]))
			sshConfigured := status["ssh_github_configured"].(bool)
			if sshConfigured {
				fmt.Printf("    %-18s %s\n", dim("GitHub Host:"), colorGreen+"configured"+colorReset)
			} else {
				fmt.Printf("    %-18s %s\n", dim("GitHub Host:"), dim("not configured"))
			}

			fmt.Printf("\n  %s\n", bold("Credentials:"))
			hasToken := status["has_github_token"]
			if hasToken != nil && hasToken.(bool) {
				fmt.Printf("    %-18s %s\n", dim("GitHub Token:"), colorGreen+"present"+colorReset)
			} else {
				fmt.Printf("    %-18s %s\n", dim("GitHub Token:"), dim("not set"))
			}

			envCount := status["env_vars_count"]
			if envCount != nil && envCount.(int) > 0 {
				fmt.Printf("    %-18s %d variables\n", dim("Environment:"), envCount.(int))
			}

			fmt.Println()
			return nil
		},
	}
}

func strOrNone(v interface{}) string {
	if v == nil || v == "" {
		return dim("not set")
	}
	return v.(string)
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATE COMMAND
// ═══════════════════════════════════════════════════════════════════════════════

func validateCmd() *cobra.Command {
	var checkToken bool
	cmd := &cobra.Command{
		Use:   "validate <name>",
		Short: "Validate a profile's configuration and credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pm, err := NewProfileManager(getBaseDir())
			if err != nil {
				return err
			}
			profile, err := pm.Get(name)
			if err != nil {
				return err
			}
			result, err := pm.Validate(name)
			if err != nil {
				return err
			}

			if checkToken && profile.GitHubToken != "" {
				info("Verifying GitHub token...")
				valid, user, err := verifyGitHubToken(profile.GitHubToken)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Token verification failed: %v", err))
					result.Valid = false
				} else if !valid {
					result.Errors = append(result.Errors, "GitHub token is invalid or expired")
					result.Valid = false
				} else {
					success("GitHub token valid (user: %s)", user)
				}
			}

			if jsonOutput {
				enc, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(enc))
				return nil
			}

			fmt.Printf("\n%s\n\n", bold("Validation: "+name))

			if profile.SSHKeyPath != "" {
				keyPath := expandPath(profile.SSHKeyPath)
				if _, err := os.Stat(keyPath); os.IsNotExist(err) {
					errorf("SSH key not found: %s", keyPath)
				} else if err := validateSSHKey(keyPath); err != nil {
					errorf("SSH key invalid: %v", err)
				} else {
					success("SSH key valid (%s)", profile.SSHKeyType)
				}
			}

			if profile.GitHubToken != "" {
				if isValidTokenFormat(profile.GitHubToken) {
					success("GitHub token format valid")
				} else {
					warn("GitHub token format is unusual")
				}
			}

			for _, e := range result.Errors {
				errorf("%s", e)
			}
			for _, w := range result.Warnings {
				warn("%s", w)
			}

			fmt.Println()
			if result.Valid {
				success("Profile '%s' is valid", name)
			} else {
				errorf("Profile '%s' has errors", name)
				return fmt.Errorf("validation failed")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkToken, "check-token", false, "Verify GitHub token via API")
	return cmd
}
