# idn

`idn` is a Go CLI for switching between different developer identities on the same machine.

I built it because working with multiple GitHub accounts usually means managing SSH keys, Git configuration, GitHub tokens, signing keys, and environment variables separately. `idn` groups those settings into profiles and lets you switch between them with one command.

```bash
idn switch work
```

## What it manages

A profile can contain:

* SSH key
* Git username
* Git email
* GitHub token
* GPG signing key
* Environment variables

Profiles are stored separately, and sensitive values are masked when displayed. 

## Install

```bash
git clone https://github.com/Rakshit-gen/idn.git
cd idn

go build -o idn .
sudo mv idn /usr/local/bin/idn
```

## Setup

Initialize `idn`:

```bash
idn init
```

It creates the required configuration and asks for a master passphrase.

Then create a profile:

```bash
idn profile create work
```

The interactive setup asks for the credentials you want associated with that profile. 

## Switching profiles

```bash
idn switch work
```

For example:

```text
work
├── SSH key
├── Git name
├── Git email
├── GitHub token
└── environment variables
```

Switching to another profile changes the active Git identity and credentials together.

If the profile has an SSH key, `idn` also adds it to the SSH agent by default. 

## Commands

### Create a profile

```bash
idn profile create personal
```

Or without prompts:

```bash
idn profile create work \
  --non-interactive \
  --ssh-key ~/.ssh/id_ed25519_work \
  --git-name "Your Name" \
  --git-email "work@example.com"
```

Environment variables can be added with `--env`:

```bash
idn profile create work \
  --non-interactive \
  --env API_URL=https://api.example.com
```

The CLI also accepts GitHub tokens and GPG signing keys. 

### List profiles

```bash
idn profile list
```

or:

```bash
idn profile ls
```

### Show a profile

```bash
idn profile show work
```

### Update a profile

```bash
idn profile update work --git-email new@example.com
```

Add or remove environment variables:

```bash
idn profile update work --add-env API_URL=https://api.example.com
idn profile update work --remove-env OLD_API_URL
```

### Delete a profile

```bash
idn profile delete personal
```

Skip confirmation:

```bash
idn profile delete personal --force
```

### Show the active profile

```bash
idn current
```

### Check configuration

```bash
idn status
```

`status` compares the Git configuration with the active profile and reports SSH and credential state. 

### Validate a profile

```bash
idn validate work
```

Check the GitHub token as well:

```bash
idn validate work --check-token
```



## JSON output

Commands support JSON output:

```bash
idn --json profile list
```

This is useful when another script needs to read the current profile or configuration.

## Example

Suppose you have two GitHub accounts:

```text
personal
  Git: rakshit-personal
  SSH: ~/.ssh/id_ed25519_personal

work
  Git: rakshit-work
  SSH: ~/.ssh/id_ed25519_work
```

Before working on a personal repository:

```bash
idn switch personal
```

Before working on a work repository:

```bash
idn switch work
```

To see which one is active:

```bash
idn current
```

## Configuration checks

`idn status` is also meant to catch cases where the active profile and the machine's actual Git configuration disagree.

```text
Configured Name:  Rakshit
Configured Email: work@example.com
Actual Name:      Rakshit
Actual Email:     personal@example.com

Warning: Git config differs from active profile
```

This is useful when switching identities manually has left Git in an unexpected state. 

## Security

`idn init` uses AES-256-GCM for its configured encryption method and requires a master passphrase of at least eight characters. 

Credentials are masked when profile details are displayed:

```text
GitHub Token: ********
```

Environment variable values are also masked in profile output. 

Do not commit your local `idn` configuration or credential storage to Git.

## Why I built it

The main idea is small:

```text
credentials
     ↓
  profile
     ↓
idn switch
     ↓
Git + SSH + environment
```

Instead of remembering which SSH key, Git email, token, or environment variables belong to which account, the profile becomes the unit you switch between.

## License

MIT
