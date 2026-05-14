package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/antgroup/CloudRec/lite/providers/alicloud"
	"golang.org/x/term"
)

const (
	credentialsFormatText = "text"
	credentialsFormatJSON = "json"
)

func runCredentials(args []string) error {
	return runCredentialsWithIO(args, os.Stdin, os.Stdout)
}

func runCredentialsWithIO(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("missing credentials subcommand")
	}
	switch args[0] {
	case "store":
		return runCredentialsStore(args[1:], in, out)
	case "status":
		return runCredentialsStatus(args[1:], out)
	case "delete":
		return runCredentialsDelete(args[1:], out)
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown credentials subcommand %q", args[0])
	}
}

func runCredentialsStore(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("credentials store", flag.ContinueOnError)
	provider := fs.String("provider", alicloud.ProviderName, "cloud provider")
	account := fs.String("account", "", "account identifier; used as profile when --profile is omitted")
	profile := fs.String("profile", "", "credential profile name")
	accessKeyID := fs.String("access-key-id", "", "Alibaba Cloud AccessKey ID; prefer --access-key-id-stdin for shared shells")
	accessKeyIDStdin := fs.Bool("access-key-id-stdin", false, "read AccessKey ID from stdin")
	secretStdin := fs.Bool("secret-stdin", false, "read AccessKey secret from stdin; otherwise an interactive hidden prompt is used")
	securityTokenStdin := fs.Bool("security-token-stdin", false, "read optional STS security token from stdin")
	region := fs.String("region", "", "optional default Alibaba Cloud region")
	format := fs.String("format", credentialsFormatText, "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCredentialProvider(*provider); err != nil {
		return err
	}

	reader := bufio.NewReader(in)
	ak := strings.TrimSpace(*accessKeyID)
	var err error
	if *accessKeyIDStdin {
		ak, err = readCredentialLine(reader)
		if err != nil {
			return fmt.Errorf("read access key id from stdin: %w", err)
		}
	}
	if ak == "" {
		return fmt.Errorf("missing access key id; pass --access-key-id or --access-key-id-stdin")
	}

	secret, err := readCredentialSecret(in, reader, out, *secretStdin)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("empty access key secret")
	}

	var securityToken string
	if *securityTokenStdin {
		securityToken, err = readCredentialLine(reader)
		if err != nil {
			return fmt.Errorf("read security token from stdin: %w", err)
		}
	}

	profileName := credentialProfileName(*profile, *account)
	status, err := alicloud.StoreCredentialProfileAuto(profileName, alicloud.Credentials{
		AccessKeyID:     ak,
		AccessKeySecret: secret,
		SecurityToken:   securityToken,
		Region:          *region,
	})
	if err != nil {
		return err
	}
	return renderCredentialStatus(out, status, *format, "stored")
}

func runCredentialsStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("credentials status", flag.ContinueOnError)
	provider := fs.String("provider", alicloud.ProviderName, "cloud provider")
	account := fs.String("account", "", "account identifier; used as profile when --profile is omitted")
	profile := fs.String("profile", "", "credential profile name")
	format := fs.String("format", credentialsFormatText, "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCredentialProvider(*provider); err != nil {
		return err
	}
	status, err := alicloud.CredentialProfileStatus(credentialProfileName(*profile, *account))
	if err != nil {
		return err
	}
	return renderCredentialStatus(out, status, *format, "status")
}

func runCredentialsDelete(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("credentials delete", flag.ContinueOnError)
	provider := fs.String("provider", alicloud.ProviderName, "cloud provider")
	account := fs.String("account", "", "account identifier; used as profile when --profile is omitted")
	profile := fs.String("profile", "", "credential profile name")
	format := fs.String("format", credentialsFormatText, "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCredentialProvider(*provider); err != nil {
		return err
	}
	profileName := credentialProfileName(*profile, *account)
	if err := alicloud.DeleteCredentialProfile(profileName); err != nil {
		return err
	}
	status := alicloud.StoredCredentialStatus{Profile: profileName}
	return renderCredentialStatus(out, status, *format, "deleted")
}

func validateCredentialProvider(provider string) error {
	if strings.ToLower(strings.TrimSpace(provider)) != alicloud.ProviderName {
		return fmt.Errorf("credentials currently support provider %q only", alicloud.ProviderName)
	}
	return nil
}

func credentialProfileName(profile string, account string) string {
	return firstNonEmptyCredentialValue(profile, account, alicloud.DefaultCredentialProfile)
}

func firstNonEmptyCredentialValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func readCredentialSecret(rawIn io.Reader, reader *bufio.Reader, out io.Writer, fromStdin bool) (string, error) {
	if fromStdin {
		return readCredentialLine(reader)
	}
	file, ok := rawIn.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", fmt.Errorf("access key secret must be entered with an interactive hidden prompt or --secret-stdin; do not pass secrets as command-line arguments")
	}
	fmt.Fprint(out, "Alibaba Cloud AccessKey Secret: ")
	secret, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", fmt.Errorf("read access key secret: %w", err)
	}
	return strings.TrimSpace(string(secret)), nil
}

func readCredentialLine(reader *bufio.Reader) (string, error) {
	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func renderCredentialStatus(out io.Writer, status alicloud.StoredCredentialStatus, format string, action string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", credentialsFormatText:
		switch action {
		case "stored":
			target := credentialStorageLabel(status)
			fmt.Fprintf(out, "Stored Alibaba Cloud credentials in %s for profile %q. Credential values were not printed.\n", target, status.Profile)
			if strings.TrimSpace(status.SecurityNote) != "" {
				fmt.Fprintf(out, "Security note: %s.\n", status.SecurityNote)
			}
		case "deleted":
			fmt.Fprintf(out, "Deleted Alibaba Cloud credential profile %q from local credential stores.\n", status.Profile)
		default:
			if !status.Found {
				fmt.Fprintf(out, "Alibaba Cloud credential profile %q is not stored.\n", status.Profile)
				return nil
			}
			parts := []string{"access key id present", "access key secret present"}
			if status.SecurityTokenPresent {
				parts = append(parts, "security token present")
			}
			if status.Region != "" {
				parts = append(parts, "region configured")
			}
			fmt.Fprintf(out, "Alibaba Cloud credential profile %q: %s; backend=%s.\n", status.Profile, strings.Join(parts, ", "), firstNonEmptyCredentialValue(status.Backend, "unknown"))
			if strings.TrimSpace(status.Path) != "" {
				fmt.Fprintf(out, "Path: %s\n", status.Path)
			}
			if strings.TrimSpace(status.SecurityNote) != "" {
				fmt.Fprintf(out, "Security note: %s.\n", status.SecurityNote)
			}
		}
		return nil
	case credentialsFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	default:
		return fmt.Errorf("unsupported credentials output format %q", format)
	}
}

func credentialStorageLabel(status alicloud.StoredCredentialStatus) string {
	switch status.Backend {
	case "local_encrypted_file":
		if strings.TrimSpace(status.Path) != "" {
			return "a local encrypted file at " + status.Path
		}
		return "a local encrypted file"
	case "keyring":
		return "the system credential store"
	default:
		return "the local credential store"
	}
}
