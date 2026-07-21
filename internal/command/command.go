// Package command implements the pulse-agent command-line boundary.
package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"pulse-agent/internal/adminipc"
	"pulse-agent/internal/config"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/standalone"
	"pulse-agent/internal/target"
)

const (
	// ExitSuccess indicates successful command completion.
	ExitSuccess = 0
	// ExitFailure indicates a runtime failure.
	ExitFailure = 1
	// ExitUsage indicates invalid command-line input.
	ExitUsage = 2
	// ExitNotImplemented indicates a recognized command owned by a later task.
	ExitNotImplemented = 3
)

const errorSchemaVersion = "pulse-agent.cli.error.v1"

var commandGroups = map[string]map[string]struct{}{
	"approval": {"deny": {}, "grant": {}},
	"config":   {"validate": {}},
	"incident": {"list": {}, "show": {}},
	"runbook":  {"register": {}, "validate": {}},
	"target":   {"register": {}},
}

var directCommands = map[string]struct{}{
	"backup": {},
	"status": {},
}

type standaloneRunner interface {
	Run(context.Context) error
}

type configuredStandaloneRunner interface {
	RunWithConfig(context.Context, config.Config) error
}

type adminClient interface {
	Status(context.Context, string, string) (adminipc.Status, error)
	Backup(context.Context, string, string, io.Writer) error
	Register(context.Context, string, string, contract.ServiceTarget) (target.RegistrationResult, error)
}

type configLoader func(string) (config.Config, error)

type diagnostic struct {
	SchemaVersion string           `json:"schema_version"`
	Error         diagnosticDetail `json:"error"`
}

type diagnosticDetail struct {
	Code      string `json:"code"`
	Command   string `json:"command,omitempty"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type configValidation struct {
	SchemaVersion string `json:"schema_version"`
	Valid         bool   `json:"valid"`
}

// Execute runs the requested command and returns its process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return executeWithProductionClient(ctx, args, stdout, stderr, standalone.New(), config.Load)
}

func execute(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
) int {
	return executeWithProductionClient(ctx, args, stdout, stderr, service, config.Load)
}

func executeWithConfig(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
	loadConfig configLoader,
) int {
	return executeWithProductionClient(ctx, args, stdout, stderr, service, loadConfig)
}

func executeWithProductionClient(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
	loadConfig configLoader,
) int {
	client, err := adminipc.NewProductionClient()
	if err != nil {
		return writeError(stderr, ExitFailure, "admin_client_unavailable", "", "administrative client initialization failed")
	}
	return executeWithDependencies(ctx, args, stdout, stderr, service, loadConfig, client)
}

func executeWithDependencies(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
	loadConfig configLoader,
	client adminClient,
) int {
	if len(args) == 0 {
		writeTopLevelUsage(stderr)
		return ExitUsage
	}

	if isHelp(args[0]) {
		writeTopLevelUsage(stdout)
		return ExitSuccess
	}

	if args[0] == "standalone" {
		return executeStandalone(ctx, args, stdout, stderr, service, loadConfig)
	}

	if args[0] == "config" {
		return executeConfig(args, stdout, stderr, loadConfig)
	}

	if _, ok := directCommands[args[0]]; ok {
		return executeAdmin(ctx, args, stdout, stderr, loadConfig, client)
	}
	if args[0] == "target" {
		return executeTarget(ctx, args, stdout, stderr, loadConfig, client)
	}

	if subcommands, ok := commandGroups[args[0]]; ok {
		return executeGroup(args, stdout, stderr, subcommands)
	}

	return writeError(stderr, ExitUsage, "unknown_command", args[0], "unknown command")
}

func executeTarget(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	loadConfig configLoader,
	client adminClient,
) int {
	const commandName = "target register"
	if len(args) == 2 && isHelp(args[1]) {
		fmt.Fprintln(stdout, "Usage: pulse-agent target register --config <path> --target <path> [--reason <code>]")
		return ExitSuccess
	}
	if len(args) == 3 && args[1] == "register" && isHelp(args[2]) {
		fmt.Fprintln(stdout, "Usage: pulse-agent target register --config <path> --target <path> [--reason <code>]")
		return ExitSuccess
	}
	if len(args) != 6 && len(args) != 8 {
		return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "target register requires --config <path> --target <path> with optional --reason <code>")
	}
	if args[1] != "register" || args[2] != "--config" || args[3] == "" || args[4] != "--target" || args[5] == "" {
		return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "target register requires --config <path> --target <path> with optional --reason <code>")
	}
	reasonCode := adminipc.DefaultReasonCode
	if len(args) == 8 {
		if args[6] != "--reason" || args[7] == "" {
			return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "target register requires --config <path> --target <path> with optional --reason <code>")
		}
		reasonCode = args[7]
	}
	runtimeConfig, err := loadConfig(args[3])
	if err != nil {
		return writeError(stderr, ExitFailure, "config_invalid", commandName, "configuration validation failed")
	}
	submitted, err := target.Load(args[5])
	if err != nil {
		return writeError(stderr, ExitUsage, "target_invalid", commandName, "target document validation failed")
	}
	result, err := client.Register(ctx, runtimeConfig.Admin.SocketPath, reasonCode, submitted)
	if err != nil {
		return writeAdminRequestError(stderr, commandName, err)
	}
	return writeTargetRegistrationResult(stdout, result)
}

func executeStandalone(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
	loadConfig configLoader,
) int {
	if len(args) == 2 && isHelp(args[1]) {
		fmt.Fprintln(stdout, "Usage: pulse-agent standalone --config <path>")
		return ExitSuccess
	}
	if len(args) != 3 || args[1] != "--config" || args[2] == "" {
		return writeError(stderr, ExitUsage, "invalid_arguments", "standalone", "standalone requires --config <path>")
	}
	runtimeConfig, err := loadConfig(args[2])
	if err != nil {
		return writeError(stderr, ExitFailure, "config_invalid", "standalone", "configuration validation failed")
	}

	if configured, ok := service.(configuredStandaloneRunner); ok {
		err = configured.RunWithConfig(ctx, runtimeConfig)
	} else {
		err = service.Run(ctx)
	}
	if err != nil {
		return writeError(stderr, ExitFailure, "standalone_failed", "standalone", err.Error())
	}
	return ExitSuccess
}

func executeConfig(args []string, stdout, stderr io.Writer, loadConfig configLoader) int {
	if len(args) == 2 && isHelp(args[1]) {
		writeConfigUsage(stdout)
		return ExitSuccess
	}
	if len(args) < 2 {
		writeGroupUsage(stderr, "config", commandGroups["config"])
		return ExitUsage
	}
	if args[1] != "validate" {
		return writeError(stderr, ExitUsage, "unknown_command", strings.Join(args[:2], " "), "unknown command")
	}
	if len(args) == 3 && isHelp(args[2]) {
		writeConfigUsage(stdout)
		return ExitSuccess
	}
	if len(args) != 4 || args[2] != "--config" || args[3] == "" {
		return writeError(stderr, ExitUsage, "invalid_arguments", "config validate", "config validate requires --config <path>")
	}
	if _, err := loadConfig(args[3]); err != nil {
		return writeError(stderr, ExitFailure, "config_invalid", "config validate", "configuration validation failed")
	}
	return writeConfigValidation(stdout)
}

func executeAdmin(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	loadConfig configLoader,
	client adminClient,
) int {
	commandName := args[0]
	if len(args) == 2 && isHelp(args[1]) {
		fmt.Fprintf(stdout, "Usage: pulse-agent %s --config <path> [--reason <code>]\n", commandName)
		return ExitSuccess
	}
	configPath, reasonCode, ok := parseAdminArguments(args)
	if !ok {
		return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "command requires --config <path> with optional --reason <code>")
	}
	runtimeConfig, err := loadConfig(configPath)
	if err != nil {
		return writeError(stderr, ExitFailure, "config_invalid", commandName, "configuration validation failed")
	}

	switch commandName {
	case "status":
		status, err := client.Status(ctx, runtimeConfig.Admin.SocketPath, reasonCode)
		if err != nil {
			return writeAdminRequestError(stderr, commandName, err)
		}
		return writeStatus(stdout, status)
	case "backup":
		if err := client.Backup(ctx, runtimeConfig.Admin.SocketPath, reasonCode, stdout); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			return writeAdminRequestError(stderr, commandName, err)
		}
		return ExitSuccess
	default:
		return writeError(stderr, ExitUsage, "unknown_command", commandName, "unknown command")
	}
}

func parseAdminArguments(args []string) (configPath, reasonCode string, ok bool) {
	if len(args) != 3 && len(args) != 5 {
		return "", "", false
	}
	if args[1] != "--config" || args[2] == "" {
		return "", "", false
	}
	if len(args) == 3 {
		return args[2], adminipc.DefaultReasonCode, true
	}
	if args[3] != "--reason" || args[4] == "" {
		return "", "", false
	}
	return args[2], args[4], true
}

func writeAdminRequestError(stderr io.Writer, commandName string, err error) int {
	if errors.Is(err, adminipc.ErrInvalidOptions) {
		return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "invalid administrative request")
	}
	return writeError(stderr, ExitFailure, "daemon_unavailable", commandName, "administrative daemon request failed")
}

func writeStatus(stdout io.Writer, status adminipc.Status) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(status); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return ExitFailure
	}
	return ExitSuccess
}

func writeTargetRegistrationResult(stdout io.Writer, result target.RegistrationResult) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return ExitFailure
	}
	return ExitSuccess
}

func executeGroup(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	subcommands map[string]struct{},
) int {
	group := args[0]
	if len(args) == 2 && isHelp(args[1]) {
		writeGroupUsage(stdout, group, subcommands)
		return ExitSuccess
	}
	if len(args) < 2 {
		writeGroupUsage(stderr, group, subcommands)
		return ExitUsage
	}

	commandName := strings.Join(args[:2], " ")
	if _, ok := subcommands[args[1]]; !ok {
		return writeError(stderr, ExitUsage, "unknown_command", commandName, "unknown command")
	}
	if len(args) == 3 && isHelp(args[2]) {
		fmt.Fprintf(stdout, "Usage: pulse-agent %s\n", commandName)
		return ExitSuccess
	}
	if len(args) != 2 {
		return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "command does not accept arguments yet")
	}
	return writeNotImplemented(stderr, commandName)
}

func writeNotImplemented(stderr io.Writer, commandName string) int {
	return writeError(
		stderr,
		ExitNotImplemented,
		"not_implemented",
		commandName,
		"command is recognized but not implemented",
	)
}

func writeError(stderr io.Writer, exitCode int, code, commandName, message string) int {
	diagnostic := diagnostic{
		SchemaVersion: errorSchemaVersion,
		Error: diagnosticDetail{
			Code:      code,
			Command:   commandName,
			Message:   message,
			Retryable: false,
		},
	}

	encoder := json.NewEncoder(stderr)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(diagnostic); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return ExitFailure
	}
	return exitCode
}

func writeConfigValidation(stdout io.Writer) int {
	result := configValidation{
		SchemaVersion: "pulse-agent.cli.config_validation.v1",
		Valid:         true,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return ExitFailure
	}
	return ExitSuccess
}

func writeTopLevelUsage(output io.Writer) {
	fmt.Fprint(output, `Usage: pulse-agent <command> [arguments]

Commands:
  standalone          Run the standalone host service
  config validate     Validate local configuration without changing state
  target register     Register a target through the local daemon
  runbook validate    Validate a runbook pair without changing state
  runbook register    Register a runbook through the local daemon
  incident list       List incidents through the local daemon
  incident show       Show an incident through the local daemon
  approval grant      Grant an approval through the local daemon
  approval deny       Deny an approval through the local daemon
  status              Show standalone daemon status
  backup              Request a daemon-owned state backup

Use "pulse-agent <command> --help" for command usage.
`)
}

func writeGroupUsage(output io.Writer, group string, subcommands map[string]struct{}) {
	fmt.Fprintf(output, "Usage: pulse-agent %s <command>\n\nCommands:\n", group)
	for _, subcommand := range orderedSubcommands(group) {
		if _, ok := subcommands[subcommand]; ok {
			fmt.Fprintf(output, "  %s\n", subcommand)
		}
	}
}

func writeConfigUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: pulse-agent config validate --config <path>")
}

func orderedSubcommands(group string) []string {
	switch group {
	case "approval":
		return []string{"grant", "deny"}
	case "config":
		return []string{"validate"}
	case "incident":
		return []string{"list", "show"}
	case "runbook":
		return []string{"validate", "register"}
	case "target":
		return []string{"register"}
	default:
		return nil
	}
}

func isHelp(argument string) bool {
	return argument == "help" || argument == "-h" || argument == "--help"
}
