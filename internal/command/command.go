// Package command implements the pulse-agent command-line boundary.
package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"pulse-agent/internal/standalone"
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

// Execute runs the requested command and returns its process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return execute(ctx, args, stdout, stderr, standalone.New())
}

func execute(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
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
		return executeStandalone(ctx, args, stdout, stderr, service)
	}

	if _, ok := directCommands[args[0]]; ok {
		return executeRecognized(args, stdout, stderr)
	}

	if subcommands, ok := commandGroups[args[0]]; ok {
		return executeGroup(args, stdout, stderr, subcommands)
	}

	return writeError(stderr, ExitUsage, "unknown_command", args[0], "unknown command")
}

func executeStandalone(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	service standaloneRunner,
) int {
	if len(args) == 2 && isHelp(args[1]) {
		fmt.Fprintln(stdout, "Usage: pulse-agent standalone")
		return ExitSuccess
	}
	if len(args) != 1 {
		return writeError(stderr, ExitUsage, "invalid_arguments", "standalone", "standalone does not accept arguments")
	}

	if err := service.Run(ctx); err != nil {
		return writeError(stderr, ExitFailure, "standalone_failed", "standalone", err.Error())
	}
	return ExitSuccess
}

func executeRecognized(args []string, stdout, stderr io.Writer) int {
	commandName := args[0]
	if len(args) == 2 && isHelp(args[1]) {
		fmt.Fprintf(stdout, "Usage: pulse-agent %s\n", commandName)
		return ExitSuccess
	}
	if len(args) != 1 {
		return writeError(stderr, ExitUsage, "invalid_arguments", commandName, "command does not accept arguments yet")
	}
	return writeNotImplemented(stderr, commandName)
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
