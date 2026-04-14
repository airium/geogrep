package geogrep

import (
	"errors"
	"fmt"
	"strings"
)

func parseCLIArgs(args []string) (CLIConfig, error) {
	cfg := CLIConfig{}
	stopFlagParsing := false

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}

		if stopFlagParsing {
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: arg, Force: ForceAuto})
			continue
		}

		switch {
		case arg == "--":
			stopFlagParsing = true
		case arg == "-v" || arg == "--version":
			cfg.ShowVersion = true
		case arg == "--report-empty":
			cfg.ReportEmpty = true
		case strings.HasPrefix(arg, "--json="):
			cfg.JSONPath = strings.TrimSpace(strings.TrimPrefix(arg, "--json="))
			if cfg.JSONPath == "" {
				return CLIConfig{}, errors.New("--json requires a non-empty path")
			}
		case arg == "--json":
			value, next, err := consumeNextArg(args, i, "--json")
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.JSONPath = value
			i = next
		case strings.HasPrefix(arg, "-db="):
			cfg.DBDir = strings.TrimSpace(strings.TrimPrefix(arg, "-db="))
			if cfg.DBDir == "" {
				return CLIConfig{}, errors.New("-db requires a non-empty directory")
			}
		case strings.HasPrefix(arg, "--db="):
			cfg.DBDir = strings.TrimSpace(strings.TrimPrefix(arg, "--db="))
			if cfg.DBDir == "" {
				return CLIConfig{}, errors.New("--db requires a non-empty directory")
			}
		case arg == "-db" || arg == "--db":
			value, next, err := consumeNextArg(args, i, arg)
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.DBDir = value
			i = next
		case strings.HasPrefix(arg, "-4="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "-4="))
			if value == "" {
				return CLIConfig{}, errors.New("-4 requires a non-empty value")
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceIPv4})
		case arg == "-4":
			value, next, err := consumeNextArg(args, i, "-4")
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceIPv4})
			i = next
		case strings.HasPrefix(arg, "-6="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "-6="))
			if value == "" {
				return CLIConfig{}, errors.New("-6 requires a non-empty value")
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceIPv6})
		case arg == "-6":
			value, next, err := consumeNextArg(args, i, "-6")
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceIPv6})
			i = next
		case strings.HasPrefix(arg, "-d="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "-d="))
			if value == "" {
				return CLIConfig{}, errors.New("-d requires a non-empty value")
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceDomain})
		case arg == "-d":
			value, next, err := consumeNextArg(args, i, "-d")
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceDomain})
			i = next
		case strings.HasPrefix(arg, "-k="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "-k="))
			if value == "" {
				return CLIConfig{}, errors.New("-k requires a non-empty value")
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceKeyword})
		case arg == "-k":
			value, next, err := consumeNextArg(args, i, "-k")
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: value, Force: ForceKeyword})
			i = next
		case strings.HasPrefix(arg, "-"):
			return CLIConfig{}, fmt.Errorf("unknown flag: %s", arg)
		default:
			cfg.Inputs = append(cfg.Inputs, RawInput{Value: arg, Force: ForceAuto})
		}
	}

	if cfg.ShowVersion {
		return cfg, nil
	}

	if len(cfg.Inputs) == 0 {
		return CLIConfig{}, errors.New("no lookup input provided")
	}

	return cfg, nil
}

func consumeNextArg(args []string, i int, flagName string) (string, int, error) {
	next := i + 1
	if next >= len(args) {
		return "", i, fmt.Errorf("%s requires a value", flagName)
	}
	value := strings.TrimSpace(args[next])
	if value == "" {
		return "", i, fmt.Errorf("%s requires a non-empty value", flagName)
	}
	return value, next, nil
}
