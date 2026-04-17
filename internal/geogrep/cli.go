package geogrep

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func parseCLIArgs(args []string) (CLIConfig, error) {
	if len(args) == 0 {
		return CLIConfig{}, errors.New("missing subcommand: use 'find', 'version', or 'web'")
	}

	subcommand := strings.TrimSpace(args[0])
	switch subcommand {
	case "version":
		if len(args) > 1 {
			return CLIConfig{}, errors.New("version subcommand does not accept additional arguments")
		}
		return CLIConfig{Command: "version"}, nil
	case "find":
		return parseFindArgs(args[1:])
	case "web":
		return parseWebArgs(args[1:])
	default:
		return CLIConfig{}, fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}

func parseFindArgs(args []string) (CLIConfig, error) {
	cfg := CLIConfig{Command: "find"}
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

		handled, err := parseVerboseArg(&cfg, arg)
		if err != nil {
			return CLIConfig{}, err
		}
		if handled {
			continue
		}

		handled, next, err := parseDatabaseArg(&cfg, args, i, arg)
		if err != nil {
			return CLIConfig{}, err
		}
		if handled {
			i = next
			continue
		}

		switch {
		case arg == "--":
			stopFlagParsing = true
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

	if len(cfg.Inputs) == 0 {
		return CLIConfig{}, errors.New("no lookup input provided")
	}

	if cfg.Verbose > 0 {
		cfg.ReportEmpty = true
	}

	return cfg, nil
}

func parseWebArgs(args []string) (CLIConfig, error) {
	cfg := CLIConfig{
		Command:    "web",
		ListenAddr: "0.0.0.0:8080",
	}

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}

		handled, err := parseVerboseArg(&cfg, arg)
		if err != nil {
			return CLIConfig{}, err
		}
		if handled {
			continue
		}

		handled, next, err := parseDatabaseArg(&cfg, args, i, arg)
		if err != nil {
			return CLIConfig{}, err
		}
		if handled {
			i = next
			continue
		}

		switch {
		case strings.HasPrefix(arg, "-l="):
			cfg.ListenAddr = strings.TrimSpace(strings.TrimPrefix(arg, "-l="))
		case strings.HasPrefix(arg, "--listen="):
			cfg.ListenAddr = strings.TrimSpace(strings.TrimPrefix(arg, "--listen="))
		case arg == "-l" || arg == "--listen":
			value, next, err := consumeNextArg(args, i, arg)
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.ListenAddr = value
			i = next
		case strings.HasPrefix(arg, "--webui="):
			cfg.WebUIPath = strings.TrimSpace(strings.TrimPrefix(arg, "--webui="))
			if cfg.WebUIPath == "" {
				return CLIConfig{}, errors.New("--webui requires a non-empty path")
			}
		case arg == "--webui":
			value, next, err := consumeNextArg(args, i, "--webui")
			if err != nil {
				return CLIConfig{}, err
			}
			cfg.WebUIPath = value
			i = next
		case arg == "--api-only":
			cfg.APIOnly = true
		case strings.HasPrefix(arg, "-"):
			return CLIConfig{}, fmt.Errorf("unknown flag: %s", arg)
		default:
			return CLIConfig{}, fmt.Errorf("unexpected positional argument for web subcommand: %s", arg)
		}
	}

	if cfg.ListenAddr == "" {
		return CLIConfig{}, errors.New("-l/--listen requires a non-empty address")
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return CLIConfig{}, fmt.Errorf("invalid listen address %q: %w", cfg.ListenAddr, err)
	}

	if cfg.Verbose > 0 {
		cfg.ReportEmpty = true
	}

	return cfg, nil
}

func parseVerboseArg(cfg *CLIConfig, arg string) (bool, error) {
	switch {
	case arg == "-v" || arg == "--verbose":
		cfg.Verbose++
		return true, nil
	case strings.HasPrefix(arg, "--verbose="):
		lvlRaw := strings.TrimSpace(strings.TrimPrefix(arg, "--verbose="))
		if lvlRaw == "" {
			return true, errors.New("--verbose requires a level")
		}
		lvl, err := strconv.Atoi(lvlRaw)
		if err != nil || lvl < 0 {
			return true, errors.New("--verbose level must be a non-negative integer")
		}
		cfg.Verbose = lvl
		return true, nil
	case strings.HasPrefix(arg, "-v") && isCompactVerboseFlag(arg):
		cfg.Verbose += len(arg) - 1
		return true, nil
	default:
		return false, nil
	}
}

func parseDatabaseArg(cfg *CLIConfig, args []string, i int, arg string) (bool, int, error) {
	switch {
	case strings.HasPrefix(arg, "-db="):
		cfg.DBDir = strings.TrimSpace(strings.TrimPrefix(arg, "-db="))
		if cfg.DBDir == "" {
			return true, i, errors.New("-db/--database requires a non-empty path")
		}
		return true, i, nil
	case strings.HasPrefix(arg, "--database="):
		cfg.DBDir = strings.TrimSpace(strings.TrimPrefix(arg, "--database="))
		if cfg.DBDir == "" {
			return true, i, errors.New("-db/--database requires a non-empty path")
		}
		return true, i, nil
	case strings.HasPrefix(arg, "--db="):
		cfg.DBDir = strings.TrimSpace(strings.TrimPrefix(arg, "--db="))
		if cfg.DBDir == "" {
			return true, i, errors.New("-db/--database requires a non-empty path")
		}
		return true, i, nil
	case arg == "-db" || arg == "--database" || arg == "--db":
		value, next, err := consumeNextArg(args, i, arg)
		if err != nil {
			return true, i, err
		}
		cfg.DBDir = value
		return true, next, nil
	default:
		return false, i, nil
	}
}

func isCompactVerboseFlag(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	for i := 1; i < len(arg); i++ {
		if arg[i] != 'v' {
			return false
		}
	}
	return true
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
