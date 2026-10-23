// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// The daemon's settings may come from three places, and the order is the
// conventional one: a command-line flag wins over the environment, which wins
// over the optional config file, which wins over the flag's own default. Each
// source fills only the flags the sources above it left alone, so a deployment
// can put its whole shape in a file and override one flag on one run.
//
// The environment spells a flag as UPFD_<FLAG>, in upper case with '-' as '_':
// -fteid-address is UPFD_FTEID_ADDRESS, -print-config is UPFD_PRINT_CONFIG.
//
// The config file names itself: -config <path> or UPFD_CONFIG. It is optional
// -- with no path named, no file is read at all, and a file the operator named
// must be readable, because a config file that was silently ignored is a
// deployment nobody described. It is one JSON object whose keys are flag names
// and whose values are strings, numbers or booleans:
//
//	{"n4": "0.0.0.0:8805", "capacity": 65536, "instances": "name=internet,domain=0,next-hop=1"}
//
// -print-config prints exactly that, after every source has been applied, which
// is also the shortest way to build the first file.
const (
	// envPrefix is what the environment spells a flag with.
	envPrefix = "UPFD_"
	// configFlag is the flag that names the config file (and so it cannot be
	// one of the file's own keys: a file that named itself would be a file
	// that decides what file is read).
	configFlag = "config"
)

// envName is a flag's environment variable: UPFD_<FLAG>, upper case, '-' as
// '_'.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// applyLayers resolves every flag of fs from the highest source that names it:
// the command line (parsed before this call), then the environment, then the
// config file. It returns the names any source named, which is what "the
// operator chose this" means downstream.
func applyLayers(fs *flag.FlagSet) (map[string]bool, error) {
	named := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { named[f.Name] = true })

	// The environment, in the flag set's own order, so a run that names
	// several bad values reports the first one as the flag set itself would.
	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		if envErr != nil || named[f.Name] {
			return
		}
		value, ok := os.LookupEnv(envName(f.Name))
		if !ok || value == "" {
			// An empty variable is how a shell spells "unset": it names no
			// value, and a flag it would set to "" is one the config file or
			// the default still owns.
			return
		}
		if err := fs.Set(f.Name, value); err != nil {
			envErr = fmt.Errorf("environment variable %s=%q: %w", envName(f.Name), value, err)
			return
		}
		named[f.Name] = true
	})
	if envErr != nil {
		return nil, envErr
	}

	// The config file, if one was named (by the command line or by the
	// environment -- the flag itself is layered like any other). Its keys are
	// sorted, so a file with several faults is refused on the same one every
	// run.
	path := ""
	if f := fs.Lookup(configFlag); f != nil {
		path = f.Value.String()
	}
	if path == "" {
		return named, nil
	}
	values, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	for _, key := range values.keys() {
		if fs.Lookup(key) == nil {
			return nil, fmt.Errorf("the config file %s names %q, which is not one of this daemon's flags", path, key)
		}
		if named[key] {
			continue
		}
		if err := fs.Set(key, values[key]); err != nil {
			return nil, fmt.Errorf("the config file %s: %s=%q: %w", path, key, values[key], err)
		}
		named[key] = true
	}
	return named, nil
}

// configSettings is a config file's settings: flag name to the text the flag
// itself would be set with.
type configSettings map[string]string

// keys lists them in a stable order.
func (v configSettings) keys() []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// readConfig reads a config file: one JSON object, its keys flag names and
// its values strings, numbers or booleans. It is read strictly, because every
// fault here is one the operator can fix and a run that ignored it would come
// up as a deployment nobody described: an unknown key (a typo) is refused, a
// key the file cannot set (config itself) is refused, and a value that is not
// a scalar is refused rather than silently dropped.
func readConfig(path string) (configSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the config file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("the config file %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(configSettings, len(raw))
	for key, value := range raw {
		switch v := value.(type) {
		case string:
			out[key] = v
		case bool:
			out[key] = fmt.Sprintf("%t", v)
		case json.Number:
			out[key] = v.String()
		default:
			return nil, fmt.Errorf(
				"the config file %s: %s must be a string, a number or a boolean, not %s",
				path, key, jsonKind(value))
		}
		if key == configFlag {
			return nil, fmt.Errorf(
				"the config file %s names %q, and the file that is read is the one -config names", path, configFlag)
		}
	}
	return out, nil
}

// jsonKind names a JSON value's type for a refusal.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case []any:
		return "a list"
	case map[string]any:
		return "an object"
	default:
		return "a value of another type"
	}
}

// effectiveConfig renders the flags' effective settings -- what each one holds
// after the command line, the environment and the config file were applied --
// as the config file's own format, so the printed text is a file -config
// reads back. The config file's own flag is left out: a file that named itself
// would be a file that decides what file is read.
func effectiveConfig(fs *flag.FlagSet) ([]byte, error) {
	out := map[string]string{}
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == configFlag {
			return
		}
		out[f.Name] = f.Value.String()
	})
	return json.MarshalIndent(out, "", "  ")
}
