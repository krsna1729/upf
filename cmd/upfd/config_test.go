// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// layeredFlags is a flag set shaped like the daemon's: one of each type the
// layering must carry, so a config file's number, boolean and duration are all
// read as the flag itself would read them.
func layeredFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("layered", flag.ContinueOnError)
	fs.String(configFlag, "", "the config file")
	fs.String("n4", "0.0.0.0:8805", "the N4 listen address")
	fs.Uint("capacity", 1<<16, "the id spaces")
	fs.Duration("urr-interval", 0, "the reporting interval")
	fs.Bool("print-config", false, "print the effective settings")
	fs.String("instances", "", "the network instances")
	return fs
}

// writeConfig writes a config file into the test's own directory and returns
// its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upfd.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the config file: %v", err)
	}
	return path
}

// TestLayeringResolvesFromTheHighestSource: an explicit flag wins over the
// environment, which wins over the config file, which wins over the default --
// and a source that names nothing leaves the flag as it was.
func TestLayeringResolvesFromTheHighestSource(t *testing.T) {
	path := writeConfig(t, `{"n4": "192.0.2.1:8805", "capacity": 4096, "urr-interval": "5s"}`)
	t.Setenv("UPFD_N4", "192.0.2.2:8805")
	t.Setenv("UPFD_INSTANCES", "name=internet,domain=0,next-hop=1")
	t.Setenv("UPFD_CONFIG", path)

	fs := layeredFlags()
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	named, err := applyLayers(fs)
	if err != nil {
		t.Fatalf("layering: %v", err)
	}
	// The environment outranks the file, so n4 is the environment's, not the
	// file's 192.0.2.1.
	if got := fs.Lookup("n4").Value.String(); got != "192.0.2.2:8805" {
		t.Errorf("n4 is %q, want the environment's 192.0.2.2:8805", got)
	}
	if got := fs.Lookup("instances").Value.String(); got != "name=internet,domain=0,next-hop=1" {
		t.Errorf("instances is %q, want the environment's value", got)
	}
	if got := fs.Lookup("capacity").Value.String(); got != "4096" {
		t.Errorf("capacity is %q, want the config file's 4096", got)
	}
	if got := fs.Lookup("urr-interval").Value.String(); got != "5s" {
		t.Errorf("urr-interval is %q, want the config file's 5s", got)
	}
	if got := fs.Lookup("print-config").Value.String(); got != "false" {
		t.Errorf("print-config is %q, want the flag's own default", got)
	}
	for _, name := range []string{"config", "n4", "instances", "capacity", "urr-interval"} {
		if !named[name] {
			t.Errorf("%s was resolved from a source and is not reported as named", name)
		}
	}
	if named["print-config"] {
		t.Error("a flag no source named is reported as named")
	}

	// The command line wins over everything.
	fs = layeredFlags()
	if err := fs.Parse([]string{"-n4", "198.51.100.1:8805", "-capacity", "16"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, err := applyLayers(fs); err != nil {
		t.Fatalf("layering: %v", err)
	}
	if got := fs.Lookup("n4").Value.String(); got != "198.51.100.1:8805" {
		t.Errorf("n4 is %q, want the command line's 198.51.100.1:8805", got)
	}
	if got := fs.Lookup("capacity").Value.String(); got != "16" {
		t.Errorf("capacity is %q, want the command line's 16", got)
	}
}

// TestNoConfigFileIsANormalRun: the config file is optional -- with no path
// named (and none in the environment), nothing is read, and the environment is
// still the second source.
func TestNoConfigFileIsANormalRun(t *testing.T) {
	t.Setenv("UPFD_CAPACITY", "8")
	t.Setenv("UPFD_CONFIG", "")
	fs := layeredFlags()
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	named, err := applyLayers(fs)
	if err != nil {
		t.Fatalf("layering with no config file: %v", err)
	}
	if got := fs.Lookup("capacity").Value.String(); got != "8" {
		t.Errorf("capacity is %q, want the environment's 8", got)
	}
	if !named["capacity"] {
		t.Error("a setting the environment named is not reported as named")
	}
	if named["config"] {
		t.Error("the empty UPFD_CONFIG counts as naming the config file")
	}
}

// TestTheConfigFileIsReadStrictly: every fault here is one the operator can
// fix, and a run that ignored it would come up as a deployment nobody
// described.
func TestTheConfigFileIsReadStrictly(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		want string
	}{
		{"a key this build has no flag for", `{"n5": "1"}`, `names "n5"`},
		{"the file naming itself", `{"config": "/etc/other.json"}`, "the file that is read"},
		{"a value that is not a scalar", `{"n4": ["a"]}`, "must be a string, a number or a boolean"},
		{"an object where a string belongs", `{"n4": {"host": "x"}}`, "must be a string, a number or a boolean"},
		{"null", `{"n4": null}`, "must be a string, a number or a boolean"},
		{"a value the flag cannot parse", `{"capacity": "many"}`, `capacity="many"`},
		{"a duration with no unit", `{"urr-interval": 5}`, "urr-interval"},
		{"not one object", `[{"n4": "1"}]`, "the config file"},
		{"not JSON at all", `n4 = 1`, "the config file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, c.body)
			fs := layeredFlags()
			if err := fs.Parse([]string{"-" + configFlag, path}); err != nil {
				t.Fatalf("parsing: %v", err)
			}
			_, err := applyLayers(fs)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestAConfigFileNamedAndMissingIsRefused: silence here is the operation that
// was described nowhere.
func TestAConfigFileNamedAndMissingIsRefused(t *testing.T) {
	fs := layeredFlags()
	missing := filepath.Join(t.TempDir(), "absent.json")
	if err := fs.Parse([]string{"-" + configFlag, missing}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	_, err := applyLayers(fs)
	if err == nil {
		t.Fatal("a config file that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "no such file") && !strings.Contains(err.Error(), "absent.json") {
		t.Errorf("the refusal says %q, want it to name the file", err)
	}
}

// TestABadEnvironmentValueNamesTheVariable: the operator has to be able to tell
// which of the three sources a bad value came from.
func TestABadEnvironmentValueNamesTheVariable(t *testing.T) {
	t.Setenv("UPFD_CAPACITY", "lots")
	fs := layeredFlags()
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	_, err := applyLayers(fs)
	if err == nil {
		t.Fatal("a capacity that is not a number was accepted")
	}
	if !strings.Contains(err.Error(), "UPFD_CAPACITY") || !strings.Contains(err.Error(), `"lots"`) {
		t.Errorf("the refusal says %q, want it to name the variable and the value", err)
	}
}

// TestPrintConfigRoundTrips: what -print-config prints is a config file, so the
// effective settings of one run are the file another run starts from.
func TestPrintConfigRoundTrips(t *testing.T) {
	fs := layeredFlags()
	if err := fs.Parse([]string{
		"-instances", "name=internet,domain=0,next-hop=1",
		"-capacity", "4096",
		"-urr-interval", "30s",
		"-print-config",
	}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	out, err := effectiveConfig(fs)
	if err != nil {
		t.Fatalf("printing the effective settings: %v", err)
	}
	var printed map[string]any
	if err := json.Unmarshal(out, &printed); err != nil {
		t.Fatalf("the printed settings are not JSON: %v", err)
	}
	if _, ok := printed["config"]; ok {
		t.Error("the printed settings name the config flag, which a config file may not set")
	}
	if got, _ := printed["capacity"].(string); got != "4096" {
		t.Errorf("the printed capacity is %q, want the command line's 4096", printed["capacity"])
	}
	// Read it back, as a second run would, and the two agree.
	path := writeConfig(t, string(out))
	other := layeredFlags()
	if err := other.Parse([]string{"-" + configFlag, path}); err != nil {
		t.Fatalf("parsing the printed file: %v", err)
	}
	if _, err := applyLayers(other); err != nil {
		t.Fatalf("the printed settings were refused as a config file: %v", err)
	}
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == configFlag {
			return
		}
		if got := other.Lookup(f.Name).Value.String(); got != f.Value.String() {
			t.Errorf("%s round-tripped to %q, want %q", f.Name, got, f.Value.String())
		}
	})
}

// TestEnvNamesFollowTheFlags: the environment's spelling of a flag is derived,
// not a table somebody has to keep in step with the flag set.
func TestEnvNamesFollowTheFlags(t *testing.T) {
	for _, c := range []struct{ flag, env string }{
		{"n4", "UPFD_N4"},
		{"n3-addr", "UPFD_N3_ADDR"},
		{"print-config", "UPFD_PRINT_CONFIG"},
		{"buffer-gate", "UPFD_BUFFER_GATE"},
	} {
		if got := envName(c.flag); got != c.env {
			t.Errorf("the environment name of -%s is %s, want %s", c.flag, got, c.env)
		}
	}
}

// TestALayeredFlagCountsAsNamed: a value that came from the file or the
// environment is the operator's choice as much as one that came from the
// command line.
func TestALayeredFlagCountsAsNamed(t *testing.T) {
	t.Setenv("UPFD_PDR_TABLE_UL", "fw_ul")
	fs := flag.NewFlagSet("layered", flag.ContinueOnError)
	fs.String("pdr-table-ul", "pdr_ul", "the uplink rule table")
	fs.Duration("urr-interval", 0, "the reporting interval")
	fs.String(configFlag, "", "the config file")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	named, err := applyLayers(fs)
	if err != nil {
		t.Fatalf("layering: %v", err)
	}
	if !named["pdr-table-ul"] {
		t.Fatal("the environment's -pdr-table-ul does not count as named")
	}
	if got := fs.Lookup("pdr-table-ul").Value.String(); got != "fw_ul" {
		t.Errorf("pdr-table-ul is %q, want the environment's fw_ul", got)
	}
	// And a flag nothing named is left at its default.
	if named["urr-interval"] {
		t.Error("a flag no source named counts as named")
	}
}

func TestTunnelFlagLayersAndRoundTrip(t *testing.T) {
	const first = "next-hop=3,gate=1,addr=192.0.2.9,mac=02:00:00:00:00:09,peer-mac=02:00:00:00:00:0a"
	const second = "next-hop=4,gate=0,addr=192.0.2.10,mac=02:00:00:00:00:0b,peer-mac=02:00:00:00:00:0c"
	const overrides = "instance=foo,addr=192.0.2.9;instance=bar,addr=192.0.2.10"
	for _, source := range []string{"file", "environment", "command line"} {
		t.Run(source, func(t *testing.T) {
			fs := layeredFlags()
			var transports, addresses entryList
			fs.Var(&transports, "tunnel-transport", "transport mappings")
			fs.Var(&addresses, "fteid-address", "F-TEID addresses")
			fs.String("n9-addr", "", "local N9 address")
			fileValue := first + ";" + second
			path := writeConfig(t, `{"n9-addr":"192.0.2.9","tunnel-transport":"`+fileValue+`","fteid-address":"`+overrides+`"}`)
			t.Setenv("UPFD_TUNNEL_TRANSPORT", "")
			t.Setenv("UPFD_FTEID_ADDRESS", "")
			t.Setenv("UPFD_N9_ADDR", "")
			t.Setenv("UPFD_CONFIG", path)
			var args []string
			switch source {
			case "environment":
				t.Setenv("UPFD_TUNNEL_TRANSPORT", second+";"+first)
				t.Setenv("UPFD_FTEID_ADDRESS", overrides)
				t.Setenv("UPFD_N9_ADDR", "192.0.2.19")
				fileValue = second + ";" + first
			case "command line":
				// Lower layers must not append mappings to CLI values.
				t.Setenv("UPFD_TUNNEL_TRANSPORT", first)
				args = []string{"-tunnel-transport", second, "-tunnel-transport", first,
					"-fteid-address", "instance=foo,addr=192.0.2.9",
					"-fteid-address", "instance=bar,addr=192.0.2.10"}
				fileValue = second + ";" + first
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			if _, err := applyLayers(fs); err != nil {
				t.Fatal(err)
			}
			if len(transports) != 2 || transports.String() != fileValue || addresses.String() != overrides {
				t.Fatalf("layers merged or lost mappings: transports %v, addresses %v", transports, addresses)
			}
			if _, err := parseTransports(transports); err != nil {
				t.Fatal(err)
			}
			if _, err := parseFTEIDAddresses(addresses); err != nil {
				t.Fatal(err)
			}
			wantN9 := "192.0.2.9"
			if source == "environment" {
				wantN9 = "192.0.2.19"
			}
			if got := fs.Lookup("n9-addr").Value.String(); got != wantN9 {
				t.Fatalf("N9 address %q, want %q", got, wantN9)
			}
			printed, err := effectiveConfig(fs)
			if err != nil {
				t.Fatal(err)
			}
			values, err := readConfig(writeConfig(t, string(printed)))
			if err != nil {
				t.Fatal(err)
			}
			var restored entryList
			if err := restored.Set(values["tunnel-transport"]); err != nil || restored.String() != transports.String() {
				t.Fatalf("print-config did not round-trip transports: %v, %v", restored, err)
			}
		})
	}
}
