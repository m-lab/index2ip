package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/rtx"
)

func TestMakeIPConfig(t *testing.T) {
	procCmdline := "rootflags=rw mount.usrflags=ro epoxy.ip=4.14.159.112::4.14.159.65:255.255.255.192:mlab4.lga0t.measurement-lab.org:eth0:off:8.8.8.8:8.8.4.4 epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4 epoxy.ipv6=2001:1900:2100:2d::112/64,2001:1900:2100:2d::1,2001:4860:4860::8888,2001:4860:4860::8844 epoxy.interface=eth0 epoxy.hostname=mlab4.lga0t.measurement-lab.org epoxy.stage3=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/4WT11StThCp5AUHOYU0RJmpDE7g/stage3 epoxy.report=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/fK8SBsveTTf7kv90RNkfM6FLfmo/report epoxy.allocate_k8s_token=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/wDBfLAQlFu37jEsHsCNT40UrIk8/extension/allocate_k8s_token epoxy.server=boot-api-dot-mlab-sandbox.appspot.com epoxy.project=mlab-sandbox net.ifnames=0 coreos.autologin=tty1"
	config, _ := MakeIPConfig(procCmdline)
	if config.CniVersion != "0.3.1" {
		t.Error("Wrong CNI version:", config.CniVersion)
	}
	if config.IPs[0].Address != "4.14.159.112/26" {
		t.Error("Wrong V4 address:", config.IPs[0].Address)
	}
	if config.IPs[0].Gateway != "4.14.159.65" {
		t.Error("Wrong gateway:", config.IPs[0].Gateway)
	}
	nameservers := map[string]bool{}
	for _, ns := range config.DNS.Nameservers {
		nameservers[ns] = true
	}
	_, has8 := nameservers["8.8.8.8"]
	_, has4 := nameservers["8.8.4.4"]
	_, hasv6a := nameservers["2001:4860:4860::8888"]
	_, hasv6b := nameservers["2001:4860:4860::8844"]
	if len(nameservers) != 4 || !has8 || !has4 || !hasv6a || !hasv6b {
		t.Error("Bad list of nameservers:", config.DNS.Nameservers)
	}
}

func TestMakeIPConfigV4Only(t *testing.T) {
	procCmdline := "rootflags=rw mount.usrflags=ro epoxy.ip=4.14.159.112::4.14.159.65:255.255.255.192:mlab4.lga0t.measurement-lab.org:eth0:off:8.8.8.8:8.8.4.4 epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4 epoxy.ip6= epoxy.interface=eth0 epoxy.hostname=mlab4.lga0t.measurement-lab.org epoxy.stage3=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/4WT11StThCp5AUHOYU0RJmpDE7g/stage3 epoxy.report=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/fK8SBsveTTf7kv90RNkfM6FLfmo/report epoxy.allocate_k8s_token=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/wDBfLAQlFu37jEsHsCNT40UrIk8/extension/allocate_k8s_token epoxy.server=boot-api-dot-mlab-sandbox.appspot.com epoxy.project=mlab-sandbox net.ifnames=0 coreos.autologin=tty1"
	config, err := MakeIPConfig(procCmdline)
	if err != nil || len(config.IPs) != 1 {
		t.Error("No ipv6 info should mean no ipv6 config")
	}
}

func TestMakeGenericIPConfig(t *testing.T) {
	_, _, _, err := MakeGenericIPConfig("", "v5")
	if err == nil {
		t.Error("IPv5 should be an error")
	}
}

func TestMakeIPConfigFails(t *testing.T) {
	badProcCmdline := []string{
		"a bad value",
		"epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8",
		"epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4 epoxy.ipv6=2001:1900:2100:2d::112/64,2001:1900:2100:2d::1,2001:4860:4860::8888",
	}
	for _, bad := range badProcCmdline {
		config, err := MakeIPConfig(bad)
		if config != nil || err == nil {
			t.Error("Failed to error out on bad input: ", bad)
		}
	}
}

func TestAddIndexToIP(t *testing.T) {
	type AddIndexTestCase struct {
		ip4     string
		ip6     string
		index   int64
		answer4 string
		answer6 string
	}
	goodInputPairs := []AddIndexTestCase{
		// Some random IPs to test every index in the expected range [1,12].
		{"1.2.3.4/26", "", 1, "1.2.3.5/26", ""},
		{"1.2.3.4/26", "", 2, "1.2.3.6/26", ""},
		{"1.2.3.4/26", "", 3, "1.2.3.7/26", ""},
		{"1.2.3.4/26", "", 4, "1.2.3.8/26", ""},
		{"1.2.3.4/26", "", 5, "1.2.3.9/26", ""},
		{"1.2.3.4/26", "1:2::/64", 6, "1.2.3.10/26", "1:2::6/64"},
		{"1.2.3.4/26", "", 7, "1.2.3.11/26", ""},
		{"1.2.3.4/26", "", 8, "1.2.3.12/26", ""},
		{"1.2.3.4/26", "", 9, "1.2.3.13/26", ""},
		{"1.2.3.4/26", "1:2::/64", 10, "1.2.3.14/26", "1:2::10/64"},
		{"1.2.3.4/26", "1::10/64", 11, "1.2.3.15/26", "1::21/64"},
		{"1.2.3.4/26", "", 12, "1.2.3.16/26", ""},
		// MLab1s are ::9, ::73, ::137, ::201. MLab4s are ::48, ::112, ::176, ::240.
		// We add at least one test case for every MLab1 or 4, and we use the higher
		// indices to catch base-conversion edge cases.
		{"1.2.3.9/26", "::9/64", 12, "1.2.3.21/26", "::21/64"},
		{"1.2.3.73/26", "::73/64", 11, "1.2.3.84/26", "::84/64"},
		{"1.2.3.137/26", "::137/64", 10, "1.2.3.147/26", "::147/64"},
		{"1.2.3.201/26", "::201/64", 9, "1.2.3.210/26", "::210/64"},
		{"1.2.3.48/26", "::48/64", 8, "1.2.3.56/26", "::56/64"},
		{"1.2.3.112/26", "::112/64", 7, "1.2.3.119/26", "::119/64"},
		{"1.2.3.176/26", "::176/64", 6, "1.2.3.182/26", "::182/64"},
		{"1.2.3.240/26", "::240/64", 5, "1.2.3.245/26", "::245/64"},
	}
	for _, testCase := range goodInputPairs {
		config := &CniConfig{
			IPs: []*IPConfig{
				{
					Version: v4,
					Address: testCase.ip4,
				},
			},
		}
		if testCase.ip6 != "" {
			config.IPs = append(config.IPs, &IPConfig{
				Version: v6,
				Address: testCase.ip6,
			})
		}
		err := AddIndexToIPs(config, testCase.index)
		if err != nil {
			t.Error("Could not AddIndexToIP:", err)
			continue
		}
		if len(config.IPs) == 0 {
			t.Errorf("No IP address produced when making %v", config)
			continue
		}
		if config.IPs[0].Address != testCase.answer4 {
			t.Errorf("%s + %d should be %s but was %s", testCase.ip4, testCase.index, testCase.answer4, config.IPs[0].Address)
		}
		if len(config.IPs) == 2 && config.IPs[1].Address != testCase.answer6 {
			t.Errorf("%s + %d should be %s but was %s", testCase.ip6, testCase.index, testCase.answer6, config.IPs[1].Address)
		}
	}
	badInputPairs := []AddIndexTestCase{
		{"1.c.3.4/26", "", 8, "", ""},
		{"1.2.3.4/26", "", 254, "", ""},
		{"1.2.3.4/26", "1:Z::/64", 6, "", ""},
		{"1.2.3.4/26", "1:2::", 6, "", ""},
		{"1.2.3.4/26", "1:2::FE/64", 6, "", ""},
	}
	for _, testCase := range badInputPairs {
		config := &CniConfig{
			IPs: []*IPConfig{
				{
					Version: v4,
					Address: testCase.ip4,
				},
			},
		}
		if testCase.ip6 != "" {
			config.IPs = append(config.IPs, &IPConfig{
				Version: v6,
				Address: testCase.ip6,
			})
		}
		err := AddIndexToIPs(config, testCase.index)
		if err == nil {
			t.Errorf("AddIndexToIp should have failed on %v", testCase)
		}
	}
	err := AddIndexToIP(&IPConfig{Version: "v5"}, 5)
	if err == nil {
		t.Error("AddIndexToIp should have failed on IPv5")
	}
}

func TestMustReadProcCmdlineOrEnv(t *testing.T) {
	if _, isPresent := os.LookupEnv("PROC_CMDLINE_FOR_TESTING"); isPresent {
		log.Println("Can't test MustReadProcCmdline because PROC_CMDLINE_FOR_TESTING is set")
		return
	}
	cmdlineBytes, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil {
		t.Error("Can't read /proc/cmdline for testing")
		return
	}
	cmdline := string(cmdlineBytes)
	output := MustReadProcCmdline()
	if output != cmdline {
		t.Errorf("Bad output from MustReadProcCmdline err(%s) '%s' != '%s'", err, output, cmdline)
	}
	revert := osx.MustSetenv("PROC_CMDLINE_FOR_TESTING", "testvalue")
	defer revert()
	output = MustReadProcCmdline()
	if output != "testvalue" {
		t.Errorf("Bad output from MustReadProcCmdline err(%s) '%s' != '%s'", err, output, "testvalue")
	}
}

func TestConfigStructure(t *testing.T) {
	jsonString := `{
  "cniVersion": "0.2.0",
  "ip4": {
      "ip": "1.2.3.4/26",
      "gateway": "1.2.3.65",
      "routes": [ { "dst": "0.0.0.0/0" } ]
  },
  "dns": {
      "nameservers": [
          "8.8.8.8",
          "8.8.4.4"
      ]
  }
}`
	config := CniConfig{}
	err := json.Unmarshal([]byte(jsonString), &config)
	if err != nil {
		t.Error(err)
	}
}

func TestReadIndexFromJSON(t *testing.T) {
	// Input taken from real input.
	input := `{"ipam":{"index":4,"type":"index2ip"},"master":"eth0","name":"ipvlan","type":"ipvlan"}`
	index, err := ReadIndexFromJSON(strings.NewReader(input))
	if err != nil {
		t.Error("ReadIndexFromJSON error:", err)
	}
	if index != 4 {
		t.Error("Index should be 4, but was", index)
	}

	// Now try with bad input
	badInput := []string{
		`{"ipam":{"index":"monkey"}}`,
		`{"ipam":{"type":"index2ip"},"master":"eth0","name":"ipvlan","type":"ipvlan"}`,
		`{"spam":{"index":4,"type":"index2ip"},"master":"eth0","name":"ipvlan","type":"ipvlan"}`,
		`{}`,
		``,
		`{{}`,
		`}`,
	}
	for _, bad := range badInput {
		index, err = ReadIndexFromJSON(strings.NewReader(bad))
		if err == nil || index >= 0 {
			t.Errorf("Should have encountered an error on input: '%s'", bad)
		}
	}
}

func AddEndToEnd(t *testing.T, addcmd string) {
	// Set up the environment to look just like it should when the program gets called.
	if _, isPresent := os.LookupEnv("PROC_CMDLINE_FOR_TESTING"); isPresent {
		log.Println("Can't test ReadProcCmdlineOrEnv because PROC_CMDLINE_FOR_TESTING is set")
		return
	}
	if _, isPresent := os.LookupEnv("CNI_ARGS"); isPresent {
		log.Println("Can't test ReadProcCmdlineOrEnv because CNI_ARGS is set")
		return
	}
	// An actual /proc/cmdline taken from mlab4.lga0t
	revertCmd := osx.MustSetenv("PROC_CMDLINE_FOR_TESTING", "rootflags=rw mount.usrflags=ro epoxy.ip=4.14.159.112::4.14.159.65:255.255.255.192:mlab4.lga0t.measurement-lab.org:eth0:off:8.8.8.8:8.8.4.4 epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4 epoxy.ipv6=2001:1900:2100:2d::112/64,2001:1900:2100:2d::1,2001:4860:4860::8888,2001:4860:4860::8844 epoxy.interface=eth0 epoxy.hostname=mlab4.lga0t.measurement-lab.org epoxy.stage3=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/4WT11StThCp5AUHOYU0RJmpDE7g/stage3 epoxy.report=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/fK8SBsveTTf7kv90RNkfM6FLfmo/report epoxy.allocate_k8s_token=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/wDBfLAQlFu37jEsHsCNT40UrIk8/extension/allocate_k8s_token epoxy.server=boot-api-dot-mlab-sandbox.appspot.com epoxy.project=mlab-sandbox net.ifnames=0 coreos.autologin=tty1")
	defer revertCmd()
	// Actual CNI_ARGS taken from a call to this plugin on that same server.
	revertCni := osx.MustSetenv("CNI_ARGS", "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-index4;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b")
	defer revertCni()

	// The IP address in this test should come from the parsed index on stdin.
	output := WithInputTestEndToEnd(t, addcmd, `{"ipam":{"index":5,"type":"index2ip"},"master":"eth0","name":"ipvlan","type":"ipvlan"}`)
	config := CniConfig{}
	rtx.Must(json.Unmarshal(output, &config), "Could not unmarshal")
	if config.CniVersion != "0.3.1" || config.IPs[0].Gateway != "4.14.159.65" {
		t.Error("Bad data output from index2ip: ", string(output))
	}
	if "4.14.159.117/26" != config.IPs[0].Address {
		t.Error("Wrong IP returned when index 5 was provided")
	}
}

func TestAddEndToEnd(t *testing.T) {
	AddEndToEnd(t, "add")
	AddEndToEnd(t, "ADD")
	AddEndToEnd(t, "unkndsjkladjoiwdqunknwn")
	AddEndToEnd(t, "")
}

func WithInputTestEndToEnd(t *testing.T, op, input string) []byte {
	defer osx.MustSetenv("CNI_COMMAND", op)()
	oldStdout := os.Stdout
	stdoutR, stdoutW, _ := os.Pipe()
	os.Stdout = stdoutW

	oldStdin := os.Stdin
	stdinR, stdinW, _ := os.Pipe()
	os.Stdin = stdinR

	go func() {
		os.Args = []string{"./index2ip", op}
		main()
		stdoutW.Close()
	}()
	fmt.Fprint(stdinW, input)
	stdinW.Close()
	output, err := ioutil.ReadAll(stdoutR)
	rtx.Must(err, "Could not read any output")
	os.Stdout = oldStdout
	os.Stdin = oldStdin

	return output
}

func int16ToTwoBytes(i int16) []byte {
	return []byte{byte(i / 256), byte(i % 256)}
}

func TestBase10AdditionInBase16(t *testing.T) {
	tests := []struct {
		octets  []byte
		index   int64
		want    []byte
		wantErr bool
	}{
		{
			octets: []byte{0, 9},
			index:  2,
			want:   int16ToTwoBytes(0x11),
		},
		{
			octets: []byte{0, 9},
			index:  12,
			want:   int16ToTwoBytes(0x21),
		},
		{
			octets:  []byte{0, 9, 10},
			index:   12,
			wantErr: true,
		},
		{
			octets:  []byte{0, 9},
			index:   65536,
			wantErr: true,
		},
		{
			octets: int16ToTwoBytes(0x201),
			index:  12,
			want:   int16ToTwoBytes(0x213),
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint("TestBase10AddtionInBase16", tt.octets, tt.index), func(t *testing.T) {
			got, err := Base10AdditionInBase16(tt.octets, tt.index)
			if (err == nil) == tt.wantErr {
				t.Errorf("Base10AdditionInBase16(%v, %d) error = %v, wantErr %v", tt.octets, tt.index, err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Base10AdditionInBase16(%v, %d) = %v, want %v", tt.octets, tt.index, got, tt.want)
			}
		})
	}
}

func TestOtherArgsDontCrash(t *testing.T) {
	WithInputTestEndToEnd(t, "DEL", ``)
	WithInputTestEndToEnd(t, "CHECK", ``)
	// No crash == success!
}

type ver struct {
	CniVersion        string   `json:"cniVersion"`
	SupportedVersions []string `json:"supportedVersions"`
}

func TestVersion(t *testing.T) {
	output := WithInputTestEndToEnd(t, "VERSION", ``)
	v := &ver{}
	rtx.Must(json.Unmarshal(output, v), "Could not unmarshal the version")
	// Should correspond to the cniVersion constant.
	if v.CniVersion != "0.3.1" {
		t.Errorf("%q != \"0.3.1\"", v.CniVersion)
	}
}
