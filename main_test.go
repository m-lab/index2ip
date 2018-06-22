package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestMakeIPConfig(t *testing.T) {
	procCmdline := "rootflags=rw mount.usrflags=ro epoxy.ip=4.14.159.112::4.14.159.65:255.255.255.192:mlab4.lga0t.measurement-lab.org:eth0:off:8.8.8.8:8.8.4.4 epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4 epoxy.ipv6=2001:1900:2100:2d::112/64,2001:1900:2100:2d::1,2001:4860:4860::8888,2001:4860:4860::8844 epoxy.interface=eth0 epoxy.hostname=mlab4.lga0t.measurement-lab.org epoxy.stage3=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/4WT11StThCp5AUHOYU0RJmpDE7g/stage3 epoxy.report=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/fK8SBsveTTf7kv90RNkfM6FLfmo/report epoxy.allocate_k8s_token=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/wDBfLAQlFu37jEsHsCNT40UrIk8/extension/allocate_k8s_token epoxy.server=boot-api-dot-mlab-sandbox.appspot.com epoxy.project=mlab-sandbox net.ifnames=0 coreos.autologin=tty1"
	config, _ := MakeIPConfig(procCmdline)
	if config.CniVersion != "0.2.0" {
		t.Error("Wrong CNI version:", config.CniVersion)
	}
	if config.IPv4.IP != "4.14.159.112/26" {
		t.Error("Wrong V4 address:", config.IPv4.IP)
	}
	if config.IPv4.Gateway != "4.14.159.65" {
		t.Error("Wrong gateway:", config.IPv4.Gateway)
	}
	nameservers := map[string]bool{}
	for _, ns := range config.DNS.Nameservers {
		nameservers[ns] = true
	}
	_, has8 := nameservers["8.8.8.8"]
	_, has4 := nameservers["8.8.4.4"]
	if len(nameservers) != 2 || !has8 || !has4 {
		t.Error("Bad list of nameservers:", config.DNS.Nameservers)
	}
}

func TestMakeIPConfigFails(t *testing.T) {
	badProcCmdline := []string{
		"a bad value",
		"epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8",
	}
	for _, bad := range badProcCmdline {
		config, err := MakeIPConfig(bad)
		if config != nil || err == nil {
			t.Error("Failed to error out on bad input: ", bad)
		}
	}
}

func failToDiscoverIndex(t *testing.T) {
	index, err := DiscoverIndex()
	if err == nil || index > 0 {
		t.Errorf("Failed to fail for '%s': err(%s), index(%d)", os.Getenv("CNI_ARGS"), err, index)
	}
}

func TestDiscoverIndex(t *testing.T) {
	os.Setenv("CNI_ARGS", "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-index4;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b")
	index, err := DiscoverIndex()
	if err != nil || index != 4 {
		t.Error("Could not discover index")
	}

	os.Setenv("CNI_ARGS", "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-index4-gmwz8;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b")
	index, err = DiscoverIndex()
	if err != nil || index != 4 {
		t.Error("Could not discover index")
	}

	badArgs := []string{
		"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-index;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b",
		"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-ind4;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b",
		"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b",
		"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b",
	}
	for _, bad := range badArgs {
		os.Setenv("CNI_ARGS", bad)
		failToDiscoverIndex(t)
	}
	os.Unsetenv("CNI_ARGS")
	failToDiscoverIndex(t)
}

func TestAddIndexToIP(t *testing.T) {
	type AddIndexTestCase struct {
		ip     string
		index  int64
		answer string
	}
	goodInputPairs := []AddIndexTestCase{
		{"1.2.3.4/26", 1, "1.2.3.5/26"},
		{"1.2.3.4/26", 2, "1.2.3.6/26"},
		{"1.2.3.4/26", 3, "1.2.3.7/26"},
		{"1.2.3.4/26", 4, "1.2.3.8/26"},
		{"1.2.3.4/26", 5, "1.2.3.9/26"},
		{"1.2.3.4/26", 6, "1.2.3.10/26"},
		{"1.2.3.4/26", 7, "1.2.3.11/26"},
		{"1.2.3.4/26", 8, "1.2.3.12/26"},
	}
	for _, testCase := range goodInputPairs {
		config := &CniConfig{
			IPv4: &IPConfig{
				IP: testCase.ip,
			},
		}
		err := AddIndexToIP(config, testCase.index)
		if err != nil {
			t.Error("Could not AddIndexToIP:", err)
			continue
		}
		if config.IPv4.IP != testCase.answer {
			t.Errorf("%s + %d should be %s but was %s", testCase.ip, testCase.index, testCase.answer, config.IPv4.IP)
		}
	}
	badInputPairs := []AddIndexTestCase{
		{"1.c.3.4/26", 8, ""},
		{"1.2.3.4/26", 254, ""},
	}
	for _, testCase := range badInputPairs {
		config := &CniConfig{
			IPv4: &IPConfig{
				IP: testCase.ip,
			},
		}
		err := AddIndexToIP(config, testCase.index)
		if err == nil {
			t.Error("AddIndexToIp should have failed")
		}
	}
}

func TestReadProcCmdlineOrEnv(t *testing.T) {
	if _, isPresent := os.LookupEnv("PROC_CMDLINE"); isPresent {
		log.Println("Can't test ReadProcCmdline because PROC_CMDLINE is set")
		return
	}
	cmdlineBytes, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil {
		t.Error("Can't read /proc/cmdline for testing")
		return
	}
	cmdline := string(cmdlineBytes)
	output, err := ReadProcCmdline()
	if err != nil || output != cmdline {
		t.Errorf("Bad output from ReadProcCmdline err(%s) '%s' != '%s'", err, output, cmdline)
	}
	os.Setenv("PROC_CMDLINE", "testvalue")
	output, err = ReadProcCmdline()
	if err != nil || output != "testvalue" {
		t.Errorf("Bad output from ReadProcCmdline err(%s) '%s' != '%s'", err, output, "testvalue")
	}
	os.Unsetenv("PROC_CMDLINE")
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

func TestEndToEnd(t *testing.T) {
	// Set up the environment to look just like it should when the program gets called.
	if _, isPresent := os.LookupEnv("PROC_CMDLINE"); isPresent {
		log.Println("Can't test ReadProcCmdlineOrEnv because PROC_CMDLINE is set")
		return
	}
	if _, isPresent := os.LookupEnv("CNI_ARGS"); isPresent {
		log.Println("Can't test ReadProcCmdlineOrEnv because CNI_ARGS is set")
		return
	}
	// An actual /proc/cmdline taken from mlab4.lga0t
	os.Setenv("PROC_CMDLINE", "rootflags=rw mount.usrflags=ro epoxy.ip=4.14.159.112::4.14.159.65:255.255.255.192:mlab4.lga0t.measurement-lab.org:eth0:off:8.8.8.8:8.8.4.4 epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4 epoxy.ipv6=2001:1900:2100:2d::112/64,2001:1900:2100:2d::1,2001:4860:4860::8888,2001:4860:4860::8844 epoxy.interface=eth0 epoxy.hostname=mlab4.lga0t.measurement-lab.org epoxy.stage3=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/4WT11StThCp5AUHOYU0RJmpDE7g/stage3 epoxy.report=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/fK8SBsveTTf7kv90RNkfM6FLfmo/report epoxy.allocate_k8s_token=https://boot-api-dot-mlab-sandbox.appspot.com/v1/boot/mlab4.lga0t.measurement-lab.org/wDBfLAQlFu37jEsHsCNT40UrIk8/extension/allocate_k8s_token epoxy.server=boot-api-dot-mlab-sandbox.appspot.com epoxy.project=mlab-sandbox net.ifnames=0 coreos.autologin=tty1")
	// Actual CNI_ARGS taken from a call to this plugin on that same server.
	os.Setenv("CNI_ARGS", "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-index4;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b")
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	go func() {
		main()
		w.Close()
	}()
	output, _ := ioutil.ReadAll(r)
	os.Stdout = oldStdout
	os.Unsetenv("CNI_ARGS")
	os.Unsetenv("PROC_CMDLINE")

	config := CniConfig{}
	json.Unmarshal(output, &config)
	if config.CniVersion != "0.2.0" || config.IPv4.IP != "4.14.159.116/26" || config.IPv4.Gateway != "4.14.159.65" {
		t.Error("Bad data output from index2ip: ", string(output))
	}
}
