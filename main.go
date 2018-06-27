package main

// A CNI IPAM plugin that takes /proc/cmdline and the environment variables and
// outputs the CNI configuration required for the external IP address for the
// pod in question.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Configuration objects to hold the CNI config that must be marshalled into Stdout

// IPConfig holds the IP configuration. The elements are strings to support v4 or v6.
type IPConfig struct {
	IP      string        `json:"ip"`
	Gateway string        `json:"gateway"`
	Routes  []RouteConfig `json:"routes"`
}

// RouteConfig holds the subnets for which an interface should receive packets.
type RouteConfig struct {
	Destination string `json:"dst"`
}

// DNSConfig holds a list of IP addresses for nameservers.
type DNSConfig struct {
	Nameservers []string `json:"nameservers"`
}

// CniConfig holds a complete CNI configuration, including the protocol version.
type CniConfig struct {
	CniVersion string     `json:"cniVersion"`
	IPv4       *IPConfig  `json:"ip4,omitempty"`
	IPv6       *IPConfig  `json:"ip6,omitempty"`
	DNS        *DNSConfig `json:"dns,omitempty"`
}

// MakeIPConfig makes the initial config from /proc/cmdline without incrementing up to the index.
func MakeIPConfig(procCmdline string) (*CniConfig, error) {
	// This value determines the output schema, and 0.2.0 is compatible with the schema defined in CniConfig.
	config := &CniConfig{CniVersion: "0.2.0"}

	// Example substring: epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4
	ipv4argsRe := regexp.MustCompile("epoxy.ipv4=([^ ]*)")
	matches := ipv4argsRe.FindStringSubmatch(procCmdline)
	if len(matches) < 2 {
		return nil, errors.New("Could not find epoxy.ipv4 args")
	}
	// Example substring: 4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4
	v4Config := strings.Split(matches[1], ",")
	if len(v4Config) != 4 {
		return nil, errors.New("Could not split up " + matches[1] + " into 4 parts")
	}

	config.IPv4 = &IPConfig{
		IP:      v4Config[0],
		Gateway: v4Config[1],
		Routes: []RouteConfig{
			RouteConfig{Destination: "0.0.0.0/0"},
		},
	}
	config.DNS = &DNSConfig{Nameservers: []string{v4Config[2], v4Config[3]}}

	// TODO: Populate the config.Ip6 entry if possible.
	return config, nil
}

// DiscoverIndex figures out what index this pod has.
func DiscoverIndex() (int64, error) {
	// The method this uses to discover the index comes pre-deprecated. We
	// should be using kubernetes annotations. Instead we are using bad
	// name-munging hacks.
	// TODO: Fix this to use k8s annotations.

	// Example CNI_ARGS: "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=poc-index4;K8S_POD_INFRA_CONTAINER_ID=adb9757c7392f7293ecc1147ee2706a70e304de2515f4f3327f37d31124df10b"
	podNameRe := regexp.MustCompile(`\bK8S_POD_NAME=([^;]*)`)
	podNameMatches := podNameRe.FindStringSubmatch(os.Getenv("CNI_ARGS"))
	if len(podNameMatches) != 2 {
		return -1, errors.New("Could not find pod name in " + os.Getenv("CNI_ARGS"))
	}
	podName := podNameMatches[1]
	indexRe := regexp.MustCompile("index([0-9]+)")
	indexMatches := indexRe.FindStringSubmatch(podName)
	if len(indexMatches) != 2 {
		return -1, errors.New("Could not find index in " + podName)
	}
	return strconv.ParseInt(indexMatches[1], 10, 64)
}

// AddIndexToIP updates the config in light of the discovered index.
func AddIndexToIP(config *CniConfig, index int64) error {
	// TODO: Add v6 support
	var a, b, c, d, subnet int64
	_, err := fmt.Sscanf(config.IPv4.IP, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &subnet)
	if err != nil {
		return errors.New("Could not parse IPv4 address: " + config.IPv4.IP)
	}
	if d+index > 255 || index < 0 {
		return errors.New("Index out of range for address")
	}
	config.IPv4.IP = fmt.Sprintf("%d.%d.%d.%d/%d", a, b, c, d+index, subnet)
	return nil
}

// ReadProcCmdline reads /proc/cmdline or (if present) the environment variable
// PROC_CMDLINE (to aid in testing).  The PROC_CMDLINE environment variable
// should only be used for unit testing, and should not be used in production.
// No guarantee of future compatibility is made or implied if you use
// PROC_CMDLINE for anything other than unit testing.
func ReadProcCmdline() (string, error) {
	if text, isPresent := os.LookupEnv("PROC_CMDLINE"); isPresent {
		return text, nil
	}
	procCmdline, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return string(procCmdline), nil
}

// ReadIndex unmarshals JSON input to read the index argument contained therein.
func ReadIndex(r io.Reader) (int64, error) {
	type JSONInput struct {
		Ipam struct {
			Index int64 `json:"index"`
		} `json:"ipam"`
	}
	dec := json.NewDecoder(r)
	config := JSONInput{}
	err := dec.Decode(&config)
	if err != nil {
		return -1, err
	}
	if config.Ipam.Index == 0 {
		return -1, errors.New("the index was either 0 or not found")
	}
	return config.Ipam.Index, nil
}

// Put it all together.
func main() {
	procCmdline, err := ReadProcCmdline()
	if err != nil {
		log.Fatal("Could not read /proc/cmdline: ", err)
	}
	config, err := MakeIPConfig(procCmdline)
	if err != nil {
		log.Fatal("Could not populate the IP configuration: ", err)
	}
	index, err := ReadIndex(os.Stdin)
	if err != nil {
		// Fallback to deprecated method.
		index, err = DiscoverIndex()
		if err != nil {
			log.Fatal("Could not discover the index :", err)
		}
	}
	err = AddIndexToIP(config, index)
	if err != nil {
		log.Fatal("Could not manipulate the IP: ", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	err = encoder.Encode(config)
	if err != nil {
		log.Fatal("Could not serialize the struct: ", err)
	}
}
