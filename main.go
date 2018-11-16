package main

// A CNI IPAM plugin that takes /proc/cmdline and the environment variables and
// outputs the CNI configuration required for the external IP address for the
// pod in question.  IPAM plugins send and receive JSON on stdout and stdin,
// respectively, and are passed arguments and configuration information via
// environment variables and the aforementioned JSON.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/m-lab/go/rtx"
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

// IPaf represents the IP address family.
type IPaf string

const (
	v4 IPaf = "v4"
	v6 IPaf = "v6"
)

// ErrNoIPv6 is returned when we attempt to configure IPv6 on a system which has no v6 address.
var ErrNoIPv6 = errors.New("IPv6 is not supported or configured")

// MakeGenericIPConfig makes IPConfig and DNSConfig objects out of the epoxy command line.
func MakeGenericIPConfig(procCmdline string, version IPaf) (*IPConfig, *DNSConfig, error) {
	var destination string
	switch version {
	case v4:
		destination = "0.0.0.0/0"
	case v6:
		destination = "::/0"
	default:
		return nil, nil, errors.New("IP version can only be v4 or v6")
	}
	// Example substring: epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4
	ipargsRe := regexp.MustCompile("epoxy.ip" + string(version) + "=([^ ]*)")
	matches := ipargsRe.FindStringSubmatch(procCmdline)
	if len(matches) < 2 {
		if version == v6 {
			return nil, nil, ErrNoIPv6
		}
		return nil, nil, fmt.Errorf("Could not find epoxy.ip" + string(version) + " args")
	}
	// Example substring: 4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4
	config := strings.Split(matches[1], ",")
	if len(config) != 4 {
		return nil, nil, errors.New("Could not split up " + matches[1] + " into 4 parts")
	}

	IP := &IPConfig{
		IP:      config[0],
		Gateway: config[1],
		Routes: []RouteConfig{
			{Destination: destination},
		},
	}
	DNS := &DNSConfig{Nameservers: []string{config[2], config[3]}}
	return IP, DNS, nil
}

// MakeIPConfig makes the initial config from /proc/cmdline without incrementing up to the index.
func MakeIPConfig(procCmdline string) (*CniConfig, error) {
	// This value determines the output schema, and 0.2.0 is compatible with the schema defined in CniConfig.
	config := &CniConfig{CniVersion: "0.2.0"}

	ipv4, dnsv4, err := MakeGenericIPConfig(procCmdline, v4)
	if err != nil {
		// v4 config is required. Return an error if it is not present.
		return nil, err
	}
	config.IPv4 = ipv4
	config.DNS = dnsv4

	ipv6, dnsv6, err := MakeGenericIPConfig(procCmdline, v6)
	switch err {
	case nil:
		// v6 config is optional. Only set it up if the error is nil.
		config.IPv6 = ipv6
		for _, server := range dnsv6.Nameservers {
			config.DNS.Nameservers = append(config.DNS.Nameservers, server)
		}
	case ErrNoIPv6:
		// Do nothing, but also don't return an error
	default:
		return nil, err
	}
	return config, nil
}

// DiscoverIndex figures out what index this pod has. The method this uses to
// discover the index is deprecated. We should be using kubernetes annotations
// or putting the index in the network config. This uses bad name-munging hacks.
func DiscoverIndex() (int64, error) {
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
	// Add the index to the IPv4 address.
	var a, b, c, d, subnet int64
	_, err := fmt.Sscanf(config.IPv4.IP, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &subnet)
	if err != nil {
		return errors.New("Could not parse IPv4 address: " + config.IPv4.IP)
	}
	if d+index > 255 || index < 0 {
		return errors.New("Index out of range for address")
	}
	config.IPv4.IP = fmt.Sprintf("%d.%d.%d.%d/%d", a, b, c, d+index, subnet)
	// Add the index to the IPv6 address, if it exists.
	if config.IPv6 != nil {
		// Due to operator preference, and to aid operators in debugging, we make the
		// last v6 octect, when rendered in hexadecimal, be the same as the last v4
		// octet when it is rendered in decimal. This is arguably dumb, but it is
		// really handy for visually mathing up v4 and v6 services, and it continues
		// existing practice.
		v6Index, _ := strconv.ParseInt(strconv.FormatInt(index, 10), 16, 64) // Ignore the error - all base 10 number strings are valid base 16 number strings.
		addrSubnet := strings.Split(config.IPv6.IP, "/")
		if len(addrSubnet) != 2 {
			return fmt.Errorf("Could not parse IPv6 IP/subnet %v", config.IPv6.IP)
		}
		ipv6 := net.ParseIP(addrSubnet[0])
		if ipv6 == nil {
			return fmt.Errorf("Cloud not parse IPv6 address %v", addrSubnet[0])
		}
		ipv6 = ipv6.To16()
		var lastoctet int64
		lastoctet = int64(ipv6[15])
		if lastoctet+v6Index > 255 || v6Index < 0 {
			return errors.New("Index out of range for IPv6 address")
		}
		ipv6[15] = byte(lastoctet + v6Index)
		config.IPv6.IP = ipv6.String() + "/" + addrSubnet[1]
	}
	return nil
}

// MustReadProcCmdline reads /proc/cmdline or (if present) the environment
// variable PROC_CMDLINE (to aid in testing).  The PROC_CMDLINE environment
// variable should only be used for unit testing, and should not be used in
// production.  No guarantee of future compatibility is made or implied if you
// use PROC_CMDLINE for anything other than unit testing.  If the environment
// variable and the file /proc/cmdline are both unreadable, call log.Fatal and
// exit.
func MustReadProcCmdline() string {
	if text, isPresent := os.LookupEnv("PROC_CMDLINE"); isPresent {
		return text
	}
	procCmdline, err := ioutil.ReadFile("/proc/cmdline")
	rtx.Must(err, "Could not read /proc/cmdline")
	return string(procCmdline)
}

// ReadIndexFromJSON unmarshals JSON input to read the index argument contained therein.
func ReadIndexFromJSON(r io.Reader) (int64, error) {
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
	procCmdline := MustReadProcCmdline()
	config, err := MakeIPConfig(procCmdline)
	rtx.Must(err, "Could not populate the IP configuration")
	index, err := ReadIndexFromJSON(os.Stdin)
	if err != nil {
		// Fallback to deprecated method.
		index, err = DiscoverIndex()
		rtx.Must(err, "Could not discover the index")
	}
	rtx.Must(AddIndexToIP(config, index), "Could not manipulate the IP")
	encoder := json.NewEncoder(os.Stdout)
	rtx.Must(encoder.Encode(config), "Could not serialize the struct")
}
