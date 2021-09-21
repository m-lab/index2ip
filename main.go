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
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	cni "github.com/containernetworking/cni/pkg/types/040"
	"github.com/m-lab/go/rtx"
)

// This value determines the output schema, and 0.3.1 is compatible with the
// schema defined in CniConfig.
const cniVersion = "0.3.1"

// Configuration objects to hold the CNI config that must be marshalled into Stdout

// IPConfig holds the IP configuration. The elements are strings to support v4 or v6.
type IPConfig struct {
	Version IPaf   `json:"version"`
	Address string `json:"address"`
	Gateway string `json:"gateway"`
}

// RouteConfig holds the subnets for which an interface should receive packets.
type RouteConfig struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gw"`
}

// DNSConfig holds a list of IP addresses for nameservers.
type DNSConfig struct {
	Nameservers []string `json:"nameservers"`
}

// CniResult holds a complete CNI result, including the protocol version.
type CniResult struct {
	CniVersion string         `json:"cniVersion"`
	IPs        []*IPConfig    `json:"ips,omitempty"`
	Routes     []*RouteConfig `json:"routes,omitempty"`
	DNS        *DNSConfig     `json:"dns,omitempty"`
}

type JSONInput struct {
	CNIVersion string `json:"cniVersion"`
	Ipam       struct {
		Index int64 `json:"index"`
	} `json:"ipam"`
}

// IPaf represents the IP address family.
type IPaf string

const (
	v4 IPaf = "4"
	v6 IPaf = "6"
)

var (
	CNIConfig JSONInput

	// ErrNoIPv6 is returned when we attempt to configure IPv6 on a system which has no v6 address.
	ErrNoIPv6 = errors.New("IPv6 is not supported or configured")
)

// MakeGenericIPConfig makes IPConfig and DNSConfig objects out of the epoxy command line.
func MakeGenericIPConfig(procCmdline string, version IPaf) (*IPConfig, *RouteConfig, *DNSConfig, error) {
	var destination string
	switch version {
	case v4:
		destination = "0.0.0.0/0"
	case v6:
		destination = "::/0"
	default:
		return nil, nil, nil, errors.New("IP version can only be v4 or v6")
	}
	// Example substring: epoxy.ipv4=4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4
	ipargsRe := regexp.MustCompile("epoxy.ipv" + string(version) + "=([^ ]+)")
	matches := ipargsRe.FindStringSubmatch(procCmdline)
	if len(matches) < 2 {
		if version == v6 {
			return nil, nil, nil, ErrNoIPv6
		}
		return nil, nil, nil, fmt.Errorf("Could not find epoxy.ip" + string(version) + " args")
	}
	// Example substring: 4.14.159.112/26,4.14.159.65,8.8.8.8,8.8.4.4
	config := strings.Split(matches[1], ",")
	if len(config) != 4 {
		return nil, nil, nil, errors.New("Could not split up " + matches[1] + " into 4 parts")
	}

	Route := &RouteConfig{
		Destination: destination,
		Gateway:     config[1],
	}

	IP := &IPConfig{
		Version: version,
		Address: config[0],
		Gateway: config[1],
	}
	DNS := &DNSConfig{Nameservers: []string{config[2], config[3]}}
	return IP, Route, DNS, nil
}

// MakeIPConfig makes the initial config from /proc/cmdline without incrementing up to the index.
func MakeIPConfig(procCmdline string) (*CniResult, error) {
	config := &CniResult{CniVersion: cniVersion}

	ipv4, route4, dnsv4, err := MakeGenericIPConfig(procCmdline, v4)
	if err != nil {
		// v4 config is required. Return an error if it is not present.
		return nil, err
	}
	config.IPs = append(config.IPs, ipv4)
	config.Routes = append(config.Routes, route4)
	config.DNS = dnsv4

	ipv6, route6, dnsv6, err := MakeGenericIPConfig(procCmdline, v6)
	switch err {
	case nil:
		// v6 config is optional. Only set it up if the error is nil.
		config.IPs = append(config.IPs, ipv6)
		config.Routes = append(config.Routes, route6)
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

// Base10AdditionInBase16 implements a subtle addition operation that aids
// M-Lab operations staff in visually aligning IPv6 and IPv4 data.
//
// In an effort to keep with an established M-Lab deployment pattern, we
// ensure that the IPv4 last octet (printed in base 10) and the IPv6 last
// grouping (printed in base 16) match up visually.
//
// Some examples:
//   IPv4 address 1.0.0.9 + index 12 -> 1.0.0.21
//   IPv6 address 1f::9 + index 12 -> 1f::21
//   IPv4 address 1.0.0.201 + index 12 -> 1.0.0.213
//   IPv6 address 1f::201 + index 12 -> 1f::213
//
// Note that in the first example, the IPv6 address, when printed in decimal,
// is actually 33 (0x21). M-Lab already assigns IPv6 subnets in matching
// base-10 configurations, so this should work for our use case.
//
// The second example is a nice illustration of why this process has to involve
// the last two bytes of the IPv6 address, because 0x213 > 0xFF. It is for this
// reason that the function returns two bytes.
func Base10AdditionInBase16(octets []byte, index int64) ([]byte, error) {
	if len(octets) != 2 {
		return []byte{0, 0}, fmt.Errorf("Passed-in slice %v was not of length 2", octets)
	}

	base16Number := 256*int64(octets[0]) + int64(octets[1])
	base16String := strconv.FormatInt(base16Number, 16)
	base10Number, err := strconv.ParseInt(base16String, 10, 64)
	if err != nil {
		return []byte{0, 0}, err
	}
	base10Number += index
	base10String := strconv.FormatInt(base10Number, 10)

	// All base 10 strings are valid base 16 numbers, so parse errors are
	// impossible here in one sense, but it is also true that the number could (in
	// the case of some edge-case strange inputs) be outside of the range of int16.
	base16Result, err := strconv.ParseInt(base10String, 16, 16)
	if err != nil {
		return []byte{0, 0}, err
	}
	return []byte{byte(base16Result / 256), byte(base16Result % 256)}, nil
}

// AddIndexToIP updates a single IP in light of the discovered index.
func AddIndexToIP(config *IPConfig, index int64) error {
	switch config.Version {
	case v4:
		// Add the index to the IPv4 address.
		var a, b, c, d, subnet int64
		_, err := fmt.Sscanf(config.Address, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &subnet)
		if err != nil {
			return errors.New("Could not parse IPv4 address: " + config.Address)
		}
		if d+index > 255 || index < 0 {
			return errors.New("Index out of range for address")
		}
		config.Address = fmt.Sprintf("%d.%d.%d.%d/%d", a, b, c, d+index, subnet)
	case v6:
		// Add the index to the IPv6 address.
		addrSubnet := strings.Split(config.Address, "/")
		if len(addrSubnet) != 2 {
			return fmt.Errorf("Could not parse IPv6 IP/subnet %v", config.Address)
		}
		ipv6 := net.ParseIP(addrSubnet[0])
		if ipv6 == nil {
			return fmt.Errorf("Cloud not parse IPv6 address %v", addrSubnet[0])
		}
		// Ensure that the byte array is 16 bytes. According to the "net" API docs,
		// the byte array length and the IP address family are purposely decoupled. To
		// ensure a 16 byte array as the underlying storage (which is what we need) we
		// call To16() which has the job of ensuring 16 bytes of storage backing.
		ipv6 = ipv6.To16()

		lastoctets, err := Base10AdditionInBase16(ipv6[14:16], index)
		if err != nil {
			return err
		}
		ipv6[14] = lastoctets[0]
		ipv6[15] = lastoctets[1]

		config.Address = ipv6.String() + "/" + addrSubnet[1]
	default:
		return errors.New("Unknown IP version")
	}
	return nil
}

// AddIndexToIPs updates the config in light of the discovered index.
func AddIndexToIPs(config *CniResult, index int64) error {
	for _, ip := range config.IPs {
		if err := AddIndexToIP(ip, index); err != nil {
			return err
		}
	}
	return nil
}

// MustReadProcCmdline reads /proc/cmdline or (if present) the environment
// variable PROC_CMDLINE_FOR_TESTING. The PROC_CMDLINE_FOR_TESTING environment
// variable should only be used for unit testing, and should not be used in
// production. No guarantee of future compatibility is made or implied if you
// use PROC_CMDLINE_FOR_TESTING for anything other than unit testing. If the
// environment variable and the file /proc/cmdline are both unreadable, call
// log.Fatal and exit.
func MustReadProcCmdline() string {
	if text, isPresent := os.LookupEnv("PROC_CMDLINE_FOR_TESTING"); isPresent {
		return text
	}
	procCmdline, err := ioutil.ReadFile("/proc/cmdline")
	rtx.Must(err, "Could not read /proc/cmdline")
	return string(procCmdline)
}

// ReadJSONInput unmarshals JSON input from stdin into a global variable.
func ReadJSONInput(r io.Reader) error {
	dec := json.NewDecoder(r)
	err := dec.Decode(&CNIConfig)
	return err
}

// Cmd represents the possible CNI operations for an IPAM plugin.
type Cmd int

// The CNI operations we know about.
const (
	AddCmd = iota
	DelCmd
	VersionCmd
	CheckCmd
	UnknownCmd
)

// ParseCmd returns the corresponding Cmd for a string.
func ParseCmd(cmd string) Cmd {
	cmd = strings.ToLower(cmd)
	switch cmd {
	case "add":
		return AddCmd
	case "del":
		return DelCmd
	case "version":
		return VersionCmd
	case "check":
		return CheckCmd
	}
	return UnknownCmd
}

// Add responds to the ADD command.
func Add() error {
	err := ReadJSONInput(os.Stdin)
	rtx.Must(err, "Could not unmarshall JSON from stdin")
	procCmdline := MustReadProcCmdline()
	config, err := MakeIPConfig(procCmdline)
	rtx.Must(err, "Could not populate the IP configuration")
	rtx.Must(AddIndexToIPs(config, CNIConfig.Ipam.Index), "Could not manipulate the IP")
	data, err := json.Marshal(config)
	result, err := cni.NewResult(data)
	return types.PrintResult(result, CNIConfig.CNIVersion)
}

// Version responds to the VERSION command.
func Version() {
	fmt.Fprintf(os.Stdout, `{
  "cniVersion": 0.3.1,
  "supportedVersions": [ "0.2.0", "0.3.0", "0.3.1", "0.4.0" ]
}`)
}

// Put it all together.
func main() {
	cmd := os.Getenv("CNI_COMMAND")
	switch ParseCmd(cmd) {
	case AddCmd:
		Add()
	case VersionCmd:
		Version()
	case DelCmd, CheckCmd:
		// For DEL and CHECK we affirmatively and successfully do nothing.
	default:
		// To preserve old behavior: when in doubt, Add()
		log.Printf("Unknown CNI_COMMAND value %q. Treating it like ADD.\n", cmd)
		Add()
	}
}
