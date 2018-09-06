# index2ip

[![GoDoc](https://godoc.org/github.com/m-lab/index2ip?status.svg)](https://godoc.org/github.com/m-lab/index2ip) [![Build Status](https://travis-ci.org/m-lab/index2ip.svg?branch=master)](https://travis-ci.org/m-lab/index2ip) [![Coverage Status](https://coveralls.io/repos/github/m-lab/index2ip/badge.svg?branch=master)](https://coveralls.io/github/m-lab/index2ip?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/index2ip)](https://goreportcard.com/report/github.com/m-lab/index2ip)


A CNI plugin to choose the right external IP for a pod running on a machine in
the M-Lab fleet.  Meant to be called as an IPAM plugin for `ipvlan`, which
itself will be called as a delegate from
[`multus`](https://github.com/intel/multus-cni).  Networking and Kubernetes is
plugins all the way down.

# Usage

The ip chosen for the pod will be an increment over the IP of the host. The 
exact amount to increment will either be extracted from the network 
configuration in k8s, or, if no k8s configuration is specified, from the name 
of the pod itself (usually derived from the name of the deployment).

## In the network config

In the network config, the increment should be specified as the `index` argument 
passed to the `index2ip` plugin.  In your network config, at some level of depth
that depends on your particular config, you should make a JSON snippet like:

```json
{
   "index": 12,
}
```

## In the name of the pod

If the pod name contains a string of the form `index[0-9]+` (for example `ndt-index12-111234-aa3b1`) then the 
