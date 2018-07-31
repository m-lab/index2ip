# index2ip

[![GoDoc](https://godoc.org/github.com/m-lab/index2ip?status.svg)](https://godoc.org/github.com/m-lab/index2ip) [![Build Status](https://travis-ci.org/m-lab/index2ip.svg?branch=master)](https://travis-ci.org/m-lab/index2ip) [![Coverage Status](https://coveralls.io/repos/github/m-lab/index2ip/badge.svg?branch=master)](https://coveralls.io/github/m-lab/index2ip?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/index2ip)](https://goreportcard.com/report/github.com/m-lab/index2ip)


A CNI plugin to choose the right external IP for a pod running on a machine in
the M-Lab fleet.  Meant to be called as an IPAM plugin for `ipvlan`, which
itself will be called as a delegate from `multus`.  Networking and Kubernetes is
plugins all the way down.
