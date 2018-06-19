A CNI plugin to choose the right external IP for a pod running on a machine in
the M-Lab fleet.  Meant to be called as an IPAM plugin for `ipvlan`, which
itself will be called as a delegate from `multus`.  Networking and Kubernetes is
plugins all the way down.
