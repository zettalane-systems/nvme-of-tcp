# nvme-of-tcp
Linux kernel module driver that provides TCP transport for NVMe over fabrics.
The initial version was made available by Solarflare Communications for v4.11 kernel and this repository is our port code to mainstream Centos 7.x releases
## Purpose
This host driver is required to connect to the MayaScale running NVMeoF over TCP. MayaScale Cloud Data Platform currently available for following marketplaces provides high-performance shared storage using the ephemeral NVMe resources.  To find more information on MayaScale
* https://www.zettalane.com/downloads.html
## BUILD
Currently this out of kernel tree driver can be built for 
* CentOS/RHEL 7.4 and 7.5
It has dependency on nvme-fabrics and common core modules and it has to be compiled against matching header files for nvme.h and fabrics.h. To build this driver
1. Install the kernel development RPM
2. To build the module
```shell
# make -C /usr/src/kernels/3.10.0-862.el7.x86_64 M=`pwd` modules
```

## Usage
```shell
# modprobe nvme-tcp
# /opt/zettalane/bin/nvme  discover -a 172.31.7.152 -s 4420 -t tcp

Discovery Log Number of Records 1, Generation counter 1
=====Discovery Log Entry 0======
trtype:  tcp
adrfam:  ipv4
subtype: nvme subsystem
treq:    not specified
portid:  0
trsvcid: 4420
subnqn:  nqn.2018-07.com.zettalane:ip-172-31-7-152.us-west-2.compute.internal.1fac9807
traddr:  
# /opt/zettalane/bin/nvme  connect  -a 172.31.7.152 -s 4420 -t tcp -n nqn.2018-07.com.zettalane:ip-172-31-7-152.us-west-2.compute.internal.1fac9807
# lsblk
NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
nvme0n1     259:0    0    8G  0 disk 
└─nvme0n1p1 259:1    0    8G  0 part /
nvme1n1     259:2    0  1.7T  0 disk
```
