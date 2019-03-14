# nvme-of-tcp
Linux kernel module driver that provides TCP transport for NVMe over fabrics.
The initial version was made available by Solarflare Communications for v4.11 kernel.
## Purpose
This host driver is required to connect to the MayaScale running NVMeoF over TCP. MayaScale Cloud Data Platform currently available for following marketplaces provides high-performance shared storage using the ephemeral NVMe resources.  To find more information on MayaScale
* https://www.zettalane.com/downloads.html
## BUILD
Currently the driver can be built for 
* CentOS/RHEL 7.4 and 7.5
## Usage
