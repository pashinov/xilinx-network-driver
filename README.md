Xilinx linux network driver sample
----------------------------------

[![Build Status][travis-badge]][travis-link]

[travis-badge]:    https://travis-ci.org/pashinov/xilinx-network-driver.svg?branch=master
[travis-link]:     https://travis-ci.org/pashinov/xilinx-network-driver

Template for Xilinx linux network driver

To build the driver:
```
$ make
```

To install the driver (if driver includes into device tree):
```
$ modprobe xlnx-dna-drv
```

The 'buildroot' folder contains Makefiles for building driver with buildroot system
