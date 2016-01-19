#Asynchronous priority based queueing mechanism

Operating Systems - Asignment 3 (Nov 2015)

- Implemented asynchronous and concurrent processing of the producer consumer problem in Linux Kernel in C
- Maintained a shared queue of jobs protected by locking mechanism. Performed expensive file operations such as encryption, decryption, compression, checksum calculation; and returning the results to the user asynchronously. Also supported changing priority of jobs or removing them.
- Implemented callback mechanism from kernel space to user space using Netlink sockets
