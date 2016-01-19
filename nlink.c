#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include "common.h"

#define MAX_PAYLOAD 1024 /* maximum payload size*/

int netlinkSockFD;
struct sockaddr_nl src_addr;
/* Intialise the Netlink message Header */
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;

/* Function to create netlink socket and bind it */
int create_socket(void)
{
	int err = 0;

	/* Create NetLink Socket */
	netlinkSockFD = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if (netlinkSockFD < 0) {
		printf("Unable to open socket\n");
		err = -1;
	}

	memset(&src_addr, 0, sizeof(struct sockaddr_nl));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(netlinkSockFD, (struct sockaddr *)&src_addr, sizeof(src_addr));

	return err;
}

/* Function to receive callback message from kernel */
void recvMsgFromKernel(void)
{
	struct msg *ret;
	char *job_name[10] = {"", "ENCRYPT", "DECRYPT", "LIST", "REMOVE",
				"CHECKSUM", "COMPRESS", "DECOMPRESS", "CONCAT",
				"CHANGE_PRIORITY"};

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Read message from kernel */
	recvmsg(netlinkSockFD, &msg, 0);
	ret = NLMSG_DATA(nlh);

	close(netlinkSockFD);

	if (ret->ret == 0)
		printf("Callback Status: Job with job id: %d and job_type: %s is Success\n",
				ret->job_id, job_name[ret->job_type]);
	else if (ret->ret == 1)
		printf("Callback Status: Job with job id: %d is Removed\n",
		       ret->job_id);
	else {
		errno = -ret->ret;
		printf("Callback Status: Job with job id %d  and "\
		       "job_type: %s is Failed with return value %d\n",
		       ret->job_id, job_name[ret->job_type], ret->ret);
		perror("");
	}
}
