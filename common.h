#ifndef COMMON_H
#define COMMON_H

#define ENCRYPT         1
#define DECRYPT         2
#define LIST            3
#define REMOVE          4
#define CHECKSUM        5
#define COMPRESS	6
#define DECOMPRESS	7
#define CONCAT		8
#define CHANGE_PRIORITY 9

#define MAX_NUM_JOBS	6
#define NETLINK_USER	31

struct msg {
	int ret;
	int job_id;
	int job_type;
};

struct job_list {
	int job_id;
	int priority;
	int job_type;
};

struct job {
	pid_t pid;
	char *infile;
	char *infile2;
	char *outfile;
	unsigned char *keybuf;
	int job_type;
	int job_id;
	int priority;
	int new_priority;
	void *extra; /* Extensibility */
};

#endif
