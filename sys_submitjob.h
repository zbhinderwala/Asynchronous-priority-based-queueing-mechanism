#ifndef SYS_SUBMITJOB_H
#define SYS_SUBMITJOB_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <net/sock.h>

#define MAX_NUM_THREADS 3
#define HASH_KEY_LENGTH_SIZE	20

int encrypt(char *infile, char *outfile, unsigned char *keybuf);
int decrypt(char *infile, char *outfile, unsigned char *keybuf);
int computeChecksum(char *in_File, char *out_File);
int concat(char *infile1, char *infile2, char *outfile);
int compressFile(char *in_File, char *out_File);
int decompressFile(char *in_File, char *out_File);

struct queue {
	struct list_head list;
	struct job *task;
};

struct sock *nl_sk = NULL;

int destroy = 0;
struct task_struct *consumer_threads[MAX_NUM_THREADS] = {NULL};
struct mutex lock_queue;
int queue_length, job_id;
wait_queue_head_t prod_wq;
wait_queue_head_t con_wq;
struct queue *q_task;

#endif
