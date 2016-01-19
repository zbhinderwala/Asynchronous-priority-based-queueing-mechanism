#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "common.h"
#include "sys_submitjob.h"

asmlinkage extern long (*sysptr)(void *args, int argslen);

/* Function to send message to User space through netlink */
static void netlink_send_msg(int pid, int job_id, int job_type, int ret)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int msg_size;
	struct msg mesg;

	mesg.ret = ret;
	mesg.job_id = job_id;
	mesg.job_type = job_type;
	msg_size = sizeof(mesg);

	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

	/*Copy data to nlmsg buffer */
	memcpy(nlmsg_data(nlh), &mesg, msg_size);

	/* Send data to User space */
	nlmsg_unicast(nl_sk, skb_out, pid);
}

/* Function to add new incoming job to queue */
int add_job_to_queue(struct job *j)
{
	struct queue *new_job;
	int err = 0;

	new_job = kzalloc(sizeof(struct queue *), GFP_KERNEL);
	if (new_job == NULL) {
		err = -ENOMEM;
		printk(KERN_ERR "Cannot add job to the queue:err %d\n", err);
		goto out;
	}
	new_job->task = j;

	/* Add new job to tail of list */
	list_add_tail(&(new_job->list), &(q_task->list));
out:
	return err;
}

/*Function to do clean up, free input and output file buffers, free job task */
void cleanup_job(struct queue *q_remove)
{
	if (q_remove->task->job_type == ENCRYPT ||
		q_remove->task->job_type == DECRYPT)
		kfree(q_remove->task->keybuf);

	kfree(q_remove->task->infile);

	if (q_remove->task->infile2)
		kfree(q_remove->task->infile2);
	kfree(q_remove->task->outfile);
	kfree(q_remove->task);
	kfree(q_remove);
	q_remove = NULL;
}

/* Function to change priority of a job */
int change_job_priority(int id, int new_priority)
{
	int err = -ENOENT;
	struct queue *tmp;
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, &(q_task->list)) {
		tmp = list_entry(pos, struct queue, list);
		if (id == tmp->task->job_id) {
			tmp->task->priority = new_priority;
			err = 0;
			break;
		}
	}
	return err;
}

/* Function to remove job from queue by job_id */
int remove_job_by_id(int id, pid_t *pid_remove)
{
	int err = -ENOENT;
	struct queue *tmp;
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, &(q_task->list)) {
		tmp = list_entry(pos, struct queue, list);
		if (id == tmp->task->job_id) {
			*pid_remove = tmp->task->pid;
			list_del(pos);
			cleanup_job(tmp);
			err = 0;
			break;
		}
	}
	return err;
}

/* Function to remove all jobs from queue, called during rmmod of module */
void remove_all_jobs(void)
{
	struct queue *tmp;
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, &(q_task->list)) {
		tmp = list_entry(pos, struct queue, list);
		list_del(pos);
		cleanup_job(tmp);
	}
}

/* Function to do initial validations on user space args struct and add job
 * to queue (Producer function mechanism) */
asmlinkage long submitjob(void *args, int argslen)
{
	struct job *k_args = NULL, *u_args;
	struct job_list *u_extra;
	int err = 0, new_priority, job_count = 0;
	struct filename *infile_buf = NULL,
			*infile_buf2 = NULL, *outfile_buf = NULL;
	struct queue *tmp;
	pid_t pid_remove;
	struct kstat in_stat, in2_stat, out_stat;
	umode_t infile_mode, outfile_mode = 0;
	mm_segment_t oldfs;
	char *in_buf = NULL, *in_buf2 = NULL, *out_buf = NULL;

	printk(KERN_INFO "submitjob received arg %p\n", args);
	if (args == NULL) {
		err = -EINVAL;
		goto out;
	}
	u_args = (struct job *) args;

	/* Print all jobs and return to user */
	if (u_args->job_type == LIST) {
		u_extra = (struct job_list *) u_args->extra;
		mutex_lock(&lock_queue);
		list_for_each_entry(tmp, &(q_task->list), list) {
			u_extra[job_count].job_id = tmp->task->job_id;
			u_extra[job_count].job_type = tmp->task->job_type;
			u_extra[job_count].priority = tmp->task->priority;
			job_count++;
		}
		mutex_unlock(&lock_queue);
		if (copy_to_user(args, u_args, sizeof(u_args))) {
			printk(KERN_ERR	"Line :[%d] ERROR in copy_to_user\n",
							__LINE__);
			err = -EFAULT;
		}
		goto out;
	}

	/* Change priority of a job and return */
	if (u_args->job_type == CHANGE_PRIORITY) {
		new_priority = u_args->new_priority;
		if (new_priority < 1 || new_priority > 3) {
			err = -EINVAL;
			printk(KERN_ERR "Line no.:[%d] Invalid priority given by "\
			       "user\n", __LINE__);
			goto out;
		}
		mutex_lock(&lock_queue);
		err = change_job_priority(u_args->job_id, new_priority);
		mutex_unlock(&lock_queue);
		if (err != 0)
			printk(KERN_ERR "Line no.:[%d] ERROR in changing "\
			       "job priority. No job id found\n", __LINE__);
		goto out;
	}

	/* Remove job by job_id */
	if (u_args->job_type == REMOVE) {
		mutex_lock(&lock_queue);
		err = remove_job_by_id(u_args->job_id, &pid_remove);
		if (err == 0)
			queue_length--;
		mutex_unlock(&lock_queue);
		if (err == 0)
			netlink_send_msg(pid_remove, u_args->job_id, u_args->job_type, 1);
		goto out;
	}

	k_args = kzalloc(sizeof(struct job), GFP_KERNEL);
	if (!k_args) {
		err = -ENOMEM;
		goto out;
	}

	/* Copying the userland arguments to kernel space arguments */
	if (copy_from_user(k_args, (struct job *)args, sizeof(struct job))) {
		printk(KERN_ERR "Line no.:[%d] ERROR in copy_from_user, "\
		       "copying the userland arguments to kernel "\
		       "space arguments\n ", __LINE__);
		err = -EFAULT;
		goto out;
	}

	infile_buf = getname(u_args->infile);
	/* Check if input file address is valid or not */
	if (!infile_buf || IS_ERR(infile_buf)) {
		printk(KERN_ERR "Line no.:[%d] ERROR in getname, input file "\
		       "address is not valid %d\n", __LINE__,
		       (int)PTR_ERR(infile_buf));
		err = PTR_ERR(infile_buf);
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* Check if input file exist or not */
	if (vfs_stat(infile_buf->name, &in_stat)) {
		printk(KERN_ERR "Line no.:[%d] ERROR in vfs_stat, Input file "\
		       "doesn't exist\n ", __LINE__);
		err = -ENOENT;
		set_fs(oldfs);
		goto out;
	}
	set_fs(oldfs);

	/* Check if input file is a regular file or not */
	infile_mode = in_stat.mode;
	if (!S_ISREG(infile_mode)) {
		printk(KERN_ERR "Line no.:[%d] ERROR Input file is not a "\
		       "regular file : %s\n", __LINE__, infile_buf->name);
		err = -EBADF;
		goto out;
	}

	in_buf = kzalloc(strlen(infile_buf->name), GFP_KERNEL);
	if (!in_buf) {
		err = -ENOMEM;
		goto out;
	}

	memcpy(in_buf, infile_buf->name, strlen(infile_buf->name));

	if (u_args->job_type == CONCAT) {
		infile_buf2 = getname(u_args->infile2);
		/* Check if input file address is valid or not */
		if (!infile_buf2 || IS_ERR(infile_buf2)) {
			printk(KERN_ERR "Line no.:[%d] ERROR in getname, input file "\
			       "address is not valid %d\n", __LINE__,
			       (int)PTR_ERR(infile_buf2));
			err = PTR_ERR(infile_buf2);
			goto out;
		}
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		/* Check if input file exist or not */
		if (vfs_stat(infile_buf2->name, &in2_stat)) {
			printk(KERN_ERR "Line no.:[%d] ERROR in vfs_stat, "\
			       "Input file doesn't exist\n", __LINE__);
			err = -ENOENT;
			set_fs(oldfs);
			goto out;
		}
		set_fs(oldfs);

		/* Check if input file is a regular file or not */
		infile_mode = in2_stat.mode;
		if (!S_ISREG(infile_mode)) {
			printk(KERN_ERR "Line no.:[%d] ERROR Input file is not a "\
			       "regular file : %s\n", __LINE__,
			       infile_buf2->name);
			err = -EBADF;
			goto out;
		}

		in_buf2 = kzalloc(strlen(infile_buf2->name), GFP_KERNEL);
		if (!in_buf2) {
			err = -ENOMEM;
			goto out;
		}

		memcpy(in_buf2, infile_buf2->name, strlen(infile_buf2->name));

		k_args->infile2 = (char *) in_buf2;
	}

	if (u_args->job_type == ENCRYPT || u_args->job_type == DECRYPT ||
				u_args->job_type == CHECKSUM ||
				u_args->job_type == COMPRESS ||
				u_args->job_type == DECOMPRESS ||
				u_args->job_type == CONCAT) {
		outfile_buf = getname(u_args->outfile);
		/* Check if output file address is valid or not */
		if (!outfile_buf || IS_ERR(outfile_buf)) {
			printk(KERN_ERR "Line no.:[%d] ERROR in getname, output file "\
			       "address is not valid %d\n", __LINE__, \
					(int)PTR_ERR(outfile_buf));

					err = PTR_ERR(outfile_buf);
			goto out;
		}
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = vfs_stat(outfile_buf->name, &out_stat);
		set_fs(oldfs);

		if (!err) {  /* Output file exists */
			outfile_mode = out_stat.mode;
			/* Check if output file is a regular file or not */
			if (!S_ISREG(outfile_mode)) {
				printk(KERN_ERR "Line no.:[%d] ERROR Output file "\
				       "is not a regular file : %s\n",
				       __LINE__, outfile_buf->name);
				err = -EBADF;
				goto out;
			}
		}
		err = 0;
		/* Checking if input file and output file are same or not; also checks
		 * if one file is symlink of another */
		if (in_stat.ino == out_stat.ino) {
			printk(KERN_ERR "Line no.:[%d] ERROR Input file and "\
			       "output file are same (either same file "\
				   "or one file is symlink of another)\n", __LINE__);
			err = -EBADF;
			goto out;
		}

		out_buf = kzalloc(strlen(outfile_buf->name), GFP_KERNEL);
		if (!out_buf) {
			err = -ENOMEM;
			goto out;
		}

		memcpy(out_buf, outfile_buf->name, strlen(outfile_buf->name));
	}

	if (u_args->job_type == ENCRYPT || u_args->job_type == DECRYPT) {
		/* Key must be present in encrypt and decrypt case*/
		k_args->keybuf = kmalloc(HASH_KEY_LENGTH_SIZE, GFP_KERNEL);
		if (!k_args->keybuf) {
			err = -ENOMEM;
			goto out;
		}

		err = copy_from_user(k_args->keybuf, u_args->keybuf,
					strlen(u_args->keybuf));
		if (err != 0) {
			printk(KERN_ERR "Line no.:[%d] ERROR in copy from user %d\n",
					__LINE__, err);
			goto out_freekey;
		}
		k_args->keybuf[strlen(u_args->keybuf)] = '\0';
		k_args->keybuf[strlen(k_args->keybuf) - 4] = 0;
	}

	/* Assign to kernel structure */
	k_args->infile = in_buf;
	k_args->outfile = out_buf;
	k_args->job_id = job_id;
	job_id++;
	k_args->priority = u_args->priority;
	k_args->job_type = u_args->job_type;

	/* Add job to queue */
start_wait:
	mutex_lock(&lock_queue);
	if (queue_length < MAX_NUM_JOBS) {
		err = add_job_to_queue(k_args);
		if (err != 0) {
			mutex_unlock(&lock_queue);
			goto out_freekey;
		}
		queue_length++;
		printk(KERN_INFO "Queue length = %d\n", queue_length);
	} else {
		mutex_unlock(&lock_queue);
		/* Producer will wait, when the queue is full */
		wait_event_interruptible(prod_wq, queue_length < MAX_NUM_JOBS);
		goto start_wait;
	}
	mutex_unlock(&lock_queue);

	/* Wake up consumer from waitqueue to process job, after
	 * add job to queue is success */
	wake_up_all(&con_wq);
	/* If we have reached here we are sure everything was good */
	return 0;

out_freekey:
	if (k_args && k_args->keybuf)
		kfree(k_args->keybuf);
out:
	if (in_buf)
		kfree(in_buf);
	if (in_buf2)
		kfree(in_buf2);
	if (out_buf)
		kfree(out_buf);
	if (infile_buf)
		putname(infile_buf);
	if (infile_buf2)
		putname(infile_buf2);
	if (outfile_buf)
		putname(outfile_buf);
	kfree(k_args);
	return err;
}

/* Function to remove job from the queue according to job priority */
struct queue *remove_job_from_queue(void)
{
	struct list_head *pos, *q;
	struct queue *tmp;
	int i;

	for (i = 3; i > 0; i--) {
		list_for_each_safe(pos, q, &(q_task->list)) {
			tmp = list_entry(pos, struct queue, list);
			if (tmp->task->priority == i) {
				list_del(pos);
				return tmp;
			}
		}
	}
	return NULL;
}

/* Consumer function to get job from queue and process it and
 * yield to scheduler */
int consumer(void *arg)
{
	struct queue *process_task = NULL;
	int err = 0;

start_wait:
	/* Consumer will wait, when the queue is empty */
	wait_event_interruptible(con_wq, queue_length > 0);

	if (destroy)
		goto out;

	mutex_lock(&lock_queue);
	if (queue_length > 0) {
		process_task = remove_job_from_queue();
		queue_length--;
	}
	mutex_unlock(&lock_queue);

	/* Wake up producer from wait queue, if a job is dequeued from queue */
	wake_up_all(&prod_wq);

	/* Process the job function */
	if (process_task) {
		printk(KERN_INFO "JOB ID being processed = %d\n",
				process_task->task->job_id);
		msleep(8000);
		if (process_task->task->job_type == ENCRYPT) {
			err = encrypt(process_task->task->infile,
				      process_task->task->outfile,
				      process_task->task->keybuf);
		} else if (process_task->task->job_type == DECRYPT) {
			err = decrypt(process_task->task->infile,
				      process_task->task->outfile,
				      process_task->task->keybuf);
		} else if (process_task->task->job_type == CHECKSUM) {
			err = computeChecksum(process_task->task->infile,
				      process_task->task->outfile);
		} else if (process_task->task->job_type == CONCAT) {
			err = concat(process_task->task->infile,
					  process_task->task->infile2,
				      process_task->task->outfile);
		} else if (process_task->task->job_type == COMPRESS) {
			err = compressFile(process_task->task->infile,
				      process_task->task->outfile);
		} else if (process_task->task->job_type == DECOMPRESS) {
			err = decompressFile(process_task->task->infile,
				      process_task->task->outfile);
		}

		/* Send return value and job_id info to user through callback */
		netlink_send_msg(process_task->task->pid,
				 process_task->task->job_id, 
				 process_task->task->job_type, err);
		cleanup_job(process_task);
	}
	schedule();
	goto start_wait;
out:
	return err;
}

static int __init init_sys_submitjob(void)
{
	int err = 0, i;
	struct netlink_kernel_cfg cfg = {
		.input  = NULL,
	};

	/* Initalize queue */
	q_task = kmalloc(sizeof(struct queue *), GFP_KERNEL);
	if (q_task == NULL) {
		printk(KERN_ERR "Error in initalizing memory for queue\n");
		err = -ENOMEM;
		goto out;
	}
	/* Init List Head */
	INIT_LIST_HEAD(&(q_task->list));
	/* Init lock */
	mutex_init(&lock_queue);

	/* Intialize waitqueue for producer and consumer */
	init_waitqueue_head(&prod_wq);
	init_waitqueue_head(&con_wq);

	queue_length = 0;
	job_id = 1;

	/* Create Consumer threads */
	for (i = 0; i < MAX_NUM_THREADS; i++) {
		consumer_threads[i] = kthread_create(consumer, NULL,
						"consumer_thread_%d", i);
		if (IS_ERR(consumer_threads[i])) {
			printk(KERN_ERR "Thread could not be created\n");
			err = -ENOMEM;
			consumer_threads[i] = NULL;
			goto out;
		}
		wake_up_process(consumer_threads[i]);
	}

	/* Create netlink socket */
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk) {
		printk(KERN_ERR  "Error creating socket.\n");
		err = -ENOMEM;
		goto out;
	}

	if (sysptr == NULL)
		sysptr = submitjob;
	printk(KERN_INFO "installed new sys_submitjob module\n");

out:
	if (err) {
		for (i = 0; MAX_NUM_THREADS; i++) {
			if (consumer_threads[i] != NULL)
				kthread_stop(consumer_threads[i]);
		}
	}

	return err;
}

static void  __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;

	mutex_lock(&lock_queue);
	/* Free List and queue */
	remove_all_jobs();
	queue_length = 0;
	mutex_unlock(&lock_queue);
	queue_length = 1;

	/* Kill all consumer threads */
	destroy = 1;
	wake_up_all(&con_wq);

	/* Free netlink socket */
	netlink_kernel_release(nl_sk);

	printk(KERN_INFO "removed sys_xcrypt module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
