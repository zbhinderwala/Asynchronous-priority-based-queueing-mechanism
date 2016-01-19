/*
 * User Space Program to test Asynchrounous job queues */
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <limits.h>
#include <pthread.h>
#include "common.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

void recvMsgFromKernel(void);
int create_socket(void);

/*
 * Function to print help information
 */
void print_usageinfo(void)
{
	printf("\n\nUSAGE: ./produce_job {-e|-d|-r|-t|-m|-s|-c|-l|-N} "\
	       "[-p|-P|-C] [infile_1] [infile_2] [outfile]\n");
	printf("-e : encrypt file\n");
	printf("-d : decrypt file\n");
	printf("-m : decompress file\n");
	printf("-s : compress file\n");
	printf("-c : compress file\n");
	printf("-l : list all queued jobs\n");
	printf("-t : concat infile_1 with infile_2\n");
	printf("-N [NEW_PRIORITY] [JOB_ID_TO_REMOVE] : Change priority of job.\n");
	printf("-r [JOB_ID_TO_REMOVE} : remove job with id = "\
	       "JOB_ID_TO_REMOVE\n");
	printf("-p : Specify Password (atleast 6 characters).\n");
	printf("-C : Set if callback is required\n");
	printf("-P [PRIORITY] : Set priority of the job.\n");
	printf("-h : Display this help message.\n");
	printf("infile_1 : input file 1 name\n");
	printf("infile_2 : input file 2 name in case of concat\n");
	printf("outfile : outfile name\n");
}

/*
 * Main Function
 */
int main(int argc, char *argv[])
{
	int rc, counter;
	struct job *job_args;
	struct job_list jobs[MAX_NUM_JOBS] = { {0} };
	int option = 0, len = 0, priority = 1, i, argslen;
	int errorflag = 0, pflag = 0, Pflag = 0, Cflag = 0;
	char *keybuf = NULL;
	unsigned char hash[SHA_DIGEST_LENGTH];
	char infile_absolute_path[PATH_MAX + 1],
	     outfile_absolute_path[PATH_MAX + 1];
	char infile2_absolute_path[PATH_MAX + 1];
	char cwd_in[PATH_MAX + 1], cwd_out[PATH_MAX + 1], cwd_in2[PATH_MAX + 1];
	char *infile_ptr, *infile2_ptr, *outfile_ptr, *current_wd_in,
	     *current_wd_out;
	char *job_name[10] = {"", "ENCRYPT", "DECRYPT", "LIST", "REMOVE",
				"CHECKSUM", "COMPRESS", "DECOMPRESS", "CONCAT",
				"CHANGE_PRIORITY"};
	pthread_t thread1;

	/* Allocate memory to user arguments struct */
	job_args = (struct job *)malloc(sizeof(struct job));
	if (!job_args) {
		printf("ERROR!! No memory allocated to struct job_args\n ");
		exit(EXIT_FAILURE);
	}

	/* If no argument other than executable name, return */
	if (argc == 1) {
		print_usageinfo();
		free(job_args);
		exit(EXIT_FAILURE);
	}

	job_args->job_type = 0;

	/* Using getopt for selecting options and parsing command line arguments */
	while ((option = getopt(argc, argv, ":Cedclsmtr:P:N:p:h")) != -1) {
		switch (option) {
		case 'p':	/* Password Option */
			if (pflag) {
				printf("%s: Can't use -p option two times\n",
						argv[0]);
				errorflag = 1;
			} else {
				pflag = 1;
				len = strlen(optarg);
				if (len < 6) {
					printf("Encryption/decryption key is too small, Enter a valid key!!!\n");
					free(job_args);
					print_usageinfo();
					exit(EXIT_FAILURE);
				} else {
					keybuf = optarg;
				}
			}
			break;
		case 'P':	/* Priority Option */
			if (Pflag) {
				printf("%s: Can't use -P option two times\n",
								argv[0]);
				errorflag = 1;
			} else {
				Pflag = 1;
				if (atoi(optarg) < 1 || atoi(optarg) > 3) {
					printf("Invalid Priority no. given!!, Enter between 1-3\n");
					errorflag = 1;
				} else {
					priority = atoi(optarg);
				}
			}
			break;
		case 'C':	/* Callback option for asynchronous jobs */
			if (Cflag) {
				printf("%s: Can't use -C option two times\n",
								argv[0]);
				errorflag = 1;
			} else
				Cflag = 1;
			break;
		case 'h':	/* Help option */
			print_usageinfo();
			free(job_args);
			exit(EXIT_FAILURE);
			break;
		case 'e':	/* Encrypt Option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = ENCRYPT;
			}
			break;
		case 's':	/* Compress Option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = COMPRESS;
			}
			break;
		case 'm':	/* Decompress option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = DECOMPRESS;
			}
			break;
		case 't':	/* Concat option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = CONCAT;
			}
			break;
		case 'd':	/* Decrypt option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = DECRYPT;
			}
			break;
		case 'l':	/* Listing jobs option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = LIST;
			}
			break;
		case 'r':	/* Remove job option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_id = atoi(optarg);
				printf("JOB id Remove: %d\n",
				       job_args->job_id);
				job_args->job_type = REMOVE;
			}
			break;
		case 'N':	/* Change Priority Option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->new_priority = atoi(optarg);
				printf("New Job priority: %d\n",
				       job_args->new_priority);
				job_args->job_type = CHANGE_PRIORITY;
			}
			break;
		case 'c':	/* Checksum Option */
			if (job_args->job_type != 0) {
				printf("%s: Can't use 2 job_type options, use only one at a time\n", argv[0]);
				errorflag = 1;
			} else {
				job_args->job_type = CHECKSUM;
			}
			break;
		case ':':
			printf("Option -%c requires an operand\n", optopt);
			errorflag = 1;
			break;
		case '?':
			printf("Unknown option: -%c\n", optopt);
			errorflag = 1;
			break;
		default:
			errorflag = 1;
		}
	}

	/* If job type other than encrypt/decrypt p flag should not be there */
	if (job_args->job_type == LIST || job_args->job_type == REMOVE
				|| job_args->job_type == CHECKSUM ||
				job_args->job_type == COMPRESS ||
				job_args->job_type == DECOMPRESS ||
				job_args->job_type == CONCAT ||
				job_args->job_type == CHANGE_PRIORITY) {
		if (pflag) {
			printf("Error!! Wrong option -p provided\n");
			errorflag = 1;
		}
	}

	/* No priority flag and callback flag needed in case of list,
	 * remove and change priority */
	if (job_args->job_type == LIST || job_args->job_type == REMOVE ||
				job_args->job_type == CHANGE_PRIORITY) {
		if (Pflag) {
			printf("Error!! Wrong option -P provided\n");
			errorflag = 1;
		}

		if (Cflag) {
			printf("Error!! Wrong option -C provided\n");
			errorflag = 1;
		}
	}

	/* Password flag is must in case of encrypt/decrypt job */
	if (job_args->job_type == ENCRYPT ||
		job_args->job_type == DECRYPT) {
		if (!pflag) {
			printf("Error!! Encryption/decryption key(-p) is missing\n");
			errorflag = 1;
		} else {
			len = strlen(keybuf);
			/* Check if cipher password length is less than 6 */
			if (len < 6) {
				printf("Encryption/decryption key is too "\
				       "small,Enter a valid key!!!\n");
				free(job_args);
				exit(EXIT_FAILURE);
			} else {
				/* Calculate SHA1 Hash of Chiper key */
				job_args->keybuf = SHA1((unsigned char *)keybuf,
						len, hash);
			}
			job_args->keybuf[SHA_DIGEST_LENGTH] = 0;
		}
	}

	/* Check if more arguments are provided than required */
	if (optind < argc) {
		if (job_args->job_type == LIST ||
				job_args->job_type == REMOVE) {
			printf("%s: ERROR!! \n", argv[0]);
			errorflag = 1;
		}
	}

	/* Job_id is needed in case of change priority  */
	if (job_args->job_type == CHANGE_PRIORITY) {
		if (optind >= argc) {
			printf("%s: missing Job id \n", argv[0]);
			errorflag = 1;
		} else {
			job_args->job_id = atoi(argv[optind]);
			printf("Job_id whose priority is to be changed: %d \n",
			       job_args->job_id);
		}

		/*Check if more arguments are provided than required */
		if (optind + 1 < argc) {
			printf("%s: ERROR!! \n", argv[0]);
			errorflag = 1;
		}
	}

	if (job_args->job_type == ENCRYPT || job_args->job_type ==\
			DECRYPT || job_args->job_type == CHECKSUM ||
			job_args->job_type == COMPRESS || job_args->job_type ==\
			DECOMPRESS) {
		/*Check for argument containing inputfile name */
		if (optind >= argc) {
			printf("%s: missing input file name\n", argv[0]);
			errorflag = 1;
		} else {
			job_args->infile = argv[optind];

			infile_ptr = realpath(job_args->infile,
					      infile_absolute_path);

			if (infile_ptr) {
				job_args->infile = infile_ptr;
			} else {
				current_wd_in = cwd_in;
				getcwd(current_wd_in, PATH_MAX + 1);
				strcat(current_wd_in, "/");
				strcat(current_wd_in, job_args->infile);
				job_args->infile = current_wd_in;
			}
		}
		/*Check for argument containing outputfile name */
		if (optind + 1 >= argc) {
			printf("%s: missing output file name\n", argv[0]);
			errorflag = 1;
		} else {
			job_args->outfile = argv[optind+1];

			outfile_ptr = realpath(job_args->outfile,
					       outfile_absolute_path);
			if (outfile_ptr) {
				job_args->outfile = outfile_ptr;
			} else {
				current_wd_out = cwd_out;
				getcwd(current_wd_out, PATH_MAX + 1);
				strcat(current_wd_out, "/");
				strcat(current_wd_out, job_args->outfile);
				job_args->outfile = current_wd_out;
			}
		}

		/*Check if more arguments are provided than required */
		if (optind + 2 < argc) {
			printf("%s: ERROR!!\n", argv[0]);
			errorflag = 1;
		}
	}

	if (job_args->job_type == CONCAT) {
		/* Check for argument containing inputfile name */
		if (optind >= argc) {
			printf("%s: missing input file name 1\n", argv[0]);
			errorflag = 1;
		} else {
			job_args->infile = argv[optind];
			infile_ptr = realpath(job_args->infile,
					      infile_absolute_path);
			if (infile_ptr) {
				job_args->infile = infile_ptr;
			} else {
				current_wd_in = cwd_in;
				getcwd(current_wd_in, PATH_MAX + 1);
				strcat(current_wd_in, "/");
				strcat(current_wd_in, job_args->infile);
				job_args->infile = current_wd_in;
			}
		}

		if (optind + 1 >= argc) {
			printf("%s: missing input file name 2\n", argv[0]);
			errorflag = 1;
		} else {
			job_args->infile2 = argv[optind + 1];

			infile2_ptr = realpath(job_args->infile2,
					      infile2_absolute_path);

			if (infile2_ptr) {
				job_args->infile2 = infile2_ptr;
			} else {
				current_wd_in = cwd_in2;
				getcwd(current_wd_in, PATH_MAX + 1);
				strcat(current_wd_in, "/");
				strcat(current_wd_in, job_args->infile2);
				job_args->infile2 = current_wd_in;
			}
		}

		/* Check for argument containing outputfile name */
		if (optind + 2 >= argc) {
			printf("%s: missing output file name\n", argv[0]);
			errorflag = 1;
		} else {
			job_args->outfile = argv[optind + 2];

			outfile_ptr = realpath(job_args->outfile,
					       outfile_absolute_path);
			if (outfile_ptr) {
				job_args->outfile = outfile_ptr;
			} else {
				current_wd_out = cwd_out;
				getcwd(current_wd_out, PATH_MAX + 1);
				strcat(current_wd_out, "/");
				strcat(current_wd_out, job_args->outfile);
				job_args->outfile = current_wd_out;
			}

		}

		/* Check if more arguments are provided than required */
		if (optind + 3 < argc) {
			printf("%s: ERROR!!\n", argv[0]);
			errorflag = 1;
		}
	}

	/* Check if any job_type option is not provided*/
	if (job_args->job_type == 0) {
		printf("%s: job_type option missing\n", argv[0]);
		errorflag = 1;
	}

	if (errorflag) {
		print_usageinfo();
		free(job_args);
		exit(EXIT_FAILURE);
	}

	/* Assign Process id */
	job_args->pid = getpid();
	job_args->priority = priority;

	/* create netlink socket in case of callback flag and file related jobs */
	if (Cflag == 1 && (job_args->job_type == ENCRYPT ||
	    job_args->job_type == DECRYPT ||
	    job_args->job_type == CHECKSUM ||
		job_args->job_type == COMPRESS ||
		job_args->job_type == DECOMPRESS ||
		job_args->job_type == CONCAT)) {
		create_socket();
	}

	if (job_args->job_type == LIST)
		job_args->extra = jobs;

	rc = syscall(__NR_submitjob, (void *)job_args, argslen);

	/* Print List of jobs recived from kernel, when job type is LIST */
	if (job_args->job_type == LIST) {
		printf("------PRINTING JOB DETAILS------\n");
		for (i = 0; i < MAX_NUM_JOBS; i++) {
			if (jobs[i].job_id == 0)
				break;
			printf("Printing job details...%d\n", i);
			printf("Job id: %d\n", jobs[i].job_id);
			printf("Job priority: %d\n", jobs[i].priority);
			printf("Job Type: %d  %s\n", jobs[i].job_type,
					job_name[jobs[i].job_type]);
			printf("---------------------------------\n");
		}
		printf("----PRINTING JOB DETAILS DONE----\n");
	}

	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else {
		printf("syscall returned %d (errno=%d)\n", rc, errno);
		perror("Error: ");
	}

	/* Create Callback thread when callback functionality is required */
	if (Cflag == 1 && rc == 0 && (job_args->job_type == ENCRYPT ||
	    job_args->job_type == DECRYPT ||
	    job_args->job_type == CHECKSUM ||
		job_args->job_type == COMPRESS ||
		job_args->job_type == DECOMPRESS ||
		job_args->job_type == CONCAT)) {

		pthread_create(&thread1, NULL,
			       (void *) &recvMsgFromKernel, NULL);

		/* Below code is to show that, we can do some other useful work,
		 * while above job is running asynchronously and its callback
		 * message is recived after job is finished */
		counter = 0;
		while (counter < 12) {
			printf("I can perform any operation now: %d\n",
			       counter);
			counter++;
			sleep(1);
		}
		pthread_join(thread1, NULL);
		printf("I can perform any more operations now also\n");
	}

	free(job_args);
	exit(rc);
}
