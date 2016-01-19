#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include <crypto/hash.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include <linux/namei.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>

/* Computes crc32 checksum of in_File and writes to out_File */
int computeChecksum(char *in_File, char *out_File)
{
	/* br - Bytes Read tfrom inputfile
	* bytes_write - Bytes written to outputfile */
	int errNo = 0, bytes_write = 0, br = 0;
	/* Input File Size */
	int inp_File_Size = 0;
	/* No.of Pages read */
	int page_count = 0;
	struct file *inFilePtr, *outFilePtr;
	struct kstat in, out;
	char *in_Buff = NULL;
	char checkSum[64];
	u32 cyc_red_check = 0;
	mm_segment_t oldfs;

	inFilePtr = NULL;
	outFilePtr = NULL;
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/* Check if the input file exist. */
	errNo = vfs_stat(in_File, &in);
	if (!errNo) {
		/* Check if the input file is regular. */
		if (S_ISREG(in.mode) == 0) {
			errNo = -EBADF;
			printk(KERN_ERR "Input File is not Regular\n");
			set_fs(oldfs);
			return errNo;
		}

		/* Check if the output file exist. */
		if (!(vfs_stat(out_File, &out))) {
			/* Check if the input file and output file
			 *  points to same object
			 */
			if (in.ino == out.ino) {
				printk(KERN_ERR "Input and Output files are same\n");
				set_fs(oldfs);
				return -EINVAL;
			}

			/* Check if the output file is regular. */
			if (S_ISREG(out.mode) == 0) {
				errNo = -EBADF;
				printk(KERN_ERR "Output File is not Regular\n");
				set_fs(oldfs);
				return errNo;
			}
		}
	}
	set_fs(oldfs);

	if (errNo) {
		printk(KERN_ERR "Input File Doesn't exist\n");
		return errNo;
	}

	/* Open the input file with read only mode. */
	inFilePtr = filp_open(in_File, O_RDONLY, 0);
	if (!(inFilePtr) || IS_ERR((inFilePtr))) {
		errNo = (int)PTR_ERR((inFilePtr));
		printk(KERN_ERR "Unable to Open input File: Error - %d\n",
		       errNo);
		return errNo;
	}

	/* Check if input file has read permissions. */
	else if (!(inFilePtr)->f_op || !(inFilePtr)->f_op->read) {
			printk(KERN_ERR "No read operations on input file \n");
			errNo = -EROFS;
			filp_close(inFilePtr, NULL);
			return errNo;
	}

	/* Open the output file with write mode. If output file does not exist
     *  create it. */
	(outFilePtr) = filp_open(out_File, O_WRONLY | O_CREAT | O_TRUNC, 0);
	if (!(outFilePtr) || IS_ERR(outFilePtr)) {
		errNo = (int)PTR_ERR((outFilePtr));
		printk(KERN_ERR "Unable to Open output File: Error - %d\n",
		       errNo);
		filp_close(inFilePtr, NULL);
		return errNo;
	}

	/* Check if output file has write permissions. */
	else if (!(outFilePtr)->f_op || !(outFilePtr)->f_op->write) {
			printk(KERN_ERR "No write operations on output file \n");
			errNo = -EROFS;
			goto OUT_FAIL;
	}

	/* Make input and output file point to the beginning of the file */
	(inFilePtr)->f_pos = 0;
	(outFilePtr)->f_pos = 0;

	/* Allocate space for buffer to read from input file. */
	in_Buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!in_Buff) {
		errNo = -ENOMEM;
		printk(KERN_ERR "Unable to allocate space for in_Buffer : Buffer to read from input file\n");
		goto OUT_FAIL;
	}

	memset((in_Buff), 0, PAGE_SIZE);

	/* Initialize crc */
	cyc_red_check = crc32(0L, NULL, 0);

	inp_File_Size = (unsigned int)inFilePtr->f_path.dentry->d_inode->i_size;

	while (inp_File_Size > 0) {
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		br = vfs_read(inFilePtr, in_Buff, PAGE_SIZE, &inFilePtr->f_pos);

		if (br < 0) {
			 errNo = br;
			 printk(KERN_ERR "Read from Input File abruptly Failed\n");
			 goto OUT_FAIL;
		}

		inp_File_Size = inp_File_Size - br;
		cyc_red_check = crc32(cyc_red_check, in_Buff, br);
		page_count = page_count + 1;
		set_fs(oldfs);
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/* Convert checksum to string */
	sprintf(checkSum, "%0X", cyc_red_check);

	bytes_write = vfs_write(outFilePtr, checkSum, strlen(checkSum),
		&outFilePtr->f_pos);

	if (bytes_write < 0) {
		errNo = bytes_write;
		printk(KERN_ERR "Write to  Output file abruptly Failed. Cannot compress the file\n");
		filp_close(outFilePtr, NULL);
		outFilePtr = filp_open(out_File, O_WRONLY | O_CREAT, 0);

		if (!(outFilePtr) || IS_ERR(outFilePtr)) {
			errNo = (int)PTR_ERR((outFilePtr));
			printk(KERN_ERR "Unable to Empty output file after compression failure: Error - %d\n", errNo);
			filp_close(inFilePtr, NULL);
			goto OUT_CHECKSUM;
		}

		goto OUT_FAIL;
	}

	set_fs(oldfs);

OUT_FAIL:
	filp_close(inFilePtr, NULL);
	filp_close(outFilePtr, NULL);

OUT_CHECKSUM:
	kfree(in_Buff);
	return errNo;
}
