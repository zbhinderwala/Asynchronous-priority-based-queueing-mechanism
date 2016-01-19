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
#include <linux/namei.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/crypto.h>
#include <linux/crc32c.h>

#define XATTR_FILE_SIZE  "user.size"

/*Compresses in_File. out_File is the compressed file. */
int compressFile(char *in_File, char *out_File)
{
	int errNo = 0, bytes_write = 0, br = 0;
	/* Input File Size */
	int inp_File_Size = 0;
	int comp_size = 0;
	int fileSize_attr_value = 0;
	struct file *inFilePtr, *outFilePtr;
	char *in_Buff = NULL, *out_Buff = NULL, *algo;
	mm_segment_t oldfs;
	struct crypto_comp *cryp_comp;
	struct kstat in, out;

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
			printk(KERN_ERR	"Input File is not Regular\n");
			set_fs(oldfs);
			return errNo;
		}

		/* Check if the output file exist. */
		if (!(vfs_stat(out_File, &out))) {
			/* Check if the input file and output file
			   points to same object.*/
			if (in.ino == out.ino) {
				printk(KERN_ERR	"Input and Output files are same\n");
				set_fs(oldfs);
				return -EINVAL;
			}

			/* Check if the output file is regular. */
			if (S_ISREG(out.mode) == 0) {
				errNo = -EBADF;
				printk(KERN_ERR	"Output File is not Regular\n");
				set_fs(oldfs);
				return errNo;
			}
		}
	}
	set_fs(oldfs);

	if (errNo) {
		printk(KERN_ERR	"Input File Doesn't exist\n");
		return errNo;
	}

	/* Open the input file with read only mode. */
	(inFilePtr) = filp_open(in_File, O_RDONLY, 0);
	if (!(inFilePtr) || IS_ERR((inFilePtr))) {
		printk(KERN_ERR	"Unable to Open input File: Error - %d\n",
		       errNo);
		errNo = (int)PTR_ERR((inFilePtr));
		return errNo;
	}

	/* Check if input file has read permissions. */
	else if (!(inFilePtr)->f_op || !(inFilePtr)->f_op->read) {
			printk(KERN_ERR	"No read operations on input file \n");
			errNo = -EROFS;
			filp_close(inFilePtr, NULL);
			return errNo;
	}

	/* Open the output file with write mode. If output file does not exist
	* create it. */
	(outFilePtr) = filp_open(out_File, O_WRONLY | O_CREAT |  O_TRUNC, 0);
	if (!(outFilePtr) || IS_ERR(outFilePtr)) {
		errNo = (int)PTR_ERR((outFilePtr));
		printk(KERN_ERR	"Unable to Open output File: Error - %d\n",
		       errNo);
		filp_close(inFilePtr, NULL);
		return errNo;
	}

	/* Check if output file has write permissions. */
	else if (!(outFilePtr)->f_op || !(outFilePtr)->f_op->write) {
			printk(KERN_ERR"No write operations on output file\n");
			errNo = -EROFS;
			goto OUT_COMPRESS;
	}

	/* Make input and output file point to the beginning of the file */
	(inFilePtr)->f_pos = 0;
	(outFilePtr)->f_pos = 0;

	inp_File_Size = (unsigned int)inFilePtr->f_path.dentry->d_inode->i_size;
	fileSize_attr_value = inp_File_Size;

	/*Set file xattr private attribute of output file to store input file size
	* which is used while decompression */
	errNo = outFilePtr->f_inode->i_op->setxattr(outFilePtr->f_path.dentry,
		XATTR_FILE_SIZE, &fileSize_attr_value,
		sizeof(fileSize_attr_value), 0);

	if (errNo < 0) {
		printk(KERN_ERR	"Unable to set file x_attr attribute\n");
		goto OUT_FAIL;
	}

	/* Allocate space for buffer to read from input file. */
	out_Buff = kmalloc(inp_File_Size + 1, GFP_KERNEL);
	if (!out_Buff) {
		errNo = -ENOMEM;
		printk(KERN_ERR	"Unable to allocate space for in_Buffer : Buffer to read from input file\n");
		goto OUT_FAIL;
	}

	memset((out_Buff), 0, inp_File_Size + 1);

	/* Allocate space for buffer to read from input file. */
	in_Buff = kmalloc(inp_File_Size + 1, GFP_KERNEL);
	if (!in_Buff) {
		errNo = -ENOMEM;
		printk(KERN_ERR	"Unable to allocate space for in_Buffer : Buffer to read from input file\n");
		goto OUT_FAIL;
	}

	memset((in_Buff), 0, inp_File_Size + 1);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	br = vfs_read(inFilePtr, in_Buff, inp_File_Size, &inFilePtr->f_pos);

	if (br < 0) {
		 errNo = br;
		 printk(KERN_ERR "Read from Input File abruptly Failed\n");
		 goto OUT_FAIL;
	}

	/* Compression happens here */
	algo = kstrdup("deflate", GFP_KERNEL);
	comp_size = inp_File_Size;
	comp_size = 3000000;
	cryp_comp = crypto_alloc_comp(algo, 0, CRYPTO_ALG_ASYNC);
	errNo = crypto_comp_compress(cryp_comp, in_Buff, br,
							out_Buff, &comp_size);

	if (errNo < 0) {
		 printk(KERN_ERR "Compression Failed\n");
		 goto OUT_FAIL;
	}
	/* Writing compressed data to output file */
	bytes_write = vfs_write(outFilePtr, out_Buff, comp_size,
		&outFilePtr->f_pos);

	/* If compression fails abruptly, output file needs to be emptied */
	if (bytes_write < 0) {
		errNo = bytes_write;
		printk(KERN_ERR "Write to  Output file abruptly Failed. Cannot compress the file\n");
		filp_close(outFilePtr, NULL);
		outFilePtr = filp_open(out_File,
				       O_WRONLY | O_CREAT | O_TRUNC, 0);
		if (!(outFilePtr) || IS_ERR(outFilePtr)) {
			errNo = (int)PTR_ERR((outFilePtr));
			printk(KERN_ERR "Unable to Empty output file after compression failure: Error - %d\n", errNo);
			filp_close(inFilePtr, NULL);
			goto OUT_COMPRESS;
		}
		goto OUT_FAIL;
	}
	set_fs(oldfs);

OUT_FAIL:
	filp_close(inFilePtr, NULL);
	filp_close(outFilePtr, NULL);

OUT_COMPRESS:
	kfree(in_Buff);
	kfree(out_Buff);
	return errNo;
}

/*De-Compresses in_File. out_File is the decompressed file. */
int decompressFile(char *in_File, char *out_File)
{
	int errNo = 0, bytes_write = 0, br = 0;
	/* Input File Size */
	int inp_File_Size = 0;
	int comp_size = 0;
	int fileSize_attr_value = 0;
	struct file *inFilePtr, *outFilePtr;
	struct crypto_comp *cryp_comp;
	struct kstat in, out;
	char *in_Buff = NULL, *out_Buff = NULL, *algo;
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
			   points to same object. */
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
	* create it. */
	(outFilePtr) = filp_open(out_File, O_WRONLY | O_CREAT |  O_TRUNC, 0);
	if (!(outFilePtr) || IS_ERR(outFilePtr)) {
		errNo = (int)PTR_ERR((outFilePtr));
		printk(KERN_ERR "Unable to Open output File: Error - %d\n",
		       errNo);
		filp_close(inFilePtr, NULL);
		return errNo;
	}

	/* Check if output file has write permissions. */
	else if (!(outFilePtr)->f_op || !(outFilePtr)->f_op->write) {
			printk(KERN_ERR"No write operations on output file\n");
			errNo = -EROFS;
			goto OUT_FAIL;
	}

	/* Make input and output file point to the beginning of the file */
	(inFilePtr)->f_pos = 0;
	(outFilePtr)->f_pos = 0;

	inp_File_Size = (unsigned int)inFilePtr->f_path.dentry->d_inode->i_size;

	/* Fetch input file xattr attribute, which basically contains size of
	* original file */
	errNo = inFilePtr->f_inode->i_op->getxattr(inFilePtr->f_path.dentry,
		XATTR_FILE_SIZE, &fileSize_attr_value,
		sizeof(fileSize_attr_value));

	if (errNo < 0) {
		printk(KERN_ERR "Unable to get file x_attr attribute\n");
		goto OUT_FAIL;
	}

	/*printk("FIle Size from get xattr is %d \n", fileSize_attr_value); */

	/* Allocate space for buffer to read from input file. */
	out_Buff = kmalloc(fileSize_attr_value + 1, GFP_KERNEL);
	if (!out_Buff) {
		errNo = -ENOMEM;
		printk(KERN_ERR "Unable to allocate space for in_Buffer : Buffer to read from input file\n");
		goto OUT_FAIL;
	}

	memset((out_Buff), 0, fileSize_attr_value + 1);

	/* Allocate space for buffer to read from input file. */
	in_Buff = kmalloc(inp_File_Size + 1, GFP_KERNEL);
	if (!in_Buff) {
		errNo = -ENOMEM;
		printk(KERN_ERR "Unable to allocate space for in_Buffer : Buffer to read from input file\n");
		goto OUT_FAIL;
	}

	memset((in_Buff), 0, inp_File_Size + 1);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	br = vfs_read(inFilePtr, in_Buff, inp_File_Size, &inFilePtr->f_pos);

	if (br < 0) {
		 errNo = br;
		 printk(KERN_ERR "Read from Input File abruptly Failed\n");
		 goto OUT_FAIL;
	}

	/* Decompression happens here */
	algo = kstrdup("deflate", GFP_KERNEL);
	comp_size = 3000000;
	cryp_comp = crypto_alloc_comp(algo, 0, CRYPTO_ALG_ASYNC);
	errNo = crypto_comp_decompress(cryp_comp, in_Buff, br,
						out_Buff, &comp_size);

	if (errNo < 0) {
		 printk(KERN_ERR "De Compression Failed\n");
		 goto OUT_FAIL;
	}

	/* Writing decompressed data to output file */
	bytes_write = vfs_write(outFilePtr, out_Buff, comp_size,
		&outFilePtr->f_pos);

	/* If decompression fails abruptly, output file needs to be emptied */
	if (bytes_write < 0) {
		errNo = bytes_write;
		printk(KERN_ERR "Write to  Output file abruptly Failed. Cannot compress the file\n");
		filp_close(outFilePtr, NULL);
		outFilePtr = filp_open(out_File,
				       O_WRONLY | O_CREAT | O_TRUNC, 0);
		if (!(outFilePtr) || IS_ERR(outFilePtr)) {
			errNo = (int)PTR_ERR((outFilePtr));
			printk(KERN_ERR "Unable to Empty output file after compression failure: Error - %d\n", errNo);
			filp_close(inFilePtr, NULL);
			goto OUT_DECOMPRESS;
		}
		goto OUT_FAIL;
	}

	set_fs(oldfs);

OUT_FAIL:
	filp_close(inFilePtr, NULL);
	filp_close(outFilePtr, NULL);

OUT_DECOMPRESS:
	kfree(in_Buff);
	kfree(out_Buff);
	return errNo;
}
