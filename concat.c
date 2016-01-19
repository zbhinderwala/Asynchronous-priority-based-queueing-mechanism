#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

/*Flag to check if O/p file exist or not*/
int output_file_exist_flag1 = 1;

/* Check file validations and file pointers of input and output files */
int file_validations1(struct file **in_filp1, struct file **in_filp2,
		      struct file **out_filp,
		      char *infile1, char *infile2, char *outfile)
{
	int err = 0;
	struct kstat in_stat, out_stat;
	umode_t infile_mode, outfile_mode = 0;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* Check if input file exist or not */
	if (vfs_stat(infile1, &in_stat)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in vfs_stat, Input file 1 doesn't exist\n", __LINE__);
		err = -ENOENT;
		set_fs(oldfs);
		goto out;
	}
	set_fs(oldfs);

	/* Check if input file is a regular file or not */
	infile_mode = in_stat.mode;
	if (!S_ISREG(infile_mode)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR Input file 1 is not a regular file\n", __LINE__);
		err = -EBADF;
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* Check if input file exist or not */
	if (vfs_stat(infile2, &in_stat)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in vfs_stat, Input file 2 doesn't exist\n ", __LINE__);
		err = -ENOENT;
		set_fs(oldfs);
		goto out;
	}
	set_fs(oldfs);

	/* Check if input file is a regular file or not */
	infile_mode = in_stat.mode;
	if (!S_ISREG(infile_mode)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR Input file 2 is not a regular file\n", __LINE__);
		err = -EBADF;
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_stat(outfile, &out_stat);
	set_fs(oldfs);
	if (!err) {  /* Output file exists */
		outfile_mode = out_stat.mode;
		output_file_exist_flag1 = 1;
		/* Check if output file is a regular file or not */
		if (!S_ISREG(outfile_mode)) {
			printk(KERN_ERR	"Line no.:[%d] ERROR Output file is not a regular file : %s\n", __LINE__, outfile);
			err = -EBADF;
			goto out;
		}
	} else {  /* Output file doesnot exist */
		output_file_exist_flag1 = 0;
	}
	err = 0;

	/* Open input file in read only mode */
	*in_filp1 = filp_open(infile1, O_RDONLY, 0);

	/* Checking if input file pointer is valid or not */
	if (!(*in_filp1) || IS_ERR(*in_filp1)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in opening input file 1 %d\n", __LINE__, (int)PTR_ERR(*in_filp1));
		err = PTR_ERR(*in_filp1);
		goto out;
    }

	/* Check if input file pointer can execute read operation */
	if (!(*in_filp1)->f_op->read) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! Input file pointer can't execute read operations \n", __LINE__);
		err = -EPERM;
		goto out;
	}

	/* Open input file in read only mode */
	*in_filp2 = filp_open(infile2, O_RDONLY, 0);

	/* Checking if input file pointer is valid or not */
	if (!(*in_filp2) || IS_ERR(*in_filp2)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in opening input file 2 %d\n", __LINE__, (int)PTR_ERR(*in_filp2));
		err = PTR_ERR(*in_filp2);
		goto out;
    }

	/* Check if input file pointer can execute read operation */
	if (!(*in_filp1)->f_op->read) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! Input file pointer can't execute read operations \n", __LINE__);
		err = -EPERM;
		goto out;
	}

	/* Open output file */
	if (!output_file_exist_flag1)
		*out_filp = filp_open(outfile, O_WRONLY | O_CREAT | O_TRUNC,
					   infile_mode);
	else
		*out_filp = filp_open(outfile, O_WRONLY | O_CREAT | O_TRUNC,
					   outfile_mode);

	/* Checking if output file pointer is valid or not */
	if (!(*out_filp) || IS_ERR(*out_filp)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in opening/creating output file %d\n", __LINE__, (int)PTR_ERR(*out_filp));
		err = PTR_ERR(*out_filp);
		goto out;
	}

out:
	return err;
}

int concat_files(struct file *in_filp1, struct file *in_filp2,
		 struct file *out_filp)
{
	mm_segment_t oldfs;
	int bytes_read = 0, bytes_write = 0;
	char *read_buf = NULL;
	int infile_size = 0;
	int ret = 0;

	/* Start offset */
	in_filp1->f_pos = 0;
	in_filp2->f_pos = 0;
	out_filp->f_pos = 0;

	/* Get the size of input file */
	infile_size = in_filp1->f_inode->i_size;

	/* Allocate memory for read buffer, used for reading data from input file in blocks of PAGE_SIZE*/
	read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buf) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to read_buf buffer\n", __LINE__);
		ret = -ENOMEM;
		goto out;
	}

	/* Run loop till end of the input file 1 */
	while (in_filp1->f_pos < infile_size) {
		/* Read data in blocks of PAGE_SIZE from input file 1 */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		memset(read_buf, 0, PAGE_SIZE);
		bytes_read = vfs_read(in_filp1, read_buf, PAGE_SIZE,
				      &in_filp1->f_pos);
		set_fs(oldfs);

		/* Check if there is error in reading data from input file 1 */
		if (bytes_read < 0) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in reading data from input file 1, bytes_read: %d\n", __LINE__, bytes_read);
			ret = bytes_read;
			goto out;
		}

		/* Write data block in output file */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		bytes_write = vfs_write(out_filp, read_buf, bytes_read,
					&out_filp->f_pos);
		set_fs(oldfs);

		/* Check if there is error in writing data to o/p file */
		if (bytes_write < bytes_read) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in writing data to output file, bytes_write: %d\n", __LINE__, bytes_write);
			ret = bytes_write;
			goto out;
		}
	}

	infile_size = in_filp2->f_inode->i_size;
	/* Run loop till end of the input file 2 */
	while (in_filp2->f_pos < infile_size) {
		/* Read data in blocks of PAGE_SIZE from input file 2 */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		memset(read_buf, 0, PAGE_SIZE);
		bytes_read = vfs_read(in_filp2, read_buf, PAGE_SIZE,
				      &in_filp2->f_pos);
		set_fs(oldfs);

		/* Check if there is error in reading data from input file 2 */
		if (bytes_read < 0) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in reading data from input file 2, bytes_read: %d\n", __LINE__, bytes_read);
			ret = bytes_read;
			goto out;
		}

		/* Write data block in output file */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		bytes_write = vfs_write(out_filp, read_buf, bytes_read,
					&out_filp->f_pos);
		set_fs(oldfs);

		/* Check if there is error in writing data to o/p file */
		if (bytes_write < bytes_read) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in writing data to output file, bytes_write: %d\n", __LINE__, bytes_write);
			ret = bytes_write;
			goto out;
		}
	}

out:
	kfree(read_buf);
	return ret;
}

/* Function to concat two input files into the output file */
int concat(char *infile1, char *infile2, char *outfile)
{
	int err = 0;
	struct file *in_filp1 = NULL, *out_filp = NULL, *in_filp2 = NULL;

	/* Check file validations and file pointers of input and output files */
	err = file_validations1(&in_filp1, &in_filp2, &out_filp, infile1,
			       infile2, outfile);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function file_validations fails, err: %d\n", __LINE__, err);
		goto out;
	}

	/* Call concat function, which reads data in PAGE_SIZE -> writes it to output file */
	err = concat_files(in_filp1, in_filp2, out_filp);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function concat_files fails, ret: %d\n", __LINE__, err);
		goto out;
	}

out:
	if (in_filp2 && !IS_ERR(in_filp2))
		filp_close(in_filp2, NULL);
	if (out_filp && !IS_ERR(out_filp))
		filp_close(out_filp, NULL);
	if (in_filp1 && !IS_ERR(in_filp1))
		filp_close(in_filp1, NULL);
	return err;
}
