#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include <linux/fs.h>

#define HASH_KEY_LENGTH_SIZE	20

/*Flag to check if O/p file exist or not*/
int output_file_exist_flag = 1;

/* Check file validations and file pointers of input and output files */
int file_validations(struct file **in_filp, struct file **out_filp,
		     struct file **out_filp_temp, char *infile,
		     char *outfile, char *keybuf)
{
	int err = 0;
	struct kstat in_stat, out_stat;
	char *temp_outfile = NULL;
	umode_t infile_mode, outfile_mode = 0;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* Check if input file exist or not */
	if (vfs_stat(infile, &in_stat)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in vfs_stat, "\
		       "Input file doesn't exist\n ", __LINE__);
		err = -ENOENT;
		set_fs(oldfs);
		goto out;
	}
	set_fs(oldfs);

	/* Check if input file is a regular file or not */
	infile_mode = in_stat.mode;
	if (!S_ISREG(infile_mode)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR Input file is "\
		       "not a regular file : %s\n", __LINE__, infile);
		err = -EBADF;
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_stat(outfile, &out_stat);
	set_fs(oldfs);
	if (!err) {  /* Output file exists */
		outfile_mode = out_stat.mode;
		output_file_exist_flag = 1;
		/* Check if output file is a regular file or not */
		if (!S_ISREG(outfile_mode)) {
			printk(KERN_ERR	"Line no.:[%d] ERROR Output file "\
			       "is not a regular file : %s\n",
			       __LINE__, outfile);
			err = -EBADF;
			goto out;
		}
	} else {  /* Output file doesnot exist */
		output_file_exist_flag = 0;
	}
	err = 0;

	/* Checking if input file and output file are same or not; also checks if one file is symlink of another */
	if (in_stat.ino == out_stat.ino) {
		printk(KERN_ERR	"Line no.:[%d] ERROR Input file and "\
		       "output file are same (either same file or one "\
		       "file is symlink of another)\n", __LINE__);
		err = -EBADF;
		goto out;
	}

	/* Open input file in read only mode */
	*in_filp = filp_open(infile, O_RDONLY, 0);

	/* Checking if input file pointer is valid or not */
	if (!(*in_filp) || IS_ERR(*in_filp)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in opening input file %d\n", __LINE__, (int)PTR_ERR(*in_filp));
		err = PTR_ERR(*in_filp);
		goto out;
	}

	/* Check if input file pointer can execute read operation */
	if (!(*in_filp)->f_op->read) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! Input file pointer can't execute read operations \n", __LINE__);
		err = -EPERM;
		goto out;
	}

	/* Open output file */
	*out_filp = filp_open(outfile, O_RDONLY | O_CREAT, 0);

	/* Checking if output file pointer is valid or not */
	if (!(*out_filp) || IS_ERR(*out_filp)) {
		printk(KERN_ERR	"Line no.:[%d] ERROR in opening/creating output file %d\n", __LINE__, (int)PTR_ERR(*out_filp));
		err = PTR_ERR(*out_filp);
		goto out;
    }

	/* Allocate memory to the temp output file */
	temp_outfile = kmalloc(strlen(outfile) + strlen(".temp"), GFP_KERNEL);
	if (!temp_outfile) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to temp output file\n ", __LINE__);
		err = -ENOMEM;
		goto out;
	}

	/* Code for naming .temp output file, temp file name is "outputfile".temp */
	strcpy(temp_outfile, outfile);
	strcat(temp_outfile, ".temp");

	/* Open .temp file, if output file exist from before open temp file with output file permission mode,
	   If output file doesnot exist from before open temp file with input file permission mode */
	if (!output_file_exist_flag)
		*out_filp_temp = filp_open(temp_outfile, O_WRONLY | O_CREAT,
					   infile_mode);
	else
		*out_filp_temp = filp_open(temp_outfile, O_WRONLY | O_CREAT,
					   outfile_mode);

	/* Checking if temp output file pointer is valid or not */
	if (!(*out_filp_temp) || IS_ERR(*out_filp_temp)) {
		printk("Line no.:[%d] ERROR in opening/creating output temp file %d\n", __LINE__, (int)PTR_ERR(*out_filp_temp));
		err = PTR_ERR(*out_filp_temp);
		goto out;
	}

	/* Check if output temp file pointer can execute write operation */
	if (!(*out_filp_temp)->f_op->write) {
		printk("Line no.:[%d] ERROR!! Temp file pointer can't execute write operations\n", __LINE__);
		err = -EPERM;
		goto out;
	}

out:
	kfree(temp_outfile);
	return err;
}

/* Description: This function encrypts the input buffer using cipher key
 *				Code reference taken from :-
 *				http://lxr.free-electrons.com/source/drivers/staging/lustre/lustre/obdclass/capa.c#L292
 *				http://www.chronox.de/crypto-API/ch06s02.html
 * @param read_buf		: Contains the input read buffer
 * @param write_buf		: Contains the resultant output encrypted buffer
 * @param read_buf_size	: Size of input read_read buffer, tells much data it
 *						  has to encrypt
 * @param out_filp_temp	: Contains the .temp output file pointer
 * @param cipherkey_buf	: Contains the cipher key, used for encrypting
 * @param page_num		: Page number of the input file (1 page contains
 *						  4096 bytes)
 * @return value		: return 0 on success, otherwise error no.
 */
int encrpt_blkcipher(char *read_buf, char *write_buf, int read_buf_size,
		     struct file *out_filp_temp, unsigned char *cipherkey_buf,
		     int page_num)
{
	struct blkcipher_desc desc;
	struct scatterlist dst;
	struct scatterlist src;
	struct crypto_blkcipher *blkcipher = NULL;
	char *iv = "dhanendrajain123";
	unsigned int ivsize = 0;
	int ret = 0;

	char *set_iv = NULL;
	char *temp = NULL;
	/* Get Inode no. of output .temp file */
	int inode = out_filp_temp->f_path.dentry->d_inode->i_ino;
	/* Cast page no. and inode no. to 8 bytes variable */
	long long int page = (long long int)page_num;
	long long int inode_num = (long long int)inode;

	/* Allocates block cipher handle or load transform for aes, used CTR mode */
	blkcipher = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(blkcipher)) {
		printk(KERN_ERR	"Line no.:[%d] could not allocate blkcipher handle or failed to load transform for aes \n", __LINE__);
		ret = -PTR_ERR(blkcipher);
		goto out;
	}

	/* Set cipher key in block cipher structure */
	ret = crypto_blkcipher_setkey(blkcipher, cipherkey_buf,
				      strlen(cipherkey_buf));
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] key could not be set for aes, key size is %d \n", __LINE__, strlen(cipherkey_buf));
		goto out_free_blkcipher;
	}

	/* Get IV size of block chipher */
	ivsize = crypto_blkcipher_ivsize(blkcipher);

	/* Allocate memory to set IV buffer */
	set_iv = kmalloc(ivsize, GFP_KERNEL);
	if (!set_iv) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to set_iv \n",
		       __LINE__);
		ret = -ENOMEM;
		goto out_free_blkcipher;
	}

	/* Allocate memory to temp buffer */
	temp = kmalloc(8, GFP_KERNEL);
	if (!temp) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to temp \
			buffer\n ", __LINE__);
		ret = -ENOMEM;
		goto out_free;
	}

	/* Copy current page no. to set IV buffer in first 8 bytes */
	sprintf(temp, "%08lld", page);
	memcpy(set_iv, temp, 8);
	/* Copy Inode no. of temp file to set IV buffer in next 8 bytes */
	sprintf(temp, "%08lld", inode_num);
	memcpy(&set_iv[8], temp, 8);

	/* Copy our augmented IV to actual IV buffer */
	memcpy(iv, set_iv, ivsize);

	/* Set the IV in blockcipher buffer */
	if (ivsize)
		crypto_blkcipher_set_iv(blkcipher, iv, ivsize);

	desc.flags = 0;
	desc.tfm = blkcipher;
	desc.info  = NULL;

	/* Initialize scatterlists for source and destination buffers */
	sg_init_table(&src, 1);
	sg_set_page(&src, virt_to_page(read_buf),
		    read_buf_size, (unsigned long)(read_buf) % PAGE_SIZE);

	sg_init_table(&dst, 1);
	sg_set_page(&dst, virt_to_page(write_buf), read_buf_size,
		    (unsigned long)(write_buf) % PAGE_SIZE);

	/* Do encryption on source buffer */
	ret = crypto_blkcipher_encrypt(&desc, &dst, &src, read_buf_size);
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] failed to encrypt for aes\n", __LINE__);
		goto out_free;
	}

out_free:
	kfree(temp);
	kfree(set_iv);
out_free_blkcipher:
	crypto_free_blkcipher(blkcipher);
out:
	return ret;
}

/* Description: This function decrypts the input buffer using cipher key
 *				Code reference taken from :-
 *				http://lxr.free-electrons.com/source/drivers/staging/lustre/lustre/obdclass/capa.c#L345
 *				http://www.chronox.de/crypto-API/ch06s02.html
 * @param read_buf		: Contains the input read buffer
 * @param write_buf		: Contains the resultant output decrypted buffer
 * @param read_buf_size	: Size of input read_read buffer, tells much data
 *						  it has to decrypt
 * @param in_filp		: Contains the input file pointer
 * @param cipherkey_buf	: Contains the cipher key, used for decrypting
 * @param page_num		: Page number of the input file (1 page contains
 *						  4096 bytes)
 * @return value		: return 0 on success, otherwise error no.
 */
int decrypt_blkcipher(char *read_buf, char *write_buf, int read_buf_size,
		      struct file *in_filp, unsigned char *cipherkey_buf,
		      int page_num)
{
	struct blkcipher_desc desc;
	struct scatterlist dst, src;
	struct crypto_blkcipher *blkcipher = NULL;
	char *iv = "dhanendrajain123";
	unsigned int ivsize = 0;
	int ret = 0;

	char *set_iv = NULL;
	char *temp = NULL;
	/* Get Inode no. of input file */
	int inode = in_filp->f_path.dentry->d_inode->i_ino;
	/* Cast page no. and inode no. to 8 bytes variable */
	long long int page = (long long int)page_num;
	long long int inode_num = (long long int)inode;

	/* Allocates block cipher handle or load transform for aes, used CTR mode */
	blkcipher = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(blkcipher)) {
		printk(KERN_ERR	"Line no.:[%d] could not allocate blkcipher handle or failed to load transform for aes \n", __LINE__);
		ret = -PTR_ERR(blkcipher);
		goto out;
	}

	/* Set cipher key in block cipher structure */
	ret = crypto_blkcipher_setkey(blkcipher, cipherkey_buf,
				      strlen(cipherkey_buf));
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] key could not be set for aes, key size is %d \n", __LINE__, strlen(cipherkey_buf));
		goto out_free_blkcipher;
	}

	/* Get IV size of block chipher */
	ivsize = crypto_blkcipher_ivsize(blkcipher);

	/* Allocate memory to set IV buffer */
	set_iv = kmalloc(ivsize, GFP_KERNEL);
	if (!set_iv) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to set_iv\n ",
		       __LINE__);
		ret = -ENOMEM;
		goto out_free_blkcipher;
	}

	/* Allocate memory to temp buffer */
	temp = kmalloc(8, GFP_KERNEL);
	if (!temp) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to temp buffer\n ", __LINE__);
		ret = -ENOMEM;
		goto out_free;
	}

	/* Copy current page no. to set IV buffer in first 8 bytes */
	sprintf(temp, "%08lld", page);
	memcpy(set_iv, temp, 8);
	/* Copy Inode no. of input file to set IV buffer in next 8 bytes */
	sprintf(temp, "%08lld", inode_num);
	memcpy(&set_iv[8], temp, 8);

	/* Copy our augmented IV to actual IV buffer */
	memcpy(iv, set_iv, ivsize);

	/* Set the IV in blockcipher buffer */
	if (ivsize)
		crypto_blkcipher_set_iv(blkcipher, iv, ivsize);

	desc.flags = 0;
	desc.tfm = blkcipher;
	desc.info  = NULL;

	/* Initialize scatterlists for source and destination buffers */
	sg_init_table(&src, 1);
	sg_set_page(&src, virt_to_page(read_buf), read_buf_size,
		    (unsigned long)(read_buf) % PAGE_SIZE);

	sg_init_table(&dst, 1);
	sg_set_page(&dst, virt_to_page(write_buf), read_buf_size,
		    (unsigned long)(write_buf) % PAGE_SIZE);

	/* Do Decryption on source buffer */
	ret = crypto_blkcipher_decrypt(&desc, &dst, &src, read_buf_size);
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] failed to decrypt for aes\n", __LINE__);
		goto out_free;
	}

out_free:
	kfree(temp);
	kfree(set_iv);
out_free_blkcipher:
	crypto_free_blkcipher(blkcipher);
out:
	return ret;
}

/* Description: This function computes the hash(SHA1) of cipher key, which is
 *				used later for storing in the preamble of encrypted file
 *				Code reference taken from :-
 *				http://lxr.free-electrons.com/source/fs/ecryptfs/crypto.c#L87
 *				http://stackoverflow.com/questions/3869028/how-to-use-cryptoapi-in-the-linux-kernel-2-6
 * @param cipherkey_buf	: Contains the cipher key
 * @param hash			: Contains the resultant output hashed key
 * @return value		: return 0 on success, otherwise error no.
 */
int compute_hash_sha1(unsigned char *cipherkey_buf, char *hash)
{
	struct scatterlist sg;
	struct hash_desc desc;
	int ret = 0;
	struct crypto_hash *hash_tfm;

	/* Allocates crypto hash handle for SHA1 */
	hash_tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		ret = -PTR_ERR(hash_tfm);
		printk(KERN_ERR	"Line no.:[%d] Error attempting to allocate crypto context, ret: %d\n", __LINE__, ret);
		goto out;
	}

	desc.tfm = hash_tfm;
	desc.flags = 0;

	/* Initialize scatterlist for cipherkey buffer */
	sg_init_one(&sg, cipherkey_buf, HASH_KEY_LENGTH_SIZE);

	/* Configures hashing method */
	ret = crypto_hash_init(&desc);
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] Error initializing "\
		       "crypto hash, ret: %d\n",
		       __LINE__, ret);
		goto out_free_cryptohash;
	}

	/* Do crypto hashing method on source*/
	ret = crypto_hash_update(&desc, &sg, HASH_KEY_LENGTH_SIZE);
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] Error updating crypto hash, ret: %d\n", __LINE__, ret);
		goto out_free_cryptohash;
	}

	/* Copy the hash computed to destination buffer (hash here) */
	ret = crypto_hash_final(&desc, hash);
	if (ret) {
		printk(KERN_ERR	"Line no.:[%d] Error finalizing crypto hash, ret: %d\n", __LINE__, ret);
		goto out_free_cryptohash;
	}

out_free_cryptohash:
	crypto_free_hash(hash_tfm);
out:
	return ret;
}

/* Description: This function read data in PAGE_SIZE blocks from input file,
 *				encrypt/decrypt it and write it to the output file. It also
 *				writes hashed key in preamble in encryption case and compare
 *				hashed key from preamble in decryption case
 * @param in_filp				: Contains the input file pointer
 * @param out_filp				: Contains the output file pointer
 * @param out_filp_temp			: Contains the temp output file pointer
 * @param cipherkey_buf			: Contains the cipher key, for encrypt/decrypt
 * @param flags					: Encrypt/Decrypt flag
 * @param output_file_exist_flag: Flag containing info of output file existince
 *								  If 1 output file exists
 * @return value				: return 0 on success, otherwise error no.
 */
int read_write_file(struct file *in_filp, struct file *out_filp,
		    struct file *out_filp_temp, unsigned char *cipherkey_buf,
		    unsigned int flag, int output_file_exist_flag)
{
	mm_segment_t oldfs;
	int bytes_read = 0, bytes_write = 0;
	char *read_buf = NULL, *write_buf = NULL,
	     *read_hashkey = NULL, *hash = NULL;
	int infile_size = 0, vfs_rename_success_flag = 0, page_num;
	int err = 0, ret1 = 0;
	struct dentry *trap = NULL;

	/* Start offset */
	in_filp->f_pos = 0;
	out_filp->f_pos = 0;
	out_filp_temp->f_pos = 0;

	/* Get the size of input file */
	infile_size = in_filp->f_inode->i_size;
#ifdef DEBUG_PRINT
	printk("Line no.:[%d] Input file size: %d\n", __LINE__, infile_size);
#endif

	/* Allocate memory for hash key buffer, which is stored in preamble */
	hash = kmalloc(HASH_KEY_LENGTH_SIZE, GFP_KERNEL);
	if (!hash) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to hash buffer\n", __LINE__);
		err = -ENOMEM;
		goto out_vfs_unlink_tempfile;
	}
	memset(hash, 0x00, HASH_KEY_LENGTH_SIZE);

	/* Compute hash(SHA1) of cipher key */
	err = compute_hash_sha1(cipherkey_buf, hash);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function compute_hash_sha1 fails, err: %d\n", __LINE__, err);
		goto out_free_hash;
	}

	/* Allocate memory for read_hash key buffer, used for reading preamble from encrypted file */
	read_hashkey = kmalloc(strlen(hash), GFP_KERNEL);
	if (!read_hashkey) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to read_hashkey buffer\n", __LINE__);
		err = -ENOMEM;
		goto out_free_hash;
	}

	/* Allocate memory for read buffer, used for reading data from input file in blocks of PAGE_SIZE*/
	read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buf) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to read_buf buffer\n", __LINE__);
		err = -ENOMEM;
		goto out_free_readhashkey;
	}

	/* Allocate memory for write buffer, used for writing data to temp file in blocks of PAGE_SIZE*/
	write_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!write_buf) {
		printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to write_buf buffer\n", __LINE__);
		err = -ENOMEM;
		goto out_free_readbuf;
	}

	if (flag == 1) {	/* Encryption case */
		/* Write the double hashed key in preamble in the temp file */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		bytes_write = vfs_write(out_filp_temp, hash,
					HASH_KEY_LENGTH_SIZE,
					&out_filp_temp->f_pos);
		set_fs(oldfs);
		/* If data written is not equal to hashed key size, error */
		if (!(bytes_write == HASH_KEY_LENGTH_SIZE)) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in write hash key to temp file, bytes_write: %d\n", __LINE__, bytes_write);
			err = bytes_write;
			goto out_free_writebuf;
		}
	} else {
		/* Decryption case */
		/* Read the hashed key from input file's preamble */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		bytes_read = vfs_read(in_filp, read_hashkey,
				      HASH_KEY_LENGTH_SIZE, &in_filp->f_pos);
		set_fs(oldfs);
		/* If data read is not equal to hashed key size, error */
		if (!(bytes_read == HASH_KEY_LENGTH_SIZE)) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in reading hash key from encrypted input file, bytes_read: %d\n", __LINE__, bytes_read);
			err = bytes_read;
			goto out_free_writebuf;
		}

		/* Compare the double hashed key and hashed key read from preamble, if match success then only proceed for decryption */
		if (memcmp(read_hashkey, hash, HASH_KEY_LENGTH_SIZE) != 0) {
			printk(KERN_ERR	"Line no.:[%d] Key Mismatch: ERROR!!!\n", __LINE__);
			err = -EINVAL;
			goto out_free_writebuf;
		} else {
			printk(KERN_DEBUG "Line no.:[%d] Key Match Success !!!\n",
			       __LINE__);
		}
	}

	page_num = 0;
	/* Run loop till end of the input file */
	while (in_filp->f_pos < infile_size) {
		/* Read data in blocks of PAGE_SIZE from input file */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		memset(read_buf, 0, PAGE_SIZE);
		bytes_read = vfs_read(in_filp, read_buf, PAGE_SIZE,
				      &in_filp->f_pos);
		set_fs(oldfs);

		/* Check if there is error in reading data from input file */
		if (bytes_read < 0) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in reading data from input file, bytes_read: %d\n", __LINE__, bytes_read);
			err = bytes_read;
			goto out_free_writebuf;
		}

		/* Do encryption/decryption for the data read from input file, resultant encrypted/decrypted output is in write_buf */
		if (flag == 1)
			err = encrpt_blkcipher(read_buf, write_buf, bytes_read,
					       out_filp_temp, cipherkey_buf,
					       page_num);
		else
			err = decrypt_blkcipher(read_buf, write_buf, bytes_read,
						in_filp, cipherkey_buf,
						page_num);

		if (err) {
			printk(KERN_ERR	"Line no.:[%d] ERROR! function encrpt_decrypt_blkcipher fails, err: %d\n", __LINE__, err);
			goto out_free_writebuf;
		}
		/* Write encrypted/decrypted data block in .temp file */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		bytes_write = vfs_write(out_filp_temp, write_buf, bytes_read,
					&out_filp_temp->f_pos);
		set_fs(oldfs);

		/* Check if there is error in writing data to temp file or data partially written*/
		if (bytes_write < bytes_read) {
			printk(KERN_ERR	"Line no.:[%d] ERROR in writing data to temp file or data partially written, bytes_write: %d\n", __LINE__, bytes_write);
			err = bytes_write;
			goto out_free_writebuf;
		}

		/* Increment page num after every iteration */
		page_num++;
	}
	/* At this point, write to temp file is fully success. Therefore rename temp file to the output file
	   Take lock before doing vfs_rename. Code reference of vfs_rename taken from - http://lxr.free-electrons.com/source/fs/ecryptfs/inode.c#L631 */
	trap = lock_rename(out_filp_temp->f_path.dentry->d_parent,
			   out_filp->f_path.dentry->d_parent);

	/* Check for source should not be ancestor of target */
	if (trap == out_filp_temp->f_path.dentry) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function lock_rename fails, source is ancestor of target\n", __LINE__);
		err = -EINVAL;
		goto out_free_writebuf;
	}
	/* Check for target should not be ancestor of source */
	if (trap == out_filp->f_path.dentry) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function lock_rename fails, target is ancestor of source\n", __LINE__);
		err = -ENOTEMPTY;
		goto out_free_writebuf;
	}

	/* Close temp file before doing vfs_rename */
	if (!IS_ERR(out_filp_temp))
		filp_close(out_filp_temp, NULL);

	err = vfs_rename(out_filp_temp->f_path.dentry->d_parent->d_inode,
			 out_filp_temp->f_path.dentry,
			 out_filp->f_path.dentry->d_parent->d_inode,
			 out_filp->f_path.dentry, NULL, 0);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function vfs_rename fails, err: %d\n", __LINE__, err);
		goto out_free_writebuf;
	} else {
		/* Flag for storing status of vfs_rename success */
		vfs_rename_success_flag = 1;
	}
	unlock_rename(out_filp_temp->f_path.dentry->d_parent,
		      out_filp->f_path.dentry->d_parent);


out_free_writebuf:
	kfree(write_buf);
out_free_readbuf:
	kfree(read_buf);
out_free_readhashkey:
	kfree(read_hashkey);
out_free_hash:
	kfree(hash);
out_vfs_unlink_tempfile:
	/* If any error Unlink the temp file, this goto also handle the cases of Partial write fail. Take lock before doing vfs_unlink
	   Code reference of vfs_unlink taken from - http://lxr.free-electrons.com/source/fs/overlayfs/dir.c#L610 */
	if (!vfs_rename_success_flag) { /* Don't unlink temp file if vfs_rename is success */
		mutex_lock(&d_inode(
			out_filp_temp->f_path.dentry->d_parent)->i_mutex);
		ret1 = vfs_unlink(
			out_filp_temp->f_path.dentry->d_parent->d_inode,
			out_filp_temp->f_path.dentry, NULL);
		if (ret1)
			printk(KERN_ERR	"Line no.:[%d] ERROR! function vfs_unlink fails, ret1: %d\n", __LINE__, ret1);
		mutex_unlock(&d_inode(out_filp_temp->f_path.dentry->d_parent)->
			     i_mutex);

		/* If any error and output file doesn't exist from before, Unlink the output file */
		if (!output_file_exist_flag) {
			mutex_lock(&d_inode(out_filp->f_path.dentry->d_parent)->
				   i_mutex);
			ret1 = vfs_unlink(out_filp->f_path.dentry->
				d_parent->d_inode, out_filp->f_path.dentry,
				NULL);
			if (ret1)
				printk(KERN_ERR	"Line no.:[%d] ERROR! function vfs_unlink fails, ret1: %d\n", __LINE__, ret1);
			mutex_unlock(&d_inode(out_filp->f_path.dentry->d_parent)
				     ->i_mutex);
		} else {
			if (out_filp && !IS_ERR(out_filp))
				filp_close(out_filp, NULL);
		}
	} else {
		if (out_filp_temp && !IS_ERR(out_filp_temp))
			filp_close(out_filp_temp, NULL);
	}

	return (err | ret1);
}

/* Function to encrypt input file into the output file using cipher key */
int encrypt(char *infile, char *outfile, unsigned char *keybuf)
{
	int err = 0;
	struct file *in_filp = NULL, *out_filp = NULL, *out_filp_temp = NULL;

	/* Check file validations and file pointers of input and output files */
	err = file_validations(&in_filp, &out_filp, &out_filp_temp, infile,
			       outfile, keybuf);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function file_validations fails, err: %d\n", __LINE__, err);
		goto out;
	}

	/* Call read write function, which reads data -> encrypt/decrypt it -> write it to output file */
	err = read_write_file(in_filp, out_filp, out_filp_temp, keybuf, 1,
			      output_file_exist_flag);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function read_write_file fails, ret: %d\n", __LINE__, err);
		goto out;
	}

out:
	if (in_filp && !IS_ERR(in_filp))
		filp_close(in_filp, NULL);
	return err;
}

/* Function to decrypt input file into the output file using cipher key */
int decrypt(char *infile, char *outfile, unsigned char *keybuf)
{
	int err = 0;
	struct file *in_filp, *out_filp, *out_filp_temp;

	/* Check file validations and file pointers of input and output files */
	err = file_validations(&in_filp, &out_filp, &out_filp_temp, infile,
			       outfile, keybuf);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function file_validations fails, err: %d\n", __LINE__, err);
		goto out;
	}

	/* Call read write function, which reads data -> encrypt/decrypt it -> write it to output file */
	err = read_write_file(in_filp, out_filp, out_filp_temp, keybuf, 0,
			      output_file_exist_flag);
	if (err) {
		printk(KERN_ERR	"Line no.:[%d] ERROR! function read_write_file fails, ret: %d\n", __LINE__, err);
		goto out;
	}

out:
	if (in_filp && !IS_ERR(in_filp))
		filp_close(in_filp, NULL);
	return err;
}
