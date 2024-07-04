#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>  	
#include <linux/slab.h>
#include <linux/fs.h>       		
#include <linux/errno.h>  
#include <linux/types.h> 
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "encdec.h"

#define MODULE_NAME "encdec"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YOUR NAME");

int 	encdec_open(struct inode *inode, struct file *filp);
int 	encdec_release(struct inode *inode, struct file *filp);
int 	encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

int memory_size = 0;

MODULE_PARM(memory_size, "i");

int major = 0;

struct file_operations fops_caesar = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_caesar,
	.write 	 =	encdec_write_caesar,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};

struct file_operations fops_xor = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_xor,
	.write 	 =	encdec_write_xor,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};

// Implemetation suggestion:
// -------------------------
// Use this structure as your file-object's private data structure
typedef struct {
	unsigned char key;
	int read_state;
} encdec_private_date;
int init_module(void)
{
	major = register_chrdev(major, MODULE_NAME, &fops_caesar);
	if (major < 0) {
		return major;
	}

	// Allocate memory for buffer1
	char* buffer1 = kmalloc(memory_size, GFP_KERNEL);
	if (!buffer1) {
		printk(KERN_ERR "Failed to allocate memory for buffer1\n");
		unregister_chrdev(major, MODULE_NAME);
		return -ENOMEM;
	}

	// Allocate memory for buffer2
	char* buffer2 = kmalloc(memory_size, GFP_KERNEL);
	if (!buffer2) {
		printk(KERN_ERR "Failed to allocate memory for buffer2\n");
		kfree(buffer1);
		unregister_chrdev(major, MODULE_NAME);
		return -ENOMEM;
	}

	return 0;
}


	// Implemetation suggestion:
	// -------------------------
	// 1. Allocate memory for the two device buffers using kmalloc (each of them should be of size 'memory_size')

	return 0;
}

void cleanup_module(void)
{
	unregister_chrdev(major, MODULE_NAME);
	if (buffer1) {
		kfree(buffer1);
	}
	if (buffer2) {
		kfree(buffer2);
	}
	// Implemetation suggestion:
	// -------------------------	
	// 1. Unregister the device-driver
	// 2. Free the allocated device buffers using kfree
}

int encdec_open(struct inode *inode, struct file *filp)
{
	int minor = MINOR(inode->i_rdev);
	if (minor == 0) {
		filp->f_op = &fops_caesar;
	}
	else if (minor == 1) {
		filp->f_op = &fops_xor;
	}
	else {
		return -ENODEV;
	}
	private_data = kmalloc(sizeof(encdec_private_data), GFP_KERNEL);
	if (!private_data) {
		printk(KERN_ERR "Failed to allocate memory for private data\n");
		return -ENOMEM;
	}
	// Initialize private data
	private_data->key = ENCDEC_CMD_CHANGE_KEY;
	private_data->read_state = ENCDEC_READ_STATE_RAW;
	// Implemetation suggestion:
	// -------------------------
	// 1. Set 'filp->f_op' to the correct file-operations structure (use the minor value to determine which)
	// 2. Allocate memory for 'filp->private_data' as needed (using kmalloc)
	filp->private_data = private_data;
	return 0;
}

int encdec_release(struct inode *inode, struct file *filp)
{
	if (filp->private_data) {
		kfree(filp->private_data);
	}
	return 0;
}

int encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ENCDEC_CMD_CHANGE_KEY:
		filp ->private_data->key = (unsigned char)arg;
		break;
	case ENCDEC_CMD_SET_READ_STATE:
		filp->private_data->read_state = (int)arg;
		break;
	case ENCDEC_CMD_ZERO:
		if (filp->private_data->buffer1) {
			memset(filp->private_data->buffer1, 0, memory_size);
		}
		if (filp->private_data->buffer2) {
			memset(filp->private_data->buffer2, 0, memory_size);
		}
		printk(KERN_INFO "Device buffer has been reset to zero.\n");
		break;
	default:
		return -ENOTTY;  
	}
	return 0;
}
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos) {

}
// Add implementations for:
// ------------------------
// 1. ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
// 2. ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);
// 3. ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
// 4. ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);