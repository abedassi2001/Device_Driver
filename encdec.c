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

// Function prototypes for the file operations
int encdec_open(struct inode* inode, struct file* filp);
int encdec_release(struct inode* inode, struct file* filp);
int encdec_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar(struct file* filp, char* buf, size_t count, loff_t* f_pos);
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos);

ssize_t encdec_read_xor(struct file* filp, char* buf, size_t count, loff_t* f_pos);
ssize_t encdec_write_xor(struct file* filp, const char* buf, size_t count, loff_t* f_pos);

// Parameters and buffers for the module
int memory_size = 0;
char* buffer1;
char* buffer2;
MODULE_PARM(memory_size, "i");

int major = 0;

// File operations for the Caesar cipher
struct file_operations fops_caesar = {
    .open = encdec_open,
    .release = encdec_release,
    .read = encdec_read_caesar,
    .write = encdec_write_caesar,
    .llseek = NULL,
    .ioctl = encdec_ioctl,
    .owner = THIS_MODULE
};

// File operations for the XOR cipher
struct file_operations fops_xor = {
    .open = encdec_open,
    .release = encdec_release,
    .read = encdec_read_xor,
    .write = encdec_write_xor,
    .llseek = NULL,
    .ioctl = encdec_ioctl,
    .owner = THIS_MODULE
};

// Structure for private data
typedef struct {
    unsigned char key;
    int read_state;
} encdec_private_date;

// Initialization function for the module
int init_module(void)
{
    // Register the device with the system
    major = register_chrdev(major, MODULE_NAME, &fops_caesar);
    if (major < 0)
    {
        return major;
    }

    // Allocate memory for buffer1
    buffer1 = kmalloc(memory_size, GFP_KERNEL);
    if (!buffer1)
    {
        unregister_chrdev(major, MODULE_NAME);
        return -ENOMEM;
    }

    // Allocate memory for buffer2
    buffer2 = kmalloc(memory_size, GFP_KERNEL);
    if (!buffer2)
    {
        kfree(buffer1);
        unregister_chrdev(major, MODULE_NAME);
        return -ENOMEM;
    }
    return 0;
}

// Cleanup function for the module
void cleanup_module(void)
{
    unregister_chrdev(major, MODULE_NAME);
    if (buffer1)
    {
        kfree(buffer1);
    }
    if (buffer2)
    {
        kfree(buffer2);
    }
    // Unregister the device-driver and free the allocated device buffers
}

// Open function for the device
int encdec_open(struct inode* inode, struct file* filp)
{
    int minor = MINOR(inode->i_rdev);
    if (minor == 0)
    {
        filp->f_op = &fops_caesar;
    }
    else if (minor == 1)
    {
        filp->f_op = &fops_xor;
    }
    else
    {
        return -ENODEV;
    }

    encdec_private_date* private_data = kmalloc(sizeof(encdec_private_date), GFP_KERNEL);
    if (!private_data)
    {
        return -ENOMEM;
    }

    private_data->key = 0;                     // Initialize key to 0
    private_data->read_state = ENCDEC_READ_STATE_RAW;
    filp->private_data = private_data;
    return 0;
}

// Release function for the device
int encdec_release(struct inode* inode, struct file* filp)
{
    if (filp->private_data)
    {
        kfree(filp->private_data);
    }
    return 0;
}

// IOCTL function for the device
int encdec_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
    case ENCDEC_CMD_CHANGE_KEY:
        ((encdec_private_date*)filp->private_data)->key = (unsigned char)arg;
        break;
    case ENCDEC_CMD_SET_READ_STATE:
        ((encdec_private_date*)filp->private_data)->read_state = (int)arg;
        break;
    case ENCDEC_CMD_ZERO:
        if (buffer1)
        {
            memset(buffer1, 0, memory_size);
        }
        if (buffer2)
        {
            memset(buffer2, 0, memory_size);
        }
        break;
    default:
        return -ENOTTY;
    }
    return 0;
}

// Write function for the Caesar cipher
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos)
{
    char buf3[memory_size]; // Stack allocation
    int i;

    if (*f_pos >= memory_size - 1)
    {
        return -ENOSPC;
    }

    if (copy_from_user(buf3, buf, count))
    {
        return -EFAULT;
    }

    i = 0;
    while (*f_pos < memory_size && i < count)
    {
        buffer1[*f_pos] = ((buf3[i] + ((encdec_private_date*)filp->private_data)->key) % 128);
        (*f_pos)++;
        i++;
    }

    return i;
}

// Write function for the XOR cipher
ssize_t encdec_write_xor(struct file* filp, const char* buf, size_t count, loff_t* f_pos)
{
    char buf3[memory_size]; // Stack allocation
    int i;

    if (*f_pos >= memory_size - 1)
    {
        return -ENOSPC;
    }

    if (copy_from_user(buf3, buf, count))
    {
        return -EFAULT;
    }

    i = 0;
    while (*f_pos < memory_size && i < count)
    {
        buffer2[*f_pos] = (buf3[i] ^ ((encdec_private_date*)filp->private_data)->key);
        (*f_pos)++;
        i++;
    }

    return i;
}

// Read function for the Caesar cipher
ssize_t encdec_read_caesar(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
    char buf3[memory_size]; // Stack allocation
    int i;

    if (*f_pos >= memory_size - 1)
    {
        return -EINVAL;
    }

    i = 0;
    if (((encdec_private_date*)filp->private_data)->read_state == ENCDEC_READ_STATE_RAW)
    {
        while (*f_pos < memory_size && i < count)
        {
            buf3[i] = buffer1[*f_pos];
            (*f_pos)++;
            i++;
        }
    }
    else if (((encdec_private_date*)filp->private_data)->read_state == ENCDEC_READ_STATE_DECRYPT)
    {
        while (*f_pos < memory_size && i < count)
        {
            buf3[i] = (((buffer1[*f_pos] - ((encdec_private_date*)filp->private_data)->key) + 128) % 128);
            (*f_pos)++;
            i++;
        }
    }

    if (copy_to_user(buf, buf3, count))
    {
        return -EFAULT;
    }

    return i;
}

// Read function for the XOR cipher
ssize_t encdec_read_xor(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
    char buf3[memory_size]; // Stack allocation
    int i;

    if (*f_pos >= memory_size - 1)
    {
        return -EINVAL;
    }

    i = 0;
    if (((encdec_private_date*)filp->private_data)->read_state == ENCDEC_READ_STATE_RAW)
    {
        while (*f_pos < memory_size && i < count)
        {
            buf3[i] = buffer2[*f_pos];
            (*f_pos)++;
            i++;
        }
    }
    else if (((encdec_private_date*)filp->private_data)->read_state == ENCDEC_READ_STATE_DECRYPT)
    {
        while (*f_pos < memory_size && i < count)
        {
            buf3[i] = (buffer2[*f_pos] ^ ((encdec_private_date*)filp->private_data)->key);
            (*f_pos)++;
            i++;
        }
    }

    if (copy_to_user(buf, buf3, count))
    {
        return -EFAULT;
    }

    return i;
}
