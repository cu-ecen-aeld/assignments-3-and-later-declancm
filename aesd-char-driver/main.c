/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Declan Mullen");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */

    // Set filp->private_data with our aesd_dev device struct

    struct aesd_dev *dev;
	dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    struct aesd_dev *dev = filp->private_data;

    mutex_lock(&dev->lock);

    size_t entry_offset_byte;
    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset_byte);

    if (entry != NULL) {
        size_t bytes_to_copy = min(count, entry->size - entry_offset_byte);

        if (copy_to_user(buf, entry->buffptr + entry_offset_byte, bytes_to_copy)) {
            retval = -EFAULT;
        } else {
            retval = bytes_to_copy;
            *f_pos += bytes_to_copy;
        }
    }

    mutex_unlock(&dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    struct aesd_dev *dev = filp->private_data;

    char *kbuf = kmalloc(count, GFP_KERNEL);
    if (kbuf == NULL) {
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    // assemble the working entry and add it once a newline is found
    
    mutex_lock(&dev->lock);

    size_t kbuf_offset = 0;

    while (kbuf_offset < count) {
        char *newline = memchr(kbuf + kbuf_offset, '\n', count - kbuf_offset);
        bool newline_found = newline != NULL;
        size_t size = newline_found ? newline - (kbuf + kbuf_offset) + 1 : count - kbuf_offset;

        char *entry_buffptr = kmalloc(dev->working_entry.size + size, GFP_KERNEL);
        if (entry_buffptr == NULL) {
            retval = -ENOMEM;
            goto cleanup;
        }

        memcpy(entry_buffptr, dev->working_entry.buffptr, dev->working_entry.size);
        memcpy(entry_buffptr + dev->working_entry.size, kbuf + kbuf_offset, size);
        if (dev->working_entry.buffptr != NULL) {
            kfree(dev->working_entry.buffptr);
        }
        dev->working_entry.buffptr = entry_buffptr;
        dev->working_entry.size += size;

        if (newline_found) {
            const char *overwritten_buffptr = aesd_circular_buffer_add_entry(&dev->buffer, &dev->working_entry);
            if (overwritten_buffptr != NULL) {
                kfree(overwritten_buffptr);
            }

            dev->working_entry.buffptr = NULL;
            dev->working_entry.size = 0;
        }

        kbuf_offset += size;
    }

    retval = count;

cleanup:
    mutex_unlock(&dev->lock);
    kfree(kbuf);
    
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos;
    size_t size = 0;
    struct aesd_dev *dev = filp->private_data;
    PDEBUG("llseek");

    mutex_lock(&dev->lock);
    
    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        int idx = (dev->buffer.out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        if (i >= (dev->buffer.in_offs - dev->buffer.out_offs + 
                 (dev->buffer.in_offs <= dev->buffer.out_offs ? 
                  AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED : 0)))
            break;
        size += dev->buffer.entry[idx].size;
    }

    switch (whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = size + off;
            break;
        default:
            mutex_unlock(&dev->lock);
            return -EINVAL;
    }

    if (newpos < 0 || newpos > size) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    filp->f_pos = newpos;
    mutex_unlock(&dev->lock);

    return newpos;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    // initialize aesd_dev structure including locking primative

    aesd_circular_buffer_init(&aesd_device.buffer);
    aesd_device.working_entry.buffptr = NULL;
    aesd_device.working_entry.size = 0;
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    // cleanup anything allocated in aesd_init_module

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
