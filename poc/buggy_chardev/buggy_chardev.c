// SPDX-License-Identifier: GPL-2.0
// A minimal kernel module with a logic bug: read() returns more bytes than requested.
// This simulates real-world bugs like CVE-2020-14386 (af_packet tpacket_rcv size miscalculation).
// Logickaller detects this; syzkaller does not because no crash occurs.

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "buggy_chardev"
#define BUF_SIZE 4096

static char internal_buf[BUF_SIZE];

static ssize_t buggy_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	// BUG: Always copies BUF_SIZE bytes and returns BUF_SIZE,
	// ignoring the user-requested count.
	// This is a logic bug (info leak / buffer overread) that does NOT crash.
	size_t to_copy = BUF_SIZE;

	if (copy_to_user(buf, internal_buf, to_copy))
		return -EFAULT;

	return to_copy; // Bug: should return min(count, to_copy)
}

static ssize_t buggy_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	size_t to_copy = count < BUF_SIZE ? count : BUF_SIZE;
	if (copy_from_user(internal_buf, buf, to_copy))
		return -EFAULT;
	return to_copy;
}

static int buggy_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int buggy_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations buggy_fops = {
	.owner   = THIS_MODULE,
	.read    = buggy_read,
	.write   = buggy_write,
	.open    = buggy_open,
	.release = buggy_release,
};

static struct miscdevice buggy_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = DEVICE_NAME,
	.fops  = &buggy_fops,
};

static int __init buggy_init(void)
{
	memset(internal_buf, 'A', BUF_SIZE);
	return misc_register(&buggy_misc);
}

static void __exit buggy_exit(void)
{
	misc_deregister(&buggy_misc);
}

module_init(buggy_init);
module_exit(buggy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Buggy chardev for logickaller PoC");
