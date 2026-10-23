// SPDX-License-Identifier: GPL-2.0
/* Explicitly triggered raw requests for virtio-fs host confinement tests. */

#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "dev.h"
#include "fuse_i.h"
#include "virtio_fs_test.h"

static struct file_system_type *virtio_fs_test_type;

static void virtio_fs_test_add_secctx(struct fuse_mount *fm,
				     struct fuse_args *args,
				     const struct fuse_secctx_header *secctx)
{
	if (!fm->fc->init_security)
		return;

	switch (args->opcode) {
	case FUSE_CREATE:
	case FUSE_MKDIR:
	case FUSE_MKNOD:
	case FUSE_SYMLINK:
		/* The negotiated extension is mandatory even with no contexts. */
		args->is_ext = true;
		args->ext_idx = args->in_numargs++;
		args->in_args[args->ext_idx].size = sizeof(*secctx);
		args->in_args[args->ext_idx].value = secctx;
		break;
	}
}

static long virtio_fs_test_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct virtio_fs_test_req req;
	struct fuse_mount *fm;
	void __user *user_req = (void __user *)arg;
	void *in = NULL, *out = NULL;
	struct fd mount;
	struct fuse_args args = {};
	struct fuse_secctx_header secctx = { .size = sizeof(secctx) };
	ssize_t result;
	long err;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != VIRTIO_FS_TEST_REQUEST)
		return -ENOTTY;
	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;
	if (req.reserved || req.in_len > VIRTIO_FS_TEST_MAX_PAYLOAD ||
	    req.out_len > VIRTIO_FS_TEST_MAX_PAYLOAD)
		return -EINVAL;

	/* Do not renegotiate or tear down a live filesystem connection. */
	switch (req.opcode) {
	case FUSE_INIT:
	case FUSE_DESTROY:
	case FUSE_INTERRUPT:
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
	case FUSE_NOTIFY_REPLY:
		return -EOPNOTSUPP;
	}

	/* Holding the file pins both the mount and its FUSE connection. */
	mount = fdget(req.mount_fd);
	if (fd_empty(mount))
		return -EBADF;
	err = -EXDEV;
	if (file_inode(fd_file(mount))->i_sb->s_type != virtio_fs_test_type)
		goto out_fd;
	fm = get_fuse_mount(file_inode(fd_file(mount)));
	if (req.in_len) {
		in = memdup_user(u64_to_user_ptr(req.in_ptr), req.in_len);
		if (IS_ERR(in)) {
			err = PTR_ERR(in);
			goto out_fd;
		}
	}
	err = -ENOMEM;
	if (req.out_len) {
		out = kzalloc(req.out_len, GFP_KERNEL);
		if (!out)
			goto out_free;
	}

	args.opcode = req.opcode;
	args.nodeid = req.nodeid;
	args.uid = req.uid;
	args.gid = req.gid;
	args.pid = req.pid;
	if (req.in_len) {
		args.in_numargs = 1;
		args.in_args[0].size = req.in_len;
		args.in_args[0].value = in;
	}
	if (req.out_len) {
		args.out_numargs = 1;
		args.out_argvar = true;
		args.out_args[0].size = req.out_len;
		args.out_args[0].value = out;
	}
	virtio_fs_test_add_secctx(fm, &args, &secctx);

	/* Preserve the supplied credentials and bypass all VFS validation. */
	result = fuse_chan_send(fm->fc->chan, &args);
	req.error = result < 0 ? result : 0;
	req.out_actual = result < 0 ? 0 : result;
	err = -EIO;
	if (req.out_actual > req.out_len)
		goto out_free;
	err = -EFAULT;
	if (req.out_actual &&
	    copy_to_user(u64_to_user_ptr(req.out_ptr), out, req.out_actual))
		goto out_free;
	if (copy_to_user(user_req, &req, sizeof(req)))
		goto out_free;
	err = 0;

out_free:
	kfree(out);
	kfree(in);
out_fd:
	fdput(mount);
	return err;
}

static const struct file_operations virtio_fs_test_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = virtio_fs_test_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static struct miscdevice virtio_fs_test_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "virtiofs-test",
	.fops = &virtio_fs_test_fops,
	.mode = 0600,
};

int virtio_fs_test_init(struct file_system_type *type)
{
	virtio_fs_test_type = type;
	return misc_register(&virtio_fs_test_dev);
}

void virtio_fs_test_exit(void)
{
	misc_deregister(&virtio_fs_test_dev);
}
