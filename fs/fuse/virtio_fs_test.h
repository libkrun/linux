/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _VIRTIO_FS_TEST_H
#define _VIRTIO_FS_TEST_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct file_system_type;

/* Private test ABI; mirrored by tools/testing/selftests/filesystems/virtiofs. */
struct virtio_fs_test_req {
	__u32 mount_fd;
	__u32 opcode;
	__u64 nodeid;
	__aligned_u64 in_ptr;
	__aligned_u64 out_ptr;
	__u32 in_len;
	__u32 out_len;
	__u32 uid;
	__u32 gid;
	__u32 pid;
	__s32 error;
	__u32 out_actual;
	__u32 reserved;
};

#define VIRTIO_FS_TEST_REQUEST _IOWR(0xe5, 0, struct virtio_fs_test_req)
#define VIRTIO_FS_TEST_MAX_PAYLOAD 16384

#ifdef CONFIG_VIRTIO_FS_TEST
int virtio_fs_test_init(struct file_system_type *type);
void virtio_fs_test_exit(void);
#else
static inline int virtio_fs_test_init(struct file_system_type *type)
{
	return 0;
}

static inline void virtio_fs_test_exit(void)
{
}
#endif

#endif /* _VIRTIO_FS_TEST_H */
