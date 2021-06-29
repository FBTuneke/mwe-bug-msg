// #include "../linux/usr/include/linux/bpf.h"
#include <linux/bpf.h>
// #include "../linux/usr/include/linux/io_uring.h"
#include <linux/io_uring.h>
// #include "../linux/tools/lib/bpf/bpf_helpers.h"
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") map =
{
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries = 2,
        .map_flags = BPF_F_MMAPABLE,
};

static long (*iouring_queue_sqe)(void *ctx, struct io_uring_sqe *sqe, __u32) = (void *) 164;
static long (*iouring_emit_cqe)(void *ctx, __u32 cq, __u64 data, __u32 res, __u32 flags) = (void *) 165;
static long (*iouring_reap_cqe)(void *ctx, __u32 cq, struct io_uring_cqe *cqe, __u32) = (void *) 166;

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    __u64 offset)
{
	sqe->opcode = op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->__pad2[0] = sqe->__pad2[1] = sqe->__pad2[2] = 0;
}

SEC("iouring.s/accept_cb")
int accept_cb(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe accept_cqe = {};
      __u32 key = 0;
      __u64 *ptr;
      char *addr;

      iouring_reap_cqe(ctx, 1, &accept_cqe, sizeof(accept_cqe));

      ptr = bpf_map_lookup_elem(&map, &key);     
      if(!ptr)
            return 0;

      addr = (char*) *ptr;

      // io_uring_prep_rw(IORING_OP_READ, &sqe, accept_cqe.res, addr, 128, 0);    
      io_uring_prep_rw(IORING_OP_RECV, &sqe, accept_cqe.res, addr, 128, 0);    
      sqe.cq_idx = 2; 
      sqe.flags = IOSQE_IO_HARDLINK;
      sqe.user_data = accept_cqe.res;
      iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

      io_uring_prep_rw(IORING_OP_BPF, &sqe, 0, 0, 0, 1);
      sqe.cq_idx = 3;
      iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

      return 0; 
}

SEC("iouring.s/read_cb")
int read_cb(struct io_uring_bpf_ctx *ctx)
{
	struct io_uring_cqe read_cqe = {};

      iouring_reap_cqe(ctx, 2, &read_cqe, sizeof(read_cqe));

      //Potentially write back received data to sender

      iouring_emit_cqe(ctx, 0, 777, read_cqe.res, 0);

      return 0; 
}

char _license[] SEC("license") = "GPL";
