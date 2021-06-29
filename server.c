// #include "../linux/usr/include/linux/bpf.h"
// #include <liburing/io_uring.h>
#include "../linux/usr/include/linux/io_uring.h"
#include <linux/bpf.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
// #include "../linux/tools/lib/bpf/libbpf.h"
// #include "../linux/tools/lib/bpf/bpf.h"
#include "liburing.h"
#include <unistd.h>
#include <sys/uio.h>


#ifndef __NR_io_uring_register
      #define __NR_io_uring_register 427
#endif

int __sys_io_uring_register(int fd, unsigned opcode, const void *arg,
                            unsigned nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

int create_tcp_server(int port)
{ 
      int listen_fd;
      struct sockaddr_in servaddr;
      int flags = 1, ret;

      bzero(&servaddr, sizeof(servaddr));
      servaddr.sin_family = AF_INET;
      servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
      servaddr.sin_port = htons(port);
      
      listen_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (listen_fd < 0){
            printf("socket error : %d ...\n", errno);
            exit(EXIT_FAILURE);
      }

      setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
      setsockopt(listen_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));


      ret = bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));
      if (ret < 0){
            printf("bind error : %d ...\n", errno);
            exit(EXIT_FAILURE);
      }

      ret = listen(listen_fd, 32);
      if (ret < 0){
            printf("listen error: %i\n", ret);
            exit(EXIT_FAILURE);
      }

      printf("Server successfully created\n");

      return listen_fd;
}

int main(int arg, char **argv)
{
      struct io_uring ring;
      struct io_uring_params params;
      struct io_uring_cqe *cqe;
      struct io_uring_sqe *sqe;
      struct bpf_object *bpf_obj;
      struct bpf_program *bpf_prog;
      struct iovec iov;
      char buf[128];
      __u64 addr = (__u64)buf;
      int ret, sock_fd, map_fd, prog_fds[2];
      __u32 cq_sizes[3] = {32, 32, 32}, key = 0;

      memset(&params, 0, sizeof(params));
      
      params.nr_cq = 3;
	params.cq_sizes = (__u64)(unsigned long)cq_sizes;

      ret = io_uring_queue_init_params(128, &ring, &params);
      if (ret < 0){
            printf("io_uring_init_failed: %i\n", ret);
            exit(1);
      }
        
      sock_fd = create_tcp_server(7000);

      bpf_obj = bpf_object__open("bpf.o");
      ret = bpf_object__load(bpf_obj);
      if(ret < 0){
            printf("Error bpf_object__load, ret: %i\n", ret);
            exit(1);
      }

      map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "map");

      bpf_prog = bpf_program__next(NULL, bpf_obj);
      prog_fds[0] = bpf_program__fd(bpf_prog);

      bpf_prog = bpf_program__next(bpf_prog, bpf_obj);
      prog_fds[1] = bpf_program__fd(bpf_prog);

      bpf_map_update_elem(map_fd, &key, &addr, BPF_ANY);
      
      ret = __sys_io_uring_register(ring.ring_fd, IORING_REGISTER_BPF, prog_fds, 2);
      if(ret < 0){
            printf("Error __sys_io_uring_register, ret: %i\n", ret);
            exit(1);
      }

      sqe = io_uring_get_sqe(&ring);
      if (!sqe){
            printf("get sqe failed\n");
            exit(1);
      }
      io_uring_prep_accept(sqe, sock_fd, NULL, NULL, 0);
      sqe->flags = IOSQE_IO_LINK;
      sqe->cq_idx = 1; 

      sqe = io_uring_get_sqe(&ring);
      if (!sqe){
            printf("get sqe failed\n");
            exit(1);
      }
      io_uring_prep_nop(sqe);
	sqe->off = 0; 
	sqe->opcode = IORING_OP_BPF;
      sqe->cq_idx = 3;

      ret = io_uring_submit(&ring);
	if (ret <= 0) {
		printf("bpf-sqe submit failed: %i\n", ret);
		exit(1);
	}

      io_uring_wait_cqe(&ring, &cqe);
      io_uring_cqe_seen(&ring, cqe);
      
      printf("cqe->user_data: %i\n", cqe->user_data);
      printf("cqe->res: %i\n", cqe->res);
      printf("received: %s\n", buf);

	return 0;
}     