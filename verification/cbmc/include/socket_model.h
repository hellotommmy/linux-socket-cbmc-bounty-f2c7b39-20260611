// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef VKERNEL_CBMC_SOCKET_MODEL_H
#define VKERNEL_CBMC_SOCKET_MODEL_H

#include "kernel_compat.h"

extern int socket_model_sock_create_calls;
extern int socket_model_sock_create_family;
extern int socket_model_sock_create_type;
extern int socket_model_sock_create_protocol;
extern int socket_model_sock_create_ret;
extern struct socket *socket_model_created_socket;

extern int socket_model_sock_map_fd_calls;
extern struct socket *socket_model_sock_map_fd_sock;
extern int socket_model_sock_map_fd_flags;
extern int socket_model_sock_map_fd_ret;

void socket_model_reset(void);
int socket_model_sock_create(int family, int type, int protocol,
			     struct socket **res);
int socket_model_sock_map_fd(struct socket *sock, int flags);

#endif
