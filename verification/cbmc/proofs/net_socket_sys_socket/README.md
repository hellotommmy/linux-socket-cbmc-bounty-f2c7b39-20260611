# net_socket_sys_socket

This proof verifies the Linux `__sys_socket` source slice against explicit
socket-creation contracts.

Key postconditions:

- unsupported creation flags return `-EINVAL`
- unsupported flags do not call `sock_create` or `sock_map_fd`
- supported flags call `sock_create` exactly once
- `sock_create` receives `type & SOCK_TYPE_MASK`
- the default protocol hook preserves `protocol`
- `sock_create` errors propagate exactly and skip fd mapping
- successful socket creation calls `sock_map_fd` exactly once
- fd mapping receives normalized `O_CLOEXEC | O_NONBLOCK` flags only
- the final result is exactly the modeled `sock_map_fd` result

The proof has two variants:

- `linux_generic`: `SOCK_NONBLOCK == O_NONBLOCK`
- `arch_distinct_nonblock`: `SOCK_NONBLOCK != O_NONBLOCK`

