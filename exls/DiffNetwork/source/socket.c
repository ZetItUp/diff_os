#include <diffnetwork/socket.h>
#include <syscall.h>

int network_socket_create(uint8_t protocol)
{
    return do_sys(SYSTEM_NET_SOCKET_CREATE, protocol, 0, 0, 0);
}

int network_socket_close(int socket_id)
{
    return do_sys(SYSTEM_NET_SOCKET_CLOSE, socket_id, 0, 0, 0);
}

int network_socket_send(int socket_id, const network_socket_send_t *send_info)
{
    return do_sys(SYSTEM_NET_SOCKET_SEND, socket_id, (int)(uintptr_t)send_info, 0, 0);
}

int network_socket_recv(int socket_id, network_socket_packet_t *out_packet)
{
    return do_sys(SYSTEM_NET_SOCKET_RECV, socket_id, (int)(uintptr_t)out_packet, 0, 0);
}
