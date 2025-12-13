#include <system/messaging.h>

int create_message_channel(int id)
{
    return system_message_create_channel(id);
}

int connect_message_channel(int id)
{
    return system_message_connect_channel(id);
}

int send_message(int id, const void *buffer, uint32_t len)
{
    return system_message_send(id, buffer, len);
}

int receive_message(int id, void *buffer, uint32_t buffer_len)
{
    return system_message_receive(id, buffer, buffer_len);
}

int receive_message_timeout(int id, void *buffer, uint32_t buffer_len, uint32_t timeout_ms)
{
    return system_message_receive_timeout(id, buffer, buffer_len, timeout_ms);
}

int try_receive_message(int id, void *buffer, uint32_t buffer_len)
{
    return system_message_try_receive(id, buffer, buffer_len);
}

int message_channel_owner(int id)
{
    return system_message_get_owner(id);
}
