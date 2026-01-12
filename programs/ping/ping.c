#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <diffnetwork/socket.h>

static int parse_ipv4(const char *text, uint8_t out_ip[4])
{
    int segment_index = 0;
    int segment_value = 0;
    int saw_digit = 0;

    if (!text || !out_ip || text[0] == '\0')
    {

        return -1;
    }

    for (const char *cursor = text; ; cursor++)
    {
        char character = *cursor;

        if (character >= '0' && character <= '9')
        {
            segment_value = segment_value * 10 + (character - '0');
            if (segment_value > 255)
            {

                return -1;
            }

            saw_digit = 1;
            continue;
        }

        if (character == '.' || character == '\0')
        {
            if (!saw_digit || segment_index >= 4)
            {

                return -1;
            }

            out_ip[segment_index] = (uint8_t)segment_value;
            segment_index++;

            if (character == '\0')
            {
                break;
            }

            segment_value = 0;
            saw_digit = 0;
            continue;
        }


        return -1;
    }

    if (segment_index != 4)
    {

        return -1;
    }

    return 0;
}

static void print_ip(const uint8_t ip_address[4])
{
    printf("%u.%u.%u.%u",
        (unsigned)ip_address[0],
        (unsigned)ip_address[1],
        (unsigned)ip_address[2],
        (unsigned)ip_address[3]);
}

int main(int argc, char *argv[])
{
    if (argc < 1)
    {
        printf("ping: usage ping <ip> [count]\n");

        return 1;
    }

    uint8_t destination_ip[4];
    if (parse_ipv4(argv[0], destination_ip) != 0)
    {
        printf("ping: invalid ip %s\n", argv[0]);

        return 1;
    }

    int count = 4;
    if (argc >= 2)
    {
        int parsed_count = atoi(argv[1]);
        if (parsed_count > 0)
        {
            count = parsed_count;
        }
    }

    int socket_id = network_socket_create(NETWORK_SOCKET_PROTOCOL_ICMP);
    if (socket_id < 0)
    {
        printf("ping: failed to open socket\n");

        return 1;
    }

    uint16_t identifier = (uint16_t)(monotonic_ms() & 0xFFFF);
    uint8_t payload[32];
    memset(payload, 0x42, sizeof(payload));

    printf("PING ");
    print_ip(destination_ip);
    printf(" %u bytes\n", (unsigned)sizeof(payload));

    for (uint16_t sequence = 0; sequence < (uint16_t)count; sequence++)
    {
        network_socket_send_t send_info;
        memset(&send_info, 0, sizeof(send_info));

        memcpy(send_info.destination_ip, destination_ip, sizeof(destination_ip));
        send_info.identifier = identifier;
        send_info.sequence = sequence;
        send_info.payload_length = (uint16_t)sizeof(payload);
        send_info.payload = payload;

        uint64_t send_time = monotonic_ms();

        if (network_socket_send(socket_id, &send_info) != 0)
        {
            printf("ping: send failed\n");

            break;
        }

        uint64_t deadline_ms = send_time + 1000;
        int received_reply = 0;

        while (monotonic_ms() < deadline_ms)
        {
            network_socket_packet_t packet;
            if (network_socket_recv(socket_id, &packet) == 0)
            {
                if (packet.identifier == identifier && packet.sequence == sequence)
                {
                    uint64_t now_ms = monotonic_ms();
                    uint32_t elapsed_ms = (uint32_t)(now_ms - send_time);

                    printf("Reply from ");
                    print_ip(packet.source_ip);
                    printf(": seq=%u time=%ums\n",
                        (unsigned)sequence,
                        (unsigned)elapsed_ms);
                    received_reply = 1;

                    break;
                }
            }

            msleep(10);
        }

        if (!received_reply)
        {
            printf("Request timed out\n");
        }

        msleep(1000);
    }

    network_socket_close(socket_id);

    return 0;
}
