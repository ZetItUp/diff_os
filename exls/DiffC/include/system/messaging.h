#pragma once

#include <syscall.h>
#include <stdint.h>

int create_message_channel(int id);
int connect_message_channel(int id);
int send_message(int id, const void *buffer, uint32_t len);
int receive_message(int id, void *buffer, uint32_t buffer_len);
int try_receive_message(int id, void *buffer, uint32_t buffer_len);
