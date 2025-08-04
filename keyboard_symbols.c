#include "ddf.h"

static const char string_table[] =
    "\x64\x64\x66\x5f\x68\x65\x61\x64\x65\x72\x00\x77\x61\x69\x74\x5f"
    "\x69\x6e\x70\x75\x74\x00\x77\x61\x69\x74\x5f\x6f\x75\x74\x70\x75"
    "\x74\x00\x6b\x62\x71\x5f\x73\x65\x6e\x64\x5f\x63\x6d\x64\x00\x6b"
    "\x62\x71\x5f\x73\x74\x61\x72\x74\x5f\x6e\x65\x78\x74\x00\x6b\x62"
    "\x71\x5f\x65\x6e\x71\x75\x65\x75\x65\x00\x69\x38\x30\x34\x32\x5f"
    "\x69\x6e\x69\x74\x00\x64\x64\x66\x5f\x64\x72\x69\x76\x65\x72\x5f"
    "\x69\x6e\x69\x74\x00\x64\x64\x66\x5f\x64\x72\x69\x76\x65\x72\x5f"
    "\x65\x78\x69\x74\x00\x64\x64\x66\x5f\x64\x72\x69\x76\x65\x72\x5f"
    "\x69\x72\x71\x00\x6b\x62\x5f\x72\x65\x73\x65\x6e\x64\x5f\x6c\x69"
    "\x6d\x69\x74\x00\x6d\x79\x5f\x6b\x65\x72\x6e\x65\x6c\x5f\x61\x64"
    "\x64\x72\x00\x6b\x65\x72\x6e\x65\x6c\x00\x6b\x62\x5f\x63\x6d\x64"
    "\x71\x00\x6b\x62\x5f\x71\x5f\x68\x65\x61\x64\x00\x6b\x62\x5f\x71"
    "\x5f\x74\x61\x69\x6c\x00\x6b\x62\x5f\x71\x5f\x63\x6f\x75\x6e\x74"
    "\x00\x6b\x62\x5f\x63\x6d\x64\x71\x5f\x73\x74\x61\x74\x65\x00"
    ;

ddf_symbol_t ddf_symbol_table[] = {
    { .name_offset = 0x0, .value_offset = 0x0, .type = 1 }, // ddf_header
    { .name_offset = 0xb, .value_offset = 0x24, .type = 0 }, // wait_input
    { .name_offset = 0x16, .value_offset = 0x5f, .type = 0 }, // wait_output
    { .name_offset = 0x22, .value_offset = 0x9a, .type = 0 }, // kbq_send_cmd
    { .name_offset = 0x2f, .value_offset = 0xf8, .type = 0 }, // kbq_start_next
    { .name_offset = 0x3e, .value_offset = 0x138, .type = 0 }, // kbq_enqueue
    { .name_offset = 0x4a, .value_offset = 0x1c4, .type = 0 }, // i8042_init
    { .name_offset = 0x55, .value_offset = 0x288, .type = 0 }, // ddf_driver_init
    { .name_offset = 0x65, .value_offset = 0x311, .type = 0 }, // ddf_driver_exit
    { .name_offset = 0x75, .value_offset = 0x341, .type = 0 }, // ddf_driver_irq
    { .name_offset = 0x84, .value_offset = 0x5a4, .type = 1 }, // kb_resend_limit
    { .name_offset = 0x94, .value_offset = 0x5a8, .type = 1 }, // my_kernel_addr
    { .name_offset = 0xa3, .value_offset = 0x5c0, .type = 1 }, // kernel
    { .name_offset = 0xaa, .value_offset = 0x5e0, .type = 1 }, // kb_cmdq
    { .name_offset = 0xb2, .value_offset = 0x670, .type = 1 }, // kb_q_head
    { .name_offset = 0xbc, .value_offset = 0x674, .type = 1 }, // kb_q_tail
    { .name_offset = 0xc6, .value_offset = 0x678, .type = 1 }, // kb_q_count
    { .name_offset = 0xd1, .value_offset = 0x67c, .type = 1 }, // kb_cmdq_state
};

const uint32_t ddf_symbol_table_count = 18;
