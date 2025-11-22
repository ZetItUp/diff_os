#pragma once

#define DWM_MAILBOX_MAGIC   0x44574D31      // DWM1

typedef enum
{
    DWM_MSG_CREATE_WINDOW = 1,
    DWM_MSG_DESTROY_WINDOW,
    DWM_MSG_EVENT
} dwm_msg_type_t;
