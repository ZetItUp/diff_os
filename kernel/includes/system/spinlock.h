#pragma once
#include <stdint.h>
#include <stdbool.h>

// Types

typedef struct
{
    volatile uint32_t value;
} spinlock_t;

// API

void spinlock_init(spinlock_t* lock);
void spin_lock(spinlock_t* lock);
void spin_unlock(spinlock_t* lock);
void spin_lock_irqsave(spinlock_t* lock, uint32_t* flags);
void spin_unlock_irqrestore(spinlock_t* lock, uint32_t flags);

