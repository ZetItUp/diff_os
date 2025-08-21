#include "system/spinlock.h"

static inline uint32_t irq_save(void)
{
    uint32_t flags;

    // Save flags and disable interrupts so nothing can preempt us here
    __asm__ __volatile__("pushf; pop %0; cli" : "=r"(flags) :: "memory");

    return flags;
}

static inline void irq_restore(uint32_t flags)
{
    // Restore previous interrupt flags
    __asm__ __volatile__("push %0; popf" :: "r"(flags) : "memory");
}

static inline uint32_t xchg_u32(volatile uint32_t* addr, uint32_t x)
{
    // Atomic exchange using x86 "lock xchg"
    // This swaps *addr with x and returns the old value
    __asm__ __volatile__("lock xchg %0, %1" : "+m"(*addr), "+r"(x) :: "memory");

    return x;
}

void spinlock_init(spinlock_t* lock)
{
    // 0 means unlocked
    lock->value = 0;
}

void spin_lock(spinlock_t* lock)
{
    // Try until we succeed, CPU hint "pause" reduces power usage while spinning
    while (xchg_u32(&lock->value, 1) != 0)
    {
        __asm__ __volatile__("pause");
    }
}

void spin_unlock(spinlock_t* lock)
{
    // Compiler + CPU barrier so nothing moves out of the critical section
    __asm__ __volatile__("" ::: "memory");

    // Release lock
    lock->value = 0;
}

void spin_lock_irqsave(spinlock_t* lock, uint32_t* flags)
{
    // Save interrupt state and disable interrupts
    uint32_t f = irq_save();

    // Acquire lock
    while (xchg_u32(&lock->value, 1) != 0)
    {
        __asm__ __volatile__("pause");
    }

    // Store saved flags so caller can restore them later
    *flags = f;
}

void spin_unlock_irqrestore(spinlock_t* lock, uint32_t flags)
{
    // Memory barrier to avoid moving instructions across unlock
    __asm__ __volatile__("" ::: "memory");

    // Release lock
    lock->value = 0;

    // Restore interrupts to previous state
    irq_restore(flags);
}

