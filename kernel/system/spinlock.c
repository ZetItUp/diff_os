#include "system/spinlock.h"

static inline uint32_t irq_save(void)
{
    uint32_t flags;
    __asm__ __volatile__("pushf; pop %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

static inline void irq_restore(uint32_t flags)
{
    __asm__ __volatile__("push %0; popf" :: "r"(flags) : "memory");
}

static inline uint32_t xchg_u32(volatile uint32_t* addr, uint32_t x)
{
    __asm__ __volatile__("lock xchg %0, %1" : "+m"(*addr), "+r"(x) :: "memory");
    return x;
}

void spinlock_init(spinlock_t* lock)
{
    lock->value = 0;
}

void spin_lock(spinlock_t* lock)
{
    while (xchg_u32(&lock->value, 1) != 0)
    {
        __asm__ __volatile__("pause");
    }
}

void spin_unlock(spinlock_t* lock)
{
    __asm__ __volatile__("" ::: "memory");
    lock->value = 0;
}

void spin_lock_irqsave(spinlock_t* lock, uint32_t* flags)
{
    uint32_t f = irq_save();
    while (xchg_u32(&lock->value, 1) != 0)
    {
        __asm__ __volatile__("pause");
    }
    *flags = f;
}

void spin_unlock_irqrestore(spinlock_t* lock, uint32_t flags)
{
    __asm__ __volatile__("" ::: "memory");
    lock->value = 0;
    irq_restore(flags);
}

