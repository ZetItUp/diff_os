#include <stddef.h>
#include <stdint.h>

#ifndef QS_INSERTION_THRESHOLD
#define QS_INSERTION_THRESHOLD 16
#endif

static inline void swap_bytes(uint8_t *a, uint8_t *b, size_t n)
{
    while (n--)
    {
        uint8_t t = *a;
        *a++ = *b;
        *b++ = t;
    }
}

static inline void swap_words(uintptr_t *a, uintptr_t *b, size_t n)
{
    while (n--)
    {
        uintptr_t t = *a;
        *a++ = *b;
        *b++ = t;
    }
}

static inline void swap_elems(void *pa, void *pb, size_t size)
{
    if (pa == pb)
    {
        return;
    }

    uintptr_t ua = (uintptr_t)pa;
    uintptr_t ub = (uintptr_t)pb;

    if (((ua | ub | size) & (sizeof(uintptr_t) - 1)) == 0)
    {
        swap_words((uintptr_t *)pa, (uintptr_t *)pb, size / sizeof(uintptr_t));
    }
    else
    {
        swap_bytes((uint8_t *)pa, (uint8_t *)pb, size);
    }
}

static inline void *elem(void *base, size_t size, size_t i)
{
    return (void *)((uint8_t *)base + i * size);
}

static size_t median3(void *base, size_t size, size_t a, size_t b, size_t c,
                      int (*cmp)(const void *, const void *))
{
    void *A = elem(base, size, a);
    void *B = elem(base, size, b);
    void *C = elem(base, size, c);

    int ab = cmp(A, B);
    int ac = cmp(A, C);
    int bc = cmp(B, C);

    if (ab < 0)
    {
        return (bc < 0) ? b : ((ac < 0) ? c : a);
    }
    else
    {
        return (bc > 0) ? b : ((ac > 0) ? c : a);
    }
}

static void insertion_sort(void *base, size_t n, size_t size,
                           int (*cmp)(const void *, const void *))
{
    uint8_t *b = (uint8_t *)base;

    for (size_t i = 1; i < n; i++)
    {
        size_t j = i;

        // Copy current element into a small stack buffer if size is tiny,
        // otherwise swap down (branch avoids large VLAs).
        uint8_t tmp_buf[64];
        uint8_t *key;
        int use_tmp = (size <= sizeof(tmp_buf));

        if (use_tmp)
        {
            key = tmp_buf;
            for (size_t k = 0; k < size; k++)
            {
                tmp_buf[k] = b[i * size + k];
            }
        }
        else
        {
            key = &b[i * size]; // will swap downward
        }

        while (j > 0)
        {
            void *prev = &b[(j - 1) * size];
            void *curr = &b[j * size];

            if (use_tmp)
            {
                if (cmp(prev, key) <= 0)
                {
                    break;
                }
                // Move prev down
                for (size_t k = 0; k < size; k++)
                {
                    ((uint8_t *)curr)[k] = ((uint8_t *)prev)[k];
                }
            }
            else
            {
                if (cmp(prev, key) <= 0)
                {
                    break;
                }
                swap_elems(prev, curr, size);
            }

            j--;
        }

        if (use_tmp)
        {
            // Place key at position j
            uint8_t *dst = &b[j * size];
            for (size_t k = 0; k < size; k++)
            {
                dst[k] = tmp_buf[k];
            }
        }
    }
}

static void sift_down(void *base, size_t n, size_t size, size_t start,
                      int (*cmp)(const void *, const void *))
{
    size_t root = start;

    while (1)
    {
        size_t child = root * 2 + 1;
        if (child >= n)
        {
            break;
        }

        size_t swap_i = root;

        if (cmp(elem(base, size, swap_i), elem(base, size, child)) < 0)
        {
            swap_i = child;
        }
        if (child + 1 < n &&
            cmp(elem(base, size, swap_i), elem(base, size, child + 1)) < 0)
        {
            swap_i = child + 1;
        }
        if (swap_i == root)
        {
            return;
        }

        swap_elems(elem(base, size, root), elem(base, size, swap_i), size);
        root = swap_i;
    }
}

static void heap_sort(void *base, size_t n, size_t size,
                      int (*cmp)(const void *, const void *))
{
    if (n < 2)
    {
        return;
    }

    // Build heap
    for (size_t start = (n - 2) / 2 + 0; start + 1 > 0; start--)
    {
        sift_down(base, n, size, start, cmp);
        if (start == 0)
        {
            break;
        }
    }

    // Pop max repeatedly
    for (size_t end = n - 1; end > 0; end--)
    {
        swap_elems(elem(base, size, 0), elem(base, size, end), size);
        sift_down(base, end, size, 0, cmp);
    }
}

static void tri_partition(void *base, size_t size, size_t lo, size_t hi,
                          size_t pivot_idx,
                          int (*cmp)(const void *, const void *),
                          size_t *out_lt_end, size_t *out_gt_begin)
{
    void *pivot = elem(base, size, pivot_idx);

    // Move pivot to lo for convenience
    swap_elems(elem(base, size, lo), elem(base, size, pivot_idx), size);
    pivot = elem(base, size, lo);

    size_t lt = lo;
    size_t i = lo + 1;
    size_t gt = hi;

    while (i < gt)
    {
        int c = cmp(elem(base, size, i), pivot);

        if (c < 0)
        {
            swap_elems(elem(base, size, lt), elem(base, size, i), size);
            lt++;
            i++;
        }
        else if (c > 0)
        {
            gt--;
            swap_elems(elem(base, size, i), elem(base, size, gt), size);
        }
        else
        {
            i++;
        }
    }

    *out_lt_end = lt;
    *out_gt_begin = gt;
}

static void introsort(void *base, size_t n, size_t size,
                      int (*cmp)(const void *, const void *),
                      int depth_limit)
{
    while (n > 1)
    {
        if ((int)n <= QS_INSERTION_THRESHOLD)
        {
            insertion_sort(base, n, size, cmp);
            return;
        }

        if (depth_limit == 0)
        {
            heap_sort(base, n, size, cmp);
            return;
        }

        // Choose pivot via median-of-3
        size_t lo = 0;
        size_t hi = n;
        size_t mid = lo + (hi - lo) / 2;

        size_t p = median3(base, size, lo, mid, hi - 1, cmp);

        size_t lt_end, gt_begin;
        tri_partition(base, size, lo, hi, p, cmp, &lt_end, &gt_begin);

        // Recurse on smaller side first (tail elimination on the larger)
        size_t left_n = (lt_end - lo);
        size_t right_n = (hi - gt_begin);

        if (left_n < right_n)
        {
            introsort(base, left_n, size, cmp, depth_limit - 1);

            // Tail-eliminate right side
            base = elem(base, size, gt_begin);
            n = right_n;
            depth_limit--;
        }
        else
        {
            introsort(elem(base, size, gt_begin), right_n, size, cmp, depth_limit - 1);

            // Tail-eliminate left side
            n = left_n;
            depth_limit--;
        }
    }
}

static int ilog2_floor(size_t x)
{
    int r = 0;
    
    while (x > 1)
    {
        x >>= 1;
        r++;
    }
    
    return r;
}

void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *))
{
    if (!base || nmemb < 2 || size == 0 || !compar)
    {
        return;
    }

    int depth_limit = 2 * ilog2_floor(nmemb);
    introsort(base, nmemb, size, compar, depth_limit);
}

