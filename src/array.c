/**
 * @file array.c
 * @brief Generic interface functions for dynamic arrays
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Array function implementations
 */

int bldr_array_append_many(bldr_array_t *array, size_t item_size, size_t count,
                           const void *items) {
    assert(item_size > 0);
    if (count) {
        assert(items != NULL);
        // Check for addition overflow: array->length + count
        if (array->length > SIZE_MAX - count) {
            BLDR_OOM_ERROR("array length %u + count %zu would overflow",
                           array->length, count);
        }

        BLDR_UNWRAP(
            bldr_array_reserve(array, item_size, array->length + count));
        memcpy(array->items + (item_size * array->length), items,
               item_size * count);

        array->length += count;
    }
    return BLDR_OK;
}

void bldr_array_done(bldr_array_t *array) {
    if (array) {
        BLDR_FREE(array->items);
        memset(array, 0, sizeof(*array));
    }
}

int bldr_array_reserve(bldr_array_t *array, size_t item_size,
                       size_t requested) {
    assert(item_size > 0);
    size_t capacity = array->capacity;

    if (requested > capacity) {
        if (capacity == 0) {
            capacity = BLDR_ARRAY_CAPACITY_MIN;
        }

        while (requested > capacity) {
            if (capacity > SIZE_MAX / 2)
                BLDR_OOM_ERROR("requested capacity %zu would overflow",
                               requested);
            capacity *= 2;
        }

        // Check for multiplication overflow: capacity * item_size
        if (capacity > SIZE_MAX / item_size) {
            BLDR_OOM_ERROR("allocation size %zu * %zu would overflow", capacity,
                           item_size);
        }

        uint8_t *items = BLDR_REALLOC(array->items, capacity * item_size);

        if (items == NULL)
            BLDR_OOM_ERROR("failed to reserve %zu array items of size %zu",
                           capacity, item_size);

        // Initialize new slots to zero, realloc doesn't
        if (capacity > array->capacity) {
            memset(&items[array->capacity * item_size], 0,
                   item_size * (capacity - array->capacity));
        }

        array->capacity = capacity;
        array->items = items;
    }
    return BLDR_OK;
}
