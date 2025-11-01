/**
 * @file arena.c
 * @brief Arena allocator
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Arena internal declarations
 */

static uint32_t _bldr_arena_magic_value = 0;

__attribute__((constructor)) static void _bldr_arena_magic_init(void);

/*
 * Arena function implementations
 */

void *bldr_arena_alloc(bldr_arena_t *arena, size_t size) {
    if (size == 0) {
        return NULL;
    }

    const size_t aligned_size = bldr_system_align(size);

    if (aligned_size > bldr_arena_available(arena))
        BLDR_OOM_NULL("not enough memory to allocate %zu bytes in arena", size);

    const size_t current_length = bldr_arena_length(arena);
    const size_t required_length = current_length + aligned_size;
    const size_t committed_length = bldr_vmem_length(&arena->vmem);

    // Commit more memory if needed
    if (required_length > committed_length) {
        const size_t additional_commit = required_length - committed_length;

        BLDR_UNWRAP_NULL(bldr_vmem_commit(&arena->vmem, additional_commit));
    }

    uint8_t *result = arena->next;
    arena->next += aligned_size;

    return result;
}

void bldr_arena_done(bldr_arena_t *arena) {
    if (arena) {
        bldr_vmem_done(&arena->vmem);
        arena->next = NULL;
    }
}

int bldr_arena_init(bldr_arena_t *arena, size_t capacity) {
    bldr_vmem_t vmem = {0};

    if (capacity == 0)
        capacity = BLDR_ARENA_DEFAULT_CAPACITY;

    BLDR_UNWRAP_ERROR(bldr_vmem_init(&vmem, capacity));
    bldr_arena_init_in(arena, vmem);
    return BLDR_OK;
}

void bldr_arena_init_in(bldr_arena_t *arena, bldr_vmem_t vmem) {
    arena->vmem = vmem;
    arena->next = (uint8_t *)bldr_vmem_base_ptr(&arena->vmem);
}

bool bldr_arena_is_empty(bldr_arena_t *arena) {
    const uint8_t *base = (uint8_t *)bldr_vmem_base_ptr(&arena->vmem);
    return arena->next == base;
}

size_t bldr_arena_length(bldr_arena_t *arena) {
    const uint8_t *base = (uint8_t *)bldr_vmem_base_ptr(&arena->vmem);
    return arena->next - base;
}

uint32_t bldr_arena_magic(void) { return _bldr_arena_magic_value; }

int bldr_arena_rewind(bldr_arena_t *arena, size_t checkpoint) {
    size_t checkpoint_length = checkpoint & 0xFFFFFFFFFFFF;
    uint32_t checkpoint_hash = (uint32_t)(checkpoint >> 48);
    uintptr_t base = (uintptr_t)bldr_vmem_base_ptr(&arena->vmem);
    uint32_t expected_hash =
        (uint32_t)((base ^ checkpoint_length ^ bldr_arena_magic()) & 0xFFFF);

    if (checkpoint_hash != expected_hash) {
        bldr_log_error("arena (%p) checkpoint hash mismatch %u, expected %u",
                       arena->vmem.base, checkpoint_hash, expected_hash);
        return BLDR_ERR_ARGS;
    }

    const size_t current_length = bldr_arena_length(arena);

    if (checkpoint_length > current_length) {
        bldr_log_error("arena (%p) checkpoint length (%zu) is larger than "
                       "arena length (%zu)",
                       arena->vmem.base, checkpoint_length, current_length);
        return BLDR_ERR_OVERFLOW;
    }
    if (checkpoint_length % bldr_system_align(1) != 0) {
        bldr_log_error("arena (%p) checkpoint length is misaligned",
                       arena->vmem.base);
        return BLDR_ERR_ALIGN;
    }

    bldr_log_debug("arena (%p) rewind from %zu to %zu", arena->vmem.base,
                   current_length, checkpoint_length);
    uint8_t *base_ptr = (uint8_t *)bldr_vmem_base_ptr(&arena->vmem);
    arena->next = base_ptr + checkpoint_length;

    return BLDR_OK;
}

size_t bldr_arena_save(bldr_arena_t *arena) {
    size_t length = bldr_arena_length(arena);
    uintptr_t base = (uintptr_t)bldr_vmem_base_ptr(&arena->vmem);
    uint32_t hash = (uint32_t)((base ^ length ^ bldr_arena_magic()) & 0xFFFF);

    bldr_log_debug("arena (%p) checkpoint at %zu", arena->vmem.base, length);
    // Pack: upper 16 bits = hash, lower 48 bits = length
    return ((size_t)hash << 48) | (length & 0xFFFFFFFFFFFF);
}

char *bldr_arena_sprintf(bldr_arena_t *arena, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int length = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (length <= 0)
        return bldr_arena_strdup(arena, "");

    char *result = bldr_arena_alloc(arena, length + 1);
    BLDR_HANDLE_NULL(result);

    va_start(args, format);
    vsnprintf(result, length + 1, format, args);
    va_end(args);

    return result;
}

char *bldr_arena_strdup(bldr_arena_t *arena, const char *str) {
    size_t length = strlen(str);
    char *result = bldr_arena_alloc(arena, length + 1);
    BLDR_HANDLE_NULL(result);

    memcpy(result, str, length);
    result[length] = '\0';
    return result;
}

char *bldr_arena_strndup(bldr_arena_t *arena, const char *str, size_t length) {
    length = MIN(length, strlen(str));
    char *result = bldr_arena_alloc(arena, length + 1);
    BLDR_HANDLE_NULL(result);

    memcpy(result, str, length);
    result[length] = '\0';
    return result;
}

/*
 * Arena static helper function implementations
 */

__attribute__((constructor)) static void _bldr_arena_magic_init(void) {
    uint32_t random_val;
    int result = bldr_crypto_random_u32(&random_val);

    if (result != 0) {
        bldr_log_error(
            "failed to initialize cryptographic random value for arenas");
        exit(BLDR_EXIT_RAND);
    }

    _bldr_arena_magic_value = random_val;
}
