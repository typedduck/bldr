/**
 * @file vmemory.c
 * @brief Virtual memory allocator
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Virtual memory internal declarations
 */

static int _bldr_get_platform_mmap_flags(void);
static int _bldr_platform_decommit_pages(void *addr, size_t length);
static int _bldr_validate_platform_assumptions(void);

/*
 * Virtual memory function implementations
 */

int bldr_vmem_commit(bldr_vmem_t *vmem, size_t size) {
    if (size == 0)
        return BLDR_OK;
    if (size > vmem->capacity)
        BLDR_OOM_ERROR("requested size %zu larger than capacity %zu", size,
                       vmem->capacity);

    size = bldr_page_align(size);

    if (SIZE_MAX - vmem->length < size)
        BLDR_OOM_ERROR("requested size %zu would overflow current length %zu",
                       size, vmem->length);
    if (vmem->length + size > vmem->capacity)
        BLDR_OOM_ERROR("not enough virtual memory to commit %zu bytes "
                       "(need %zu, have %zu)",
                       size, vmem->length + size, vmem->capacity);

    const size_t new_length = vmem->length + size;
    void *commit_ptr = vmem->base + vmem->length;
    const int result = mprotect(commit_ptr, size, PROT_READ | PROT_WRITE);

    if (result != 0) {
        vmem->error = errno;
        BLDR_OOM_ERROR("failed to commit %zu bytes of virtual memory (%s)",
                       size, strerror(errno));
    }

    vmem->length = new_length;
    vmem->error = 0;
    return BLDR_OK;
}

int bldr_vmem_decommit(bldr_vmem_t *vmem, size_t size) {
    assert(vmem != NULL);
    if (size == 0) {
        return BLDR_OK;
    }

    size = bldr_page_align(size);

    if (size > vmem->length)
        BLDR_OOM_ERROR("decommit of %zu bytes exceeds committed virtual "
                       "memory of %zu bytes",
                       size, vmem->length);

    const size_t new_length = vmem->length - size;
    void *decommit_ptr = vmem->base + new_length;
    const int result = _bldr_platform_decommit_pages(decommit_ptr, size);

    if (result != 0) {
        vmem->error = errno;
        BLDR_OOM_ERROR(
            "failed to decommit %zu bytes in virtual memory of %zu bytes (%s)",
            size, vmem->length, strerror(errno));
    }

    vmem->length = new_length;
    vmem->error = 0;
    return BLDR_OK;
}

void bldr_vmem_done(bldr_vmem_t *vmem) {
    if (vmem && vmem->original.base) {
        munmap(vmem->original.base, vmem->original.capacity);
        memset(vmem, 0, sizeof(*vmem));
    }
}

int bldr_vmem_init(bldr_vmem_t *vmem, size_t capacity) {
    int result = _bldr_validate_platform_assumptions();
    if (result != BLDR_OK) {
        return result;
    }
    if (capacity > SIZE_MAX - bldr_page_size()) {
        BLDR_OOM_ERROR("capacity %zu too large for page alignment", capacity);
    }

    const int mmap_flags = _bldr_get_platform_mmap_flags();

    memset(vmem, 0, sizeof(*vmem));
    vmem->capacity = bldr_page_align(capacity);
    vmem->base = mmap(NULL, vmem->capacity, PROT_NONE, mmap_flags, -1, 0);

    if (vmem->base == MAP_FAILED) {
        vmem->error = errno;
        BLDR_OOM_ERROR("failed to reserve %zu bytes of virtual memory (%s)",
                       capacity, strerror(errno));
    }

    vmem->original.base = vmem->base;
    vmem->original.capacity = vmem->capacity;

    return BLDR_OK;
}

int bldr_vmem_rebase(bldr_vmem_t *vmem) {
    if (vmem->length == 0) {
        return BLDR_OK;
    }
    if (vmem->capacity <= vmem->length)
        BLDR_OOM_ERROR("failed to rebase, no virtual memory available");

    if (vmem->original.base == NULL) {
        vmem->original.base = vmem->base;
        vmem->original.capacity = vmem->capacity;
    }

    vmem->base += vmem->length;
    vmem->capacity -= vmem->length;
    vmem->length = 0;

    return BLDR_OK;
}

/*
 * Virtual memory static helper function implementations
 */

static int _bldr_get_platform_mmap_flags(void) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

#ifdef __linux__
    // On Linux, don't reserve swap space for large allocations
    flags |= MAP_NORESERVE;
#elif defined(__FreeBSD__)
    // FreeBSD optimization for large allocations
    flags |= MAP_NOSYNC;
#endif

    return flags;
}

static int _bldr_platform_decommit_pages(void *addr, size_t length) {
#ifdef __linux__
    // On Linux, MADV_DONTNEED actually frees the physical pages
    return madvise(addr, length, MADV_DONTNEED);
#elif defined(__APPLE__)
    // On macOS, MADV_FREE is preferred (faster) but MADV_DONTNEED works too
    int result = madvise(addr, length, MADV_FREE);
    if (result != 0) {
        // Fallback to MADV_DONTNEED if MADV_FREE fails
        result = madvise(addr, length, MADV_DONTNEED);
    }
    return result;
#else
    // Generic fallback - just change protection (doesn't free physical memory)
    return mprotect(addr, length, PROT_NONE);
#endif
}

static int _bldr_validate_platform_assumptions(void) {
    static bool validated = false;

    if (!validated) {
        validated = true;
        size_t page_size = bldr_page_size();

        // Verify page size is power of 2
        if ((page_size & (page_size - 1)) != 0) {
            bldr_log_error("page size %zu is not a power of 2", page_size);
            return BLDR_ERR_SYNTAX;
        }

        // Warn about unusual page sizes
        if (page_size != 4096) {
            bldr_log_warn("unusual page size detected: %zu bytes", page_size);
        }

#ifdef __APPLE__
        // Check if we're on Apple Silicon (larger page size)
        if (page_size == 16384) {
            bldr_log_info("detected Apple Silicon with 16KB pages");
        }
#endif
    }
    return BLDR_OK;
}
