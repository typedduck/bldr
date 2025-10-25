/**
 * @file builder.c
 * @brief Main builder API
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Builder internal declarations
 */

#if BLDR_OOM_ABORT
#define BLDR_REBUILD_UNWRAP(caller) (caller)
#else
#define BLDR_REBUILD_UNWRAP(caller)                                            \
    do {                                                                       \
        int result = (caller);                                                 \
        if (result != BLDR_OK) {                                               \
            exit(BLDR_EXIT_FAIL);                                              \
        }                                                                      \
    } while (0)
#endif

const char bldr_empty_string[] = "";

/*
 * Builder function implementations
 */

int bldr_needs_rebuild_many(const char *output_path, size_t input_paths_count,
                            const char **input_paths) {
    struct stat statbuf = {0};

    if (stat(output_path, &statbuf) < 0) {
        if (errno == ENOENT)
            return 1;
        bldr_log_error("could not stat '%s' (%s)", output_path,
                       strerror(errno));
        return BLDR_ERR_FILE_STAT;
    }

    int output_path_time = statbuf.st_mtime;

    for (size_t i = 0; i < input_paths_count; ++i) {
        const char *input_path = input_paths[i];

        if (stat(input_path, &statbuf) < 0) {
            bldr_log_error("could not stat '%s' (%s)", input_path,
                           strerror(errno));
            return BLDR_ERR_FILE_STAT;
        }
        if (statbuf.st_mtime > output_path_time) {
            return 1;
        }
    }

    return 0;
}

void bldr_build_yourself_many(int argc, char **argv, const char *source_path,
                              size_t extra_count, const char **extra_paths) {
    assert(argc > 0);
    const char *binary_path = bldr_arg_shift(&argc, &argv);

    // ===== Check if rebuild is needed ========================================
    BLDR_DEFER(bldr_strings_t source_paths, bldr_strs_done) = {0};
    BLDR_REBUILD_UNWRAP(bldr_strs_append(&source_paths, source_path));
    BLDR_REBUILD_UNWRAP(
        bldr_strs_append_many(&source_paths, extra_count, extra_paths));

    int rebuild_needed = bldr_needs_rebuild_many(
        binary_path, source_paths.length, source_paths.items);

    if (rebuild_needed < 0) {
        exit(BLDR_EXIT_FAIL);
    }
    if (!rebuild_needed) {
        return;
    }

    // ===== Rebuild is needed, start procedure ================================
    BLDR_DEFER(bldr_arena_t arena, bldr_arena_done) = {0};
    BLDR_REBUILD_UNWRAP(bldr_arena_init(&arena, BLDR_REBUILD_ARENA));

    bldr_log_time(true);
    bldr_log_info("rebuilding '%s'", source_path);

    // ===== Rename old binary =================================================
    const char *old_binary_path =
        bldr_arena_sprintf(&arena, "%s.old", binary_path);

#if !BLDR_OOM_ABORT
    if (!old_binary_path)
        exit(BLDR_EXIT_FAIL);
#endif
    if (bldr_file_rename(binary_path, old_binary_path) != BLDR_OK)
        exit(BLDR_EXIT_FAIL);

    // ===== Rebuild the binary ================================================
    BLDR_DEFER(bldr_cmd_t cmd, bldr_cmd_done) = {0};
    BLDR_DEFER(bldr_proc_handle_t handle, bldr_proc_handle_done) = {0};

    BLDR_REBUILD_UNWRAP(
        bldr_cmd_append(&cmd, BLDR_REBUILD_CMD(binary_path, source_path)));

    int exit_code;
    int result = bldr_proc_exec(&cmd, &exit_code, .log_command = true,
                                .log_stdout = true, .log_stderr = true,
                                .timeout_ms = 5000);
    if (result == BLDR_OK) {
        if (exit_code != 0) {
            bldr_log_error("%s failed with exit code %d", cmd.items[0],
                           exit_code);
            exit(BLDR_EXIT_FAIL);
        }
        bldr_log_info("%s exited successful", cmd.items[0]);
    } else {
        exit(BLDR_EXIT_FAIL);
    }

    // ===== Execute the rebuild binary ========================================
    bldr_log_info("calling rebuild binary");
    bldr_cmd_reset(&cmd);
    BLDR_REBUILD_UNWRAP(bldr_cmd_append(&cmd, binary_path));
    BLDR_REBUILD_UNWRAP(bldr_cmd_append_many(&cmd, argc, (const char **)argv));

    exit_code = 0;
    result = bldr_proc_exec(&cmd, &exit_code, .no_redirect = true);
    if (result != BLDR_OK)
        exit(BLDR_EXIT_FAIL);

    exit(exit_code);
}

/*
 * General function implementations
 */

int bldr_crypto_random(void *buf, size_t size) {
    assert(size > 0);
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE__)
    arc4random_buf(buf, size);
    return 0;
#elif defined(__linux__) || defined(__unix__)
    // Try getentropy first (limited to 256 bytes per call)
    if (size <= 256 && getentropy(buf, size) == 0) {
        return 0;
    }

    // Fall back to /dev/urandom for larger sizes or if getentropy fails
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return BLDR_ERR_OPEN;
    }

    size_t total_read = 0;
    uint8_t *byte_buf = (uint8_t *)buf;

    while (total_read < size) {
        ssize_t bytes_read = read(fd, byte_buf + total_read, size - total_read);
        if (bytes_read <= 0) {
            close(fd);
            return BLDR_ERR_READ;
        }
        total_read += (size_t)bytes_read;
    }

    close(fd);
    return BLDR_OK;
#else
    return BLDR_ERR_PLATFORM;
#endif
}

size_t bldr_page_size(void) {
    static size_t page_size = 0;

    if (page_size == 0)
        page_size = sysconf(_SC_PAGESIZE);

    return page_size;
}

size_t bldr_processor_count() {
    static size_t processor_count = 0;

    if (processor_count == 0)
        processor_count = sysconf(_SC_NPROCESSORS_ONLN);

    return processor_count;
}

void bldr_realloc_cleanup(void **data) {
    if (data) {
        BLDR_FREE(*data);
        *data = NULL;
    }
}

size_t bldr_system_align(const size_t value) {
    static size_t alignment = 0;

    if (alignment == 0) {
        alignment = alignof(max_align_t);
    }

    return (value + alignment - 1) & ~(alignment - 1);
}

double bldr_time_now() {
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) == -1)
        exit(BLDR_EXIT_TIME);
    return (double)tp.tv_sec + ((double)tp.tv_nsec * 1e-9);
}
