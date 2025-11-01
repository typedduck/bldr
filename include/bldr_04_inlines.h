/*
 * General inline function implementations
 */

static inline size_t bldr_align_to(size_t value, size_t alignment) {
    // Alignment must be power of 2
    assert((alignment & (alignment - 1)) == 0);
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline char *bldr_arg_shift(int *argc, char ***argv) {
    assert(argc != NULL && *argc > 0 && *argv != NULL);
    char *arg = **argv;
    (*argc)--, (*argv)++;
    return arg;
}

static inline int bldr_crypto_random_u32(uint32_t *out) {
    return bldr_crypto_random(out, sizeof(uint32_t));
}

static inline int bldr_crypto_random_u64(uint64_t *out) {
    return bldr_crypto_random(out, sizeof(uint64_t));
}

static inline size_t bldr_page_align(const size_t value) {
    size_t page_mask = bldr_page_size() - 1;
    return (value + page_mask) & ~(page_mask);
}

/*
 * Arena inline function implementations
 */

static inline size_t bldr_arena_capacity(bldr_arena_t *arena) {
    return bldr_vmem_capacity(&arena->vmem);
}

static inline size_t bldr_arena_available(bldr_arena_t *arena) {
    return bldr_vmem_capacity(&arena->vmem) - bldr_arena_length(arena);
}

/*
 * Array inline function implementations
 */

static inline int bldr_array_resize(bldr_array_t *array, size_t item_size,
                                    size_t size) {
    int result = bldr_array_reserve(array, item_size, size);
    if (result != BLDR_OK) {
        return result;
    }
    array->length = size;
    return BLDR_OK;
}

/*
 * Command inline function implementations
 */

static inline int bldr_cmd_append_many(bldr_cmd_t *cmd, size_t count,
                                       const char **items) {
    assert(!cmd->sealed && !cmd->static_mem);
    BLDR_UNWRAP_ERROR(bldr_array_append_many((bldr_array_t *)cmd,
                                             sizeof(char *), count, items));
    return bldr_cmd_resize(cmd, cmd->length);
}

static inline void bldr_cmd_done(bldr_cmd_t *cmd) {
    if (!cmd->static_mem)
        bldr_array_done((bldr_array_t *)cmd);
}

static inline void bldr_cmd_print(const bldr_cmd_t *cmd) {
    if (bldr_cmd_valid(cmd)) {
        printf("%s", cmd->items[0]);
        for (uint32_t i = 1; i < cmd->length; i++)
            printf(" %s", cmd->items[i]);
    }
}

static inline int bldr_cmd_procs_append_many(bldr_cmd_procs_t *procs,
                                             size_t count,
                                             bldr_proc_handle_t *items) {
    int result = bldr_array_append_many(
        (bldr_array_t *)procs, sizeof(bldr_proc_handle_t), count, items);

    if (result == BLDR_OK) {
        for (size_t i = 0; i < count; i++)
            bldr_proc_handle_init(&items[i]);
    }
    return result;
}

static inline int bldr_cmd_reserve(bldr_cmd_t *cmd, size_t requested) {
    assert(!cmd->sealed && !cmd->static_mem);
    return bldr_array_reserve((bldr_array_t *)cmd, sizeof(char *),
                              requested + 1);
}

static inline int bldr_cmd_resize(bldr_cmd_t *cmd, size_t size) {
    assert(!cmd->sealed && !cmd->static_mem);

    BLDR_UNWRAP_ERROR(
        bldr_array_reserve((bldr_array_t *)cmd, sizeof(char *), size + 1));
    BLDR_UNWRAP_ERROR(
        bldr_array_resize((bldr_array_t *)cmd, sizeof(char *), size));

    cmd->items[size] = NULL;
    return BLDR_OK;
}

static inline size_t bldr_cmd_save(bldr_cmd_t *cmd) { return cmd->length; }

static inline bool bldr_cmd_valid(const bldr_cmd_t *cmd) {
    return cmd->length > 0 && cmd->length <= BLDR_COMMAND_ARGS_MAX &&
           cmd->items[0] && *cmd->items[0] != '\0' &&
           cmd->items[cmd->length] == NULL;
}

/*
 * Process inline function implementations
 */

static inline void bldr_proc_handle_init(bldr_proc_handle_t *handle) {
    handle->stdin_fd = -1;
    handle->stdout_fd = -1;
    handle->stderr_fd = -1;
    handle->pid = -1;
    handle->is_running = false;
}

static inline int bldr_proc_read_stderr(bldr_proc_handle_t *handle,
                                        char *buffer, size_t buffer_size,
                                        size_t *bytes_read) {
    return bldr_fd_read(handle->stderr_fd, buffer, buffer_size, bytes_read);
}

static inline int bldr_proc_read_stdout(bldr_proc_handle_t *handle,
                                        char *buffer, size_t buffer_size,
                                        size_t *bytes_read) {
    return bldr_fd_read(handle->stdout_fd, buffer, buffer_size, bytes_read);
}

/*
 * Strings inline function implementations
 */

static inline int bldr_strs_append_many(bldr_strings_t *strings, size_t count,
                                        const char **items) {
    return bldr_array_append_many((bldr_array_t *)strings, sizeof(char *),
                                  count, items);
}

static inline void bldr_strs_done(bldr_strings_t *strings) {
    bldr_array_done((bldr_array_t *)strings);
}

static inline void bldr_strs_print(const bldr_strings_t *strings) {
    for (size_t i = 0; i < strings->length; i++) {
        printf("%s\n", strings->items[i]);
    }
}

static inline int bldr_strs_reserve(bldr_strings_t *strings, size_t requested) {
    return bldr_array_reserve((bldr_array_t *)strings, sizeof(char *),
                              requested);
}

static inline int bldr_strs_resize(bldr_strings_t *strings, size_t size) {
    return bldr_array_resize((bldr_array_t *)strings, sizeof(char *), size);
}

static inline size_t bldr_strs_save(bldr_strings_t *strings) {
    return strings->length;
}

/*
 * Virtual memory inline function implementations
 */

static inline size_t bldr_vmem_available(bldr_vmem_t *vmem) {
    return vmem->capacity - vmem->length;
}

static inline void *bldr_vmem_base_ptr(bldr_vmem_t *vmem) { return vmem->base; }

static inline size_t bldr_vmem_capacity(bldr_vmem_t *vmem) {
    return vmem->capacity;
}

static inline bool bldr_vmem_is_empty(bldr_vmem_t *vmem) {
    return vmem->length == 0;
}

static inline size_t bldr_vmem_length(bldr_vmem_t *vmem) {
    return vmem->length;
}

static inline void *bldr_vmem_top_ptr(bldr_vmem_t *vmem) {
    return vmem->base + vmem->length;
}
