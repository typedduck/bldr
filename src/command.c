/**
 * @file command.c
 * @brief Executable command structure
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Command function implementations
 */

bldr_cmd_t *bldr_cmd_clone_in(const bldr_cmd_t *cmd, bldr_arena_t *arena) {
    if (!bldr_cmd_valid(cmd))
        BLDR_OOM_NULL("cloning invalid command");

    size_t total_size = bldr_align_type(sizeof(bldr_cmd_t), bldr_cmd_t);
    const size_t array_size = sizeof(const char *) * (cmd->length + 1);
    const size_t array_offset = total_size;

    total_size += bldr_align_type(array_size, const char *);

    const size_t strings_offset = total_size;
    for (size_t i = 0; i < cmd->length; i++) {
        BLDR_ERROR_NULL(cmd->items[i], "invalid NULL string in source command");

        const size_t str_len = bldr_system_align(strlen(cmd->items[i]) + 1);

        if (total_size > UINT32_MAX - str_len)
            BLDR_OOM_NULL("total string size too large");

        total_size += str_len;
    }

    // Allocate all memory in one go
    uint8_t *data = (uint8_t *)bldr_arena_alloc(arena, total_size);
    BLDR_HANDLE_NULL(data);

    // Set up the command structure
    bldr_cmd_t *cloned = (bldr_cmd_t *)data;
    cloned->items = (const char **)(data + array_offset);
    cloned->length = cmd->length;
    cloned->capacity = cmd->length + 1;
    cloned->sealed = true;
    cloned->static_mem = true;

    // Copy strings and set up pointer array
    uint8_t *string_ptr = data + strings_offset;
    for (size_t i = 0; i < cmd->length; i++) {
        const size_t str_len = strlen(cmd->items[i]) + 1;
        const size_t str_size = bldr_system_align(str_len);

        cloned->items[i] = (const char *)string_ptr;
        memcpy(string_ptr, cmd->items[i], str_len);
        string_ptr += str_size;
    }

    // NULL terminate the pointer array
    cloned->items[cmd->length] = NULL;

    return cloned;
}

void bldr_cmd_procs_done(bldr_cmd_procs_t *procs) {
    BLDR_TODO("Implement bldr_cmd_procs_done");
}
bool bldr_cmd_procs_wait(bldr_cmd_procs_t *procs, size_t timeout_sec) {
    BLDR_TODO("Implement bldr_cmd_procs_wait");
}

int bldr_cmd_run_opt(const bldr_cmd_t *cmd, bldr_cmd_options_t options) {
    if (!bldr_cmd_valid(cmd)) {
        bldr_log_error("invalid command");
        return BLDR_ERR_ARGS;
    }

    if (options.async) {
        const size_t max_processes =
            MAX(MIN(options.max_processes ? options.max_processes
                                          : bldr_processor_count(),
                    BLDR_COMMAND_PROCS_MAX),
                BLDR_COMMAND_PROCS_MIN);

        while (options.async->length >= max_processes) {
            // Wait or terminate after timeout
            bool removed =
                bldr_cmd_procs_wait(options.async, options.timeout_sec);

            if (!removed) // If no process was removed, exit loop
                break;
        }

        BLDR_DEFER(bldr_proc_handle_t handle, bldr_proc_handle_done);
        bldr_proc_handle_init(&handle);
        int result = bldr_proc_exec_async(
            cmd, &handle, .close_stdin = true,
            .working_dir = options.working_dir, .hook = options.hook,
            .log_command = true, .proc_group = options.async->proc_group);

        if (result != BLDR_OK)
            return result;

        if (options.async->proc_group == 0)
            options.async->proc_group = handle.pid;

        BLDR_UNWRAP(bldr_cmd_procs_append(options.async, handle));

        return BLDR_OK;
    } else {
        int result = bldr_proc_exec(cmd, NULL, .hook = options.hook,
                                    .log_command = true, .log_stderr = true,
                                    .timeout_ms = options.timeout_sec,
                                    .working_dir = options.working_dir);

        return result;
    }
}
