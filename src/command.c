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

int bldr_cmd_procs_sync(bldr_cmd_procs_t *procs, size_t timeout_ms) {
    if (procs->length == 0) {
        return BLDR_OK;
    }

    int last_error = BLDR_OK;

    // Wait for all processes
    while (procs->length > 0) {
        int exit_code = -1;
        bldr_proc_handle_t handle;
        int result =
            bldr_cmd_procs_wait(procs, &handle, &exit_code, timeout_ms);

        last_error = result != BLDR_OK ? result : last_error;
        bldr_proc_handle_done(&handle);
    }

    return last_error;
}

int bldr_cmd_procs_wait(bldr_cmd_procs_t *procs, bldr_proc_handle_t *handle_out,
                        int *exit_code, size_t timeout_ms) {
    if (procs->length == 0)
        return BLDR_OK;
    if (procs->length == 1) {
        bldr_proc_handle_t *handle = &procs->items[0];
        int result = bldr_proc_wait(handle, exit_code, timeout_ms);

        if (handle_out)
            memcpy(handle_out, handle, sizeof(*handle_out));
        else
            bldr_proc_handle_done(handle);

        procs->length--;
        return result;
    }

    // Multiple processes - wait on any in the process group
    if (procs->proc_group <= 0) {
        bldr_log_error("attempt to wait on invalid process group id");
        return BLDR_ERR_ARGS;
    }

    bldr_timer_t timer;
    bldr_timer_init_now(&timer, timeout_ms);

    while (true) {
        // Use waitpid with -pgid to wait for any process in the group
        int status;
        pid_t pid = waitpid(-procs->proc_group, &status, WNOHANG);

        if (pid > 0) {
            // Found a completed process - find it in procs
            for (uint32_t i = 0; i < procs->length; i++) {
                if (procs->items[i].pid == pid) {
                    bldr_proc_handle_t *handle = &procs->items[i];
                    handle->is_running = false;

                    if (handle_out)
                        memcpy(handle_out, handle, sizeof(*handle_out));
                    else
                        bldr_proc_handle_done(handle);

                    // Remove from array by shifting remaining elements
                    memmove(&procs->items[i], &procs->items[i + 1],
                            (procs->length - i - 1) *
                                sizeof(bldr_proc_handle_t));
                    procs->length--;

                    return BLDR_OK;
                }
            }

            // Process not in our array - shouldn't happen
            bldr_log_warn(
                "waitpid returned unexpected pid %d, not in process list", pid);
            continue;
        } else if (pid == -1) {
            if (errno == ECHILD && procs->length > 0)
                bldr_log_warn("process group (%d) has no more children, %d "
                              "processes left",
                              procs->proc_group, procs->length);
            bldr_log_error("waitpid failed (%s)", strerror(errno));
            return BLDR_ERR_WAIT;
        }

        if (bldr_timer_sleep(&timer) == BLDR_ERR_TIMEOUT) {
            bldr_log_warn("timeout waiting for processes in group %d",
                          procs->proc_group);
            return BLDR_ERR_TIMEOUT;
        }
    }
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

        while (options.async->length &&
               options.async->length >= max_processes) {
            uint32_t length = options.async->length;
            int result = bldr_cmd_procs_wait(options.async, NULL, NULL,
                                             options.timeout_ms);

            // if an error occured and no process was removed, return error to
            // avoid infinite loop
            if (result != BLDR_OK && length == options.async->length)
                return result;
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

        BLDR_UNWRAP_ERROR(bldr_cmd_procs_append(options.async, handle));

        return BLDR_OK;
    } else {
        int result =
            bldr_proc_exec(cmd, NULL, .hook = options.hook, .log_command = true,
                           .log_stderr = true, .log_stdout = true,
                           .timeout_ms = options.timeout_ms,
                                    .working_dir = options.working_dir);

        return result;
    }
}
