/**
 * @file process.c
 * @brief Process execution
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Process internal declarations
 */

static void _bldr_proc_child_fds(int pipes[3][2]);
static void _bldr_proc_close_pipes(int pipes[3][2], bool parent_side);
static int _bldr_proc_create_pipes(int pipes[3][2]);
#if BLDR_PROC_STRICT_FCNTL
static int _bldr_proc_exec_async_strict(bldr_proc_handle_t *handle);
#else
static int _bldr_proc_exec_async_lenient(bldr_proc_handle_t *handle);
#endif
static int _bldr_proc_exit_status(int status, int *exit_code);
static void _bldr_proc_hook(bldr_proc_hook_t hook, const bldr_cmd_t *cmd);
static void _bldr_proc_setcwd(const char *working_dir);
static void _bldr_proc_setpgid(pid_t proc_group);
static int _bldr_proc_wait_timeout(pid_t pid, int *status, size_t timeout_sec);

/*
 * Process function implementations
 */

int bldr_proc_exec_opt(const bldr_cmd_t *cmd, int *exit_code_ret,
                       const bldr_proc_options_t options) {
    if (options.no_redirect && (options.log_stdout || options.log_stderr)) {
        bldr_log_error("options `no_capture` and `log_stdout` or "
                       "`log_stderr` are mutual exclusive");
        return BLDR_ERR_ARGS;
    }

    bldr_proc_async_options_t async_options = {
        .close_stdin = true,
        .working_dir = options.working_dir,
        .hook = options.hook,
        .log_command = options.log_command,
        .no_redirect = options.no_redirect,
    };
    BLDR_DEFER(bldr_proc_handle_t handle, bldr_proc_handle_done);
    bldr_proc_handle_init(&handle);
    int exit_code = 0;
    int result = BLDR_OK;

    BLDR_AND_THEN(result,
                  bldr_proc_exec_async_opt(cmd, &handle, async_options));
    BLDR_AND_THEN(result,
                  bldr_proc_wait(&handle, &exit_code, options.timeout_ms));

    if (options.no_redirect == false) {
        if (options.log_stdout)
            bldr_log_stdout(&handle);
        if (options.log_stderr)
            bldr_log_stderr(&handle);
    }
    if (exit_code_ret)
        *exit_code_ret = exit_code;
    if (exit_code != BLDR_EXIT_OK)
        bldr_log_warn("process %d exited with code %d", handle.pid, exit_code);

    return result != BLDR_OK           ? result
           : exit_code != BLDR_EXIT_OK ? BLDR_ERR_EXEC
                                       : BLDR_OK;
}

int bldr_proc_exec_async_opt(const bldr_cmd_t *cmd, bldr_proc_handle_t *handle,
                             bldr_proc_async_options_t options) {
    if (!bldr_cmd_valid(cmd)) {
        bldr_log_error("invalid command");
        return BLDR_ERR_ARGS;
    }
    if (options.log_command)
        bldr_log_cmd(cmd);

    bldr_proc_handle_init(handle);

    // Create pipes: [0] = stdin, [1] = stdout, [2] = stderr
    int pipes[3][2] = {{-1, -1}, {-1, -1}, {-1, -1}};
    if (options.no_redirect == false) {
        int result = _bldr_proc_create_pipes(pipes);
        if (result != BLDR_OK)
            return result;
    }

    pid_t pid = fork();
    if (pid < 0) {
        bldr_log_error("failed to fork child process (%s)", strerror(errno));
        if (options.no_redirect == false) {
            _bldr_proc_close_pipes(pipes, true);  // Close parent pipes
            _bldr_proc_close_pipes(pipes, false); // Close child pipes
        }
        return BLDR_ERR_FORK;
    }

    if (pid == 0) { // Child process
        if (options.no_redirect == false) {
            _bldr_proc_close_pipes(pipes, true); // Close parent ends
            _bldr_proc_child_fds(pipes);
        }
        _bldr_proc_setcwd(options.working_dir);
        _bldr_proc_setpgid(
            options.proc_group); // Child sets its own process group - this
                                 // avoids race conditions
        _bldr_proc_hook(options.hook, cmd);

        // Execute the program
        execvp(cmd->items[0], (char *const *)cmd->items);

        // If execvp returns, it failed
        bldr_log_error("execution failed for '%s' (%s)", cmd->items[0],
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD);
    } else { // Parent process
        if (options.no_redirect == false)
            _bldr_proc_close_pipes(pipes, false); // Close child ends

        // Set up handle before any potential error paths
        if (options.no_redirect == false) {
            handle->stdin_fd = pipes[0][1];  // Write end of stdin pipe
            handle->stdout_fd = pipes[1][0]; // Read end of stdout pipe
            handle->stderr_fd = pipes[2][0]; // Read end of stderr pipe
        }
        handle->pid = pid;
        handle->is_running = true;

        // Close stdin immediately if requested
        if (options.no_redirect == false && options.close_stdin) {
            close(handle->stdin_fd);
            handle->stdin_fd = -1;
        }

        if (options.no_redirect == false) {
#if BLDR_PROC_STRICT_FCNTL
            return _bldr_proc_exec_async_strict(handle);
#else
            return _bldr_proc_exec_async_lenient(handle);
#endif
        }
        return BLDR_OK;
    }
}

void bldr_proc_handle_done(bldr_proc_handle_t *handle) {
    if (!handle) {
        return;
    }

    // Close file descriptors
    if (handle->stdin_fd >= 0) {
        if (close(handle->stdin_fd) == -1) {
            bldr_log_warn("failed to close stdin file descriptor");
        }
        handle->stdin_fd = -1;
    }
    if (handle->stdout_fd >= 0) {
        if (close(handle->stdout_fd) == -1) {
            bldr_log_warn("failed to close stdout file descriptor");
        }
        handle->stdout_fd = -1;
    }
    if (handle->stderr_fd >= 0) {
        if (close(handle->stderr_fd) == -1) {
            bldr_log_warn("failed to close stderr file descriptor");
        }
        handle->stderr_fd = -1;
    }

    // If process is still running, terminate it
    if (handle->is_running && handle->pid > 0) {
        bldr_proc_terminate(handle, false);
        // Wait for process to avoid zombie
        waitpid(handle->pid, NULL, WNOHANG);
    }

    bldr_proc_handle_init(handle);
}

bool bldr_proc_is_running(pid_t pid) {
    if (pid <= 0)
        return false;
    return kill(pid, 0) == 0;
}

int bldr_proc_terminate(bldr_proc_handle_t *handle, bool force) {
    if (handle->pid <= 0) {
        bldr_log_error("attempt to terminate an invalid process id");
        return BLDR_ERR_ARGS;
    }
    if (!bldr_proc_is_running(handle->pid)) {
        handle->is_running = false;
        return BLDR_OK;
    }
    if (force)
        bldr_log_warn("forcing process (%d) to terminate", handle->pid);

    int signal = force ? SIGKILL : SIGTERM;
    if (kill(handle->pid, signal) == -1) {
        if (errno == ESRCH || signal == SIGKILL) {
            // Process already terminated or was killed
            handle->is_running = false;
            return BLDR_OK;
        }
        bldr_log_error("failed to send signal (%d) to process %d (%s)", signal,
                       handle->pid, strerror(errno));
        return BLDR_ERR_TERMINATED;
    }

    // If using SIGTERM, wait a bit and then use SIGKILL if still running
    if (!force) {
        usleep(100000); // 100ms grace period
        if (bldr_proc_is_running(handle->pid)) {
            // Don't check error here - process might have exited between
            // checks
            kill(handle->pid, SIGKILL);
        }
    }

    handle->is_running = false;
    return BLDR_OK;
}

int bldr_proc_wait(bldr_proc_handle_t *handle, int *exit_code,
                   size_t timeout_ms) {
    if (handle->pid <= 0) {
        bldr_log_error("attempt to wait on invalid process id");
        return BLDR_ERR_ARGS;
    }

    int status;
    int result = _bldr_proc_wait_timeout(handle->pid, &status, timeout_ms);

    if (result != BLDR_OK) {
        // Try to kill the child process if timeout occurred
        if (result == BLDR_ERR_TIMEOUT) {
            bldr_proc_terminate(handle, false);
            // Clean up zombie
            waitpid(handle->pid, NULL, WNOHANG);
        }
        return result;
    }

    return _bldr_proc_exit_status(status, exit_code);
}

int bldr_proc_write(bldr_proc_handle_t *handle, const char *buffer,
                    size_t buffer_size, size_t *bytes_written) {
    int result =
        bldr_fd_write(handle->stdin_fd, buffer, buffer_size, bytes_written);

    if (result == BLDR_ERR_WRITE && errno == EPIPE) {
        // Child process closed its stdin
        handle->is_running = false;
    }
    return result;
}

/*
 * Process static helper function implementations
 */

static void _bldr_proc_child_fds(int pipes[3][2]) {
    // Redirect stdin with error checking
    if (dup2(pipes[0][0], STDIN_FILENO) == -1) {
        bldr_log_error("unable to redirect stdin for child process (%s)",
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD_STDIN);
    }
    if (close(pipes[0][0]) == -1) {
        bldr_log_error("unable to close stdin on child process (%s)",
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD_STDIN);
    }

    // Redirect stdout with error checking
    if (dup2(pipes[1][1], STDOUT_FILENO) == -1) {
        bldr_log_error("unable to redirect stdout for child process (%s)",
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD_STDOUT);
    }
    if (close(pipes[1][1]) == -1) {
        bldr_log_error("unable to close stdout on child process (%s)",
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD_STDOUT);
    }

    // Redirect stderr with error checking
    if (dup2(pipes[2][1], STDERR_FILENO) == -1) {
        bldr_log_error("unable to redirect stderr for child process (%s)",
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD_STDERR);
    }
    if (close(pipes[2][1]) == -1) {
        bldr_log_error("unable to close stderr on child process (%s)",
                       strerror(errno));
        _exit(BLDR_EXIT_CHILD_STDERR);
    }
}

static void _bldr_proc_close_pipes(int pipes[3][2], bool parent_side) {
    for (int i = 0; i < 3; i++) {
        int fd_to_close;

        if (parent_side)
            fd_to_close = pipes[i][i == 0 ? 1 : 0];
        else
            fd_to_close = pipes[i][i == 0 ? 0 : 1];

        if (fd_to_close >= 0 && close(fd_to_close) == -1)
            bldr_log_warn("failed to close pipe file descriptor");
    }
}

static int _bldr_proc_create_pipes(int pipes[3][2]) {
    for (int i = 0; i < 3; i++) {
        if (pipe(pipes[i]) == -1) {
            // Clean up any pipes created so far
            for (int j = 0; j < i; j++) {
                // Log but don't fail on close errors during cleanup
                if (close(pipes[j][0]) == -1)
                    bldr_log_warn("failed to close pipe during cleanup");
                if (close(pipes[j][1]) == -1)
                    bldr_log_warn("failed to close pipe during cleanup");
            }
            return BLDR_ERR_PIPE;
        }
    }
    return BLDR_OK;
}

#if BLDR_PROC_STRICT_FCNTL
static int _bldr_proc_exec_async_strict(bldr_proc_handle_t *handle) {
    int flags;

    // Set stdout to non-blocking
    if ((flags = fcntl(handle->stdout_fd, F_GETFL)) == -1) {
        bldr_log_error("failed to get stdout flags for process %d (%s)",
                       handle->pid, strerror(errno));
        goto cleanup_and_fail;
    }
    if (fcntl(handle->stdout_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        bldr_log_error(
            "failed to set stdout to non-blocking mode for process %d (%s)",
            handle->pid, strerror(errno));
        goto cleanup_and_fail;
    }

    // Set stderr to non-blocking
    if ((flags = fcntl(handle->stderr_fd, F_GETFL)) == -1) {
        bldr_log_error("failed to get stderr flags for process %d (%s)",
                       handle->pid, strerror(errno));
        goto cleanup_and_fail;
    }
    if (fcntl(handle->stderr_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        bldr_log_error(
            "failed to set stderr to non-blocking mode for process %d (%s)",
            handle->pid, strerror(errno));
        goto cleanup_and_fail;
    }

    return BLDR_OK;

cleanup_and_fail:
    // Clean up the process and file descriptors
    bldr_proc_terminate(handle, true);
    bldr_proc_handle_done(handle);
    return BLDR_ERR_PLATFORM;
}
#else
static int _bldr_proc_exec_async_lenient(bldr_proc_handle_t *handle) {
    bool fcntl_failed = false;

    // Set stdout to non-blocking
    int flags = fcntl(handle->stdout_fd, F_GETFL);
    if (flags == -1) {
        bldr_log_warn("failed to get stdout flags (%s)", strerror(errno));
        fcntl_failed = true;
    } else if (fcntl(handle->stdout_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        bldr_log_warn("failed to set stdout to non-blocking mode (%s)",
                      strerror(errno));
        fcntl_failed = true;
    }

    // Set stderr to non-blocking
    flags = fcntl(handle->stderr_fd, F_GETFL);
    if (flags == -1) {
        bldr_log_warn("failed to get stderr flags (%s)", strerror(errno));
        fcntl_failed = true;
    } else if (fcntl(handle->stderr_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        bldr_log_warn("failed to set stderr to non-blocking mode (%s)",
                      strerror(errno));
        fcntl_failed = true;
    }

    if (fcntl_failed)
        bldr_log_warn(
            "process started successfully but with blocking I/O pipes");

    return BLDR_OK;
}
#endif

static int _bldr_proc_exit_status(int status, int *exit_code) {
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (exit_code)
            *exit_code = code;

        switch (code) {
        case BLDR_EXIT_CHILD:
        case BLDR_EXIT_CHILD_CHDIR:
        case BLDR_EXIT_CHILD_STDIN:
        case BLDR_EXIT_CHILD_STDOUT:
        case BLDR_EXIT_CHILD_STDERR:
        case BLDR_EXIT_CHILD_SETPGID:
        case BLDR_EXIT_CHILD_HOOK:
            return BLDR_ERR_EXEC;
        default:
            return BLDR_OK;
        }
    } else if (WIFSIGNALED(status)) {
        if (exit_code)
            *exit_code = -WTERMSIG(status); // Negative signal number
        bldr_log_warn("process already terminated with exit code %d",
                      *exit_code);
        return BLDR_OK;
    }

    return BLDR_ERR_WAIT;
}

static void _bldr_proc_hook(bldr_proc_hook_t hook, const bldr_cmd_t *cmd) {
    if (hook) {
        if (hook(cmd) != BLDR_OK) {
            bldr_log_error("hook execution failed for process %d", getpid());
            _exit(BLDR_EXIT_CHILD_HOOK);
        }
    }
}

static void _bldr_proc_setcwd(const char *working_dir) {
    if (working_dir && working_dir[0] != '\0') {
        if (chdir(working_dir) == -1) {
            bldr_log_error("unable set cwd for process to '%s' (%s)",
                           working_dir, strerror(errno));
            _exit(BLDR_EXIT_CHILD_CHDIR);
        }
    }
}

static void _bldr_proc_setpgid(pid_t proc_group) {
    if (proc_group > 0) {
        // Join existing process group
        if (setpgid(0, proc_group) == -1) {
            bldr_log_error("failed to join process group %d for %d (%s)",
                           proc_group, getpid(), strerror(errno));
            _exit(BLDR_EXIT_CHILD_SETPGID);
        }
    } else if (proc_group == 0) {
        // Create new process group (first child becomes leader)
        if (setpgid(0, 0) == -1) {
            bldr_log_error("failed to create new process group for %d (%s)",
                           getpid(), strerror(errno));
            _exit(BLDR_EXIT_CHILD_SETPGID);
        }
    }
    // If proc_group < 0, don't change process group
}

static int _bldr_proc_wait_timeout(pid_t pid, int *status, size_t timeout_ms) {
    if (timeout_ms == 0) {
        // No timeout - wait indefinitely
        if (waitpid(pid, status, 0) == -1) {
            bldr_log_error("failed to wait on process %d (%s)", pid,
                           strerror(errno));
            return BLDR_ERR_WAIT;
        }
        return BLDR_OK;
    }

    bldr_timer_t timer;
    bldr_timer_init_now(&timer, timeout_ms);

    while (true) {
        pid_t result = waitpid(pid, status, WNOHANG);

        if (result == -1) {
            bldr_log_error("failed to wait on process %d (%s)", pid,
                           strerror(errno));
            return BLDR_ERR_WAIT;
        } else if (result == pid) {
            // Process has terminated
            return BLDR_OK;
        } else if (result == 0) {
            int result = bldr_timer_sleep(&timer);

            if (result == BLDR_ERR_TIMEOUT) {
                bldr_log_warn("process %d timed out", pid);
                return BLDR_ERR_TIMEOUT;
            }
        }
    }
}
