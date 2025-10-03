/**
 * @file logger.c
 * @brief Logging
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Logger internal declarations
 */

#define BLDR_ELLIPSE " ...\n"
#define BLDR_ELLIPSE_LEN (sizeof(BLDR_ELLIPSE) - 1)

typedef struct {
    const char *text;
    const size_t length;
} _bldr_log_suffix_t;

#ifdef BLDR_LOGGER_THREAD_SAFE
static thread_local char _bldr_message_buffer[BLDR_MESSAGE_SIZE];
#else
static char _bldr_message_buffer[BLDR_MESSAGE_SIZE];
#endif

const _bldr_log_suffix_t _bldr_log_suffix_ellipse = {
    .text = BLDR_ELLIPSE,
    .length = BLDR_ELLIPSE_LEN,
};
const _bldr_log_suffix_t _bldr_log_suffix_newline = {
    .text = "\n",
    .length = 1,
};

static bldr_log_level_t _bldr_log_level = BLDR_LOG_LEVEL_DEFAULT;

static void _bldr_log_message_write(const char *buffer, size_t length);

/*
 * Logger function implementations
 */

void bldr_log_cmd(const bldr_cmd_t *cmd) {
    if (_bldr_log_level == BLDR_LOG_OFF || !bldr_cmd_valid(cmd))
        return;

    int written = 0;
    int available = BLDR_MESSAGE_SIZE - 1;

    // Build command string
    written = snprintf(_bldr_message_buffer, available, "%s", cmd->items[0]);
    if (written < 0)
        exit(BLDR_EXIT_IO);

    for (size_t i = 1; i < cmd->length && written < available; i++) {
        int arg_written = snprintf(_bldr_message_buffer + written,
                                   available - written, " %s", cmd->items[i]);
        if (arg_written < 0)
            exit(BLDR_EXIT_IO);
        written += arg_written;
    }

    // Let _bldr_message_write handle newlines and truncation
    _bldr_log_message_write(_bldr_message_buffer, MIN(written, available));
}

void bldr_log_dump(const char *buffer, size_t length) {
    // Let _bldr_message_write handle newlines and truncation
    _bldr_log_message_write(buffer, length);
}

void bldr_log_fddump(int fd) {
    size_t written = 0;
    const size_t length = BLDR_MESSAGE_SIZE - 1; // Null terminator
    int result = bldr_fd_read(fd, _bldr_message_buffer, length, &written);

    if (result < 0) {
        bldr_log_error("failed to dump file contents to log (%s)",
                       strerror(errno));
        return;
    }
    _bldr_message_buffer[written] = '\0';
    bldr_log_dump(_bldr_message_buffer, written);
}

bldr_log_level_t bldr_log_get_level() { return _bldr_log_level; }

void bldr_log_message(bldr_log_level_t level, const char *fmt, ...) {
    if (level > _bldr_log_level)
        return;

    va_list args;
    va_start(args, fmt);
    bldr_log_message_va(level, fmt, args);
    va_end(args);
}

void bldr_log_message_va(bldr_log_level_t level, const char *fmt,
                         va_list args) {
    if (level > _bldr_log_level)
        return;

    int written = 0;
    int available = BLDR_MESSAGE_SIZE - 1;

    // Add log level prefix
    switch (level) {
    case BLDR_LOG_INFO:
        written = snprintf(_bldr_message_buffer, available, "[INFO ] ");
        break;
    case BLDR_LOG_WARN:
        written = snprintf(_bldr_message_buffer, available, "[WARN ] ");
        break;
    case BLDR_LOG_ERROR:
        written = snprintf(_bldr_message_buffer, available, "[ERROR] ");
        break;
    case BLDR_LOG_OFF:
        return;
    default:
        BLDR_UNREACHABLE("bldr_message");
    }

    if (written < 0)
        exit(BLDR_EXIT_IO);

    available = MAX(0, available - written);

    // Add formatted message
    int msg_written =
        vsnprintf(_bldr_message_buffer + written, available, fmt, args);
    if (msg_written < 0)
        exit(BLDR_EXIT_IO);

    size_t total_length = written + MIN(msg_written, available);

    // Let _bldr_message_write handle newlines and truncation
    _bldr_log_message_write(_bldr_message_buffer, total_length);
}

bldr_log_level_t bldr_log_set_level(bldr_log_level_t level) {
    bldr_log_level_t result = _bldr_log_level;

    _bldr_log_level = MIN(MAX(level, BLDR_LOG_OFF), BLDR_LOG_INFO);
    return result;
}

void bldr_log_stderr(bldr_proc_handle_t *handle) {
    size_t written = 0;
    const size_t length = BLDR_MESSAGE_SIZE - 1; // Null terminator
    int result =
        bldr_proc_read_stderr(handle, _bldr_message_buffer, length, &written);

    if (result < 0) {
        bldr_log_error("failed to dump process standard error to log (%s)",
                       strerror(errno));
        return;
    }
    _bldr_message_buffer[written] = '\0';
    bldr_log_dump(_bldr_message_buffer, written);
}

void bldr_log_stdout(bldr_proc_handle_t *handle) {
    size_t written = 0;
    const size_t length = BLDR_MESSAGE_SIZE - 1; // Null terminator
    int result =
        bldr_proc_read_stdout(handle, _bldr_message_buffer, length, &written);

    if (result < 0) {
        bldr_log_error("failed to dump process standard output to log (%s)",
                       strerror(errno));
        return;
    }
    _bldr_message_buffer[written] = '\0';
    bldr_log_dump(_bldr_message_buffer, written);
}

void bldr_log_time(bool local) {
    static char time_format[32] = "%a, %d %b %y %T %z";
    static char time_output[128];

    time_t now = time(NULL);
    struct tm *time_transformed = local ? localtime(&now) : gmtime(&now);

    if (!time_transformed) {
        bldr_log_error("failed to get local time");
        return;
    }

    size_t result = strftime(time_output, sizeof(time_output), time_format,
                             time_transformed);
    if (result == 0) {
        bldr_log_error("failed to format time");
        return;
    }

    bldr_log_info("%s", time_output);
}

/*
 * Logger static helper function implementations
 */

static void _bldr_log_message_write(const char *buffer, size_t length) {
    if (length == 0)
        return;

    bool needs_newline = (buffer[length - 1] != '\n');
    size_t total_needed = length + (needs_newline ? 1 : 0);

    if (total_needed > BLDR_MESSAGE_SIZE) {
        // Message too long - truncate with ellipsis
        const size_t content_length = BLDR_MESSAGE_SIZE - BLDR_ELLIPSE_LEN;
        fwrite(buffer, sizeof(char), content_length, BLDR_LOG_OUT);
        fwrite(_bldr_log_suffix_ellipse.text, sizeof(char),
               _bldr_log_suffix_ellipse.length, BLDR_LOG_OUT);
    } else if (needs_newline) {
        fwrite(buffer, sizeof(char), length, BLDR_LOG_OUT);
        fwrite(_bldr_log_suffix_newline.text, sizeof(char),
               _bldr_log_suffix_newline.length, BLDR_LOG_OUT);
    } else {
        fwrite(buffer, sizeof(char), length, BLDR_LOG_OUT);
    }
}
