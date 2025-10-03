/**
 * @file file.c
 * @brief File I/O and manipulation
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * File internal declarations
 */

typedef struct {
    const mode_t mode;
    const char *src_base;
    const char *dst_base;
    const size_t src_base_len;
    const size_t dst_base_len;
    const char *pattern;
    char *dst_buffer; // Pre-allocated buffer for destination paths
    size_t dst_buffer_size;
} _bldr_file_dupdir_ctx_t;

static void _bldr_cleanup_dir(DIR **dir_ptr);
static int _bldr_file_dupdir_fn(const char *src_path, void *data);
static int _bldr_file_map_errno(int sys_errno);
static inline int _bldr_file_mkdir_map_errno(int sys_errno, const char *path);
static int _bldr_file_mkdir_parents(char *path, mode_t mode);
static int _bldr_file_mkdir_single(const char *path, mode_t mode);
static int _bldr_file_walk_recursive(const char *pattern,
                                     bldr_file_walk_fn_t callback,
                                     const bldr_file_walk_opt_t options,
                                     char *path_buffer,
                                     const size_t path_buffer_size,
                                     size_t current_len, size_t *file_count);
static size_t _bldr_path_append_component(char *path_buffer, size_t current_len,
                                          const char *component,
                                          size_t max_len);
static size_t _bldr_path_append_mark(char *path_buffer, size_t current_len,
                                     size_t max_len);
static inline void _bldr_path_restore_length(char *path_buffer,
                                             size_t restore_len);
static inline int _bldr_pathsubst_count_wildcards(const char *str);
static inline const char *_bldr_pathsubst_find_wildcard(const char *str);
static bool _bldr_pathsubst_match_pattern(const char *path, const char *pattern,
                                          const char **wildcard_start,
                                          size_t *wildcard_len);

/*
 * File function implementations
 */

void bldr_fd_done(int *fd) {
    if (fd && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

int bldr_fd_read(int fd, char *buffer, size_t buffer_size, size_t *bytes_read) {
    *bytes_read = 0;
    if (fd < 0) {
        errno = 0;
        bldr_log_error("attempt to read from invalid file descriptor");
        return BLDR_ERR_WRITE;
    }
    if (buffer_size) {
        ssize_t result = read(
            fd, buffer, buffer_size - 1); // Leave space for null terminator

        if (result == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return BLDR_OK; // No data available (non-blocking)
            return BLDR_ERR_READ;
        }

        *bytes_read = (size_t)result;
        buffer[result] = '\0'; // Null terminate for string safety
    }
    return BLDR_OK;
}

int bldr_fd_write(int fd, const char *buffer, size_t buffer_size,
                  size_t *bytes_written) {
    if (fd < 0) {
        errno = 0;
        bldr_log_error("attempt to write to invalid file descriptor");
        return BLDR_ERR_WRITE;
    }
    if (buffer_size) {
        ssize_t result = write(fd, buffer, buffer_size);

        if (result == -1)
            return BLDR_ERR_WRITE;
        *bytes_written = (size_t)result;
    } else {
        *bytes_written = 0;
    }
    return BLDR_OK;
}

int bldr_file_cat_opt(FILE *out, const char *path,
                      const bldr_file_cat_opt_t options) {
    const size_t buffer_size =
        options.buffer_size ? options.buffer_size : BLDR_BUFFER_SIZE;
    char *buffer = options.buffer;
    BLDR_DEFER(void *buffer_cleanup, bldr_realloc_cleanup) = NULL;
    if (!buffer) {
        buffer = BLDR_REALLOC(NULL, buffer_size);
        if (buffer == NULL)
            BLDR_OOM_ERROR("failed to allocated file buffer for concatination");
        buffer_cleanup = buffer;
    }
    bldr_log_info("appending file: %s", path);
    BLDR_DEFER(int fdin, bldr_fd_done) = open(path, 0);
    if (fdin < 0) {
        bldr_log_error("failed to open file '%s' (%s)", path, strerror(errno));
        return _bldr_file_map_errno(errno);
    }

    size_t bytes_read = 0;
    size_t lines_skipped = 0;
    int result = BLDR_OK;

    do {
        BLDR_AND_THEN(result,
                      bldr_fd_read(fdin, buffer, buffer_size, &bytes_read));

        if (lines_skipped < options.skip_lines) {
            char *current = buffer;
            const char *end = &buffer[bytes_read];

            // Skip characters until we've skipped enough lines
            while (current < end && lines_skipped < options.skip_lines) {
                if (*current == '\n')
                    lines_skipped++;
                current++;
            }

            // Write remainder of buffer after skipping
            size_t bytes_to_write = end - current;
            if (bytes_to_write > 0)
                fwrite(current, sizeof(char), bytes_to_write, out);
        } else {
            fwrite(buffer, sizeof(char), bytes_read, out);
        }
    } while (bytes_read > 0);

    return BLDR_OK;
}

void bldr_file_done(FILE **file) {
    if (file && *file) {
        fclose(*file);
        *file = NULL;
    }
}

int bldr_file_dupdirs_opt(const char *src_path, const char *dst_path,
                          const char *pattern,
                          const bldr_file_dupdirs_opt_t options) {
    if (src_path[0] == '\0' || dst_path[0] == '\0' || pattern[0] == '\0') {
        bldr_log_error("empty path or pattern arguments");
        return BLDR_ERR_ARGS;
    }
    if (options.buffer_mkdir && options.buffer_walk &&
        options.buffer_mkdir == options.buffer_walk) {
        bldr_log_error("mkdir buffer must be destinct from walk buffer");
        return BLDR_ERR_ARGS;
    }

    const size_t buffer_size =
        options.buffer_size ? MIN(options.buffer_size, BLDR_FILE_PATH_MAX)
                            : BLDR_FILE_PATH_MAX;
    const size_t src_len = strlen(src_path);
    const size_t dst_len = strlen(dst_path);

    if (src_len >= buffer_size || dst_len >= buffer_size) {
        bldr_log_error("path too long: src=%zu, dst=%zu, max=%zu", src_len,
                       dst_len, buffer_size);
        return BLDR_ERR_OVERFLOW;
    }

    char *dst_buffer = options.buffer_mkdir;
    BLDR_DEFER(void *path_cleanup, bldr_realloc_cleanup) = NULL;
    if (!dst_buffer) {
        dst_buffer = BLDR_REALLOC(NULL, buffer_size);
        if (dst_buffer == NULL)
            BLDR_OOM_ERROR(
                "failed to allocate path buffer for directory duplication");
        path_cleanup = dst_buffer;
    }

    bldr_log_info("duplicating directory structure");
    bldr_log_info("  source: %s", src_path);
    bldr_log_info("  destination: %s", dst_path);
    bldr_log_info("  pattern: %s", pattern);

    int result = bldr_file_mkdir(
        dst_path, .parents = true, .mode = options.mode ? options.mode : 0755,
        .buffer = dst_buffer, .buffer_size = buffer_size);
    if (result != BLDR_OK)
        return result;

    _bldr_file_dupdir_ctx_t ctx = {.mode = options.mode,
                                   .src_base = src_path,
                                   .dst_base = dst_path,
                                   .src_base_len = src_len,
                                   .dst_base_len = dst_len,
                                   .pattern = pattern,
                                   .dst_buffer = dst_buffer,
                                   .dst_buffer_size = buffer_size};
    result = bldr_file_walk(src_path, pattern, _bldr_file_dupdir_fn,
                            .recursive = true, .data = &ctx, .no_files = true,
                            .buffer = options.buffer_walk,
                            .buffer_size = buffer_size);

    if (result != BLDR_OK)
        bldr_log_warn("directory duplication completed with warnings");
    else
        bldr_log_info("directory duplication completed successfully");

    return result;
}

int bldr_file_mkdir_opt(const char *path, const bldr_file_mkdir_opt_t options) {
    const size_t buffer_size =
        options.buffer_size ? MIN(options.buffer_size, BLDR_FILE_PATH_MAX)
                            : BLDR_FILE_PATH_MAX;
    const size_t path_len = strlen(path);
    const mode_t path_mode = options.mode != 0 ? options.mode : 0755;

    if (path[0] == '\0') {
        bldr_log_error("path may not be zero length");
        return BLDR_ERR_ARGS;
    }
    if (!options.parents) // Ignore buffer for single directory
        return _bldr_file_mkdir_single(path, path_mode);
    if (path_len >= buffer_size) {
        bldr_log_error("path too long (max=%zu): %s", buffer_size, path);
        return BLDR_ERR_OVERFLOW;
    }

    // Need to create parent directories
    // Make a working copy of the path since we'll modify it
    char *path_buffer = options.buffer;
    BLDR_DEFER(void *path_cleanup, bldr_realloc_cleanup) = NULL;
    if (!path_buffer) {
        path_buffer = BLDR_REALLOC(NULL, buffer_size);
        if (path_buffer == NULL)
            BLDR_OOM_ERROR("failed to allocate path buffer to make directory");
        path_cleanup = path_buffer;
    }

    strcpy(path_buffer, path);

    // Create parent directories first
    int result = _bldr_file_mkdir_parents(path_buffer, path_mode);
    if (result != BLDR_OK)
        return result;

    // Create the final directory
    return _bldr_file_mkdir_single(path, path_mode);
}

int bldr_file_pathsubst(const char *src_path, const char *src_pattern,
                        const char *dst_pattern, char *dst_path,
                        size_t dst_size) {
    if (src_path[0] == '\0' || src_pattern[0] == '\0' ||
        dst_pattern[0] == '\0') {
        bldr_log_error("empty source path or pattern arguments");
        return BLDR_ERR_ARGS;
    }
    if (dst_size == 0) {
        bldr_log_error("destination path buffer size may not be zero");
        return BLDR_ERR_UNDERFLOW;
    }
    if (_bldr_pathsubst_count_wildcards(src_pattern) > 1 ||
        _bldr_pathsubst_count_wildcards(dst_pattern) > 1) {
        bldr_log_error("source or destionation patterns missing wildcards");
        return BLDR_ERR_PATTERN;
    }

    // Match source path against source pattern
    const char *wildcard_content;
    size_t wildcard_len;

    if (!_bldr_pathsubst_match_pattern(src_path, src_pattern, &wildcard_content,
                                       &wildcard_len)) {
        return BLDR_ERR_NOT_FOUND;
    }

    // Build destination path using destination pattern
    const char *dst_wildcard_pos = _bldr_pathsubst_find_wildcard(dst_pattern);

    if (dst_wildcard_pos == NULL) {
        // No wildcard in destination pattern, just copy it
        size_t dst_len = strlen(dst_pattern);
        if (dst_len >= dst_size) {
            return BLDR_ERR_OVERFLOW;
        }
        strcpy(dst_path, dst_pattern);
        return BLDR_OK;
    }

    // Calculate required buffer size
    size_t prefix_len = dst_wildcard_pos - dst_pattern;
    size_t suffix_len = strlen(dst_wildcard_pos + 1);
    size_t required_len =
        prefix_len + wildcard_len + suffix_len + 1; // +1 for null terminator

    if (required_len > dst_size) {
        return BLDR_ERR_OVERFLOW;
    }

    // Build the result
    char *pos = dst_path;

    // Copy prefix
    if (prefix_len > 0) {
        memcpy(pos, dst_pattern, prefix_len);
        pos += prefix_len;
    }

    // Copy wildcard content
    if (wildcard_len > 0 && wildcard_content) {
        memcpy(pos, wildcard_content, wildcard_len);
        pos += wildcard_len;
    }

    // Copy suffix
    if (suffix_len > 0)
        strcpy(pos, dst_wildcard_pos + 1);
    else
        *pos = '\0';

    return BLDR_OK;
}

int bldr_file_printf(FILE *out, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = vfprintf(out, format, args);
    va_end(args);

    if (result < 0) {
        bldr_log_error("error printing to file");
        return BLDR_ERR_FILE;
    }
    return BLDR_OK;
}

int bldr_file_rename(const char *old_path, const char *new_path) {
    bldr_log_info("renaming '%s' to '%s'", old_path, new_path);

    if (rename(old_path, new_path) != 0) {
        bldr_log_error("failed to rename '%s' to '%s' (%s)", old_path, new_path,
                       strerror(errno));
        return BLDR_ERR_FILE;
    }

    return BLDR_OK;
}

int bldr_file_walk_opt(const char *base_path, const char *pattern,
                       bldr_file_walk_fn_t callback,
                       const bldr_file_walk_opt_t options) {
    if (options.no_files && options.no_dirs)
        return BLDR_OK;

    const size_t buffer_size =
        options.buffer_size ? MIN(options.buffer_size, BLDR_FILE_PATH_MAX)
                            : BLDR_FILE_PATH_MAX;
    size_t base_len = strlen(base_path);
    size_t file_count = 0;
    if (base_len >= buffer_size) {
        bldr_log_error("base path too long (max=%zu): %s", buffer_size,
                       base_path);
        return BLDR_ERR_OVERFLOW;
    }

    // Allocate single path buffer for entire walk
    char *path_buffer = options.buffer;
    BLDR_DEFER(void *path_cleanup, bldr_realloc_cleanup) = NULL;
    if (!path_buffer) {
        path_buffer = BLDR_REALLOC(NULL, buffer_size);
        if (path_buffer == NULL)
            BLDR_OOM_ERROR("failed to allocate path buffer for directory walk");
        path_cleanup = path_buffer;
    }

    // Initialize buffer with base path
    memcpy(path_buffer, base_path, base_len);
    path_buffer[base_len] = '\0';

    return _bldr_file_walk_recursive(pattern, callback, options, path_buffer,
                                     buffer_size, base_len, &file_count);
}

/*
 * File static helper function implementations
 */

static void _bldr_cleanup_dir(DIR **dir_ptr) {
    if (dir_ptr && *dir_ptr) {
        closedir(*dir_ptr);
        *dir_ptr = NULL;
    }
}

static int _bldr_file_dupdir_fn(const char *src_path, void *data) {
    _bldr_file_dupdir_ctx_t *ctx = (_bldr_file_dupdir_ctx_t *)data;
    const char *rel_path = src_path + ctx->src_base_len;

    if (*rel_path == '/')
        rel_path++;

    // Find the directory part of the relative path
    const char *last_slash = strrchr(rel_path, '/');
    if (!last_slash) {
        // File is directly in the base directory, no subdirectory to create
        return BLDR_OK;
    }

    size_t dir_len = last_slash - rel_path;
    size_t dst_len = ctx->dst_base_len;

    // Copy destination base
    memcpy(ctx->dst_buffer, ctx->dst_base, dst_len);
    // Add separator if needed
    if (dst_len > 0 && ctx->dst_buffer[dst_len - 1] != '/') {
        ctx->dst_buffer[dst_len++] = '/';
    }
    // Add relative directory path
    if (dst_len + dir_len + 1 >= ctx->dst_buffer_size) {
        bldr_log_error("destination path too long: %s + %.*s", ctx->dst_base,
                       (int)dir_len, rel_path);
        return BLDR_ERR_OVERFLOW;
    }

    memcpy(ctx->dst_buffer + dst_len, rel_path, dir_len);
    dst_len += dir_len;
    ctx->dst_buffer[dst_len] = '\0';

    return bldr_file_mkdir(ctx->dst_buffer, .parents = true,
                           .mode = ctx->mode ? ctx->mode : 0755);
}

static int _bldr_file_map_errno(int sys_errno) {
    int result = 0;

    switch (sys_errno) {
    case EACCES:
    case EPERM:
    case EROFS:
        result = BLDR_ERR_FILE_PERM;
        break;
    case EEXIST:
    case EISDIR:
        result = BLDR_ERR_FILE_TYPE;
        break;
    case EMFILE:
        result = BLDR_ERR_FILE_LIMIT;
        break;
    case ENOENT:
        result = BLDR_ERR_FILE_STAT;
        break;
    case ENOSPC:
    case EDQUOT:
        result = BLDR_ERR_FILE_QUOTA;
        break;
    case EIO:
        result = BLDR_ERR_FILE;
        break;
    case ENAMETOOLONG:
        result = BLDR_ERR_OVERFLOW;
        break;
    default:
        result = BLDR_ERR_FILE;
        break;
    }
    return result;
}

static inline int _bldr_file_mkdir_map_errno(int sys_errno, const char *path) {
    bldr_log_error("failed to create directory '%s' (%s)", path,
                   strerror(errno));
    return _bldr_file_map_errno(sys_errno);
}

static int _bldr_file_mkdir_parents(char *path, mode_t mode) {
    char *slash = path;
    if (*slash == '/') // Skip leading slash for absolute paths
        slash++;

    // Find each path component and create it
    while ((slash = strchr(slash, '/')) != NULL) {
        *slash = '\0'; // Temporarily terminate string

        int result = _bldr_file_mkdir_single(path, mode);
        if (result != BLDR_OK) {
            *slash = '/'; // Restore path
            return result;
        }
        *slash = '/'; // Restore path
        slash++;
    }

    return BLDR_OK;
}

static int _bldr_file_mkdir_single(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0)
        return BLDR_OK;

    if (errno == EEXIST) {
        // Check if existing path is a directory
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                errno = 0;
                return BLDR_OK; // Directory already exists, that's fine
            } else {
                return _bldr_file_mkdir_map_errno(
                    EEXIST, path); // Exists but not a directory
            }
        }
    }

    return _bldr_file_mkdir_map_errno(errno, path);
}

static int _bldr_file_walk_recursive(const char *pattern,
                                     bldr_file_walk_fn_t callback,
                                     const bldr_file_walk_opt_t options,
                                     char *path_buffer,
                                     const size_t path_buffer_size,
                                     size_t current_len, size_t *file_count) {
    BLDR_DEFER(DIR * dir, _bldr_cleanup_dir) = opendir(path_buffer);
    if (!dir) {
        if (options.fail_on_error) {
            bldr_log_error("failed to open directory: %s (%s)", path_buffer,
                           strerror(errno));
            return BLDR_ERR_OPEN;
        } else {
            bldr_log_warn("could not open directory: %s (%s)", path_buffer,
                          strerror(errno));
            return BLDR_OK;
        }
    }

    struct dirent *entry;
    int walk_result = BLDR_OK;

    *file_count = 0;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Append entry name to current path
        size_t new_len = _bldr_path_append_component(
            path_buffer, current_len, entry->d_name, path_buffer_size);

        if (new_len == 0) {
            if (options.fail_on_error) {
                bldr_log_error("path too long when appending: %s",
                               entry->d_name);
                return BLDR_ERR_OVERFLOW;
            } else {
                bldr_log_warn("skipping path too long when appending: %s",
                              entry->d_name);
                continue;
            }
        }

        // Get file stats to determine type
        struct stat file_stat;
        if (stat(path_buffer, &file_stat) != 0) {
            if (options.fail_on_error) {
                bldr_log_error("failed to stat: %s (%s)", path_buffer,
                               strerror(errno));
                _bldr_path_restore_length(path_buffer, current_len);
                return BLDR_ERR_FILE_STAT;
            } else {
                bldr_log_warn("could not stat: %s (%s)", path_buffer,
                              strerror(errno));
                _bldr_path_restore_length(path_buffer, current_len);
                continue;
            }
        }

        bool is_directory = S_ISDIR(file_stat.st_mode);
        const bool flags =
            FNM_PATHNAME | (options.no_escape ? FNM_NOESCAPE : 0);
        bool matches_pattern = fnmatch(pattern, entry->d_name, flags) == 0;

        // Handle directories
        if (is_directory) {
            size_t file_count = 0;

            // Recurse into subdirectory if requested
            if (options.recursive) {
                int recurse_result = _bldr_file_walk_recursive(
                    pattern, callback, options, path_buffer, path_buffer_size,
                    new_len, &file_count);
                if (recurse_result != BLDR_OK) {
                    if (options.fail_on_error) {
                        _bldr_path_restore_length(path_buffer, current_len);
                        return recurse_result;
                    } else {
                        // Remember last error but continue
                        walk_result = recurse_result;
                    }
                }
            }

            // Call callback for directory if requested and pattern matched
            if (!options.no_dirs && file_count) {
                if (!options.no_mark) {
                    new_len = _bldr_path_append_mark(path_buffer, new_len,
                                                     path_buffer_size);
                    if (new_len == 0) {
                        if (options.fail_on_error) {
                            bldr_log_error(
                                "path too long when appending separator");
                            return BLDR_ERR_OVERFLOW;
                        } else {
                            bldr_log_warn("skipping path too long when "
                                          "appending separator");
                            continue;
                        }
                    }
                }

                int callback_result = callback(path_buffer, options.data);

                if (callback_result != BLDR_OK) {
                    if (options.fail_on_error) {
                        bldr_log_error("callback failed for directory: %s",
                                       path_buffer);
                        _bldr_path_restore_length(path_buffer, current_len);
                        return callback_result;
                    } else {
                        bldr_log_warn("callback failed for directory: %s",
                                      path_buffer);
                        // Remember last error but continue
                        walk_result = callback_result;
                    }
                }
            }
        } else {
            // Handle regular files
            if (matches_pattern) {
                int callback_result = !options.no_files
                                          ? callback(path_buffer, options.data)
                                          : BLDR_OK;

                (*file_count)++;
                if (callback_result != BLDR_OK) {
                    if (options.fail_on_error) {
                        bldr_log_error("callback failed for file: %s",
                                       path_buffer);
                        _bldr_path_restore_length(path_buffer, current_len);
                        return callback_result;
                    } else {
                        bldr_log_warn("callback failed for file: %s",
                                      path_buffer);
                        // Remember last error but continue
                        walk_result = callback_result;
                    }
                }
            }
        }

        // Restore path to original length after processing this entry
        _bldr_path_restore_length(path_buffer, current_len);
    }

    // Check if readdir failed
    if (errno != 0) {
        if (options.fail_on_error) {
            bldr_log_error("error reading directory: %s (%s)", path_buffer,
                           strerror(errno));
            return BLDR_ERR_READ;
        } else {
            bldr_log_warn("error reading directory: %s (%s)", path_buffer,
                          strerror(errno));
            if (walk_result == BLDR_OK) {
                walk_result = BLDR_ERR_READ;
            }
        }
    }

    return walk_result;
}

static size_t _bldr_path_append_component(char *path_buffer, size_t current_len,
                                          const char *component,
                                          size_t max_len) {
    const size_t component_len = strlen(component);

    // Check if we need a separator and if there's room
    bool needs_separator =
        current_len > 0 && path_buffer[current_len - 1] != '/';
    size_t total_needed = current_len + (needs_separator ? 1 : 0) +
                          component_len + 1; // +1 for null terminator

    if (total_needed > max_len) {
        return 0; // Not enough space
    }

    // Add separator if needed
    if (needs_separator) {
        path_buffer[current_len++] = '/';
    }

    // Copy component
    memcpy(path_buffer + current_len, component, component_len);
    current_len += component_len;
    path_buffer[current_len] = '\0';

    return current_len;
}

static size_t _bldr_path_append_mark(char *path_buffer, size_t current_len,
                                     size_t max_len) {
    // Check if we need a separator and if there's room
    bool needs_mark = current_len > 0 && path_buffer[current_len - 1] != '/';
    size_t total_needed =
        current_len + (needs_mark ? 1 : 0) + 1; // +1 for null terminator

    if (total_needed > max_len) {
        return 0; // Not enough space
    }
    if (needs_mark) {
        path_buffer[current_len++] = '/';
        path_buffer[current_len] = '\0';
    }

    return current_len;
}

static inline void _bldr_path_restore_length(char *path_buffer,
                                             size_t restore_len) {
    path_buffer[restore_len] = '\0';
}

static inline int _bldr_pathsubst_count_wildcards(const char *str) {
    int count = 0;
    for (const char *p = str; *p != '\0'; p++) {
        if (*p == '%')
            count++;
    }
    return count;
}

static inline const char *_bldr_pathsubst_find_wildcard(const char *str) {
    return strchr(str, '%');
}

static bool _bldr_pathsubst_match_pattern(const char *path, const char *pattern,
                                          const char **wildcard_start,
                                          size_t *wildcard_len) {
    const char *wildcard_pos = _bldr_pathsubst_find_wildcard(pattern);

    if (wildcard_pos == NULL) {
        // No wildcard, must be exact match
        if (strcmp(path, pattern) == 0) {
            *wildcard_start = NULL;
            *wildcard_len = 0;
            return true;
        }
        return false;
    }

    // Calculate prefix and suffix lengths
    size_t prefix_len = wildcard_pos - pattern;
    size_t suffix_len = strlen(wildcard_pos + 1);
    size_t path_len = strlen(path);

    // Path must be at least as long as prefix + suffix
    if (path_len < prefix_len + suffix_len)
        return false;

    // Check prefix match
    if (prefix_len > 0 && strncmp(path, pattern, prefix_len) != 0)
        return false;

    // Check suffix match
    if (suffix_len > 0) {
        const char *path_suffix = path + path_len - suffix_len;
        const char *pattern_suffix = wildcard_pos + 1;
        if (strcmp(path_suffix, pattern_suffix) != 0)
            return false;
    }

    // Extract wildcard content
    *wildcard_start = path + prefix_len;
    *wildcard_len = path_len - prefix_len - suffix_len;

    return true;
}
