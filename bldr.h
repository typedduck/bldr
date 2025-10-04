/*
Copyright 2025 Marc H. Göldner (typedduck)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef _BLDR_H_
#define _BLDR_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =====================================================================
 * HEADER SECTION
 * =====================================================================
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Preconditions
 */

static_assert(sizeof(size_t) == 8, "Not a 64-bit system");
static_assert(sizeof(void *) == 8, "Not a 64-bit system");

/*
 * Function hooks
 */

#ifndef BLDR_REALLOC
#define BLDR_REALLOC realloc
#endif

#ifndef BLDR_FREE
#define BLDR_FREE free
#endif

/*
 * Configuration options
 */

#ifndef BLDR_ARENA_CAPACITY
#define BLDR_ARENA_CAPACITY (8 * 1024 * 1024)
#endif

#ifndef BLDR_ARRAY_CAPACITY_MIN
#define BLDR_ARRAY_CAPACITY_MIN (16)
#endif

#ifndef BLDR_BUFFER_SIZE
#define BLDR_BUFFER_SIZE (4096)
#endif

#ifndef BLDR_COMMAND_ARGS_MAX
#define BLDR_COMMAND_ARGS_MAX (1024)
#endif

#ifndef BLDR_COMMAND_PROCS_MAX
#define BLDR_COMMAND_PROCS_MAX (64)
#endif
static_assert(BLDR_COMMAND_PROCS_MAX > 1,
              "maximum command processes must be greater than 1");

#ifndef BLDR_COMMAND_PROCS_MIN
#define BLDR_COMMAND_PROCS_MIN (2)
#endif
static_assert(BLDR_COMMAND_PROCS_MIN > 1,
              "minimum command processes must be greater than 1");
static_assert(BLDR_COMMAND_PROCS_MIN <= BLDR_COMMAND_PROCS_MAX,
              "minimum command processes must be less than maximum");

#ifndef BLDR_FILE_PATH_MAX
#define BLDR_FILE_PATH_MAX (4096)
#endif

#ifndef BLDR_LOG_LEVEL_DEFAULT
#define BLDR_LOG_LEVEL_DEFAULT BLDR_LOG_INFO
#endif

#ifndef BLDR_LOG_LEVEL_MAX
#define BLDR_LOG_LEVEL_MAX BLDR_LOG_WARN
#endif

#ifndef BLDR_LOG_OUT
#define BLDR_LOG_OUT (stderr)
#endif

#ifndef BLDR_MESSAGE_SIZE
#define BLDR_MESSAGE_SIZE (1024)
#endif

#ifndef BLDR_OOM_ABORT
#define BLDR_OOM_ABORT (true)
#endif

#ifndef BLDR_PROC_STRICT_FCNTL
#define BLDR_PROC_STRICT_FCNTL (true)
#endif

#ifndef BLDR_REBUILD_ARENA
#define BLDR_REBUILD_ARENA (2 * bldr_page_size())
#endif

#ifndef BLDR_REBUILD_CMD
#define BLDR_REBUILD_CMD(binary_path, source_path)                             \
    "gcc", "-s", "-O2", "-DNDEBUG", "-o", binary_path, source_path
#endif

#ifdef BLDR_THREAD_SAFE
#define BLDR_LOGGER_THREAD_SAFE
#endif

/*
 * Function macros
 */

#define BLDR_AND_THEN(result, caller)                                          \
    ((result) = ((result) == BLDR_OK ? (caller) : (result)))
#define BLDR_DEFER(decl, dtor) decl __attribute__((cleanup(dtor)))
#define BLDR_IS_ERR(result) ((result) < BLDR_OK)
#define BLDR_IS_FALSE(result) ((result) == BLDR_FALSE)
#define BLDR_IS_OK(result) ((result) == BLDR_OK)
#define BLDR_IS_TRUE(result) ((result) == BLDR_TRUE)
#define BLDR_TODO(message)                                                     \
    do {                                                                       \
        fprintf(stderr, "%s:%d: TODO: %s\n", __FILE__, __LINE__, message);     \
        abort();                                                               \
    } while (0)
#define BLDR_UNREACHABLE(message)                                              \
    do {                                                                       \
        fprintf(stderr, "%s:%d: UNREACHABLE: %s\n", __FILE__, __LINE__,        \
                message);                                                      \
        abort();                                                               \
    } while (0)
#define BLDR_UNUSED(value) (void)(value)

#if BLDR_OOM_ABORT
#define BLDR_CHECK_NULLPTR(ptr)
#define BLDR_ERROR_NULL(ptr, msg, ...)                                         \
    if ((ptr) == NULL) {                                                       \
        bldr_log_error("OOM: " msg, ##__VA_ARGS__);                            \
        exit(BLDR_EXIT_NOMEM);                                                 \
    }
#define BLDR_HANDLE_NULL(ptr)
#define BLDR_OOM_ERROR(msg, ...)                                               \
    do {                                                                       \
        bldr_log_error("OOM: " msg, ##__VA_ARGS__);                            \
        exit(BLDR_EXIT_NOMEM);                                                 \
    } while (0)
#define BLDR_OOM_NULL(msg, ...)                                                \
    do {                                                                       \
        bldr_log_error("OOM: " msg, ##__VA_ARGS__);                            \
        exit(BLDR_EXIT_NOMEM);                                                 \
    } while (0)
#define BLDR_UNWRAP(caller) (caller)
#define BLDR_UNWRAP_NULL(caller) (caller)
#else
#define BLDR_CHECK_NULLPTR(ptr)                                                \
    if ((ptr == NULL))                                                         \
    return BLDR_ERR_MEMORY
#define BLDR_ERROR_NULL(ptr, msg, ...)                                         \
    if ((ptr) == NULL) {                                                       \
        bldr_log_error("OOM: " msg, ##__VA_ARGS__);                            \
        return NULL;                                                           \
    }
#define BLDR_HANDLE_NULL(ptr)                                                  \
    if (!(ptr))                                                                \
    return NULL
#define BLDR_OOM_ERROR(msg, ...)                                               \
    do {                                                                       \
        bldr_log_error("OOM: " msg, ##__VA_ARGS__);                            \
        return BLDR_ERR_MEMORY;                                                \
    } while (0)
#define BLDR_OOM_NULL(msg, ...)                                                \
    do {                                                                       \
        bldr_log_error("OOM: " msg, ##__VA_ARGS__);                            \
        return NULL;                                                           \
    } while (0)
#define BLDR_UNWRAP(caller)                                                    \
    do {                                                                       \
        int result = (caller);                                                 \
        if (result != BLDR_OK) {                                               \
            return result;                                                     \
        }                                                                      \
    } while (0)
#define BLDR_UNWRAP_NULL(caller)                                               \
    do {                                                                       \
        int result = (caller);                                                 \
        if (result != BLDR_OK) {                                               \
            return NULL;                                                       \
        }                                                                      \
    } while (0)
#endif

/*
 * General enums
 */

typedef enum {
    // Successful returns
    BLDR_OK = 0,    // Success
    BLDR_FALSE = 0, // Success with false-value
    BLDR_TRUE = 1,  // Success with true-value

    // Error returns
    BLDR_ERR_ALIGN = -2001,      // Value does not align properly
    BLDR_ERR_ARGS = -2002,       // Arguments have invalid values
    BLDR_ERR_CLOSE = -2003,      // Failed to close file
    BLDR_ERR_CLOSE_TAG = -2004,  // No matching closing tag
    BLDR_ERR_DUPLICATE = -2005,  // Duplicate name or object
    BLDR_ERR_EXEC = -2006,       // Child process exited with failure
    BLDR_ERR_FILE = -2007,       // Operation on file failed
    BLDR_ERR_FILE_LIMIT = -2008, // Maximum number of open files reached
    BLDR_ERR_FILE_PERM = -2009,  // Not enough permission
    BLDR_ERR_FILE_QUOTA = -2010, // Not enough space on media
    BLDR_ERR_FILE_STAT = -2011,  // No file information
    BLDR_ERR_FILE_TYPE = -2012,  // File exists but has wrong type
    BLDR_ERR_FORK = -2013,       // Failed to fork child process
    BLDR_ERR_KILL = -2014,       // Failed to send signal to process
    BLDR_ERR_LOCK = -2015,       // FAiled to lock mutex
    BLDR_ERR_MEMORY = -2016,     // Failed to allocate memory
    BLDR_ERR_NOT_FOUND = -2017,  // Search or match was unsuccessful
    BLDR_ERR_OPEN = -2018,       // Failed to open file
    BLDR_ERR_OVERFLOW = -2019,   // Overflow of buffer or range
    BLDR_ERR_PATTERN = -2020,    // Invalid matching pattern
    BLDR_ERR_PIPE = -2021,       // Failed to create a pipe
    BLDR_ERR_PLATFORM = -2022,   // Operation not supported on platform
    BLDR_ERR_READ = -2023,       // Failed to read from file
    BLDR_ERR_SYNTAX = -2024,     // Syntax error occured
    BLDR_ERR_TERMINATED = -2025, // Process terminated
    BLDR_ERR_TIMEOUT = -2026,    // Timeout occured
    BLDR_ERR_UNDERFLOW = -2027,  // Underflow of buffer or range
    BLDR_ERR_WAIT = -2028,       // Failed to wait on process
    BLDR_ERR_WRITE = -2029,      // Failed to write to file
} bldr_result_t;

typedef enum {
    BLDR_EXIT_OK = 0, // Successful exit

    // Error exit of main process
    BLDR_EXIT_REBUILD = 1, // Rebuild failed
    BLDR_EXIT_NOMEM = 2,   // Out of memory occured
    BLDR_EXIT_IO = 3,      // I/O error
    BLDR_EXIT_RAND = 4,    // Failed to generate random number
    BLDR_EXIT_TIME = 5,    // Failed to get system time

    // Error exit of child process
    BLDR_EXIT_CHILD = 128,         // Forked child process exited with error
    BLDR_EXIT_CHILD_CHDIR = 129,   // Failed to change working directory
    BLDR_EXIT_CHILD_STDIN = 130,   // Failed to pipe stdin
    BLDR_EXIT_CHILD_STDOUT = 131,  // Failed to pipe stdout
    BLDR_EXIT_CHILD_STDERR = 132,  // Failed to pipe stderr
    BLDR_EXIT_CHILD_SETPGID = 133, // Failed to create process group id
    BLDR_EXIT_CHILD_HOOK = 134,    // Process hook exited with error
} bldr_exit_t;

/*
 * Global variables
 */

extern const char bldr_empty_string[];

/*
 * General functions declarations
 */

#define bldr_align_type(size, type) bldr_align_to((size), alignof(type))

int bldr_crypto_random(void *buf, size_t size) __attribute((nonnull(1)));
size_t bldr_page_size(void);
size_t bldr_processor_count();
void bldr_realloc_cleanup(void **data);
size_t bldr_system_align(const size_t value);
double bldr_time_now();

static inline size_t bldr_align_to(size_t value, size_t alignment);
static inline char *bldr_arg_shift(int *argc, char ***argv)
    __attribute((nonnull(1, 2)));
static inline int bldr_crypto_random_u32(uint32_t *out)
    __attribute((nonnull(1)));
static inline int bldr_crypto_random_u64(uint64_t *out)
    __attribute((nonnull(1)));
static inline size_t bldr_page_align(const size_t value);

/*
 * Virtual memory declarations
 */

typedef struct {
    uint8_t *base;
    size_t length;
    size_t capacity;
    struct {
        uint8_t *base;
        size_t capacity;
    } original;
    int error;
} bldr_vmem_t;

int bldr_vmem_commit(bldr_vmem_t *vmem, size_t size)
    __attribute__((nonnull(1)));
int bldr_vmem_decommit(bldr_vmem_t *vmem, size_t size)
    __attribute__((nonnull(1)));
void bldr_vmem_done(bldr_vmem_t *vmem);
int bldr_vmem_init(bldr_vmem_t *vmem, size_t capacity)
    __attribute__((nonnull(1)));
int bldr_vmem_rebase(bldr_vmem_t *vmem) __attribute__((nonnull(1)));

static inline size_t bldr_vmem_available(bldr_vmem_t *vmem)
    __attribute__((nonnull(1)));
static inline void *bldr_vmem_base_ptr(bldr_vmem_t *vmem)
    __attribute__((nonnull(1)));
static inline size_t bldr_vmem_capacity(bldr_vmem_t *vmem)
    __attribute__((nonnull(1)));
static inline bool bldr_vmem_is_empty(bldr_vmem_t *vmem)
    __attribute__((nonnull(1)));
static inline size_t bldr_vmem_length(bldr_vmem_t *vmem)
    __attribute__((nonnull(1)));
static inline void *bldr_vmem_top_ptr(bldr_vmem_t *vmem)
    __attribute__((nonnull(1)));

/*
 * Arena declarations
 */

typedef struct {
    bldr_vmem_t vmem;
    uint8_t *next;
} bldr_arena_t;

void *bldr_arena_alloc(bldr_arena_t *arena, size_t size)
    __attribute__((nonnull(1)));
void bldr_arena_done(bldr_arena_t *arena);
int bldr_arena_init(bldr_arena_t *arena, size_t capacity)
    __attribute__((nonnull(1)));
void bldr_arena_init_in(bldr_arena_t *arena, bldr_vmem_t vmem)
    __attribute__((nonnull(1)));
bool bldr_arena_is_empty(bldr_arena_t *arena) __attribute__((nonnull(1)));
size_t bldr_arena_length(bldr_arena_t *arena) __attribute__((nonnull(1)));
uint32_t bldr_arena_magic(void);
int bldr_arena_rewind(bldr_arena_t *arena, size_t checkpoint)
    __attribute__((nonnull(1)));
size_t bldr_arena_save(bldr_arena_t *arena) __attribute__((nonnull(1)));
char *bldr_arena_sprintf(bldr_arena_t *arena, const char *format, ...)
    __attribute__((format(printf, 2, 3), nonnull(1, 2)));
char *bldr_arena_strdup(bldr_arena_t *arena, const char *str)
    __attribute__((nonnull(1, 2)));
char *bldr_arena_strndup(bldr_arena_t *arena, const char *str, size_t length)
    __attribute__((nonnull(1, 2)));

static inline size_t bldr_arena_available(bldr_arena_t *arena)
    __attribute__((nonnull(1)));
static inline size_t bldr_arena_capacity(bldr_arena_t *arena)
    __attribute__((nonnull(1)));

/*
 * Array declarations
 */

typedef struct {
    uint8_t *items;
    uint32_t length;
    uint32_t capacity;
} bldr_array_t;

int bldr_array_append_many(bldr_array_t *array, size_t items_size, size_t count,
                           const void *items) __attribute__((nonnull(1, 4)));
void bldr_array_done(bldr_array_t *array);
int bldr_array_reserve(bldr_array_t *array, size_t item_size, size_t requested)
    __attribute__((nonnull(1)));

static inline int bldr_array_resize(bldr_array_t *array, size_t items_size,
                                    size_t size) __attribute__((nonnull(1)));

/*
 * Builder declarations
 */

#define bldr_build_yourself(argc, argv, source_path, ...)                      \
    bldr_build_yourself_many(                                                  \
        argc, argv, source_path,                                               \
        (sizeof((const char *[]){__VA_ARGS__}) / sizeof(const char *)),        \
        ((const char *[]){__VA_ARGS__}))

#define bldr_needs_rebuild(output_path, ...)                                   \
    bldr_build_yourself_many(                                                  \
        output_path,                                                           \
        (sizeof((const char *[]){__VA_ARGS__}) / sizeof(const char *)),        \
        ((const char *[]){__VA_ARGS__}))

int bldr_needs_rebuild_many(const char *output_path, size_t input_paths_count,
                            const char **input_paths)
    __attribute__((nonnull(1)));
void bldr_build_yourself_many(int argc, char **argv, const char *source_path,
                              size_t extra_count, const char **extra_paths)
    __attribute__((nonnull(2, 3)));

/*
 * Command declarations
 */

#define bldr_cmd_append(cmd, ...)                                              \
    bldr_cmd_append_many(                                                      \
        cmd, (sizeof((const char *[]){__VA_ARGS__}) / sizeof(const char *)),   \
        ((const char *[]){__VA_ARGS__}))
#define bldr_cmd_procs_append(procs, ...)                                      \
    bldr_cmd_procs_append_many(                                                \
        procs,                                                                 \
        (sizeof((const bldr_proc_handle_t[]){__VA_ARGS__}) /                   \
         sizeof(bldr_proc_handle_t)),                                          \
        ((bldr_proc_handle_t[]){__VA_ARGS__}))
#define bldr_cmd_reset(cmd) bldr_cmd_resize(cmd, 0)
#define bldr_cmd_rewind(cmd, n) bldr_cmd_resize(cmd, n)
#define bldr_cmd_run(cmd, handle, ...)                                         \
    bldr_cmd_run_opt(cmd, handle, (bldr_cmd_options_t){__VA_ARGS__})

typedef struct bldr_cmd_t {
    const char **items;
    uint32_t length;
    uint32_t capacity;
    bool sealed;
    bool static_mem;
} bldr_cmd_t;

typedef struct bldr_cmd_procs_t bldr_cmd_procs_t;
typedef struct bldr_proc_handle_t bldr_proc_handle_t;
typedef int (*bldr_proc_hook_t)(const bldr_cmd_t *cmd)
    __attribute__((nonnull(1)));

typedef struct {
    bldr_cmd_procs_t *async;
    size_t timeout_sec;
    size_t max_processes;
    const char *working_dir;
    bldr_proc_hook_t hook;
} bldr_cmd_options_t;

typedef struct bldr_cmd_procs_t {
    bldr_proc_handle_t *items;
    uint32_t length;
    uint32_t capacity;
    pid_t proc_group;
} bldr_cmd_procs_t;

void bldr_cmd_procs_done(bldr_cmd_procs_t *procs);
bool bldr_cmd_procs_wait(bldr_cmd_procs_t *procs, size_t timeout_sec)
    __attribute__((nonnull(1)));
int bldr_cmd_run_opt(const bldr_cmd_t *cmd, bldr_cmd_options_t options)
    __attribute__((nonnull(1)));

static inline int bldr_cmd_append_many(bldr_cmd_t *cmd, size_t count,
                                       const char **items)
    __attribute__((nonnull(1, 3)));
bldr_cmd_t *bldr_cmd_clone_in(const bldr_cmd_t *cmd, bldr_arena_t *arena)
    __attribute__((nonnull(1, 2)));
static inline void bldr_cmd_done(bldr_cmd_t *cmd);
static inline void bldr_cmd_print(const bldr_cmd_t *cmd)
    __attribute__((nonnull(1)));
static inline int bldr_cmd_reserve(bldr_cmd_t *cmd, size_t requested)
    __attribute__((nonnull(1)));
static inline int bldr_cmd_resize(bldr_cmd_t *cmd, size_t size)
    __attribute__((nonnull(1)));
static inline size_t bldr_cmd_save(bldr_cmd_t *cmd) __attribute__((nonnull(1)));
static inline bool bldr_cmd_valid(const bldr_cmd_t *cmd)
    __attribute__((nonnull(1)));

static inline int bldr_cmd_procs_append_many(bldr_cmd_procs_t *procs,
                                             size_t count,
                                             bldr_proc_handle_t *items)
    __attribute__((nonnull(1, 3)));

/*
 * File declarations
 */

#define bldr_file_cat(out, path, ...)                                          \
    bldr_file_cat_opt(out, path, (bldr_file_cat_opt_t){__VA_ARGS__})
#define bldr_file_dupdir(src_path, dst_path, pattern, ...)                     \
    bldr_file_dupdir_opt(src_path, dst_path, pattern,                          \
                         (bldr_file_dupdirs_opt_t){__VA_ARGS__})
#define bldr_file_mkdir(path, ...)                                             \
    bldr_file_mkdir_opt(path, (bldr_file_mkdir_opt_t){__VA_ARGS__})
#define bldr_file_walk(base_path, pattern, callback, ...)                      \
    bldr_file_walk_opt(base_path, pattern, callback,                           \
                       (bldr_file_walk_opt_t){__VA_ARGS__})

typedef struct {
    size_t skip_lines;
    char *buffer;
    size_t buffer_size;
} bldr_file_cat_opt_t;

typedef struct {
    const mode_t mode;
    char *buffer_mkdir;
    char *buffer_walk;
    size_t buffer_size; // Default `BLDR_FILE_PATH_MAX`
                        // length
} bldr_file_dupdirs_opt_t;

typedef struct {
    const mode_t mode;
    const bool parents;
    char *buffer;
    size_t buffer_size; // Default `BLDR_FILE_PATH_MAX` length
} bldr_file_mkdir_opt_t;

typedef struct {
    const bool fail_on_error;
    const bool recursive;
    const bool no_dirs;
    const bool no_files;
    const bool no_escape;
    const bool no_mark;
    void *data;
    char *buffer;
    size_t buffer_size; // Default `BLDR_FILE_PATH_MAX` length
} bldr_file_walk_opt_t;

typedef int (*bldr_file_walk_fn_t)(const char *path, void *data);

void bldr_fd_done(int *fd);
int bldr_fd_read(int fd, char *buffer, size_t buffer_size, size_t *bytes_read)
    __attribute((nonnull(2, 4)));
int bldr_fd_write(int fd, const char *buffer, size_t buffer_size,
                  size_t *bytes_written) __attribute((nonnull(2, 4)));

int bldr_file_cat_opt(FILE *out, const char *path,
                      const bldr_file_cat_opt_t options)
    __attribute((nonnull(1, 2)));
void bldr_file_done(FILE **file);
int bldr_file_dupdir_opt(const char *src_path, const char *dst_path,
                         const char *pattern,
                         const bldr_file_dupdirs_opt_t options)
    __attribute((nonnull(1, 2, 3)));
int bldr_file_mkdir_opt(const char *path, const bldr_file_mkdir_opt_t options)
    __attribute__((nonnull(1)));
int bldr_file_pathsubst(const char *src_path, const char *src_pattern,
                        const char *dst_pattern, char *dst_path,
                        size_t dst_size) __attribute__((nonnull(1, 2, 3, 4)));
int bldr_file_printf(FILE *out, const char *format, ...)
    __attribute__((format(printf, 2, 3), nonnull(1, 2)));
int bldr_file_rename(const char *old_path, const char *new_path)
    __attribute__((nonnull(1, 2)));
int bldr_file_walk_opt(const char *base_path, const char *pattern,
                       bldr_file_walk_fn_t callback,
                       const bldr_file_walk_opt_t options)
    __attribute((nonnull(1, 2, 3)));

/*
 * Logger declarations
 */

typedef enum {
    BLDR_LOG_OFF = 0,
    BLDR_LOG_ERROR = 1,
    BLDR_LOG_WARN = 2,
    BLDR_LOG_INFO = 3,
} bldr_log_level_t;

#define BLDR_LOG_OFF 0
#define BLDR_LOG_ERROR 1
#define BLDR_LOG_WARN 2
#define BLDR_LOG_INFO 3

#if BLDR_LOG_LEVEL_MAX >= BLDR_LOG_INFO
#define bldr_log_info(fmt, ...)                                                \
    bldr_log_message(BLDR_LOG_INFO, fmt, ##__VA_ARGS__)
#else
#define bldr_log_info(fmt, ...)
#endif

#if BLDR_LOG_LEVEL_MAX >= BLDR_LOG_WARN
#define bldr_log_warn(fmt, ...)                                                \
    bldr_log_message(BLDR_LOG_WARN, fmt, ##__VA_ARGS__)
#else
#define bldr_log_warn(fmt, ...)
#endif

#if BLDR_LOG_LEVEL_MAX >= BLDR_LOG_ERROR
#define bldr_log_error(fmt, ...)                                               \
    bldr_log_message(BLDR_LOG_ERROR, fmt, ##__VA_ARGS__)
#else
#define bldr_log_error(fmt, ...)
#endif

void bldr_log_cmd(const bldr_cmd_t *cmd) __attribute((nonnull(1)));
void bldr_log_dump(const char *buffer, size_t length) __attribute((nonnull(1)));
void bldr_log_fddump(int fd);
bldr_log_level_t bldr_log_get_level();
void bldr_log_message(bldr_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3), nonnull(2)));
void bldr_log_message_va(bldr_log_level_t level, const char *fmt, va_list args)
    __attribute__((nonnull(2)));
bldr_log_level_t bldr_log_set_level(bldr_log_level_t level);
void bldr_log_stderr(bldr_proc_handle_t *handle) __attribute((nonnull(1)));
void bldr_log_stdout(bldr_proc_handle_t *handle) __attribute((nonnull(1)));
void bldr_log_time(bool local);

/*
 * Process declarations
 */

#define bldr_proc_exec(cmd, exit_code, ...)                                    \
    bldr_proc_exec_opt(cmd, exit_code, (bldr_proc_options_t){__VA_ARGS__})
#define bldr_proc_exec_async(cmd, handle, ...)                                 \
    bldr_proc_exec_async_opt(cmd, handle,                                      \
                             (bldr_proc_async_options_t){__VA_ARGS__})

typedef struct bldr_cmd_t bldr_cmd_t;

typedef struct bldr_proc_handle_t {
    int stdout_fd;
    int stderr_fd;
    int stdin_fd;
    pid_t pid;
    bool is_running;
} bldr_proc_handle_t;

typedef struct {
    size_t timeout_ms;
    const char *working_dir;
    bldr_proc_hook_t hook;
    bool log_command;
    bool log_stdout;
    bool log_stderr;
    bool no_redirect;
} bldr_proc_options_t;

typedef struct {
    bool close_stdin;
    pid_t proc_group;
    const char *working_dir;
    bldr_proc_hook_t hook;
    bool log_command;
    bool no_redirect;
} bldr_proc_async_options_t;

int bldr_proc_exec_opt(const bldr_cmd_t *cmd, int *exit_code,
                       bldr_proc_options_t options) __attribute__((nonnull(1)));
int bldr_proc_exec_async_opt(const bldr_cmd_t *cmd, bldr_proc_handle_t *handle,
                             bldr_proc_async_options_t options)
    __attribute__((nonnull(1, 2)));
void bldr_proc_handle_done(bldr_proc_handle_t *handle);
bool bldr_proc_is_running(pid_t pid);
int bldr_proc_terminate(bldr_proc_handle_t *handle, bool force)
    __attribute__((nonnull(1)));
int bldr_proc_wait(bldr_proc_handle_t *handle, int *exit_code,
                   size_t timeout_ms) __attribute__((nonnull(1)));
int bldr_proc_write(bldr_proc_handle_t *handle, const char *buffer,
                    size_t buffer_size, size_t *bytes_written)
    __attribute__((nonnull(1, 4)));

static inline void bldr_proc_handle_init(bldr_proc_handle_t *handle)
    __attribute__((nonnull(1)));
static inline int bldr_proc_read_stderr(bldr_proc_handle_t *handle,
                                        char *buffer, size_t buffer_size,
                                        size_t *bytes_read)
    __attribute__((nonnull(1, 4)));
static inline int bldr_proc_read_stdout(bldr_proc_handle_t *handle,
                                        char *buffer, size_t buffer_size,
                                        size_t *bytes_read)
    __attribute__((nonnull(1, 4)));

/*
 * String declarations
 */

#define bldr_strs_append(strs, ...)                                            \
    bldr_strs_append_many(                                                     \
        strs, (sizeof((const char *[]){__VA_ARGS__}) / sizeof(const char *)),  \
        ((const char *[]){__VA_ARGS__}))
#define bldr_strs_glob(strings, arena, pattern, ...)                           \
    bldr_strs_glob_opt(strings, arena, pattern,                                \
                       (bldr_strs_glob_opt_t){__VA_ARGS__})
#define bldr_strs_reset(strs) bldr_strs_resize(strs, 0)
#define bldr_strs_rewind(cmd, n) bldr_strs_resize(cmd, n)
#define bldr_strs_walk(strings, arena, base_path, pattern, ...)                \
    bldr_strs_walk_opt(strings, arena, base_path, pattern,                     \
                       (bldr_strs_walk_opt_t){__VA_ARGS__})

typedef struct {
    const char **items;
    uint32_t length;
    uint32_t capacity;
} bldr_strings_t;

typedef struct {
    bool fail_on_error;
    bool no_files;
    bool no_dirs;
    bool no_mark;
    bool no_sort;
    bool no_escape;
} bldr_strs_glob_opt_t;

typedef struct {
    bool fail_on_error;
    bool recursive;
    bool no_dirs;
    bool no_files;
    bool no_sort;
    bool no_escape;
    bool no_mark;
} bldr_strs_walk_opt_t;

int bldr_strs_glob_opt(bldr_strings_t *strings, bldr_arena_t *arena,
                       const char *pattern, bldr_strs_glob_opt_t options)
    __attribute__((nonnull(1, 2, 3)));
void bldr_strs_sort(bldr_strings_t *strings) __attribute__((nonnull(1)));
int bldr_strs_walk_opt(bldr_strings_t *strings, bldr_arena_t *arena,
                       const char *base_path, const char *pattern,
                       bldr_strs_walk_opt_t options)
    __attribute__((nonnull(1, 2, 3, 4)));

static inline int bldr_strs_append_many(bldr_strings_t *strings, size_t count,
                                        const char **items)
    __attribute__((nonnull(1, 3)));
static inline void bldr_strs_done(bldr_strings_t *strings);
static inline void bldr_strs_print(const bldr_strings_t *strings)
    __attribute__((nonnull(1)));
static inline int bldr_strs_reserve(bldr_strings_t *strings, size_t requested)
    __attribute__((nonnull(1)));
static inline int bldr_strs_resize(bldr_strings_t *strings, size_t size)
    __attribute__((nonnull(1)));
static inline size_t bldr_strs_save(bldr_strings_t *strings)
    __attribute__((nonnull(1)));

/*
 * General inline function implementations
 */

static inline size_t bldr_align_to(size_t value, size_t alignment) {
    // Alignment must be power of 2
    assert((alignment & (alignment - 1)) == 0);
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline char *bldr_arg_shift(int *argc, char ***argv) {
    assert(argc != NULL && *argc > 0 && argv != NULL);
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
    BLDR_UNWRAP(bldr_array_append_many((bldr_array_t *)cmd, sizeof(char *),
                                       count, items));
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

    BLDR_UNWRAP(
        bldr_array_reserve((bldr_array_t *)cmd, sizeof(char *), size + 1));
    BLDR_UNWRAP(bldr_array_resize((bldr_array_t *)cmd, sizeof(char *), size));

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

static inline void *bldr_vmem_base_ptr(bldr_vmem_t *vmem) {
    assert(vmem->base != NULL); // not initialized
    return vmem->base;
}

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
    assert(vmem->base != NULL); // not initialized
    return vmem->base + vmem->length;
}

/*
 * =====================================================================
 * IMPLEMENTATION SECTION
 * =====================================================================
 */

#ifdef BLDR_IMPLEMENTATION

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

    BLDR_UNWRAP(bldr_vmem_init(&vmem, capacity));
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

    bldr_log_info("arena (%p) rewind from %zu to %zu", arena->vmem.base,
                  current_length, checkpoint_length);
    uint8_t *base_ptr = (uint8_t *)bldr_vmem_base_ptr(&arena->vmem);
    arena->next = base_ptr + checkpoint_length;

    return BLDR_OK;
}

size_t bldr_arena_save(bldr_arena_t *arena) {
    size_t length = bldr_arena_length(arena);
    uintptr_t base = (uintptr_t)bldr_vmem_base_ptr(&arena->vmem);
    uint32_t hash = (uint32_t)((base ^ length ^ bldr_arena_magic()) & 0xFFFF);

    bldr_log_info("arena (%p) checkpoint at %zu", arena->vmem.base, length);
    // Pack: upper 16 bits = hash, lower 48 bits = length
    return ((size_t)hash << 48) | (length & 0xFFFFFFFFFFFF);
}

char *bldr_arena_sprintf(bldr_arena_t *arena, const char *format, ...) {
    static const char empty_string[] = "";

    va_list args;
    va_start(args, format);
    int length = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (length <= 0) {
        return (char *)empty_string;
    }

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
            exit(BLDR_EXIT_REBUILD);                                           \
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
        exit(BLDR_EXIT_REBUILD);
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
        exit(BLDR_EXIT_REBUILD);
#endif
    if (bldr_file_rename(binary_path, old_binary_path) != BLDR_OK)
        exit(BLDR_EXIT_REBUILD);

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
            exit(BLDR_EXIT_REBUILD);
        }
        bldr_log_info("%s exited successful", cmd.items[0]);
    } else {
        exit(BLDR_EXIT_REBUILD);
    }

    // ===== Execute the rebuild binary ========================================
    bldr_log_info("calling rebuild binary");
    bldr_cmd_reset(&cmd);
    BLDR_REBUILD_UNWRAP(bldr_cmd_append(&cmd, binary_path));
    BLDR_REBUILD_UNWRAP(bldr_cmd_append_many(&cmd, argc, (const char **)argv));

    exit_code = 0;
    result = bldr_proc_exec(&cmd, &exit_code, .no_redirect = true);
    if (result != BLDR_OK)
        exit(BLDR_EXIT_REBUILD);

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

    if (exit_code_ret)
        *exit_code_ret = exit_code;
    if (exit_code != BLDR_EXIT_OK)
        bldr_log_warn("process %d exited with code %d", handle.pid, exit_code);
    if (result != BLDR_OK)
        return result;
    if (options.no_redirect == false) {
        if (options.log_stdout)
            bldr_log_stdout(&handle);
        if (options.log_stderr)
            bldr_log_stderr(&handle);
    }

    return result;
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

        if (options.proc_group == 0)
            options.proc_group = pid;

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

    int signal = force ? SIGKILL : SIGTERM;
    if (kill(handle->pid, signal) == -1) {
        if (errno == ESRCH) {
            // Process already terminated
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
            bldr_log_warn("forcing process (%d) to terminate", handle->pid);
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
    pid_t result = _bldr_proc_wait_timeout(handle->pid, &status, timeout_ms);

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

    double start_time = bldr_time_now();
    const double timeout_time = (double)timeout_ms / 1000.0;

    // Adaptive polling: start with shorter intervals, increase gradually
    const long min_sleep = 1000;  // 1ms minimum
    const long max_sleep = 50000; // 50ms maximum
    long current_sleep = min_sleep;

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
            // Process is still running, check timeout
            double elapsed_time = bldr_time_now() - start_time;

            if (elapsed_time >= timeout_time) {
                bldr_log_warn("process %d timed out", pid);
                return BLDR_ERR_TIMEOUT;
            }
            // For the last second, use shorter sleep intervals for
            // responsiveness
            if (elapsed_time >= timeout_time - 1) {
                current_sleep = min_sleep;
            }

            // Sleep with adaptive interval (exponential backoff with cap)
            if (usleep(current_sleep) == -1 && errno == EINTR) {
                // If interrupted by signal, just continue - don't treat as
                // error
                continue;
            }

            // Gradually increase sleep time to reduce CPU usage with 1.5x
            // multiplier
            current_sleep = MIN((current_sleep * 3) / 2, max_sleep);
        }
    }
}

/*
 * Strings internal declarations
 */

typedef struct {
    bldr_strings_t *strings;
    bldr_arena_t *arena;
} _bldr_strs_walk_data_t;

static int _bldr_strs_glob_opt_error(const char *path, int error);
static int _bldr_strs_sort_compare(const void *a, const void *b);
static int _bldr_strs_walk_callback(const char *path, void *void_data);

/*
 * Strings function implementations
 */

int bldr_strs_glob_opt(bldr_strings_t *strings, bldr_arena_t *arena,
                       const char *pattern, bldr_strs_glob_opt_t options) {
    if (pattern[0] == '\0' || (options.no_dirs && options.no_files))
        return BLDR_OK;

    int flags =
        (options.fail_on_error ? GLOB_ERR : 0) |
        (!options.no_mark || options.no_dirs || options.no_files ? GLOB_MARK
                                                                 : 0) |
        (options.no_escape ? GLOB_NOESCAPE : 0) |
        (options.no_sort ? GLOB_NOSORT : 0);
    BLDR_DEFER(glob_t paths, globfree) = {0};
    int result = glob(pattern, flags, _bldr_strs_glob_opt_error, &paths);

    switch (result) {
    case GLOB_NOSPACE:
        BLDR_OOM_ERROR("not enough memory to store glob-results");
    case GLOB_ABORTED:
        bldr_log_error("unable to read file or directory");
        return BLDR_ERR_READ;
    case GLOB_NOMATCH:
        bldr_log_info("no matches found for pattern: %s", pattern);
        return BLDR_ERR_NOT_FOUND;
    }

    size_t total_size = 0;
    size_t path_count = 0;
    const bool keep_mark =
        (!options.no_mark && (options.no_dirs || options.no_files));

    for (size_t i = 0; i < paths.gl_pathc; i++) {
        size_t len = strlen(paths.gl_pathv[i]);

        if (len == 0)
            continue;
        if (options.no_dirs && paths.gl_pathv[i][len - 1] == '/')
            continue;
        if (options.no_files && paths.gl_pathv[i][len - 1] != '/')
            continue;
        total_size += (len + (keep_mark ? 1 : 0));
        path_count++;
    }

    if (path_count == 0) {
        bldr_log_info("no matches found for pattern: %s", pattern);
        return BLDR_ERR_NOT_FOUND;
    }

    BLDR_UNWRAP(bldr_strs_reserve(strings, strings->length + path_count));

    char *buffer = bldr_arena_alloc(arena, total_size);
    BLDR_CHECK_NULLPTR(buffer);

    for (size_t i = 0; i < paths.gl_pathc; i++) {
        size_t len = strlen(paths.gl_pathv[i]);

        if (len == 0)
            continue;
        if (options.no_dirs && paths.gl_pathv[i][len - 1] == '/')
            continue;
        if (options.no_files && paths.gl_pathv[i][len - 1] != '/')
            continue;
        if (keep_mark) {
            memcpy(buffer, paths.gl_pathv[i], len + 1);
        } else {
            memcpy(buffer, paths.gl_pathv[i], len);
            buffer[len - 1] = '\0';
        }
        strings->items[strings->length++] = buffer;
        buffer += (len + (keep_mark ? 1 : 0));
    }

    return BLDR_OK;
}

void bldr_strs_sort(bldr_strings_t *strings) {
    if (strings->length <= 1) {
        return;
    }

    qsort(strings->items, strings->length, sizeof(char *),
          _bldr_strs_sort_compare);
}

int bldr_strs_walk_opt(bldr_strings_t *strings, bldr_arena_t *arena,
                       const char *base_path, const char *pattern,
                       bldr_strs_walk_opt_t options) {
    if (base_path[0] == '\0' || pattern[0] == '\0' ||
        (options.no_dirs && options.no_files))
        return BLDR_OK;

    _bldr_strs_walk_data_t walk_data = {
        .strings = strings,
        .arena = arena,
    };
    bldr_file_walk_opt_t walk_options = {
        .fail_on_error = options.fail_on_error,
        .recursive = options.recursive,
        .no_dirs = options.no_dirs,
        .no_files = options.no_files,
        .no_escape = options.no_escape,
        .no_mark = options.no_mark,
        .data = &walk_data,
    };

    BLDR_UNWRAP(bldr_file_walk_opt(base_path, pattern, _bldr_strs_walk_callback,
                                   walk_options));
    if (options.no_sort == false)
        bldr_strs_sort(strings);

    return BLDR_OK;
}

/*
 * Strings static helper function implementations
 */

static int _bldr_strs_glob_opt_error(const char *path, int error) {
    bldr_log_warn("unable to access path '%s' (%s)", path, strerror(error));
    return 0;
}

static int _bldr_strs_sort_compare(const void *a, const void *b) {
    const char *str_a = *(const char **)a;
    const char *str_b = *(const char **)b;

    // Handle NULL pointers - treat as less than any string
    if (!str_a && !str_b)
        return 0;
    if (!str_a)
        return -1;
    if (!str_b)
        return 1;

    return strcmp(str_a, str_b);
}

static int _bldr_strs_walk_callback(const char *path, void *void_data) {
    _bldr_strs_walk_data_t *data = (_bldr_strs_walk_data_t *)void_data;
    char *copied_path = bldr_arena_strdup(data->arena, path);

    BLDR_CHECK_NULLPTR(copied_path);
    BLDR_UNWRAP(bldr_strs_append(data->strings, copied_path));
    return BLDR_OK;
}

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

    memset(vmem, 0, sizeof(bldr_vmem_t));
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

#endif // BLDR_IMPLEMENTATION

/*
 * =====================================================================
 * STRIP PREFIX SECTION
 * =====================================================================
 */

#ifdef BLDR_STRIP_PREFIX
#define BLDR_STRIP_PREFIX_ARENA
#define BLDR_STRIP_PREFIX_ARRAY
#define BLDR_STRIP_PREFIX_BUILDER
#define BLDR_STRIP_PREFIX_COMMAND
#define BLDR_STRIP_PREFIX_DEFINES
#define BLDR_STRIP_PREFIX_LOGGER
#define BLDR_STRIP_PREFIX_FILE
#define BLDR_STRIP_PREFIX_PROCESS
#define BLDR_STRIP_PREFIX_STRINGS
#define BLDR_STRIP_PREFIX_VMEMORY
#endif // BLDR_STRIP_PREFIX

#ifdef BLDR_STRIP_PREFIX_ARENA
#define arena_t bldr_arena_t

#define arena_alloc bldr_arena_alloc
#define arena_available bldr_arena_available
#define arena_capacity bldr_arena_capacity
#define arena_done bldr_arena_done
#define arena_init bldr_arena_init
#define arena_init_in bldr_arena_init_in
#define arena_is_empty bldr_arena_is_empty
#define arena_length bldr_arena_length
#define arena_magic bldr_arena_magic
#define arena_rewind bldr_arena_rewind
#define arena_save bldr_arena_save
#define arena_sprintf bldr_arena_sprintf
#define arena_strdup bldr_arena_strdup
#define arena_strndup bldr_arena_strndup
#endif // BLDR_STRIP_PREFIX_ARENA

#ifdef BLDR_STRIP_PREFIX_ARRAY
#define array_t bldr_array_t

#define array_append_many bldr_array_append_many
#define array_done bldr_array_done
#define array_reserve bldr_array_reserve
#define array_resize bldr_array_resize
#endif // BLDR_STRIP_PREFIX_ARRAY

#ifdef BLDR_STRIP_PREFIX_BUILDER
#define needs_rebuild bldr_needs_rebuild
#define needs_rebuild_many bldr_needs_rebuild_many
#define build_yourself bldr_build_yourself
#define build_yourself_many bldr_build_yourself_many
#endif // BLDR_STRIP_PREFIX_BUILDER

#ifdef BLDR_STRIP_PREFIX_COMMAND
#define cmd_t bldr_cmd_t
#define cmd_options_t bldr_cmd_options_t
#define cmd_procs_t bldr_cmd_procs_t

#define cmd_append bldr_cmd_append
#define cmd_append_many bldr_cmd_append_many
#define cmd_clone_in bldr_cmd_clone_in
#define cmd_done bldr_cmd_done
#define cmd_print bldr_cmd_print
#define cmd_procs_append bldr_cmd_procs_append
#define cmd_procs_append_many bldr_cmd_procs_append_many
#define cmd_procs_done bldr_cmd_procs_done
#define cmd_procs_wait bldr_cmd_procs_wait
#define cmd_reserve bldr_cmd_reserve
#define cmd_reset bldr_cmd_reset
#define cmd_resize bldr_cmd_resize
#define cmd_rewind bldr_cmd_rewind
#define cmd_run bldr_cmd_run
#define cmd_run_opt bldr_cmd_run_opt
#define cmd_save bldr_cmd_save
#define cmd_valid bldr_cmd_valid
#endif // BLDR_STRIP_PREFIX_COMMAND

#ifdef BLDR_STRIP_PREFIX_DEFINES
#define ARENA_CAPACITY BLDR_ARENA_CAPACITY
#define ARRAY_CAPACITY_MIN BLDR_ARRAY_CAPACITY_MIN
#define COMMAND_ARGS_MAX BLDR_COMMAND_ARGS_MAX
#define FILE_PATH_MAX BLDR_FILE_PATH_MAX
#define LOG_LEVEL_MIN BLDR_LOG_LEVEL_MIN
#define LOG_OUT BLDR_LOG_OUT
#define MESSAGE_SIZE BLDR_MESSAGE_SIZE

#define AND_THEN BLDR_AND_THEN
#define DEFER BLDR_DEFER
#define IS_ERR BLDR_IS_ERR
#define IS_FALSE BLDR_IS_FALSE
#define IS_OK BLDR_IS_OK
#define IS_TRUE BLDR_IS_TRUE
#define TODO BLDR_TODO
#define UNREACHABLE BLDR_UNREACHABLE
#define UNUSED BLDR_UNUSED

#define CHECK_NULLPTR BLDR_CHECK_NULLPTR
#define ERROR_NULL BLDR_ERROR_NULL
#define HANDLE_NULL BLDR_HANDLE_NULL
#define OOM_ERROR BLDR_OOM_ERROR
#define OOM_NULL BLDR_OOM_NULL
#define UNWRAP BLDR_UNWRAP
#define UNWRAP_NULL BLDR_UNWRAP_NULL

#define OK BLDR_OK
#define FALSE BLDR_FALSE
#define TRUE BLDR_TRUE

#define ERR_ALIGN BLDR_ERR_ALIGN
#define ERR_ARGS BLDR_ERR_ARGS
#define ERR_CLOSE BLDR_ERR_CLOSE
#define ERR_CLOSE_TAG BLDR_ERR_CLOSE_TAG
#define ERR_DUPLICATE BLDR_ERR_DUPLICATE
#define ERR_EXEC BLDR_ERR_EXEC
#define ERR_FILE BLDR_ERR_FILE
#define ERR_FILE_PERM BLDR_ERR_FILE_PERM
#define ERR_FILE_QUOTA BLDR_ERR_FILE_QUOTA
#define ERR_FILE_STAT BLDR_ERR_FILE_STAT
#define ERR_FILE_TYPE BLDR_ERR_FILE_TYPE
#define ERR_FORK BLDR_ERR_FORK
#define ERR_KILL BLDR_ERR_KILL
#define ERR_LOCK BLDR_ERR_LOCK
#define ERR_MEMORY BLDR_ERR_MEMORY
#define ERR_NOT_FOUND BLDR_ERR_NOT_FOUND
#define ERR_OPEN BLDR_ERR_OPEN
#define ERR_OVERFLOW BLDR_ERR_OVERFLOW
#define ERR_PATTERN BLDR_ERR_PATTERN
#define ERR_PIPE BLDR_ERR_PIPE
#define ERR_PLATFORM BLDR_ERR_PLATFORM
#define ERR_READ BLDR_ERR_READ
#define ERR_SYNTAX BLDR_ERR_SYNTAX
#define ERR_TERMINATED BLDR_ERR_TERMINATED
#define ERR_TIMEOUT BLDR_ERR_TIMEOUT
#define ERR_UNDERFLOW BLDR_ERR_UNDERFLOW
#define ERR_WAIT BLDR_ERR_WAIT
#define ERR_WRITE BLDR_ERR_WRITE

#define EXIT_OK BLDR_EXIT_OK

#define EXIT_REBUILD BLDR_EXIT_REBUILD
#define EXIT_NOMEM BLDR_EXIT_NOMEM
#define EXIT_IO BLDR_EXIT_IO
#define EXIT_RAND BLDR_EXIT_RAND
#define EXIT_TIME BLDR_EXIT_TIME

#define EXIT_CHILD BLDR_EXIT_CHILD
#define EXIT_CHILD_CHDIR BLDR_EXIT_CHILD_CHDIR
#define EXIT_CHILD_STDIN BLDR_EXIT_CHILD_STDIN
#define EXIT_CHILD_STDOUT BLDR_EXIT_CHILD_STDOUT
#define EXIT_CHILD_STDERR BLDR_EXIT_CHILD_STDERR
#define EXIT_CHILD_SETPGID BLDR_EXIT_CHILD_SETPGID
#define EXIT_CHILD_HOOK BLDR_EXIT_CHILD_HOOK

#define empty_string bldr_empty_string

#define align_to bldr_align_to
#define align_type bldr_align_type
#define arg_shift bldr_arg_shift
#define crypto_random bldr_crypto_random
#define crypto_random_u32 bldr_crypto_random_u32
#define crypto_random_u64 bldr_crypto_random_u64
#define page_align bldr_page_align
#define page_size bldr_page_size
#define processor_count bldr_processor_count
#define system_align bldr_system_align
#define time_now bldr_time_now
#endif // BLDR_STRIP_PREFIX_DEFINES

#ifdef BLDR_STRIP_PREFIX_FILE
#define file_cat_opt_t bldr_file_cat_opt_t
#define file_dupdirs_opt_t bldr_file_dupdirs_opt_t
#define file_mkdir_opt_t bldr_file_mkdir_opt_t
#define file_walk_opt_t bldr_file_walk_opt_t
#define file_walk_fn_t bldr_file_walk_fn_t

#define fd_done bldr_fd_done
#define fd_read bldr_fd_read
#define fd_write bldr_fd_write

#define file_cat bldr_file_cat
#define file_cat_opt bldr_file_cat_opt
#define file_done bldr_file_done
#define file_dupdirs bldr_file_dupdirs
#define file_dupdirs_opt bldr_file_dupdirs_opt
#define file_mkdir bldr_file_mkdir
#define file_mkdir_opt bldr_file_mkdir_opt
#define file_pathsubst bldr_file_pathsubst
#define file_printf bldr_file_printf
#define file_rename bldr_file_rename
#define file_walk bldr_file_walk
#define file_walk_opt bldr_file_walk_opt
#endif // BLDR_STRIP_PREFIX_FILE

#ifdef BLDR_STRIP_PREFIX_LOGGER
#define LOG_INFO BLDR_LOG_INFO
#define LOG_WARN BLDR_LOG_WARN
#define LOG_ERROR BLDR_LOG_ERROR
#define LOG_OFF BLDR_LOG_OFF

#define log_level_t bldr_log_level_t

#define log_cmd bldr_log_cmd
#define log_dump bldr_log_dump
#define log_error bldr_log_error
#define log_fddump bldr_log_fddump
#define log_get_level bldr_log_get_level
#define log_info bldr_log_info
#define log_message bldr_log_message
#define log_message_va bldr_log_message_va
#define log_set_level bldr_log_set_level
#define log_stderr bldr_log_stderr
#define log_stdout bldr_log_stdout
#define log_time bldr_log_time
#define log_warn bldr_log_warn
#endif // BLDR_STRIP_PREFIX_LOGGER

#ifdef BLDR_STRIP_PREFIX_PROCESS
#define proc_handle_t bldr_proc_handle_t
#define proc_hook_t bldr_proc_hook_t
#define proc_options_t bldr_proc_options_t

#define proc_exec bldr_proc_exec
#define proc_exec_async bldr_proc_exec_async
#define proc_exec_async_opt bldr_proc_exec_async_opt
#define proc_exec_opt bldr_proc_exec_opt
#define proc_handle_done bldr_proc_handle_done
#define proc_handle_init bldr_proc_handle_init
#define proc_is_running bldr_proc_is_running
#define proc_read_stderr bldr_proc_read_stderr
#define proc_read_stdout bldr_proc_read_stdout
#define proc_terminate bldr_proc_terminate
#define proc_wait bldr_proc_wait
#define proc_write bldr_proc_write
#endif // BLDR_STRIP_PREFIX_PROCESS

#ifdef BLDR_STRIP_PREFIX_STRINGS
#define strings_t bldr_strings_t
#define strs_glob_opt_t bldr_strs_glob_opt_t
#define strs_walk_opt_t bldr_strs_walk_opt_t

#define strs_append bldr_strs_append
#define strs_append_many bldr_strs_append_many
#define strs_done bldr_strs_done
#define strs_glob bldr_strs_glob
#define strs_glob_opt bldr_strs_glob_opt
#define strs_print bldr_strs_print
#define strs_reserve bldr_strs_reserve
#define strs_reset bldr_strs_reset
#define strs_resize bldr_strs_resize
#define strs_rewind bldr_strs_rewind
#define strs_save bldr_strs_save
#define strs_sort bldr_strs_sort
#define strs_walk bldr_strs_walk
#define strs_walk_opt bldr_strs_walk_opt
#endif // BLDR_STRIP_PREFIX_STRINGS

#ifdef BLDR_STRIP_PREFIX_VMEMORY
#define vmem_t bldr_vmem_t

#define vmem_available bldr_vmem_available
#define vmem_base_ptr bldr_vmem_base_ptr
#define vmem_capacity bldr_vmem_capacity
#define vmem_commit bldr_vmem_commit
#define vmem_decommit bldr_vmem_decommit
#define vmem_done bldr_vmem_done
#define vmem_init bldr_vmem_init
#define vmem_is_empty bldr_vmem_is_empty
#define vmem_length bldr_vmem_length
#define vmem_rebase bldr_vmem_rebase
#define vmem_top_ptr bldr_vmem_top_ptr
#endif // BLDR_STRIP_PREFIX_VMEMORY

#ifdef __cplusplus
}
#endif

#endif // _BLDR_H_

/*
CREDITS:

Partially based and inspired by the work of:
- https://github.com/tsoding/nob.h
*/
