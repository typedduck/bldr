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

bldr_cmd_t *bldr_cmd_clone_in(const bldr_cmd_t *cmd, bldr_arena_t *arena)
    __attribute__((nonnull(1, 2)));
void bldr_cmd_procs_done(bldr_cmd_procs_t *procs);
bool bldr_cmd_procs_wait(bldr_cmd_procs_t *procs, size_t timeout_sec)
    __attribute__((nonnull(1)));
int bldr_cmd_run_opt(const bldr_cmd_t *cmd, bldr_cmd_options_t options)
    __attribute__((nonnull(1)));

static inline int bldr_cmd_append_many(bldr_cmd_t *cmd, size_t count,
                                       const char **items)
    __attribute__((nonnull(1, 3)));
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

#define bldr_log_info(fmt, ...)                                                \
    bldr_log_message(BLDR_LOG_INFO, fmt, ##__VA_ARGS__)
#define bldr_log_warn(fmt, ...)                                                \
    bldr_log_message(BLDR_LOG_WARN, fmt, ##__VA_ARGS__)
#define bldr_log_error(fmt, ...)                                               \
    bldr_log_message(BLDR_LOG_ERROR, fmt, ##__VA_ARGS__)

typedef enum {
    BLDR_LOG_OFF,
    BLDR_LOG_ERROR,
    BLDR_LOG_WARN,
    BLDR_LOG_INFO,
} bldr_log_level_t;

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
