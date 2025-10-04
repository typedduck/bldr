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
#define BLDR_LOG_LEVEL_MAX BLDR_LOG_INFO
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
