/**
 * @file strings.c
 * @brief Dynamic array of strings
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

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
