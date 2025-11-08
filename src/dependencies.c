/**
 * @file dependencies.c
 * @brief Dependency information and parser
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Dependencies internal declarations
 */

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} _bldr_deps_buffer_t;

typedef struct {
    const char *content; // File content
    size_t length;       // Total content length
    size_t pos;          // Current position
    size_t line;         // Current line (1-indexed)
    size_t column;       // Current column (1-indexed)
    bldr_arena_t *arena; // Arena for allocations
} _bldr_deps_parser_t;

static bool _bldr_deps_parse_continuation(_bldr_deps_parser_t *parser)
    __attribute__((nonnull(1)));
static int _bldr_deps_parse_filename(_bldr_deps_parser_t *parser,
                                     _bldr_deps_buffer_t *output)
    __attribute__((nonnull(1, 2)));
static int _bldr_deps_parse_line(_bldr_deps_parser_t *parser,
                                 _bldr_deps_buffer_t *output, bldr_deps_t *deps)
    __attribute__((nonnull(1, 2, 3)));
static void _bldr_deps_parser_advance(_bldr_deps_parser_t *parser)
    __attribute__((nonnull(1)));
static inline bool _bldr_deps_parser_at_end(const _bldr_deps_parser_t *parser);
static int _bldr_deps_parser_buffer_add(_bldr_deps_buffer_t *buffer, char c)
    __attribute__((nonnull(1)));
static inline bool _bldr_deps_parser_isspace(char c);
static inline char _bldr_deps_parser_peek(const _bldr_deps_parser_t *parser)
    __attribute__((nonnull(1)));
static inline char
_bldr_deps_parser_peek_ahead(const _bldr_deps_parser_t *parser, size_t offset)
    __attribute__((nonnull(1)));
static void _bldr_deps_parser_skip_space(_bldr_deps_parser_t *parser)
    __attribute__((nonnull(1)));

/*
 * Dependencies function implementations
 */

int bldr_deps_needs_rebuild(bldr_deps_t *deps, bool *needs_rebuild) {
    *needs_rebuild = false;
    if (deps->target == NULL || deps->target[0] == '\0') {
        bldr_log_error("dependency target not specified");
        return BLDR_ERR_ARGS;
    }

    struct stat target_stat;
    if (stat(deps->target, &target_stat) != 0) {
        if (errno == ENOENT) {
            // Missing target triggers rebuild
            *needs_rebuild = true;
            return BLDR_OK;
        }
        bldr_log_error("could not stat '%s' (%s)", deps->target,
                       strerror(errno));
        return BLDR_ERR_FILE_STAT;
    }

    for (size_t i = 0; i < deps->dependencies.length; i++) {
        struct stat dep_stat;
        if (stat(deps->dependencies.items[i], &dep_stat) != 0) {
            // Dependencies must exist
            bldr_log_error("could not stat '%s' (%s)",
                           deps->dependencies.items[i], strerror(errno));
            *needs_rebuild = false;
            return BLDR_ERR_FILE_STAT;
        }

        if (dep_stat.st_mtime > target_stat.st_mtime) {
            *needs_rebuild = true;
            return BLDR_OK;
        }
    }

    return BLDR_OK;
}

int bldr_deps_needs_regen(const char *dep_path, const char *src_path,
                          bool *needs_regen) {
    struct stat dep_stat, src_stat;

    *needs_regen = false;
    if (stat(dep_path, &dep_stat) != 0) {
        if (errno == ENOENT) {
            // Missing dependency file triggers regeneration
            *needs_regen = true;
            return BLDR_OK;
        }
        bldr_log_error("could not stat '%s' (%s)", dep_path, strerror(errno));
        return BLDR_ERR_FILE_STAT;
    }

    if (stat(src_path, &src_stat) != 0) {
        // Source file must exist
        bldr_log_error("could not stat '%s' (%s)", src_path, strerror(errno));
        return BLDR_ERR_FILE_STAT;
    }

    *needs_regen = src_stat.st_mtime > dep_stat.st_mtime;
    return BLDR_OK;
}

int bldr_deps_read_opt(bldr_arena_t *arena, const char *dep_path,
                       bldr_deps_t *deps, const bldr_deps_read_opt_t options) {
    _bldr_deps_buffer_t buffer = {0};

    buffer.capacity =
        options.buffer_size ? options.buffer_size : BLDR_FILE_PATH_MAX;
    buffer.data = options.buffer;
    BLDR_DEFER(void *buffer_cleanup, bldr_realloc_cleanup) = NULL;
    if (!buffer.data) {
        buffer.data = BLDR_REALLOC(NULL, buffer.capacity);
        if (buffer.data == NULL)
            BLDR_OOM_ERROR(
                "failed to allocated buffer for reading dependency file");
        buffer_cleanup = buffer.data;
    }

    struct stat st;
    if (stat(dep_path, &st) != 0) {
        bldr_log_error("could not stat '%s' (%s)", dep_path, strerror(errno));
        return BLDR_ERR_FILE_STAT;
    }

    if (st.st_size == 0) {
        bldr_log_warn("empty dependency file: %s", dep_path);
        return BLDR_OK;
    }

    BLDR_DEFER(FILE * f, bldr_file_done) = fopen(dep_path, "rb");
    if (f == NULL) {
        bldr_log_error("unable to open dependency file '%s' for reading (%s)",
                       dep_path, strerror(errno));
        return BLDR_ERR_FILE;
    }

    _bldr_deps_parser_t parser = {
        .arena = arena, .length = st.st_size, .column = 1, .line = 1, .pos = 0};
    char *content = bldr_arena_alloc(arena, parser.length + 1);
    BLDR_CHECK_NULLPTR(content);

    size_t read = fread(content, 1, parser.length, f);
    if (read != parser.length) {
        if (ferror(f)) {
            bldr_log_error("unable to read dependency file '%s' (%s)", dep_path,
                           strerror(errno));
        } else {
            bldr_log_error("unexpected EOF reading dependency file '%s'",
                           dep_path);
        }
        return BLDR_ERR_FILE;
    }
    content[parser.length] = '\0';
    parser.content = content;

    return _bldr_deps_parse_line(&parser, &buffer, deps);
}

/*
 * Dependencies static helper function implementations
 */

static bool _bldr_deps_parse_continuation(_bldr_deps_parser_t *parser) {
    if (_bldr_deps_parser_peek(parser) != '\\')
        return false;

    char next = _bldr_deps_parser_peek_ahead(parser, 1);
    if (next == '\n') {
        _bldr_deps_parser_advance(parser); // Skip backslash
        _bldr_deps_parser_advance(parser); // Skip newline
        return true;
    }

    if (next == '\r') {
        char after_cr = _bldr_deps_parser_peek_ahead(parser, 2);
        _bldr_deps_parser_advance(parser); // Skip backslash
        _bldr_deps_parser_advance(parser); // Skip CR
        if (after_cr == '\n')
            _bldr_deps_parser_advance(parser); // Skip LF
        return true;
    }

    return false;
}

static int _bldr_deps_parse_filename(_bldr_deps_parser_t *parser,
                                     _bldr_deps_buffer_t *output) {
    while (!_bldr_deps_parser_at_end(parser)) {
        char current = _bldr_deps_parser_peek(parser);

        // Stop at unescaped whitespace or colon or newline
        if (_bldr_deps_parser_isspace(current) || current == ':' ||
            current == '\n' || current == '\r') {
            break;
        }

        // Handle backslash escapes
        if (current == '\\') {
            char next = _bldr_deps_parser_peek_ahead(parser, 1);

            // Escaped space
            if (next == ' ') {
                _bldr_deps_parser_advance(parser); // Skip backslash
                _bldr_deps_parser_advance(parser); // Skip space
                BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, ' '));
                continue;
            }

            // Escaped backslash
            if (next == '\\') {
                _bldr_deps_parser_advance(parser); // Skip first backslash
                _bldr_deps_parser_advance(parser); // Skip second backslash
                BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, '\\'));
                continue;
            }

            // Escaped hash
            if (next == '#') {
                _bldr_deps_parser_advance(parser); // Skip backslash
                _bldr_deps_parser_advance(parser); // Skip hash
                BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, '#'));
                continue;
            }

            // Line continuation - should not appear in filename
            if (next == '\n' || next == '\r') {
                bldr_log_error("(%zu, %zu) line continuation in filename",
                               parser->line, parser->column);
                return BLDR_ERR_SYNTAX;
            }

            // Backslash without recognized escape - treat as literal
            _bldr_deps_parser_advance(parser);
            BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, '\\'));
            continue;
        }

        // Handle dollar sign (Make uses $$ for literal $)
        if (current == '$') {
            char next = _bldr_deps_parser_peek_ahead(parser, 1);
            if (next == '$') {
                _bldr_deps_parser_advance(parser); // Skip first $
                _bldr_deps_parser_advance(parser); // Skip second $
                BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, '$'));
                continue;
            }
        }

        // Regular character - Ensure buffer has space
        BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, current));
        _bldr_deps_parser_advance(parser);
    }

    if (output->length == 0)
        return BLDR_ERR_SYNTAX;

    // Null terminate
    BLDR_UNWRAP_ERROR(_bldr_deps_parser_buffer_add(output, '\0'));
    return BLDR_OK;
}

static int _bldr_deps_parse_line(_bldr_deps_parser_t *parser,
                                 _bldr_deps_buffer_t *output,
                                 bldr_deps_t *deps) {
    // Skip leading whitespace
    _bldr_deps_parser_skip_space(parser);

    // Parse target
    output->length = 0;
    BLDR_UNWRAP_ERROR(_bldr_deps_parse_filename(parser, output));

    if (output->length == 0) {
        bldr_log_error("(%zu, %zu) no target specified", parser->line,
                       parser->column);
        return BLDR_ERR_SYNTAX;
    }

    deps->target =
        bldr_arena_strndup(parser->arena, output->data, output->length);
    BLDR_CHECK_NULLPTR(deps->target);

    // Skip whitespace after target
    _bldr_deps_parser_skip_space(parser);

    // Expect colon
    if (_bldr_deps_parser_peek(parser) != ':') {
        bldr_log_error("(%zu, %zu) missing colon after target", parser->line,
                       parser->column);
        return BLDR_ERR_SYNTAX;
    }
    _bldr_deps_parser_advance(parser); // Skip colon

    // Parse dependencies
    while (!_bldr_deps_parser_at_end(parser)) {
        // Skip whitespace
        _bldr_deps_parser_skip_space(parser);

        // Check for line continuation
        if (_bldr_deps_parse_continuation(parser))
            continue;

        // Check for end of line
        char current = _bldr_deps_parser_peek(parser);
        if (current == '\n' || current == '\r' || current == '\0')
            break;

        // Check for comment (unescaped #)
        if (current == '#')
            break;

        // Parse dependency filename
        output->length = 0;
        BLDR_UNWRAP_ERROR(_bldr_deps_parse_filename(parser, output));

        // Skip empty tokens
        if (output->length == 0)
            continue;

        // Add to dependencies array
        char *dependency =
            bldr_arena_strndup(parser->arena, output->data, output->length);
        BLDR_CHECK_NULLPTR(dependency);
        bldr_deps_append(deps, dependency);
    }

    return BLDR_OK;
}

static void _bldr_deps_parser_advance(_bldr_deps_parser_t *parser) {
    if (parser->pos >= parser->length)
        return;

    char current = parser->content[parser->pos];
    parser->pos++;

    if (current == '\n') {
        parser->line++;
        parser->column = 1;
    } else {
        parser->column++;
    }
}

static inline bool _bldr_deps_parser_at_end(const _bldr_deps_parser_t *parser) {
    return parser->pos >= parser->length;
}

static int _bldr_deps_parser_buffer_add(_bldr_deps_buffer_t *buffer, char c) {
    if (buffer->length >= buffer->capacity) {
        bldr_log_error("dependency parser buffer overflow");
        return BLDR_ERR_OVERFLOW;
    }
    buffer->data[buffer->length++] = c;
    return BLDR_OK;
}

static inline bool _bldr_deps_parser_isspace(char c) {
    return c == ' ' || c == '\t';
}

static inline char _bldr_deps_parser_peek(const _bldr_deps_parser_t *parser) {
    if (parser->pos >= parser->length)
        return '\0';
    return parser->content[parser->pos];
}

static inline char
_bldr_deps_parser_peek_ahead(const _bldr_deps_parser_t *parser, size_t offset) {
    size_t peek_pos = parser->pos + offset;
    if (peek_pos >= parser->length)
        return '\0';
    return parser->content[peek_pos];
}

static void _bldr_deps_parser_skip_space(_bldr_deps_parser_t *parser) {
    while (_bldr_deps_parser_isspace(_bldr_deps_parser_peek(parser)))
        _bldr_deps_parser_advance(parser);
}
