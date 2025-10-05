#define BLDR_IMPLEMENTATION
#define BLDR_STRIP_PREFIX

// Default: Abort on OOM condtion
#include "bldr.h"

constexpr char bldr_header[] = "bldr.h";
constexpr char bldr_source[] = "bldr.c";

static int build_stb_library(arena_t *arena);

int main(int argc, char **argv) {
    log_set_level(LOG_WARN);
    build_yourself(argc, argv, bldr_source, bldr_header);

    DEFER(arena_t arena, arena_done) = {0};
    size_t checkpoint = 0;
    int result = OK;

    // Initialize
    AND_THEN(result, arena_init(&arena, 64 * 1024));

    // STB version of library
    checkpoint = arena_save(&arena);
    AND_THEN(result, build_stb_library(&arena));
    AND_THEN(result, arena_rewind(&arena, checkpoint));

    return result;
}

constexpr char stb_text_1[] = "/*\n";
constexpr char stb_text_2[] =
    "*/\n\n"
    "#ifndef _BLDR_H_\n#define _BLDR_H_\n\n"
    "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n"
    "/*\n"
    " * =====================================================================\n"
    " * HEADER SECTION\n"
    " * =====================================================================\n"
    " */\n\n";
constexpr char stb_text_3[] =
    "/*\n"
    " * =====================================================================\n"
    " * IMPLEMENTATION SECTION\n"
    " * =====================================================================\n"
    " */\n\n"
    "#ifdef BLDR_IMPLEMENTATION\n";
constexpr char stb_text_4[] =
    "\n#endif // BLDR_IMPLEMENTATION\n\n"
    "/*\n"
    " * =====================================================================\n"
    " * STRIP PREFIX SECTION\n"
    " * =====================================================================\n"
    " */\n\n";
constexpr char stb_text_5[] = "\n#ifdef __cplusplus\n}\n#endif\n\n"
                              "#endif // _BLDR_H_\n\n"
                              "/*\n";
constexpr char stb_text_6[] = "*/\n";

static int build_stb_library(arena_t *arena) {
    int result = OK;
    size_t cp_headers = 0;
    size_t cp_sources = 0;
    // Paths defining the stb-library
    DEFER(strings_t paths, strs_done) = {0};

    // Collect paths that define the stb-library, headers first then sources
    AND_THEN(result, strs_walk(&paths, arena, "include", "bldr_??_*.h",
                               .no_dirs = true, .recursive = true));
    cp_headers = strs_save(&paths);
    AND_THEN(result, strs_append(&paths, "include/bldr_strip.h"));
    cp_sources = strs_save(&paths);
    AND_THEN(result, strs_walk(&paths, arena, "src", "*.c", .no_dirs = true,
                               .recursive = true));

    // Check if headers or sources have changed and rebuild is needed
    result = needs_rebuild_many(bldr_header, paths.length, paths.items);
    if (result <= 0) // No rebuild needed or an error occured
        return result;
    log_info("building stb library");

    // Rename old header file
    const char *bldr_header_old =
        bldr_arena_sprintf(arena, "%s.old", bldr_header);

    result = bldr_file_rename(bldr_header, bldr_header_old);
    if (result != OK)
        return result;

    // Open or create the stb-library header file
    DEFER(FILE * out, file_done) = fopen(bldr_header, "w");
    if (out == NULL) {
        log_error("unable to open output file '%s' for writing (%s)",
                  bldr_header, strerror(errno));
        return ERR_OPEN;
    }

    // Write the stb-library
    constexpr size_t buffer_size = 4096;
    char *buffer = arena_alloc(arena, buffer_size);
    CHECK_NULLPTR(buffer);
    file_cat_opt_t options = (file_cat_opt_t){
        .buffer = buffer,
        .buffer_size = buffer_size,
    };

    AND_THEN(result, file_printf(out, stb_text_1));
    AND_THEN(result, file_cat_opt(out, "LICENSE", options));
    AND_THEN(result, file_printf(out, stb_text_2));
    for (size_t i = 0; i < cp_headers; i++) {
        AND_THEN(result, file_cat_opt(out, paths.items[i], options));
        AND_THEN(result, file_printf(out, "\n"));
    }
    AND_THEN(result, file_printf(out, stb_text_3));
    options.skip_lines = 9;
    for (size_t i = cp_sources; i < paths.length; i++)
        AND_THEN(result, file_cat_opt(out, paths.items[i], options));
    options.skip_lines = 0;
    AND_THEN(result, file_printf(out, stb_text_4));
    AND_THEN(result, file_cat_opt(out, "include/bldr_strip.h", options));
    AND_THEN(result, file_printf(out, stb_text_5));
    AND_THEN(result, file_cat_opt(out, "CREDITS", options));
    AND_THEN(result, file_printf(out, stb_text_6));

    return result;
}
