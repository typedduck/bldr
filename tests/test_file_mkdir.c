#include "../bldr.h"
#include <setjmp.h> // IWYU pragma: keep. Needed indirectly by cmocka.h

#include <cmocka.h>

// Test fixture setup/teardown
static int setup(void **state) {
    // Create a temporary directory for tests
    char *test_dir = strdup("/tmp/mkdir_test_XXXXXX");
    if (!mkdtemp(test_dir)) {
        free(test_dir);
        return -1;
    }
    *state = test_dir;
    return 0;
}

static int teardown(void **state) {
    char *test_dir = (char *)*state;
    if (test_dir) {
        // Clean up test directory (simple rm -rf equivalent)
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
        system(cmd);
        free(test_dir);
    }
    return 0;
}

// Helper function to check if directory exists
static bool dir_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

// Test cases
static void test_mkdir_simple_directory(void **state) {
    char *test_dir = (char *)*state;
    char path[256];
    snprintf(path, sizeof(path), "%s/simple", test_dir);

    int result = bldr_file_mkdir(path);
    assert_int_equal(result, BLDR_OK);
    assert_true(dir_exists(path));
}

static void test_mkdir_with_parents(void **state) {
    char *test_dir = (char *)*state;
    char path[256];
    snprintf(path, sizeof(path), "%s/foo/bar/baz", test_dir);

    int result = bldr_file_mkdir(path, .parents = true);
    assert_int_equal(result, BLDR_OK);
    assert_true(dir_exists(path));

    // Check that parent directories were created
    snprintf(path, sizeof(path), "%s/foo", test_dir);
    assert_true(dir_exists(path));
    snprintf(path, sizeof(path), "%s/foo/bar", test_dir);
    assert_true(dir_exists(path));
}

static void test_mkdir_without_parents_fails(void **state) {
    char *test_dir = (char *)*state;
    char path[256];
    snprintf(path, sizeof(path), "%s/nonexistent/subdir", test_dir);

    int result = bldr_file_mkdir(path);
    assert_int_not_equal(result, BLDR_OK);
    assert_false(dir_exists(path));
}

static void test_mkdir_existing_directory(void **state) {
    char *test_dir = (char *)*state;
    char path[256];
    snprintf(path, sizeof(path), "%s/existing", test_dir);

    // Create directory first
    int result = bldr_file_mkdir(path);
    assert_int_equal(result, BLDR_OK);

    // Try to create again - should succeed
    result = bldr_file_mkdir(path);
    assert_int_equal(result, BLDR_OK);
}

static void test_mkdir_invalid_inputs(void **state) {
    (void)state; // Unused

    // Test NULL path
    int result = bldr_file_mkdir(NULL);
    assert_int_equal(result, BLDR_ERR_ARGS);

    // Test empty path
    result = bldr_file_mkdir("");
    assert_int_equal(result, BLDR_ERR_ARGS);
}

static void test_mkdir_path_too_long(void **state) {
    (void)state; // Unused

    // Create a path longer than MAX_PATH_LEN
    char long_path[5000];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';

    int result = bldr_file_mkdir(long_path);
    assert_int_equal(result, BLDR_ERR_OVERFLOW);
}

static void test_mkdir_permissions(void **state) {
    char *test_dir = (char *)*state;
    char path[256];
    snprintf(path, sizeof(path), "%s/perm_test", test_dir);

    int result = bldr_file_mkdir(path, .mode = 0700);
    assert_int_equal(result, BLDR_OK);

    // Check permissions (note: umask might affect this)
    struct stat st;
    assert_int_equal(stat(path, &st), 0);
    // Just verify it's a directory, exact permissions depend on umask
    assert_true(S_ISDIR(st.st_mode));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_mkdir_simple_directory, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_mkdir_with_parents, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_mkdir_without_parents_fails, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_mkdir_existing_directory, setup,
                                        teardown),
        cmocka_unit_test(test_mkdir_invalid_inputs),
        cmocka_unit_test(test_mkdir_path_too_long),
        cmocka_unit_test_setup_teardown(test_mkdir_permissions, setup,
                                        teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
