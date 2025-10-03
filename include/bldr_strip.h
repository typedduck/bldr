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
#define log_message bldr_log_message
#define log_message_va bldr_log_message_va
#define log_info bldr_log_info
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
