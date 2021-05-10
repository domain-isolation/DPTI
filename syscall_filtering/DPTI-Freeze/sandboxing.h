/** @file */

#ifndef _SANDBOXING_H_
#define _SANDBOXING_H_

#include "module/sandbox.h"
#include <sys/types.h>
#include <syscall.h>


/**
 * Different colors and tags for pretty printing
 *
 * @defgroup COLORS
 *
 * @{
 *
 */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RESET   "\x1b[0m"

#define TAG_OK COLOR_GREEN "[+]" COLOR_RESET " "
#define TAG_FAIL COLOR_RED "[-]" COLOR_RESET " "
#define TAG_PROGRESS COLOR_YELLOW "[~]" COLOR_RESET " "
/** @} */

/**
 * The bits in a page-table entry
 *
 * @defgroup PAGETABLE_BITS Page Table Bits
 *
 * @{
 *
 */
 /** Page is present */
#define SANDBOXING_PAGE_BIT_PRESENT 0
/** Page is writeable */
#define SANDBOXING_PAGE_BIT_RW 1
/** Page is userspace addressable */
#define SANDBOXING_PAGE_BIT_USER 2
/** Page write through */
#define SANDBOXING_PAGE_BIT_PWT 3
/** Page cache disabled */
#define SANDBOXING_PAGE_BIT_PCD 4
/** Page was accessed (raised by CPU) */
#define SANDBOXING_PAGE_BIT_ACCESSED 5
/** Page was written to (raised by CPU) */
#define SANDBOXING_PAGE_BIT_DIRTY 6
/** 4 MB (or 2MB) page */
#define SANDBOXING_PAGE_BIT_PSE 7
/** PAT (only on 4KB pages) */
#define SANDBOXING_PAGE_BIT_PAT 7
/** Global TLB entry PPro+ */
#define SANDBOXING_PAGE_BIT_GLOBAL 8
/** Available for programmer */
#define SANDBOXING_PAGE_BIT_SOFTW1 9
/** Available for programmer */
#define SANDBOXING_PAGE_BIT_SOFTW2 10
/** Available for programmer */
#define SANDBOXING_PAGE_BIT_SOFTW3 11
/** PAT (on 2MB or 1GB pages) */
#define SANDBOXING_PAGE_BIT_PAT_LARGE 12
/** Available for programmer */
#define SANDBOXING_PAGE_BIT_SOFTW4 58
/** Protection Keys, bit 1/4 */
#define SANDBOXING_PAGE_BIT_PKEY_BIT0 59
/** Protection Keys, bit 2/4 */
#define SANDBOXING_PAGE_BIT_PKEY_BIT1 60
/** Protection Keys, bit 3/4 */
#define SANDBOXING_PAGE_BIT_PKEY_BIT2 61
/** Protection Keys, bit 4/4 */
#define SANDBOXING_PAGE_BIT_PKEY_BIT3 62
/** No execute: only valid after cpuid check */
#define SANDBOXING_PAGE_BIT_NX 63
/** @} */

/**
 * Basic functionality required in every program
 *
 * @defgroup BASIC Basic Functionality
 *
 * @{
 */

/**
 * Global variable that holds the max number of syscalls.
 * Filled by sandboxing_init.
 */
int sandboxing_max_num_syscalls;

 /**
  * Initializes (and acquires) Sandbox kernel module
  *
  * @return 0 Initialization was successful
  * @return -1 Initialization failed
  */
int sandboxing_init();

/**
 * Releases Sandbox kernel module
 *
 */
void sandboxing_cleanup();

/**
 * Resolves the page-table entries of all levels for a virtual address of a given process.
 *
 * @param[in] address The virtual address to resolve
 * @param[in] pid The pid of the process (0 for own process)
 *
 * @return A structure containing the page-table entries of all levels.
 */
sandbox_entry_t sandboxing_resolve(void*, pid_t);

/**
 * Retrieves the maxium number of syscalls the system provides.
 *
 * @return The maximum number of syscalls provided by the system as an int.
 */
int sandboxing_get_max_num_syscalls(void);

/**
 * Prints the filters stored in the kernel.
 *
 * @return 0
 */
int sandboxing_print_filters_kernel(void);

/**
 * Prints the filters in userspace.
 * @param[in] nr The syscall for which we want to print the filters
 *
 * @return 0
 */
void sandboxing_print_filters_userspace(filter_info_t *filters, int nr);

/**
 * Installs the provided syscall filters.
 *
 * @param[in] filters The processes filters to be installed
 *
 * @return 1 for success, 0 for failure
 */
int sandboxing_install_filters(filter_info_t *filters);

/**
 * Clear userspace syscall filter list, should be called after installing the filters in the kernel.
 *
 * @param[in] filters The processes filters to be installed
 *
 * @return void
 */
void sandboxing_clear_filters(filter_info_t **filters);

/**
 * Creates an empty filter_info_t for all syscalls.
 *
 * @return filter_info_t* Allocated memory for the filters
 */
filter_info_t* sandboxing_create_filters(void);

/**
 * Adds a simple syscall filter rule to the provided syscall filters.
 *
 * @param[in] filters The processes filters to which we add our rule
 * @param[in] nr The syscall for which we add the filter
 *
 * @return void
 */
void sandboxing_add_syscall_filter_rule(filter_info_t *filters, int nr);

/**
 * Adds a integer argument syscall filter rule to the provided syscall filters.
 *
 * @param[in] filters The processes filters to which we add our rule
 * @param[in] nr The syscall for which we add the filter
 * @param[in] arg_pos The position of the argument in the argument list (0-6)
 * @param[in] comp The comparsion operator to be used
 * @param[in] argument The actual integer argument that should be checked against
 *
 * @return int -1 on failure, 0 on success
 */
int sandboxing_add_syscall_argument_filter_rule_int(filter_info_t *filters, int nr, int arg_pos, argument_comp_e comp, int argument);

/**
 * Adds a string argument syscall filter rule to the provided syscall filters.
 *
 * @param[in] filters The processes filters to which we add our rule
 * @param[in] nr The syscall for which we add the filter
 * @param[in] arg_pos The position of the argument in the argument list (0-6)
 * @param[in] comp The comparsion operator to be used
 * @param[in] argument The actual string argument that should be checked against
 *
 * @return int -1 on failure, 0 on success
 */
int sandboxing_add_syscall_argument_filter_rule_string(filter_info_t *filters, int nr, int arg_pos, argument_comp_e comp, char *argument);

#define SANDBOXING_PAGE_PRESENT 1

/**
 * Struct to access the fields of the PGD
 */
#pragma pack(push,1)
typedef struct {
  size_t present : 1;
  size_t writeable : 1;
  size_t user_access : 1;
  size_t write_through : 1;
  size_t cache_disabled : 1;
  size_t accessed : 1;
  size_t ignored_3 : 1;
  size_t size : 1;
  size_t ignored_2 : 4;
  size_t pfn : 28;
  size_t reserved_1 : 12;
  size_t ignored_1 : 11;
  size_t execution_disabled : 1;
} sandboxing_pgd_t;
#pragma pack(pop)


/**
 * Struct to access the fields of the P4D
 */
typedef sandboxing_pgd_t sandboxing_p4d_t;


/**
 * Struct to access the fields of the PUD
 */
typedef sandboxing_pgd_t sandboxing_pud_t;


/**
 * Struct to access the fields of the PMD
 */
typedef sandboxing_pgd_t sandboxing_pmd_t;


/**
 * Struct to access the fields of the PMD when mapping a  large page (2MB)
 */
#pragma pack(push,1)
typedef struct {
  size_t present : 1;
  size_t writeable : 1;
  size_t user_access : 1;
  size_t write_through : 1;
  size_t cache_disabled : 1;
  size_t accessed : 1;
  size_t dirty : 1;
  size_t size : 1;
  size_t global : 1;
  size_t ignored_2 : 3;
  size_t pat : 1;
  size_t reserved_2 : 8;
  size_t pfn : 19;
  size_t reserved_1 : 12;
  size_t ignored_1 : 11;
  size_t execution_disabled : 1;
} sandboxing_pmd_large_t;
#pragma pack(pop)

/**
 * Struct to access the fields of the PTE
 */
#pragma pack(push,1)
typedef struct {
  size_t present : 1;
  size_t writeable : 1;
  size_t user_access : 1;
  size_t write_through : 1;
  size_t cache_disabled : 1;
  size_t accessed : 1;
  size_t dirty : 1;
  size_t size : 1;
  size_t global : 1;
  size_t ignored_2 : 3;
  size_t pfn : 28;
  size_t reserved_1 : 12;
  size_t ignored_1 : 11;
  size_t execution_disabled : 1;
} sandboxing_pte_t;
#pragma pack(pop)

 /** @} */

/**
 * Pretty print
 *
 * @defgroup PRETTYPRINT Pretty print
 *
 * @{
 */

 /**
  * Pretty prints a sandbox_entry_t struct.
  *
  * @param[in] entry A sandbox_entry_t struct
  *
  */
void sandboxing_print_entry_t(sandbox_entry_t entry);

/**
 * Pretty prints a page-table entry.
 *
 * @param[in] entry A page-table entry
 *
 */
void sandboxing_print_entry(size_t entry);

/**
 * Prints a single line of the pretty-print representation of a page-table entry.
 *
 * @param[in] entry A page-table entry
 * @param[in] line The line to print (0 to 3)
 *
 */
void sandboxing_print_entry_line(size_t entry, int line);

/** @} */

#endif // _SANDBOXING_H_
