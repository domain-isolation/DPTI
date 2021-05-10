#ifndef SANDBOX_MODULE_H
#define SANDBOX_MODULE_H

#include <stddef.h>

#define SANDBOX_DEVICE_NAME "sandbox"
#define SANDBOX_DEVICE_PATH "/dev/" SANDBOX_DEVICE_NAME

#define MAX_ARGUMENT_NUMBER 6

/**
 * Structure containing the page-table entries of all levels.
 * The Linux names are aliased with the Intel names.
 */
typedef struct {
  /** Process ID */
  size_t pid;
  /** Virtual address */
  size_t vaddr;

  /** Page global directory / Page map level 5 */
  union {
      size_t pgd;
      size_t pml5;
  };
  /** Page directory 4 / Page map level 4 */
  union {
      size_t p4d;
      size_t pml4;
  };
  /** Page upper directory / Page directory pointer table */
  union {
      size_t pud;
      size_t pdpt;
  };
  /** Page middle directory / Page directory */
  union {
      size_t pmd;
      size_t pd;
  };
  /** Page table entry */
  size_t pte;
  /** Bitmask indicating which entries are valid/should be updated */
  size_t valid;
} sandbox_entry_t;

typedef enum {
  UNDEF,
  INT,
  STRING
} argument_type_e;

typedef enum {
  EQ, // ==
  NEQ, // !=
  GT, // >
  GTE, // >=
  LT, // <
  LTE // <=
} argument_comp_e;

typedef struct {
  char is_filtered;
  int num_possible_options;
  argument_type_e type;
  argument_comp_e *comp;
  union {
    int *int_syscall_arg;
    char **string_syscall_arg;
  };
} argument_t;

typedef struct {
  int allowed;
  int num_syscall_args_filtered;
  argument_t arg[MAX_ARGUMENT_NUMBER];
  int ref_count;
} filter_info_t;

#define SANDBOX_VALID_MASK_PGD (1<<0)
#define SANDBOX_VALID_MASK_P4D (1<<1)
#define SANDBOX_VALID_MASK_PUD (1<<2)
#define SANDBOX_VALID_MASK_PMD (1<<3)
#define SANDBOX_VALID_MASK_PTE (1<<4)

#define SANDBOX_IOCTL_MAGIC_NUMBER (long)0x3d17

#define SANDBOX_IOCTL_CMD_VM_RESOLVE \
  _IOR(SANDBOX_IOCTL_MAGIC_NUMBER, 1, size_t)

#define SANDBOX_IOCTL_CMD_GET_NUM_SYSCALLS \
  _IOR(SANDBOX_IOCTL_MAGIC_NUMBER, 2, size_t)

#define SANDBOX_IOCTL_CMD_INSTALL_FILTER \
  _IOR(SANDBOX_IOCTL_MAGIC_NUMBER, 3, size_t)

#define SANDBOX_IOCTL_CMD_PRINT_FILTERS \
  _IOR(SANDBOX_IOCTL_MAGIC_NUMBER, 4, size_t)

#endif // SANDBOX_MODULE_H
