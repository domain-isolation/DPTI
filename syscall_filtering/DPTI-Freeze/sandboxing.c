#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include "module/sandbox.h"
#include "sandboxing.h"
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/mman.h>


#define DPTI_COLOR_RED     "\x1b[31m"
#define SANDBOXING_COLOR_GREEN   "\x1b[32m"
#define DPTI_COLOR_RESET   "\x1b[0m"


static int dpti_fd;

// ---------------------------------------------------------------------------
#define DPTI_B(val, bit) (!!((val) & (1ull << (bit))))

#define DPTI_PRINT_B(fmt, bit)                                                \
  if ((bit)) {                                                                 \
    printf(SANDBOXING_COLOR_GREEN);                                                       \
    printf((fmt), (bit));                                                      \
    printf(DPTI_COLOR_RESET);                                                       \
  } else {                                                                     \
    printf((fmt), (bit));                                                      \
  }                                                                            \
  printf("|");


// ---------------------------------------------------------------------------
void dpti_print_entry_line(size_t entry, int line) {
  if (line == 0 || line == 3) printf("+--+------------------+-+-+-+-+-+-+-+-+--+--+-+-+-+\n");
  if (line == 1) printf("|NX|       PFN        |H|?|?|?|G|S|D|A|UC|WT|U|W|P|\n");
  if (line == 2) {
    printf("|");
    DPTI_PRINT_B(" %d", DPTI_B(entry, DPTI_PAGE_BIT_NX));
    printf(" %16p |", (void*)((entry >> 12) & ((1ull << 40) - 1)));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_PAT_LARGE));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_SOFTW3));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_SOFTW2));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_SOFTW1));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_GLOBAL));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_PSE));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_DIRTY));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_ACCESSED));
    DPTI_PRINT_B(" %d", DPTI_B(entry, DPTI_PAGE_BIT_PCD));
    DPTI_PRINT_B(" %d", DPTI_B(entry, DPTI_PAGE_BIT_PWT));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_USER));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_RW));
    DPTI_PRINT_B("%d", DPTI_B(entry, DPTI_PAGE_BIT_PRESENT));
    printf("\n");
  }
}


// ---------------------------------------------------------------------------
void dpti_print_entry(size_t entry) {
  int i = 0;
  for (i = 0; i < 4; i++) {
    dpti_print_entry_line(entry, i);
  }
}

// ---------------------------------------------------------------------------
void dpti_print_entry_t(dpti_entry_t entry) {
  if (entry.valid & DPTI_VALID_MASK_PGD) {
    printf("PGD of address\n");
    dpti_print_entry(entry.pgd);
  }
  if (entry.valid & DPTI_VALID_MASK_P4D) {
    printf("P4D of address\n");
    dpti_print_entry(entry.p4d);
  }
  if (entry.valid & DPTI_VALID_MASK_PUD) {
    printf("PUD of address\n");
    dpti_print_entry(entry.pud);
  }
  if (entry.valid & DPTI_VALID_MASK_PMD) {
    printf("PMD of address\n");
    dpti_print_entry(entry.pmd);
  }
  if (entry.valid & DPTI_VALID_MASK_PTE) {
    printf("PTE of address\n");
    dpti_print_entry(entry.pte);
  }
}

// ---------------------------------------------------------------------------
dpti_entry_t dpti_resolve(void* address, pid_t pid) {
  dpti_entry_t vm;
  memset(&vm, 0, sizeof(vm));
  vm.vaddr = (size_t)address;
  vm.pid = (size_t)pid;
  ioctl(dpti_fd, DPTI_IOCTL_CMD_VM_RESOLVE, (size_t)&vm);
  
  return vm;
}

// ---------------------------------------------------------------------------
int dpti_get_max_num_syscalls(void) {
  return (int) ioctl(dpti_fd, DPTI_IOCTL_CMD_GET_NUM_SYSCALLS, 0);
}

// ---------------------------------------------------------------------------
int dpti_print_filters_kernel(void) {
  return (int) ioctl(dpti_fd, DPTI_IOCTL_CMD_PRINT_FILTERS, 0);
}

// ---------------------------------------------------------------------------
void dpti_print_filters_userspace(filter_info_t *filters, int nr) {
  if(!filters) {
    fprintf(stderr, DPTI_COLOR_RED "[-]" DPTI_COLOR_RESET "Error: No memory for filters was allocated.\n");
    return;
  }

  printf("-----------SYSCALL %d START-----------\n", nr);
  printf("Allowed: %d\n", filters[nr].allowed);
  for(int i=0; i<MAX_ARGUMENT_NUMBER; i++) {
    argument_t *arg = &filters[nr].arg[i];
    // if(!arg->is_filtered)
    //   continue;
    printf("Num possible options: %d\n", arg->num_possible_options);
    for(int j=0; j<arg->num_possible_options; j++) {
      switch (arg->type)
      {
      case INT:
        printf("\tOption %d: %u\n", j, (arg->int_syscall_arg) ? arg->int_syscall_arg[j] : 0);
        break;
      case STRING:
        printf("\tOption %d: %s\n", j, (arg->string_syscall_arg) ? arg->string_syscall_arg[j] : "NULL");
        break;
      default:
        break;
      }
    }
  }
  printf("-----------SYSCALL %d END-----------\n", nr);
}

// ---------------------------------------------------------------------------
void dpti_request_violation_logging(void) {
  (void) ioctl(dpti_fd, DPTI_IOCTL_CMD_REQUEST_VIOLATION_LOGGING, 0);
}

// ---------------------------------------------------------------------------
int dpti_install_filters(filter_info_t* filters) {
  return (int) ioctl(dpti_fd, DPTI_IOCTL_CMD_INSTALL_FILTER, (size_t)filters);
}

// ---------------------------------------------------------------------------
void dpti_clear_filters(filter_info_t **filters) {
  for(int i=0; i<dpti_max_num_syscalls; i++) {
    filter_info_t *filter = &((*filters)[i]);
    for(int i=0; i<MAX_ARGUMENT_NUMBER; i++) {
      argument_t *arg = &filter->arg[i];
      free(arg->comp);

      if(arg->type == INT) {
        free(arg->int_syscall_arg);
      } else if(arg->type == STRING) {
        for(int j=0; j<arg->num_possible_options; j++) {
          free(arg->string_syscall_arg[j]);
          arg->string_syscall_arg[j] = NULL;
        }
        free(arg->string_syscall_arg);
      }
      arg->type = UNDEF;
    }
  }
  memset(*filters, 0, sizeof(filter_info_t) * dpti_max_num_syscalls);
  free(*filters);
  *filters = NULL;
}

// ---------------------------------------------------------------------------
filter_info_t* dpti_create_filters(void) {
  filter_info_t *filters = (filter_info_t*) calloc(dpti_max_num_syscalls, sizeof(filter_info_t));
  if(!filters) {
    fprintf(stderr, DPTI_COLOR_RED "[-]" DPTI_COLOR_RESET "Error: Could not allocate memory for filters, terminating.\n");
    exit(1);
  }

  return filters;
}

// ---------------------------------------------------------------------------
void dpti_add_filter_rule(filter_info_t *filters, int nr) {
  filters[nr].allowed = 1;
  filters[nr].num_syscall_args_filtered = 0;
}

// ---------------------------------------------------------------------------
int dpti_add_filter_rule_int(filter_info_t *filters, int nr, int arg_pos, argument_comp_e comp, int argument) {
  if(arg_pos < 0 || arg_pos >= MAX_ARGUMENT_NUMBER) {
    fprintf(stderr, DPTI_COLOR_RED "[-]" DPTI_COLOR_RESET "Error: Trying to create argument filter outside of argument range [0-%d)\n", MAX_ARGUMENT_NUMBER);
    return -1;
  }

  argument_t *arg = &filters[nr].arg[arg_pos];

  filters[nr].allowed = 1;
  arg->num_possible_options++;
  // allocate memory for our comparison and the possible argument options
  arg->comp = realloc((void*)(arg->comp), sizeof(argument_comp_e) * arg->num_possible_options);
  arg->int_syscall_arg = realloc((void*)(arg->int_syscall_arg), sizeof(int) * arg->num_possible_options);

  arg->int_syscall_arg[arg->num_possible_options-1] = argument;
  arg->comp[arg->num_possible_options-1] = comp;
  arg->type = INT;
  arg->is_filtered = 1;
  // we only want to increase the argument count once
  if(arg->num_possible_options == 1)
    filters[nr].num_syscall_args_filtered++;

  return 0;
}

// ---------------------------------------------------------------------------
int dpti_add_filter_rule_string(filter_info_t *filters, int nr, int arg_pos, argument_comp_e comp, char *argument) {
  if(arg_pos < 0 || arg_pos >= MAX_ARGUMENT_NUMBER) {
    fprintf(stderr, DPTI_COLOR_RED "[-]" DPTI_COLOR_RESET "Error: Trying to create argument filter outside of argument range (0-6)\n");
    return -1;
  }
  int argument_len = strlen(argument) + 1;
  argument_t *arg = &filters[nr].arg[arg_pos];

  filters[nr].allowed = 1;
  arg->num_possible_options++;
  // allocate memory for our comparison and the possible argument options
  arg->comp = realloc((void*)(arg->comp), sizeof(argument_comp_e) * arg->num_possible_options);
  arg->string_syscall_arg = realloc((void*)(arg->string_syscall_arg), sizeof(char*) * arg->num_possible_options);
  arg->string_syscall_arg[arg->num_possible_options-1] = malloc(sizeof(char) * (argument_len));

  strncpy(arg->string_syscall_arg[arg->num_possible_options-1], argument, argument_len);
  arg->comp[arg->num_possible_options-1] = comp;
  arg->type = STRING;
  arg->is_filtered = 1;
  // we only want to increase the argument count once
  if(arg->num_possible_options == 1)
    filters[nr].num_syscall_args_filtered++;

  return 0;
}

// ---------------------------------------------------------------------------
int dpti_init() {
  dpti_fd = open(DPTI_DEVICE_PATH, O_RDONLY);
  if (dpti_fd < 0) {
    fprintf(stderr, DPTI_COLOR_RED "[-]" DPTI_COLOR_RESET "Error: Could not open Sandbox device: %s\n", DPTI_DEVICE_PATH);
    return -1;
  }

  dpti_max_num_syscalls = dpti_get_max_num_syscalls();
  return 0;
}


// ---------------------------------------------------------------------------
void dpti_cleanup() {
  if (dpti_fd >= 0) {
    close(dpti_fd);
  }
}