#include <asm/tlbflush.h>
#include <asm/syscall.h>
#include <linux/sched/signal.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/signal.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>
#include <linux/sched/debug.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#include "sandbox.h"

MODULE_AUTHOR("Anonymous author");
MODULE_DESCRIPTION("Device for filtering syscalls, including deep argument filtering");
MODULE_LICENSE("GPL");

#define _PAGE_RESERVED_BIT 49
#define _PAGE_RESERVED (_AT(pteval_t, 1) << _PAGE_RESERVED_BIT)

#define DEBUG_INFO 0
#define DEBUG_ALERT 0
#define debug_info(...) do { if(DEBUG_INFO) pr_info(__VA_ARGS__); } while(0)
#define debug_alert(...) do { if(DEBUG_ALERT) pr_alert(__VA_ARGS__); } while(0)
#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[sandbox-module] " ": " fmt

#define REGS_DEFINES const struct pt_regs* regs
#define REGS regs
#define ARG1 regs->di
#define ARG2 regs->si
#define ARG3 regs->dx
#define ARG4 regs->cx
#define ARG5 regs->r8
#define ARG6 regs->r9
#define SYSNO regs->orig_ax

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define from_user raw_copy_from_user
#define to_user raw_copy_to_user
#else
#define from_user copy_from_user
#define to_user copy_to_user
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
unsigned long kallsyms_lookup_name(const char* name) {
  struct kprobe kp = {
    .symbol_name	= name,
  };

  int ret = register_kprobe(&kp);
  if (ret < 0) {
    return 0;
  };

  unregister_kprobe(&kp);

  return (unsigned long) kp.addr;
}
#endif

// kernel provided write_cr0 checks whether the WP bit has changed and automatically sets it again
// hence, we implement our own write to cr0
inline void write_cr0_nocheck(unsigned long cr0) {
  asm volatile("mov %0, %%cr0" : "+r"(cr0) : __FORCE_ORDER);
}

#define unprotect_memory() \
({ \
	write_cr0_nocheck(read_cr0() & ~0x10000); /* Set WP flag to 0 */ \
});
#define protect_memory() \
({ \
	write_cr0_nocheck(read_cr0() | 0x10000); /* Set WP flag to 1 */ \
});

// ---------------------------------------------------------------------------
typedef struct {
    size_t pid;
    pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d_t *p4d;
#else
    size_t *p4d;
#endif
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    size_t valid;
} vm_t;

char sandboxed_pids[PID_MAX_DEFAULT] = {0};
filter_info_t *filter_list;
static bool mm_is_locked = false;

void (*flush_tlb_mm_range_func)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool);

static sys_call_ptr_t old_sys_call_table[__NR_syscall_max];
static sys_call_ptr_t* syscall_tbl;

// ---------------------------------------------------------------------------
static int device_open(struct inode *inode, struct file *file) {
  return 0;
}

static int device_release(struct inode *inode, struct file *file) {
  return 0;
}

// ---------------------HOOKING-RELATED CODE------------------------------------------------------
static long hook_generic(REGS_DEFINES);
static long hook_clone(REGS_DEFINES);
static long hook_exit(REGS_DEFINES);
static long hook_exec(REGS_DEFINES);

static void hook_syscall(int nr, sys_call_ptr_t hook) {
  // unprotect syscall table
  unprotect_memory();
  debug_info("Hooking syscall %d\n", nr);
  syscall_tbl[nr] = hook;
  protect_memory();
}

static void unhook_syscall(int nr) {
  // unprotect syscall table
  unprotect_memory();
  debug_info("Unhooking syscall %d\n", nr);
  syscall_tbl[nr] = old_sys_call_table[nr];
  protect_memory();
}

// ---------------------PAGING-RELATED CODE------------------------------------------------------
static inline pte_t pte_mkuser(pte_t pte) {
	return pte_set_flags(pte, _PAGE_USER);
}

static inline pte_t pte_mknotuser(pte_t pte) {
	return pte_clear_flags(pte, _PAGE_USER);
}

static struct mm_struct* get_mm(void) {
  if(current->mm) {
    return current->mm;
  } else {
    return current->active_mm;
  }
  return NULL;
}

static int resolve_vm(size_t addr, vm_t* entry, int lock) {
  struct mm_struct *mm;

  if(!entry) return 1;
  entry->pud = NULL;
  entry->pmd = NULL;
  entry->pgd = NULL;
  entry->pte = NULL;
  entry->p4d = NULL;
  entry->valid = 0;

  mm = get_mm();
  if(!mm) {
      return 1;
  }

  /* Lock mm */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_lock(mm);
#else
  if(lock) down_read(&mm->mmap_sem);
#endif

  /* Return PGD (page global directory) entry */
  entry->pgd = pgd_offset(mm, addr);
  if (pgd_none(*(entry->pgd)) || pgd_bad(*(entry->pgd))) {
    entry->pgd = NULL;
    goto error_out;
  }
  entry->valid |= SANDBOX_VALID_MASK_PGD;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
  /* Return p4d offset */
  entry->p4d = p4d_offset(entry->pgd, addr);
  if (p4d_none(*(entry->p4d)) || p4d_bad(*(entry->p4d))) {
    entry->p4d = NULL;
    goto error_out;
  }
  entry->valid |= SANDBOX_VALID_MASK_P4D;

  /* Get offset of PUD (page upper directory) */
  entry->pud = pud_offset(entry->p4d, addr);
  if (pud_none(*(entry->pud))) {
    entry->pud = NULL;
    goto error_out;
  }
  entry->valid |= SANDBOX_VALID_MASK_PUD;
#else
  /* Get offset of PUD (page upper directory) */
  entry->pud = pud_offset(entry->pgd, addr);
  if (pud_none(*(entry->pud))) {
    entry->pud = NULL;
    goto error_out;
  }
  entry->valid |= SANDBOX_VALID_MASK_PUD;
#endif


  /* Get offset of PMD (page middle directory) */
  entry->pmd = pmd_offset(entry->pud, addr);
  if (pmd_none(*(entry->pmd)) || pud_large(*(entry->pud))) {
    entry->pmd = NULL;
    goto error_out;
  }
  entry->valid |= SANDBOX_VALID_MASK_PMD;

  /* Map PTE (page table entry) */
  entry->pte = pte_offset_map(entry->pmd, addr);
  if (entry->pte == NULL || pmd_large(*(entry->pmd))) {
    goto error_out;
  }
  entry->valid |= SANDBOX_VALID_MASK_PTE;

  /* Unmap PTE, fine on x86 and ARM64 -> unmap is NOP */
  pte_unmap(entry->pte);

  /* Unlock mm */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_unlock(mm);
#else
  if(lock) up_read(&mm->mmap_sem);
#endif

  return 0;

error_out:

  /* Unlock mm */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_unlock(mm);
#else
  if(lock) up_read(&mm->mmap_sem);
#endif

  return 1;
}

static int update_vm_set_user_inaccessible(size_t addr, int lock) {
  vm_t old_entry;
  struct mm_struct *mm = get_mm();

  if(!mm) return 1;

  // Lock mm
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_lock(mm);
#else
  if(lock) down_read(&mm->mmap_sem);
#endif

  resolve_vm(addr, &old_entry, 0);
    
  debug_info("Updating PTE (setting to user inaccessible)\n");
  // set page to user inaccessible, update PTE, flush tlb
  set_pte_at(mm, addr, old_entry.pte, pte_mknotuser(*(old_entry.pte)));
  // *(old_entry.pte) = pte_mknotuser(*(old_entry.pte));
  flush_tlb_mm_range_func(mm, addr, addr + PAGE_SIZE, PAGE_SHIFT, false);

  // Unlock mm
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_unlock(mm);
#else
  if(lock) up_read(&mm->mmap_sem);
#endif

  return 0;
}

static int update_vm_set_user_accessible(size_t addr, int lock) {
  vm_t old_entry;
  struct mm_struct *mm = get_mm();
  
  if(!mm) return 1;

  // Lock mm
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_lock(mm);
#else
  if(lock) down_read(&mm->mmap_sem);
#endif

  resolve_vm(addr, &old_entry, 0);

  // set one of the reserved bits to 1, update PTE, flush tlb
  debug_info("Updating PTE (setting to user accessible)\n");
  set_pte_at(mm, addr, old_entry.pte, pte_mkuser(*(old_entry.pte)));
  // *(old_entry.pte) = pte_mkuser(*(old_entry.pte));
  flush_tlb_mm_range_func(mm, addr, addr + PAGE_SIZE, PAGE_SHIFT, false);

  // Unlock mm
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_unlock(mm);
#else
  if(lock) up_read(&mm->mmap_sem);
#endif

  return 0;
}


// ---------------------DEBUGGING CODE------------------------------------------------------
static void vm_to_user(sandbox_entry_t* user, vm_t* vm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#if CONFIG_PGTABLE_LEVELS > 4
  if(vm->p4d) user->p4d = (vm->p4d)->p4d;
#else
#if !defined(__ARCH_HAS_5LEVEL_HACK)
  if(vm->p4d) user->p4d = (vm->p4d)->pgd.pgd;
#else
  if(vm->p4d) user->p4d = (vm->p4d)->pgd;    
#endif
#endif
#endif
#if defined(__i386__) || defined(__x86_64__)
  if(vm->pgd) user->pgd = (vm->pgd)->pgd;
  if(vm->pmd) user->pmd = (vm->pmd)->pmd;
  if(vm->pud) user->pud = (vm->pud)->pud;
  if(vm->pte) user->pte = (vm->pte)->pte;
#elif defined(__aarch64__)
  if(vm->pgd) user->pgd = pgd_val(*(vm->pgd));
  if(vm->pmd) user->pmd = pmd_val(*(vm->pmd));
  if(vm->pud) user->pud = pud_val(*(vm->pud));
  if(vm->pte) user->pte = pte_val(*(vm->pte));
#endif
    user->valid = vm->valid;
}

static int copy_filters_to_kernel_memory(filter_info_t *filter_list) {
  filter_info_t *filter;
  int arg_index, option_index, sys_nr;
  size_t user_string_length;
  void *filter_string;
  char **argument_filter_string;
  int *filter_ints;
  argument_comp_e *filter_comp;

  if(!filter_list) {
    pr_info("copy_filters_to_kernel_memory: no filters found for pid %d\n", task_pid_nr(current));
    return -1;
  }

  for(sys_nr=0; sys_nr<__NR_syscall_max; sys_nr++) {
    filter = &filter_list[sys_nr];
    if(filter->num_syscall_args_filtered > 0) { // we only need to check filters where actual arguements are checked
      for(arg_index=0; arg_index<MAX_ARGUMENT_NUMBER; arg_index++) {
        if(!filter->arg[arg_index].is_filtered) // skip arguments that are not filtered
          continue;

        switch (filter->arg[arg_index].type) {
          case INT:
            if(!(filter_ints = kmalloc(sizeof(int) * filter->arg[arg_index].num_possible_options, GFP_KERNEL))) {
              pr_alert("Could not allocate kernel memory for integer arguments, killing process\n");
              kill_pid(task_pid(current), SIGKILL, 1);
              return -1;
            }
            // copy string to kernel and replace pointer in filter
            from_user(filter_ints, filter->arg[arg_index].int_syscall_arg, sizeof(int) * filter->arg[arg_index].num_possible_options);
            filter->arg[arg_index].int_syscall_arg = filter_ints;
            break;
          case STRING:
            // allocate memory for pointers to the string filters in kernelspace, this will replace our userspace pointers at the end in our filter for this syscall
            argument_filter_string = kmalloc(sizeof(char*) * filter->arg[arg_index].num_possible_options, GFP_KERNEL);
            from_user(argument_filter_string, filter->arg[arg_index].string_syscall_arg, sizeof(char*) * filter->arg[arg_index].num_possible_options);

            for(option_index=0; option_index<filter->arg[arg_index].num_possible_options; option_index++) {
              // we need to get the length of the userspace string for copying
              user_string_length = strnlen_user(argument_filter_string[option_index], 32767);

              if(!(filter_string = kmalloc(user_string_length, GFP_KERNEL))) {
                pr_alert("Could not allocate kernel memory for string arguments, killing process\n");
                kill_pid(task_pid(current), SIGKILL, 1);
                return -1;
              }
              // copy filter string to kernel memory and replace pointer to userspace string
              from_user(filter_string, argument_filter_string[option_index], user_string_length);
              argument_filter_string[option_index] = filter_string;
            }
            // finally replace filters for strings in userspace with their copied version in the kernel
            filter->arg[arg_index].string_syscall_arg = argument_filter_string;
            break;
          default:
            break;
        }

        if(!(filter_comp = kmalloc(sizeof(argument_comp_e) * filter->arg[arg_index].num_possible_options, GFP_KERNEL))) {
          pr_alert("Could not allocate kernel memory for comparison, killing process\n");
          kill_pid(task_pid(current), SIGKILL, 1);
          return -1;
        }

        // copy string to kernel and replace pointer in filter
        from_user(filter_comp, filter->arg[arg_index].comp, sizeof(argument_comp_e) * filter->arg[arg_index].num_possible_options);
        filter->arg[arg_index].comp = filter_comp;
      }
    }
  }

  return 0;
}

static int free_filters(filter_info_t *filter_list) {
  filter_info_t *filter;
  int arg_index, option_index, sys_nr;

  debug_info("Trying to free filter memory for pid %d\n", task_tgid_nr(current));

  if(!filter_list) {
    pr_info("free_filters: no filters found for pid %d\n", task_tgid_nr(current));
    return -1;
  }
  
  for(sys_nr=0; sys_nr<__NR_syscall_max; sys_nr++) {
    filter = &filter_list[sys_nr];
    if(filter->num_syscall_args_filtered > 0) { // we only need to check filters where actual arguements are checked
      for(arg_index=0; arg_index<MAX_ARGUMENT_NUMBER; arg_index++) {
        if(!filter->arg[arg_index].is_filtered) // skip arguments that are not filtered
          continue;

        switch (filter->arg[arg_index].type) {
          case INT:
            kfree(filter->arg[arg_index].int_syscall_arg);
            filter->arg[arg_index].int_syscall_arg = NULL;
            break;
          case STRING:
            for(option_index=0; option_index<filter->arg[arg_index].num_possible_options; option_index++) {
              kfree(filter->arg[arg_index].string_syscall_arg[option_index]);
            }
            // finally replace filters for strings to old filter rules with their copied version
            kfree(filter->arg[arg_index].string_syscall_arg);
            filter->arg[arg_index].string_syscall_arg = NULL;
            break;
          default:
            break;
        }

        kfree(filter->arg[arg_index].comp);
        filter->arg[arg_index].comp = NULL;
      }
    }
  }

  kfree(filter_list);
  return 0;
}

static inline __attribute__((always_inline)) void print_argument_comp(argument_comp_e comp) {
  switch (comp) {
    case EQ:
      pr_info("\t\tComp: EQ\n");
      break;
    case NEQ:
      pr_info("\t\tComp: NEQ\n");
      break;
    case GT:
      pr_info("\t\tComp: GT\n");
      break;
    case GTE:
      pr_info("\t\tComp: GTE\n");
      break;
    case LT:
      pr_info("\t\tComp: LT\n");
      break;
    case LTE:
      pr_info("\t\tComp: LTE\n");
      break;
    default:
      pr_info("\t\tComp: Unknown\n");
      break;
  }
}

static void print_filter(pid_t pid, int syscall_nr, int only_allowed) {
  filter_info_t filter;
  int arg_index, option_index;
  if(!filter_list) {
    pr_info("print_filter: no filters found for pid %d\n", pid);
    return;
  }

  filter = filter_list[syscall_nr];

  if(only_allowed && !filter.allowed)
    return;

  pr_info("----------------Printing filters for syscall %d and process %d-----------------\n", syscall_nr, pid);
  pr_info("Allowed: %s\n", (filter.allowed) ? "true" : "false");
  pr_info("Number of argument filters: %d\n", filter.num_syscall_args_filtered);
  for(arg_index=0; arg_index<MAX_ARGUMENT_NUMBER; arg_index++) {
    if(filter.arg[arg_index].is_filtered) {
      pr_info("Argument #%d: specialized argument filter available\n", arg_index);
      switch (filter.arg[arg_index].type)       {
        case INT:
          pr_info("\tType: INT\n");
          for(option_index=0; option_index<filter.arg[arg_index].num_possible_options; option_index++) {
            pr_info("\tOption %d:\n", option_index);
            pr_info("\t\taddress %px\n", &filter.arg[arg_index].int_syscall_arg[option_index]);
            pr_info("\t\targument val: %d", filter.arg[arg_index].int_syscall_arg[option_index]);
            print_argument_comp(filter.arg[arg_index].comp[option_index]);
          }
          break;
        case STRING:
          pr_info("\tType: STRING\n");
          for(option_index=0; option_index<filter.arg[arg_index].num_possible_options; option_index++) {
            pr_info("\tOption %d:\n", option_index);
            pr_info("\t\tLength of string \"%s\" at address %px: %lu\n", filter.arg[arg_index].string_syscall_arg[option_index], filter.arg[arg_index].string_syscall_arg[option_index],  strlen(filter.arg[arg_index].string_syscall_arg[option_index]));
            pr_info("\t\targument val: %s", filter.arg[arg_index].string_syscall_arg[option_index]);
            print_argument_comp(filter.arg[arg_index].comp[option_index]);
          }
          break;
        default:
          pr_info("\tType: Unknown, ");
          break;
      }
    }
  }
  pr_info("------------Finished printing filters for syscall %d and process %d------------\n", syscall_nr, pid);
}

static void print_filters(pid_t pid, int only_allowed) {
  int nr;
  for(nr=0; nr<__NR_syscall_max; nr++)
    print_filter(pid, nr, only_allowed);
}

// static void print_all_sandboxed_pids(void) {
//   int i;
//   for(i=0; i<PID_MAX_DEFAULT; i++) {
//     if(sandboxed_pids[i])
//       pr_info("Pid %d has requested sandboxing\n", sandboxed_pids[i]);
//   }
// }

// ---------------------SANDBOXING-RELATED CODE------------------------------------------------------
void thread_group_clear_filter(void) {
  // print the number of threads for debug_infoging purposes
  debug_info("number of threads: %d\n", current->signal->nr_threads);
  // a task group wants to exit, so we decrement the ref count for the thread group by the number of threads in it
  filter_list->ref_count -= current->signal->nr_threads;
  sandboxed_pids[task_tgid_nr(current)] = 0;

  // now we free the memory if no thread in this thread group needs it anymore
  if(!filter_list->ref_count) {
    free_filters(filter_list);
    filter_list = NULL;
  }
}

inline __attribute__((always_inline)) int is_stack(size_t address) {
  struct vm_area_struct *vma;
  vma = find_vma(get_mm(), address);
  if(!vma) {
    pr_alert("Could not find vma for given address in process %d, killing process!!\n", task_pid_nr(current));
    kill_pid(task_pid(current), SIGKILL, 1);
  }

  /*
  * We make no effort to guess what a given thread considers to be
  * its "stack".  It's not even well-defined for programs written
  * languages like Go.
  */
  return vma->vm_start <= vma->vm_mm->start_stack && vma->vm_end >= vma->vm_mm->start_stack;
}

inline __attribute__((always_inline)) unsigned long get_syscall_argument_by_index(REGS_DEFINES, int arg_pos) {
  switch (arg_pos) {
    case 0:
      return ARG1;
      break;
    case 1:
      return ARG2;
      break;
    case 2:
      return ARG3;
      break;
    case 3:
      return ARG4;
      break;
    case 4:
      return ARG5;
      break;
    case 5:
      return ARG6;
      break;
    default:
      pr_alert("Requested non-existing argument. Index range is 0-5, so check your filters.\n");
      return 0; // we return 0 as this will never be a valid address, so we can check against it
  }
}

inline __attribute__((always_inline)) int check_int_argument(REGS_DEFINES, filter_info_t *syscall_filter, int arg_pos) {
  int option_index;
  unsigned long argument = get_syscall_argument_by_index(REGS, arg_pos);
  for(option_index=0; option_index<syscall_filter->arg[arg_pos].num_possible_options; option_index++) {
    switch (syscall_filter->arg[arg_pos].comp[option_index]) {
      case EQ:
        if(syscall_filter->arg[arg_pos].int_syscall_arg[option_index] == argument)
          return 1;
        break;
      case NEQ:
        if(syscall_filter->arg[arg_pos].int_syscall_arg[option_index] != argument)
          return 1;
        break;
      case GT:
        if(syscall_filter->arg[arg_pos].int_syscall_arg[option_index] > argument)
          return 1;
        break;
      case GTE:
        if(syscall_filter->arg[arg_pos].int_syscall_arg[option_index] >= argument)
          return 1;
        break;
      case LT:
        if(syscall_filter->arg[arg_pos].int_syscall_arg[option_index] < argument)
          return 1;
        break;
      case LTE:
        if(syscall_filter->arg[arg_pos].int_syscall_arg[option_index] <= argument)
          return 1;
        break;
      default:
        break;
    }
  }
  return 0;
}

inline __attribute__((always_inline)) int check_string_argument(REGS_DEFINES, filter_info_t *syscall_filter, int arg_pos, bool needs_cow) {
  int option_index;
  int is_stack_address;

  // we retrieve the pointer to the userspace address at which the string is stored
  char *argument = (char*) get_syscall_argument_by_index(REGS, arg_pos);
  is_stack_address = is_stack((size_t) argument);

  // for exec syscalls, we first need to trigger a COW violation as otherwise we run into a problem
  // as we cannot make the shared mapping userspace accessible again
  // to trigger COW, we simply disable smap and write the original value back to the page and then re-enable smap
  // a full implementation should do this without disabling smap
  if(needs_cow && !is_stack_address) {
    debug_info("Disabling smap, triggering cow, enabling smap in process %d\n", task_pid_nr(current));
    stac();
    // prevent the compiler from performing dead store elimination
    ((unsigned char volatile *)argument)[0] = argument[0];
    clac();
  }
  // now we start making the location inaccessible to userspace to prevent TOCTOU vulnerabilities
  // note that we only need to do this for strings, not for integers.
  // We only do this for addresses that are not on the stack, for stack arguments we copy the value
  // into the kernel and then perform the check, preventing TOCTOU vulnerabilities
  if(is_stack_address) {
    debug_info("String argument is stack address\n");
    argument = strndup_user(argument, 65536);
  } else {
    update_vm_set_user_inaccessible((size_t) argument, 1);
  }

  // Now that it is userspace inaccessible we can start checking the arguments without TOCTOU
  for(option_index=0; option_index<syscall_filter->arg[arg_pos].num_possible_options; option_index++) {
    switch (syscall_filter->arg[arg_pos].comp[option_index]) {
      case EQ:
        if(strncmp(syscall_filter->arg[arg_pos].string_syscall_arg[option_index], argument, strlen(syscall_filter->arg[arg_pos].string_syscall_arg[option_index])) == 0)
          return 1;
        break;
      case NEQ:
        if(strncmp(syscall_filter->arg[arg_pos].string_syscall_arg[option_index], argument, strlen(syscall_filter->arg[arg_pos].string_syscall_arg[option_index])) != 0)
          return 1;
        break;
      case GT:
        debug_info("GT string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        return 0;
        break;
      case GTE:
        debug_info("GTE string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        return 0;
        break;
      case LT:
        debug_info("LT string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        return 0;
        break;
      case LTE:
        debug_info("LTE string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        return 0;
        break;
      default:
        return 0;
        break;
    }
  }
  return 0;
}

inline __attribute__((always_inline)) int check_argument(REGS_DEFINES, filter_info_t *syscall_filter, bool needs_cow) {
  int i;
  int allowed = 0;
  for(i=0; i<MAX_ARGUMENT_NUMBER; i++) {
    if(!syscall_filter->arg[i].is_filtered)
      continue;
    switch(syscall_filter->arg[i].type) {
      case INT:
        allowed |= check_int_argument(REGS, syscall_filter, i);
        break;
      case STRING:
        allowed |= check_string_argument(REGS, syscall_filter, i, needs_cow);
        break;
      default:
        break;
    }
    // we perform an early out if one of the arguments fails the check even though other arguments might succeed in the check
    if(!allowed)
      return 0;
  }

  return 1;
}

inline __attribute__((always_inline)) void make_all_strings_user_accessible(REGS_DEFINES, filter_info_t *syscall_filter) {
  int i;
  // we have no syscall argument filters, so just return
  if(syscall_filter->num_syscall_args_filtered == 0)
    return;

  for(i=0; i<MAX_ARGUMENT_NUMBER; i++) {
    if(syscall_filter->arg[i].type == STRING) {
      const char *argument = (const char*) get_syscall_argument_by_index(REGS, i);
      if(argument != 0) {
        update_vm_set_user_accessible((size_t) argument, 1);
      }
    }
  }
}

static asmlinkage long hook_generic(REGS_DEFINES) {
  pid_t pid = task_pid_nr(current);
  pid_t gid = task_tgid_nr(current);
  int sys_nr = SYSNO;
  long syscall_result;
  filter_info_t syscall_filter;

  if(sandboxed_pids[gid]) {
    debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

    if(!filter_list)  {
      debug_alert("Pid %d requested sandboxing but we cannot find any filters! We assume all syscalls blocked!\n", pid);
      goto syscall_blocked;
    }

    syscall_filter = filter_list[sys_nr];

    // check whether the syscall is allowed at all before we go into possible detailed argument checks
    if(!syscall_filter.allowed) {
      debug_alert("Trying to execute forbidden syscall %d (PID: %d)\n", sys_nr, pid);
      // goto syscall_blocked;
    }

    // now we can check individual arguments if such a check was requested
    if(syscall_filter.num_syscall_args_filtered > 0) {
      // start checking arguments, checking integers is simply, strings need our new approach
      if(!check_argument(REGS, &syscall_filter, false)) {
        pr_alert("Argument check failed for pid %d and syscall %d\n", pid, sys_nr);
        // goto syscall_blocked;
      }
    }
  }
  // we need to save the result for the syscall as we need to do some additional housekeeping for argument filtering
  syscall_result = old_sys_call_table[sys_nr](REGS);
  if(sandboxed_pids[gid]) {
    // at this point, we can make string arguments userspace accessible again
    make_all_strings_user_accessible(REGS, &syscall_filter);
  }
  return syscall_result;

syscall_blocked:
  kill_pid(task_pid(current), SIGKILL, 1);
// error:
  return -1;
}

static asmlinkage long hook_clone(REGS_DEFINES) {
  pid_t pid = task_pid_nr(current);
  pid_t gid = task_tgid_nr(current);
  int sys_nr = SYSNO;
  long syscall_result;
  filter_info_t syscall_filter;

  if(sandboxed_pids[gid]) {
    debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

    if(!filter_list)  {
      debug_alert("Pid %d requested sandboxed but we cannot find any filters! We assume all syscalls blocked!\n", pid);
      goto syscall_blocked;
    }

    syscall_filter = filter_list[sys_nr];

    // check whether the syscall is allowed at all before we go into possible detailed argument checks
    if(!syscall_filter.allowed) {
      debug_alert("Trying to execute forbidden syscall %d (PID: %d)\n", sys_nr, pid);
      // goto syscall_blocked;
    }

    // now we can check individual arguments if such a check was requested
    if(syscall_filter.num_syscall_args_filtered > 0) {
      // start checking arguments, checking integers is simply, strings need our new approach
      if(!check_argument(REGS, &syscall_filter, false)) {
        pr_alert("Argument check failed for pid %d and syscall %d\n", pid, sys_nr);
        // goto syscall_blocked;
      }
    }
  }
  // we need to save the result for the syscall as we need to do some additional housekeeping.
  // for instance, we need to copy the filters for fork and clone syscalls to the new pids
  // this is easy as we have a ref count we only need to insert the same filters to the new pid
  syscall_result = old_sys_call_table[sys_nr](REGS);
  if(sandboxed_pids[gid]) {
    filter_list->ref_count++;
    // check if we used fork instead of clone, we find this out by checking the thread group id
    // if it was a fork call, we need to mark the process as sandboxed
    if(task_tgid_nr(get_pid_task(find_get_pid(syscall_result), PIDTYPE_PID)) != gid) {
      debug_info("Start sandboxing of forked process %lu\n", syscall_result);
      sandboxed_pids[syscall_result] = 1;
    }
    
    // at this point, we can make string arguments userspace accessible again
    make_all_strings_user_accessible(REGS, &syscall_filter);
  }
  return syscall_result;

syscall_blocked:
  kill_pid(task_pid(current), SIGKILL, 1);
// error:
  return -1;
}

static asmlinkage long hook_exec(REGS_DEFINES) {
  pid_t pid = task_pid_nr(current);
  pid_t gid = task_tgid_nr(current);
  int sys_nr = SYSNO;
  filter_info_t syscall_filter;

  if(sandboxed_pids[gid]) {
    debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

    if(!filter_list)  {
      debug_alert("Pid %d requested sandboxed but we cannot find any filters! We assume all syscalls blocked!\n", pid);
      goto syscall_blocked;
    }

    syscall_filter = filter_list[sys_nr];

    // check whether the syscall is allowed at all before we go into possible detailed argument checks
    if(!syscall_filter.allowed) {
      debug_alert("Trying to execute forbidden syscall %d (PID: %d)\n", sys_nr, pid);
      // goto syscall_blocked;
    }

    // now we can check individual arguments if such a check was requested
    if(syscall_filter.num_syscall_args_filtered > 0) {
      // start checking arguments, checking integers is simply, strings need our new approach
      if(!check_argument(REGS, &syscall_filter, true)) {
        pr_alert("Argument check failed for pid %d and syscall %d\n", pid, sys_nr);
        // goto syscall_blocked;
      }
    }
  }

  return old_sys_call_table[sys_nr](REGS);

syscall_blocked:
  kill_pid(task_pid(current), SIGKILL, 1);
// error:
  return -1;
}

// we always allow the exit syscall, so we only hook it to perform a cleanup of our filters
static asmlinkage long hook_exit(REGS_DEFINES) {
  pid_t pid = task_pid_nr(current);
  pid_t gid = task_tgid_nr(current);
  int sys_nr = SYSNO;

  if(sandboxed_pids[gid]) {
    debug_info("PID %d is trying to exit using syscall %d \n", pid, sys_nr);
    thread_group_clear_filter();
  }

  return old_sys_call_table[sys_nr](REGS);
}

// ---------------------IOCTL CODE------------------------------------------------------
static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
  switch (ioctl_num) {
    case SANDBOX_IOCTL_CMD_VM_RESOLVE: {
      sandbox_entry_t vm_user;
      vm_t vm;
      (void)from_user(&vm_user, (void*)ioctl_param, sizeof(vm_user));
      vm.pid = vm_user.pid;
      resolve_vm(vm_user.vaddr, &vm, !mm_is_locked);
      vm_to_user(&vm_user, &vm);
      (void)to_user((void*)ioctl_param, &vm_user, sizeof(vm_user));
      return 0;
    }
    case SANDBOX_IOCTL_CMD_GET_NUM_SYSCALLS:
      return __NR_syscall_max;
    case SANDBOX_IOCTL_CMD_INSTALL_FILTER: {
      if(task_no_new_privs(current)) // do not allow installing new filters if no_new_privs is set
        return -1;
      filter_list = kmalloc(sizeof(filter_info_t) * __NR_syscall_max, GFP_KERNEL);
      (void)from_user(filter_list, (void*)ioctl_param, sizeof(filter_info_t) * __NR_syscall_max);
      if(copy_filters_to_kernel_memory(filter_list)) {
        kfree(filter_list);
        return -1;
      }
      filter_list->ref_count = 1;

      sandboxed_pids[task_tgid_nr(current)] = 1;
      task_set_no_new_privs(current);
      return 0;
    }
    case SANDBOX_IOCTL_CMD_PRINT_FILTERS: {
      print_filters(task_tgid_nr(current), 1);
      return 0;
    }
    default:
      return -1;
  }

  return 0;
}

// ---------------------MODULE INIT AND CLEANUP CODE------------------------------------------------------
static struct file_operations f_ops = {.owner = THIS_MODULE,
                                       .unlocked_ioctl = device_ioctl,
                                       .open = device_open,
                                       .release = device_release};

static struct miscdevice misc_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = SANDBOX_DEVICE_NAME,
  .fops = &f_ops,
  .mode = S_IRWXUGO,
};

int init_module(void) {
  int r, nr;

  /* Register device */
  r = misc_register(&misc_dev);
  if (r != 0) {
    pr_alert("Failed registering device with %d\n", r);
    return 1;
  }

  // retrieve the flush_tlb_mm_range function and store its address in the function pointer
  flush_tlb_mm_range_func = (void *) kallsyms_lookup_name("flush_tlb_mm_range");
  if(!flush_tlb_mm_range_func) {
    debug_alert("Could not retrieve flush_tlb_mm_range function pointer\n");
  }

  syscall_tbl = (sys_call_ptr_t*)kallsyms_lookup_name("sys_call_table");
  debug_info("Syscall table @ %zx\n", (size_t)syscall_tbl);

  // backup old syscall table and install our hook
  debug_info("Saving old syscall table and installing hook\n");
  for(nr=0; nr < __NR_syscall_max; nr++) {
    old_sys_call_table[nr] = syscall_tbl[nr];
    if(nr == __NR_exit_group || nr == __NR_exit)
      hook_syscall(nr, hook_exit);
    else if(nr == __NR_execve || nr == __NR_execveat)
      hook_syscall(nr, hook_exec);
    else if(nr == __NR_fork || nr == __NR_clone)
      hook_syscall(nr, hook_clone);
    else
      hook_syscall(nr, hook_generic);
  }
  
  pr_info("Loaded.\n");

  return 0;
}

void cleanup_module(void) {
  int nr;
  misc_deregister(&misc_dev);

  // restore old syscall table
  debug_info("Restoring old syscall table\n");
  for(nr=0; nr<__NR_syscall_max; nr++) {
    unhook_syscall(nr);
  }
  
  pr_info("Removed.\n");
}
