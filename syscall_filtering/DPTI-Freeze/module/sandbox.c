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
#include <linux/mman.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#include "sandbox.h"

MODULE_AUTHOR("Anonymous author");
MODULE_DESCRIPTION("Device for filtering syscalls, including deep argument filtering");
MODULE_LICENSE("GPL");

#define DEBUG_INFO 0
#define DEBUG_ALERT 0
#define debug_info(...) do { if(DEBUG_INFO) pr_info(__VA_ARGS__); } while(0)
#define debug_alert(...) do { if(DEBUG_ALERT) pr_alert(__VA_ARGS__); } while(0)
#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[dpti-freeze] " ": " fmt

#define NUM_TRACKED_ADDRESSES 20

#define REGS_DEFINES const struct pt_regs* regs
#define REGS regs
#define ARG1 regs->di
#define ARG2 regs->si
#define ARG3 regs->dx
#define ARG4 regs->r10
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
#define KPROBE_KALLSYMS_LOOKUP 1
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
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
RADIX_TREE(tgid_modified_pages_list, GFP_KERNEL);  /* Declare and initialize */
bool need_tracking = false;

void (*flush_tlb_mm_range_func)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool);

static sys_call_ptr_t old_syscall_table[__NR_syscall_max];
static sys_call_ptr_t* syscall_tbl;

struct alias_mapping {
  pid_t pid;
  struct mm_struct *mm;
  size_t address;
  vm_t *vm;
  bool modified;
  struct list_head node;
};

struct pfn_mapping {
  unsigned long pfn;
  int num_alias;
  struct list_head alias;
  struct hlist_node node;
};

DEFINE_HASHTABLE(pfn_table,8);

static struct mm_struct* get_mm(void);
static int resolve_vm(size_t address, vm_t* entry);

struct proc_mem_struct {
  struct file *file;
  void *private_data;
};

// ---------------------------------------------------------------------------
static int device_open(struct inode *inode, struct file *file) {
  return 0;
}

static int device_release(struct inode *inode, struct file *file) {
  return 0;
}

// ---------------------PFN-TABLE HELPER-------------------------------------------------------

static inline int is_address_tracked(struct pfn_mapping *cur, size_t address) {
  struct alias_mapping *alias_mapping = NULL;

  list_for_each_entry(alias_mapping, &cur->alias, node) {
    // if pid and address match one already in the list, we have a perfect match and don't need to add anything new
    if(alias_mapping->pid == task_tgid_nr(current) && alias_mapping->address == address) {
      debug_info("Address (%px) is already tracked (PID: %d)\n", (void*)address, task_pid_nr(current));
      return 1;
    }
  }
  return 0;
}

static inline void fill_alias_mapping(struct alias_mapping *alias_mapping, vm_t *vm, size_t address) {
  alias_mapping->pid = task_tgid_nr(current);
  vm->pid = alias_mapping->pid;
  alias_mapping->mm = get_mm();
  alias_mapping->vm = vm;
  alias_mapping->address = address;
}

static inline int new_pfn_table_entry(vm_t *vm, unsigned long pfn, size_t address) {
  struct pfn_mapping *pfn_mapping;
  struct alias_mapping *alias_mapping;
  pfn_mapping = kmalloc(sizeof(struct pfn_mapping), GFP_KERNEL);
  if(!pfn_mapping) {
    pr_alert("Could not allocate memory for the new pfn mapping (PID: %d)\n", task_pid_nr(current));
    kfree(vm);
    return -1;
  }
  alias_mapping = kmalloc(sizeof(struct alias_mapping), GFP_KERNEL);
  if(!alias_mapping) {
    pr_alert("Could not allocate memory for the new alias mapping (PID: %d)\n", task_pid_nr(current));
    kfree(vm);
    kfree(pfn_mapping);
    return -1;
  }
  // first, we fill the new alias mapping
  fill_alias_mapping(alias_mapping, vm, address);

  // now we fill the new pfn mapping, intialize its linked list, and add the alias mapping to the linked list
  pfn_mapping->pfn = pfn;
  pfn_mapping->num_alias = 1;
  INIT_LIST_HEAD(&pfn_mapping->alias);
  list_add(&alias_mapping->node, &pfn_mapping->alias); // add alias mapping to pfn
  hash_add(pfn_table, &pfn_mapping->node, pfn); // add pfn mapping to hash table
  return 1;
}

static inline int update_pfn_table(size_t address) {
  struct pfn_mapping *cur;
  unsigned long pfn;
  vm_t *vm;

  vm = kmalloc(sizeof(vm_t), GFP_KERNEL);
  if(!vm)
    goto error;
  if(unlikely(resolve_vm(address, vm))) {
    pr_alert("Could not resolve vm (page fault handler) (PID: %d)\n", task_pid_nr(current));
    kfree(vm);
    goto error;
  }

  pfn = pte_pfn(*(vm->pte));

  hash_for_each_possible(pfn_table, cur, node, pfn) {
    // check if pfn is already used, if it is we first check whether we are already tracking that alias.
    // if not, we add our new virtual address to the pfn mappings linked list
    if(cur->pfn == pfn) {
      struct alias_mapping *alias_mapping;
      debug_info("Found existing pfn mapping (pfn: %lx), checking whether address (%px) is already tracked (PID: %d)\n", pfn, (void*)address, task_pid_nr(current));
      if(is_address_tracked(cur, address)) {
        goto out;
      }
      debug_info("Address (%px) is not tracked, adding it\n", (void*)address);
      // no match occurred, create new mapping and add it to pfn mapping
      alias_mapping = kmalloc(sizeof(struct alias_mapping), GFP_KERNEL);
      if(!alias_mapping) {
        pr_alert("Could not allocate memory for the new alias mapping (PID: %d)\n", task_pid_nr(current));
        kfree(vm);
        goto error;
      }
      // first, we fill the new alias mapping
      fill_alias_mapping(alias_mapping, vm, address);
      cur->num_alias++; // we also increase the counter of aliased mappings
      list_add(&alias_mapping->node, &cur->alias); // add alias mapping to pfn
      goto out;
    }
  }
  debug_info("No existing pfn entry found, creating new one for pfn %lx, faulting address %px (PID: %d)\n", pfn, (void*)address, task_pid_nr(current));
  // if we get here, then this is the first time this pfn is assigned
  if(unlikely(!new_pfn_table_entry(vm, pfn, address)))
    goto error;

out:
  return 0;

error:
  return 1;
}

static inline void alias_mapping_cleanup(struct pfn_mapping *cur, size_t address) {
  struct alias_mapping *alias_mapping, *tmp;

  list_for_each_entry_safe(alias_mapping, tmp, &cur->alias, node) {
    if((alias_mapping->pid == task_tgid_nr(current) && address == 0) || (alias_mapping->pid == task_tgid_nr(current) && address == alias_mapping->address)) {
    // if(alias_mapping->pid == task_tgid_nr(current) && address == alias_mapping->address) {
      debug_info("Found matching alias mapping for pfn (%lx), removing it (PID: %d)\n", cur->pfn, task_pid_nr(current));
      // remove from list, then free all associated memory, decrease counter in pfn mapping
      list_del(&alias_mapping->node);
      kfree(alias_mapping->vm);
      kfree(alias_mapping);
      cur->num_alias--;
    }
  }

  // check if there are any alias mappings left for this pfn, if not we remove it
  if(!cur->num_alias) {
    debug_info("PFN (%lx) no longer has any alias mappings, indicating it is no longer assigned, removing it entirely (PID: %d)\n", cur->pfn, task_pid_nr(current));
    hash_del(&cur->node);
    kfree(cur);
  }
}

static inline void pfn_table_exit_cleanup(void) {
  int bkt;
  struct pfn_mapping *cur;
  struct hlist_node *tmp;

  hash_for_each_safe(pfn_table, bkt, tmp, cur, node) {
    alias_mapping_cleanup(cur, 0);
  }
}

// ------------------HOUSEKEEPING CODE---------------------------------------------------------
static int track_page(size_t tracked_addresses[NUM_TRACKED_ADDRESSES], size_t address) {
  int i;
  if(!tracked_addresses) {
    debug_info("Tracking array not allocated\n");
    return -1;
  }
  for(i=0; i<NUM_TRACKED_ADDRESSES; i++) {
    if(tracked_addresses[i] == 0) {
      tracked_addresses[i] = address;
      return 0;
    }
  }
  debug_info("Too many addresses to track, make this tracking dynamic in size\n");
  return -1;
}

static int is_page_tracked(size_t tracked_addresses[NUM_TRACKED_ADDRESSES], size_t address) {
  int i;
  if(!tracked_addresses) {
    debug_info("Tracking array not allocated\n");
    return -1;
  }
  for(i=0; i<NUM_TRACKED_ADDRESSES; i++) {
    if(tracked_addresses[i] == address) {
      return i;
    }
  }
  return -1;
}

static int clear_tracked_page(size_t tracked_addresses[NUM_TRACKED_ADDRESSES], int index) {
  if(index >= NUM_TRACKED_ADDRESSES) {
    debug_info("Array index too large in clearing page\n");
    return -1;
  }
  if(!tracked_addresses) {
    debug_info("Tracking array not allocated\n");
    return -1;
  }
  tracked_addresses[index] = 0;
  return 0;
}

// ---------------------HOOKING-RELATED CODE------------------------------------------------------
static long hook_generic(REGS_DEFINES);
static long hook_clone(REGS_DEFINES);
static long hook_exit(REGS_DEFINES);
static long hook_exec(REGS_DEFINES);
static long hook_munmap(REGS_DEFINES);

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
  syscall_tbl[nr] = old_syscall_table[nr];
  protect_memory();
}

static int fault_entry_handler(struct kretprobe_instance *ri, struct pt_regs* regs) {
  size_t *fault_address;
  struct vm_area_struct *vma;

  // ensure that the return handler is not executed for non-sandboxed applications
  if(!sandboxed_pids[task_tgid_nr(current)])
    return 1;

  vma = find_vma(get_mm(), ARG2);
  if(unlikely(!vma)) // skip return handler if we don't have a vma, because then it was not mmap'ed
    return 1;

  if(!(vma->vm_flags & VM_SHARED)) // we only need to look at shared mappings
    return 1;

  fault_address = (size_t*)ri->data;
  *fault_address = ARG2; // second parameter is the address causing the page fault
  debug_info("faulting address (entry handler): %px (PID: %d)\n", (void*)*fault_address, task_pid_nr(current));
  return 0;
}

static int fault_ret_handler(struct kretprobe_instance *ri, struct pt_regs* regs) {
  size_t *fault_address = (size_t*)ri->data;
  vm_fault_t vm_fault = regs_return_value(regs);

  debug_info("faulting address (ret handler): %px (PID: %d)\n", (void*)*fault_address, task_pid_nr(current));

  // check if we are retrying the fault (most likely, retrying because of artificial slowdown in writeback memory)
  if(vm_fault & VM_FAULT_RETRY) {
    debug_info("retrying fault, skip tracking until fault handled successfully (PID: %d)\n", task_pid_nr(current));
    goto out;
  }

  if(update_pfn_table(*fault_address)) {
    goto error;
  }

out:
  return 0;

error:
  kill_pid(task_pid(current), SIGKILL, 1);
  return -1;
}

static int proc_mem_write_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct proc_mem_struct *probe_data;
  size_t offset = (size_t) regs->r10;
  struct file *file = (struct file*) regs->di;

  probe_data = (struct proc_mem_struct*)ri->data;
  probe_data->file = file;
  probe_data->private_data = file->private_data;
  file->private_data = NULL;
  debug_info("Trying to write to offset %px through /proc/pid/mem, preventing it\n", (void*) offset);
  return 0;
}

static int proc_mem_write_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct proc_mem_struct *probe_data = (struct proc_mem_struct*)ri->data;
  probe_data->file->private_data = probe_data->private_data;

  debug_info("Restored private data after preventing /proc/pid/mem write\n");
  return 0;
}

static struct kretprobe proc_mem_write_probe = {
  .kp.symbol_name	= "mem_write",
  .entry_handler = proc_mem_write_entry_handler,
  .handler = proc_mem_write_ret_handler,
  .data_size = sizeof(struct proc_mem_struct*),
  .maxactive = 20
};

static struct kretprobe page_fault_probe = {
  .kp.symbol_name = "handle_mm_fault",
  .entry_handler = fault_entry_handler,
  .handler = fault_ret_handler,
  .data_size = sizeof(size_t),
  .maxactive = 20
};


static inline int install_pf_kretprobe(void) {
  // install kretprobe on the page fault handler
  int retval = register_kretprobe(&page_fault_probe);
  if (unlikely(retval < 0)) {
    pr_alert("Could not probe page fault handler, error code: %d\n", retval);
  } else {
    debug_info("Pagefault handler is now probed\n");
  }
  return retval;
}

static inline int install_proc_mem_probe(void) {
  // install kprobe on mem_write
  int retval = register_kretprobe(&proc_mem_write_probe);
  if (unlikely(retval < 0)) {
    pr_alert("Could not probe mem_write, error code: %d\n", retval);
  } else {
    debug_info("mem_write is now probed\n");
  }
  return retval;
}

// ---------------------PAGING-RELATED CODE------------------------------------------------------
static struct mm_struct* get_mm(void) {
  if(current->mm) {
    return current->mm;
  } else {
    return current->active_mm;
  }
  return NULL;
}

static inline void lock_mm_read(struct mm_struct *mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  mmap_read_lock(mm);
#else
  down_read(&mm->mmap_sem);
#endif
}

static inline void lock_mm_write(struct mm_struct *mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  mmap_write_lock(mm);
#else
  down_write(&mm->mmap_sem);
#endif
}

static inline void unlock_mm_read(struct mm_struct *mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  mmap_read_unlock(mm);
#else
  up_read(&mm->mmap_sem);
#endif
}

static inline void unlock_mm_write(struct mm_struct *mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  mmap_write_unlock(mm);
#else
  up_write(&mm->mmap_sem);
#endif
}

static int resolve_vm(size_t address, vm_t* entry) {
  struct mm_struct *mm;

  if(!entry) return 1;
  entry->pud = NULL;
  entry->pmd = NULL;
  entry->pgd = NULL;
  entry->pte = NULL;
  entry->p4d = NULL;
  entry->valid = 0;

  mm = get_mm();
  if(unlikely(!mm)) return 1;

  /* Lock mm */
  lock_mm_read(mm);

  /* Return PGD (page global directory) entry */
  entry->pgd = pgd_offset(mm, address);
  if (pgd_none(*(entry->pgd)) || pgd_bad(*(entry->pgd))) {
    entry->pgd = NULL;
    goto error_out;
  }
  entry->valid |= DPTI_VALID_MASK_PGD;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
  /* Return p4d offset */
  entry->p4d = p4d_offset(entry->pgd, address);
  if (p4d_none(*(entry->p4d)) || p4d_bad(*(entry->p4d))) {
    entry->p4d = NULL;
    goto error_out;
  }
  entry->valid |= DPTI_VALID_MASK_P4D;

  /* Get offset of PUD (page upper directory) */
  entry->pud = pud_offset(entry->p4d, address);
  if (pud_none(*(entry->pud))) {
    entry->pud = NULL;
    goto error_out;
  }
  entry->valid |= DPTI_VALID_MASK_PUD;
#else
  /* Get offset of PUD (page upper directory) */
  entry->pud = pud_offset(entry->pgd, address);
  if (pud_none(*(entry->pud))) {
    entry->pud = NULL;
    goto error_out;
  }
  entry->valid |= DPTI_VALID_MASK_PUD;
#endif


  /* Get offset of PMD (page middle directory) */
  entry->pmd = pmd_offset(entry->pud, address);
  if (pmd_none(*(entry->pmd)) || pud_large(*(entry->pud))) {
    entry->pmd = NULL;
    goto error_out;
  }
  entry->valid |= DPTI_VALID_MASK_PMD;

  /* Map PTE (page table entry) */
  entry->pte = pte_offset_map(entry->pmd, address);
  if (entry->pte == NULL || pmd_large(*(entry->pmd))) {
    goto error_out;
  }
  entry->valid |= DPTI_VALID_MASK_PTE;

  /* Unmap PTE, fine on x86 and ARM64 -> unmap is NOP */
  pte_unmap(entry->pte);

  /* Unlock mm */
  unlock_mm_read(mm);

  return 0;

error_out:
  /* Unlock mm */
  unlock_mm_read(mm);

  return 1;
}

static inline int make_read_only(struct alias_mapping *alias, bool track) {
  struct vm_area_struct *vma;

  if(!pte_write(*(alias->vm->pte))) {
    debug_info("Page is already not writable, no update necessary\n");
    return 0;
  }

  debug_info("Updating PTE of address %px (setting to read only) (PID: %ld)\n", (void*)alias->address, alias->vm->pid);
  // clear RW bit, update PTE, flush tlb
  lock_mm_write(alias->mm);

  if(unlikely(!(vma = find_vma(alias->mm, alias->address)))) return 1;

  // set page to write-protected, update PTE, flush tlb
  set_pte_at(alias->mm, alias->address, alias->vm->pte, pte_wrprotect(*(alias->vm->pte)));
  // we also need to clear the vm_write flag from the vma otherwise the page fault handler maps it on a subsequent access as it thinks it is a spurious page fault
  vma->vm_flags &= ~VM_WRITE; 
  flush_tlb_mm_range_func(alias->mm, alias->address, alias->address + PAGE_SIZE, PAGE_SHIFT, false);

  if(track)
    track_page(radix_tree_lookup(&tgid_modified_pages_list, task_tgid_nr(current)), alias->address);
  else
    alias->modified = true;

  unlock_mm_write(alias->mm);
  return 0;
}

static inline int make_writable(struct alias_mapping *alias, bool track) {
  struct vm_area_struct *vma;
  int tracked_index = 0;
  size_t *modified_pages_list;

  if(track) {
    modified_pages_list = radix_tree_lookup(&tgid_modified_pages_list, task_tgid_nr(current));
    tracked_index = is_page_tracked(modified_pages_list, (size_t) alias->address);
    if(tracked_index == -1)
      return 0;
  }
  else if(!alias->modified)
    return 0;

  debug_info("Updating PTE of address %px (setting to writable) (PID: %ld)\n", (void*)alias->address, alias->vm->pid);
  lock_mm_write(alias->mm);

  if(unlikely(!(vma = find_vma(alias->mm, alias->address)))) return 1;
  // set page to writable again, update PTE, flush tlb
  set_pte_at(alias->mm, alias->address, alias->vm->pte, pte_mkwrite(*(alias->vm->pte)));
  // we also need to clear the vm_write flag from the vma otherwise the page fault handler maps it on a subsequent access
  vma->vm_flags |= VM_WRITE;
  flush_tlb_mm_range_func(alias->mm, alias->address, alias->address + PAGE_SIZE, PAGE_SHIFT, false);
  unlock_mm_write(alias->mm);

  if(track)
    clear_tracked_page(modified_pages_list, tracked_index);
  else
    alias->modified = false;

  return 0;
}

static int update_vm_clear_write(size_t address) {
  vm_t vm;
  struct pfn_mapping *cur;
  unsigned long pfn;
  struct vm_area_struct *vma;
  struct mm_struct *mm = get_mm();

  if(unlikely(!mm)) return 1;
  vma = find_vma(mm, address);
  if(unlikely(!vma)) return 1;

  resolve_vm(address, &vm);
  pfn = pte_pfn(*(vm.pte));

  // check whether we need to check ouf pfn mappings list, we only need to do this for shared mapping
  if(vma->vm_flags & VM_SHARED) {
    hash_for_each_possible(pfn_table, cur, node, pfn) {
      // make all addresses mapping to the same pfn read only
      if(cur->pfn == pfn) {
        struct alias_mapping *alias_mapping;
        // iterate over the linked list, making each one read only
        list_for_each_entry(alias_mapping, &cur->alias, node) {
          make_read_only(alias_mapping, false);
        }
        goto done;
      }
    }
  } else {
    struct alias_mapping alias = {
      .address = address,
      .vm = &vm,
      .mm = mm
    };
    // pfn is not shared, so we only need to make our current argument virtual address read only
    debug_info("Not a shared mapping, only making current address %px read only (PID: %d)\n", (void*)address, task_pid_nr(current));
    make_read_only(&alias, true);
  }

done:
  return 0;
}

static int update_vm_set_writable(size_t address) {
  vm_t vm;
  struct pfn_mapping *cur;
  unsigned long pfn;
  struct vm_area_struct *vma;
  struct mm_struct *mm = get_mm();

  if(unlikely(!mm)) return 1;
  vma = find_vma(mm, address);
  if(unlikely(!vma)) return 1;

  resolve_vm(address, &vm);

  pfn = pte_pfn(*(vm.pte));

  // check whether we need to check ouf pfn mappings list, we only need to do this for shared mapping
  if(vma->vm_flags & VM_SHARED) {
    hash_for_each_possible(pfn_table, cur, node, pfn) {
      // make all addresses mapping to the same pfn writable again
      if(cur->pfn == pfn) {
        struct alias_mapping *alias_mapping;
        // iterate over the linked list, making each one writable
        list_for_each_entry(alias_mapping, &cur->alias, node) {
          make_writable(alias_mapping, false);
        }
        goto done;
      }
    }
  }
  else {
    struct alias_mapping alias = {
      .address = address,
      .vm = &vm,
      .mm = mm
    };
    // pfn is not shared, so we only need to make our current argument virtual address accessible
    debug_info("Not a shared mapping, only making current address %px writable (PID: %d)\n", (void*)address, task_pid_nr(current));
    make_writable(&alias, true);
  }

done:
  return 0;
}


// ---------------------DEBUGGING CODE------------------------------------------------------
static void vm_to_user(dpti_entry_t* user, vm_t* vm) {
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

  if(unlikely(!filter_list)) {
    pr_alert("copy_filters_to_kernel_memory: no filters found for pid %d\n", task_pid_nr(current));
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
            // we have a string filter, so we need to track alias mappings
            need_tracking = true;
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

  if(need_tracking)
    enable_kretprobe(&page_fault_probe);

  return 0;
}

static int free_filters(filter_info_t *filter_list) {
  filter_info_t *filter;
  int arg_index, option_index, sys_nr;

  debug_info("Trying to free filter memory for pid %d\n", task_tgid_nr(current));

  if(unlikely(!filter_list)) {
    pr_alert("free_filters: no filters found for pid %d\n", task_tgid_nr(current));
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
  if(unlikely(!filter_list)) {
    pr_alert("print_filter: no filters found for pid %d\n", pid);
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
      switch (filter.arg[arg_index].type) {
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

// ---------------------SANDBOXING-RELATED CODE------------------------------------------------------
void thread_group_clear_filter(void) {
  bool tmp_need_tracking = need_tracking;
  // the thread group exits, so we don't need to keep track of modified pages anymore, free memory
  size_t *modified_pages_list = radix_tree_delete(&tgid_modified_pages_list, task_tgid_nr(current));
  kfree(modified_pages_list);

  // print the number of threads for debug_infoging purposes
  debug_info("number of threads: %d\n", current->signal->nr_threads);
  // a task group wants to exit, so we decrement the ref count for the thread group by the number of threads in it
  filter_list->ref_count -= current->signal->nr_threads;
  sandboxed_pids[task_tgid_nr(current)] = 0;

  // now we free the memory if no thread in this thread group needs it anymore
  // we also reset the need_tracking flag and unregister the kretprobe on the page fault handler
  if(!filter_list->ref_count) {
    free_filters(filter_list);
    filter_list = NULL;
    need_tracking = false;
    disable_kretprobe(&page_fault_probe);
  }
  // clean up the alias mapping tracking for the exiting process
  if(tmp_need_tracking)
    pfn_table_exit_cleanup();
}

inline __attribute__((always_inline)) int is_stack(size_t address) {
  struct vm_area_struct *vma;
  vma = find_vma(get_mm(), address);
  if(unlikely(!vma)) {
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
    case 1:
      return ARG2;
    case 2:
      return ARG3;
    case 3:
      return ARG4;
    case 4:
      return ARG5;
    case 5:
      return ARG6;
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
  int allowed = 0;
  // we retrieve the pointer to the userspace address at which the string is stored
  char *argument = (char*) get_syscall_argument_by_index(REGS, arg_pos);
  // argument is NULL, this indicates a problem in the filters as a compared string should not be NULL
  if(unlikely(!argument))
    return 0;

  // for exec syscalls, we first need to trigger a COW violation as otherwise we run into a problem
  // as we cannot make the shared mapping writable again
  // to trigger COW, we simply disable smap and write the original value back to the page and then re-enable smap
  // a full implementation should do this without disabling smap
  if(needs_cow) {
    debug_info("Disabling smap, triggering cow, enabling smap in process %d\n", task_pid_nr(current));
    stac();
    // prevent the compiler from performing dead store elimination
    ((unsigned char volatile *)argument)[0] = argument[0];
    clac();
  }
  update_vm_clear_write((size_t) argument);
  // disable smap for the comparison, data can't be modified anymore
  stac();
  // Now that it is no longer writable and copied to kernelspace without toctou we can start checking the arguments
  for(option_index=0; option_index<syscall_filter->arg[arg_pos].num_possible_options; option_index++) {
    switch (syscall_filter->arg[arg_pos].comp[option_index]) {
      case EQ:
        if(strncmp(syscall_filter->arg[arg_pos].string_syscall_arg[option_index], argument, strlen(syscall_filter->arg[arg_pos].string_syscall_arg[option_index])) == 0) {
          allowed = 1;
          goto out;
        }
        break;
      case NEQ:
        if(strncmp(syscall_filter->arg[arg_pos].string_syscall_arg[option_index], argument, strlen(syscall_filter->arg[arg_pos].string_syscall_arg[option_index])) != 0) {
          allowed = 1;
          goto out;
        }
        break;
      case GT:
        debug_info("GT string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        goto out;
        break;
      case GTE:
        debug_info("GTE string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        break;
      case LT:
        debug_info("LT string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        goto out;
        break;
      case LTE:
        debug_info("LTE string comparison requested, but not possible. Force exiting application as this indicates a mistake in the generated filter\n");
        break;
      default:
        break;
    }
  }

out:
  // enable smap again
  clac();
  return allowed;
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

inline __attribute__((always_inline)) void make_strings_writable_again(REGS_DEFINES, filter_info_t *syscall_filter) {
  int i;
  // we have no syscall argument filters, so just return
  if(syscall_filter->num_syscall_args_filtered == 0)
    return;

  for(i=0; i<MAX_ARGUMENT_NUMBER; i++) {
    if(syscall_filter->arg[i].type == STRING) {
      const char *argument = (const char*) get_syscall_argument_by_index(REGS, i);
      if(argument != 0) {
        update_vm_set_writable((size_t) argument);
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

  if(!sandboxed_pids[gid])
    return old_syscall_table[sys_nr](REGS);

  debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

  if(unlikely(!filter_list)) {
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

  // we need to save the result for the syscall as we need to do some additional housekeeping for argument filtering
  syscall_result = old_syscall_table[sys_nr](REGS);

  // at this point, we can make string arguments userspace accessible again
  make_strings_writable_again(REGS, &syscall_filter);

  return syscall_result;

syscall_blocked:
  kill_pid(task_pid(current), SIGKILL, 1);
// error:
  return -1;
}

static asmlinkage long hook_clone(REGS_DEFINES) {
  pid_t pid = task_pid_nr(current);
  pid_t gid = task_tgid_nr(current);
  size_t *modified_pages_list;
  int sys_nr = SYSNO;
  long syscall_result;
  filter_info_t syscall_filter;

  if(!sandboxed_pids[gid])
    return old_syscall_table[sys_nr](REGS);

  debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

  if(unlikely(!filter_list)) {
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

  // we need to save the result for the syscall as we need to do some additional housekeeping.
  // for instance, we need to increase the ref count of our filters
  syscall_result = old_syscall_table[sys_nr](REGS);

  filter_list->ref_count++;
  // check if we used fork instead of clone, we find this out by checking the thread group id
  // if it was a fork call, we need to mark the process as sandboxed
  // we also need to allocate memory for keeping track of modified pages in the case of fork
  if(task_tgid_nr(get_pid_task(find_get_pid(syscall_result), PIDTYPE_PID)) != gid) {
    debug_info("Start sandboxing of forked process %lu\n", syscall_result);
    sandboxed_pids[syscall_result] = 1;

    modified_pages_list = kzalloc(sizeof(size_t) * NUM_TRACKED_ADDRESSES, GFP_KERNEL);
    radix_tree_insert(&tgid_modified_pages_list, syscall_result, (void*)modified_pages_list);
  }

  // at this point, we can make string arguments writable again if necessary
  make_strings_writable_again(REGS, &syscall_filter);

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

  if(!sandboxed_pids[gid])
    return old_syscall_table[sys_nr](REGS);

  debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

  if(unlikely(!filter_list)) {
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

  return old_syscall_table[sys_nr](REGS);

syscall_blocked:
  kill_pid(task_pid(current), SIGKILL, 1);
// error:
  return -1;
}

static asmlinkage long hook_munmap(REGS_DEFINES) {
  pid_t pid = task_pid_nr(current);
  pid_t gid = task_tgid_nr(current);
  int sys_nr = SYSNO;
  int index;
  filter_info_t syscall_filter;
  struct vm_area_struct *vma;
  size_t address = ARG1;

  if(!sandboxed_pids[gid])
    return old_syscall_table[sys_nr](REGS);

  debug_info("Trying to execute syscall %d (PID: %d)\n", sys_nr, pid);

  if(unlikely(!filter_list)) {
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

  // clean up our alias tracking if alias tracking was necessary for the application
  if(need_tracking) {
    vma = find_vma(get_mm(), address);
    if(vma->vm_flags & VM_SHARED) {
      for(index=0; index<ARG2; index+=PAGE_SIZE) {
        struct pfn_mapping *cur;
        struct hlist_node *tmp;
        unsigned long pfn;
        vm_t vm;
        debug_info("Munmap: Trying to clear alias mapping for address %px (PID: %d)\n", (void*)(address + index), pid);
        if(unlikely(resolve_vm((size_t)&((char*)address)[index], &vm))) {
          pr_alert("Munmap: Could not resolve vm for address %px\n", (void*)(address + index));
          goto syscall_blocked;
        }
        pfn = pte_pfn(*(vm.pte));

        hash_for_each_possible_safe(pfn_table, cur, tmp, node, pfn) {
          // check if pfn is already used, if it is we first check whether we are already tracking that alias.
          // if not, we add our new virtual address to the pfn mappings linked list
          if(cur->pfn == pfn) {
            debug_info("Munmap: Found existing pfn mapping (pfn: %lx), checking whether address (%px) is already tracked (PID: %d)\n", pfn, (void*)(address + index), pid);
            alias_mapping_cleanup(cur, address + index);
          }
        }
      }
    }
  }

  return old_syscall_table[sys_nr](REGS);

syscall_blocked:
  debug_info("killing process (PID: %d)\n", pid);
  kill_pid(task_pid(current), SIGKILL, 1);
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

  return old_syscall_table[sys_nr](REGS);
}

// ---------------------IOCTL CODE------------------------------------------------------
static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
  switch (ioctl_num) {
    case DPTI_IOCTL_CMD_VM_RESOLVE: {
      dpti_entry_t vm_user;
      vm_t vm;
      (void)from_user(&vm_user, (void*)ioctl_param, sizeof(vm_user));
      vm.pid = vm_user.pid;
      resolve_vm(vm_user.vaddr, &vm);
      vm_to_user(&vm_user, &vm);
      (void)to_user((void*)ioctl_param, &vm_user, sizeof(vm_user));
      return 0;
    }
    case DPTI_IOCTL_CMD_GET_NUM_SYSCALLS:
      return __NR_syscall_max;
    case DPTI_IOCTL_CMD_INSTALL_FILTER: {
      size_t *modified_pages_list;
      if(task_no_new_privs(current)) // do not allow installing new filters if no_new_privs is set
        return -1;
      filter_list = kmalloc(sizeof(filter_info_t) * __NR_syscall_max, GFP_KERNEL);
      modified_pages_list = kzalloc(sizeof(size_t) * NUM_TRACKED_ADDRESSES, GFP_KERNEL);
      (void)from_user(filter_list, (void*)ioctl_param, sizeof(filter_info_t) * __NR_syscall_max);
      if(unlikely(copy_filters_to_kernel_memory(filter_list))) {
        kfree(filter_list);
        return -1;
      }
      filter_list->ref_count = 1;

      radix_tree_insert(&tgid_modified_pages_list, task_tgid_nr(current), (void*)modified_pages_list);
      sandboxed_pids[task_tgid_nr(current)] = 1;
      task_set_no_new_privs(current);
      return 0;
    }
    case DPTI_IOCTL_CMD_PRINT_FILTERS: {
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
  .name = DPTI_DEVICE_NAME,
  .fops = &f_ops,
  .mode = S_IRWXUGO,
};

int init_module(void) {
  int r, nr;

  /* Register device */
  r = misc_register(&misc_dev);
  if (unlikely(r != 0)) {
    pr_alert("Failed registering device with %d\n", r);
    return -ENXIO;
  }

#ifdef KPROBE_KALLSYMS_LOOKUP
  /* register the kprobe */
  register_kprobe(&kp);

  /* assign kallsyms_lookup_name symbol to kp.addr */
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

  /* done with the kprobe, so unregister it */
  unregister_kprobe(&kp);

  if(unlikely(!kallsyms_lookup_name)) {
    pr_alert("Could not retrieve kallsyms_lookup_name\n");
    misc_deregister(&misc_dev);
    return -ENXIO;
  }
#endif

  if(unlikely(install_pf_kretprobe() < 0))
    return -ENXIO;

  // temporarily disable the probe until it is needed
  disable_kretprobe(&page_fault_probe);

  if(unlikely(install_proc_mem_probe() < 0))
    return -ENXIO;

  // retrieve the flush_tlb_mm_range function and store its address in the function pointer
  flush_tlb_mm_range_func = (void *) kallsyms_lookup_name("flush_tlb_mm_range");
  if(unlikely(!flush_tlb_mm_range_func)) {
    debug_alert("Could not retrieve flush_tlb_mm_range function pointer\n");
    misc_deregister(&misc_dev);
    return -ENXIO;
  }

  syscall_tbl = (sys_call_ptr_t*)kallsyms_lookup_name("sys_call_table");
  if(unlikely(!syscall_tbl)) {
    pr_alert("Could not find syscall table\n");
    misc_deregister(&misc_dev);
    return -ENXIO;
  }
  debug_info("Syscall table @ %zx\n", (size_t)syscall_tbl);

  // backup old syscall table and install our hook
  debug_info("Saving old syscall table and installing hook\n");
  for(nr=0; nr < __NR_syscall_max; nr++) {
    old_syscall_table[nr] = syscall_tbl[nr];
    if(nr == __NR_exit_group || nr == __NR_exit)
      hook_syscall(nr, hook_exit);
    else if(nr == __NR_execve || nr == __NR_execveat)
      hook_syscall(nr, hook_exec);
    else if(nr == __NR_fork || nr == __NR_clone)
      hook_syscall(nr, hook_clone);
    else if(nr == __NR_munmap)
      hook_syscall(nr, hook_munmap);
    else
      hook_syscall(nr, hook_generic);
  }

  pr_info("Loaded.\n");

  return 0;
}

void cleanup_module(void) {
  int nr;
  misc_deregister(&misc_dev);

  unregister_kretprobe(&page_fault_probe);
  unregister_kretprobe(&proc_mem_write_probe);

  // restore old syscall table
  debug_info("Restoring old syscall table\n");
  for(nr=0; nr<__NR_syscall_max; nr++) {
    unhook_syscall(nr);
  }

  pr_info("Removed.\n");
}
