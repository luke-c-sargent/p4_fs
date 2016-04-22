#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

//------------------------------------------------
#define DEBUG 0
#define UNUSED_CHILD_EXIT_STATUS -666
#define SYSCALL_ERROR -1
//------------------------------------------------

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  // added ---------------------------------------
  // parse command line, copy string
  char * arg_copy = palloc_get_page (0);
  if (arg_copy == NULL){
    printf("ERROR: ARG COPY FAIL\n");
    return TID_ERROR;
  }

  strlcpy (arg_copy, file_name, PGSIZE); 
  char *token, *save_ptr;
  int indexer = 0;
  for (token = strtok_r (arg_copy, " ", &save_ptr); token != NULL;
    token = strtok_r (NULL, " ", &save_ptr))
  {
    int length = strlen(token);
    if (DEBUG)
      printf ("[%d]'%s'\n", length, token);
    strlcpy (arg_copy + indexer, token, length+1);
    indexer += length + 1;
  }
  while (indexer!=PGSIZE)
  {
    arg_copy[indexer] = 0;
    ++indexer;
  } 

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;

  /* copy file, disregarding spaces by saving index position of
     valid strings */
  indexer = 0;
  while ( indexer < PGSIZE)
  {
    fn_copy[indexer] = arg_copy[indexer];
    ++indexer;
  }
  /* Create a new thread to execute FILE_NAME. */
  /*
  if (DEBUG)
  {
    printf ("fn_copy hexdump:\n");
    hex_dump (fn_copy, fn_copy, 80, 1);
  }*/
  tid = thread_create (arg_copy, PRI_DEFAULT, start_process, fn_copy);
  if(DEBUG)
    printf("gettig TID %d child struct\n", tid);

  struct thread* child_thread_ptr = get_child_by_tid (tid)->child_pointer;
  if(DEBUG)
  {
    struct thread_child* tcp = get_child_struct_by_child(child_thread_ptr);
    printf("!!!!!! %p exit status %d parent: %p\n", tcp, tcp->exit_status, tcp->child_pointer->parent);
  }
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);

  palloc_free_page(arg_copy);
  //-------------------------------------- end modified segment
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  if (DEBUG)
    printf("starting filename: %s...........", file_name);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  // ADDED----------------------------------------------------
  //sema_up(&child_struct_ptr->child_pointer->sema);
  // ADDED----------------------------------------------------
  /* If load failed, quit. */
  palloc_free_page (file_name);
  struct thread_child* child_struct_ptr  = list_entry (thread_current()->child_list_elem, struct thread_child, elem);
  if(!success)
    child_struct_ptr->exit_status = SYSCALL_ERROR;
  
  if(child_struct_ptr->parent_waiting){
    if(DEBUG)
      printf("child thread sema'ing up on: %s\n",child_struct_ptr->child_pointer->parent->name);
    //child_struct_ptr->parent_waiting = 0;
    //sema_up(&child_struct_ptr->child_pointer->parent->sema);
    
  }
  if (!success) 
  {
    
    child_struct_ptr->exit_status = SYSCALL_ERROR;
    //if_.eax = SYSCALL_ERROR;
    if(DEBUG)
    {
      printf("...%p : %s not successful, exit status %d\n",child_struct_ptr, child_struct_ptr->child_pointer->name, SYSCALL_ERROR);
      //if_.eax = SYSCALL_ERROR;
      //exit(-1);
    }
    thread_exit ();
  }
  if(DEBUG)
  {
    printf("...  successfully loaded\n");
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  // added --------------------------------------------------
  // check: invalid TID, not child, process_wait already called
  // struct thread* child_tp = get_child_by_tid (child_tid);
  struct thread_child* child_struct_ptr  = get_child_by_tid (child_tid);

  if (child_struct_ptr == NULL)
  {
    if (DEBUG)
      printf("NULL child tid in process_wait; tid not found\n");

    return SYSCALL_ERROR;
  }

  int exit_status = 1;

  // get the child struct pointer for use with synchronization
  //printf("child struct pointer %p \n", child_struct_ptr);
  if (DEBUG)
  {
    printf ("child exit status during process wait: %d\n", child_struct_ptr->exit_status);
  }
  //printf("child struct tid %d \n", child_struct_ptr->tid);
  // if the status hasn't been set, child hasn't exited
  sema_down (&thread_current()->wait_sema);
  /*
  if (child_struct_ptr->parent_waiting == 0)
  {
    if(DEBUG)
      printf("% s's parent sema-downing\n", child_struct_ptr->child_pointer->name);
    child_struct_ptr->parent_waiting = 1;
    sema_down (&thread_current()->sema);
  }*/
  //printf("child struct pointer 2 %p \n", child_struct_ptr);
  exit_status = child_struct_ptr->exit_status;
  // remove child from child list
  list_remove(&child_struct_ptr->elem);


  //if(DEBUG)
    //printf("exit status of %p: %s is now %d \n", child_struct_ptr->child_pointer, child_struct_ptr->child_pointer->name, child_struct_ptr->exit_status);

  return exit_status;
  // --------------------------------------------------------
}

/* Free the current process's resources. */
void
process_exit (void)
{
  if (DEBUG)
    printf ("process_exit called\n");
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char * arg_array);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  thread_current()->executable = file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      // HERE IS WHERE WORK SHOULD CONTINUE ON EXIT STUFF
      struct thread_child* tcp = get_child_struct_by_child(thread_current());
      if(DEBUG)
        printf("%s failed its load\n", tcp->child_pointer->name);
      tcp->exit_status = SYSCALL_ERROR;
      goto done; 
    }
  // ----------------------------------
  file_deny_write(file);
  // ----------------------------------
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name)){
    if (DEBUG)
    {
      printf("!!SETUP_STACK FAILED\n");
    }
    goto done;
  }

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  success = success;
  /* We arrive here whether the load is successful or not. */
  //  file_close (file);
  // ADDED FOR EXEC-MISSING
  struct thread_child* tcp = get_child_struct_by_child(thread_current());
  if(!success)
    tcp->exit_status = SYSCALL_ERROR;

  tcp->parent_waiting = 0;
  sema_up(&thread_current()->parent->load_sema);

  /*
  if(tcp->parent_waiting){
    if(DEBUG)
      printf("Sema up on %s \n", thread_current()->parent->name);
    tcp->parent_waiting = 0;
    tcp->exit_status = SYSCALL_ERROR;
    sema_up(&thread_current()->parent->load_sema);
  }*/
  
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char * arg_array)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  // added -----------------------------------------------------------------
  // populate stack with arguments in reverse order
  char * my_esp = (char*) *esp;
  int idx=0;//number of chars, including null terminators, in args
  while(idx < PGSIZE) // if every byte is used as an arg
  { 
    //not first
    if (idx)
    {
      if ( !arg_array[idx] && !arg_array[idx-1] ) // if two consecutive zeros
        break;
    }
    ++idx; // otherwise character was in sequence
  }

  int max_idx = idx;

  // avoid corrupting thread page
  // limit arguments to pagesize / 2
  int actual_thread_size = (int)&(thread_current()->magic) + 4 - (int)thread_current();
  if(PGSIZE - actual_thread_size < idx)
    return false;
  
  // populate stack
  for(idx; idx >0; --idx)
  {
    *(my_esp - idx) = arg_array[max_idx - idx];
  }
  my_esp -= max_idx;

  // word alignment by 4
  int remain = 4 - (max_idx % 4);
  int copy_remain = remain;
  for(remain; remain; --remain)
    *(my_esp - remain) = 0;

  my_esp -= copy_remain;
  
  /* skip over 4 0x00 bytes for null entry to array,
     then another 4 bytes to place pointer for next entry */
  my_esp -= 8;
  char ** my_cpp = my_esp;
  my_esp = PHYS_BASE;
  
  // add addresses to compose char* array argv
  int argc=0;
  for(idx=2; idx <= max_idx+1; ++idx)
  {
    // identify the boundaries
    if ( *(my_esp-idx) == NULL )
    {
      *my_cpp = (my_esp-idx+1);
      --my_cpp;
      ++argc;
    }
  }
  *my_cpp = my_cpp+1; // place last address, address of argv[0], on stack
  --my_cpp;

  *((int*)my_cpp) = argc; // place argc on stack

  *esp = (void *) (my_cpp-1);
/*
  // hex dump
  if (DEBUG)
  {
    printf("t:%d STACK HEX DUMP: \n", thread_current()->tid);
    hex_dump(*esp, *esp, PHYS_BASE-*esp, 1);
  }
*/
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
