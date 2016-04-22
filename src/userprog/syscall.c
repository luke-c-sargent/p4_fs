#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
// added includes and definitions -----------------
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"

#define SYSCALL_ERROR -1

struct filesys_sema;

void arg_error_check (void* _esp, int arg_width);
bool is_paged (void* addr);
int get_file_descriptor (char* file_ptr);
struct file * fd_to_file_ptr (int fd);
bool is_user_and_mapped (void* addr);
//-----------------------------------------------
static void syscall_handler (struct intr_frame *);

#define DEBUG 0

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // switch statement differentiates between system calls
  /*
  if (DEBUG)
  {
    printf ("syscall_handle hex dump\n");
    hex_dump ((f->esp), (f->esp), 112, 1);
  }
*/
  if(DEBUG)
    printf("syscall handler\n");
  // validate initial memory access
  int valid_memory=1;

  if (!is_user_vaddr (f->esp))
  {
    if (DEBUG)
      printf ("ptr not virtual address\n");
        
    valid_memory = 0;
  } 
  else if (f->esp == NULL)
  {
    if (DEBUG)
      printf ("nullptr error\n");
    valid_memory = 0;
  }
  else if (!is_paged (f->esp))
  {
      if (DEBUG)
        printf ("ptr not to paged memory\n");
    valid_memory = 0;
  }

  if (!valid_memory){
    f->eax = SYSCALL_ERROR;
    exit (SYSCALL_ERROR);
  }

  int syscall_id = *(int*)(f->esp);
  
  // 
  switch (syscall_id)
  {
    case SYS_HALT:
    {
      if (DEBUG)
        printf ("SYS_HALT signal\n");
      halt ();
      break;
    }
    case SYS_EXIT:
    {
      int exit_code = 0;
      arg_error_check (f->esp, 1);
      exit_code = *(int *)(f->esp + 4);
      if (DEBUG)
        printf ("SYS_EXIT signal with code %d\n", exit_code);
      f->eax = exit_code;
      exit (exit_code);
      break;
    }
    case SYS_EXEC:
    { 
      if (DEBUG){
        printf ("SYS_EXEC signal\n");
        //hex_dump ((f->esp), (f->esp), 80, 1);
      }
      arg_error_check (f->esp,1);
      f->eax = exec (*(char**)(f->esp + 4));
      break;
    }
    case SYS_WAIT:
    { 
      if (DEBUG)
        printf ("SYS_WAIT signal\n");
      arg_error_check (f->esp,1);
      f->eax = wait (*(int *)(f->esp + 4));
      break;
    }
    case SYS_CREATE:
    { 
      if (DEBUG)
        printf ("SYS_CREATE signal\n");
      arg_error_check (f->esp,2);
      f->eax = create (*(char**)(f->esp + 4),*(int *)(f->esp + 8));
      if (DEBUG)
        printf ("EAX set!\n");
      break;
    }
    case SYS_REMOVE:
    { 
      if (DEBUG)
        printf ("SYS_REMOVE signal\n");

      arg_error_check (f->esp,1);
      remove (*(char**)(f->esp + 4));
      break;
    }
    case SYS_OPEN:
    { 
      if (DEBUG)
        printf ("SYS_OPEN signal %p\n", *(char**)(f->esp+4));
      arg_error_check (f->esp,1);
      if (!is_paged(*(char**)(f->esp+4)))
      {
          if (DEBUG)
              printf ("not a user virtual address\n");
          f->eax = SYSCALL_ERROR;
          exit (SYSCALL_ERROR);
      }

      f->eax = open (*(char**)(f->esp+4));
      break;
    }
    case SYS_FILESIZE:
    { 
      if (DEBUG)
        printf ("SYS_FILESIZE signal\n");
      arg_error_check (f->esp,1);
      if (DEBUG)
          printf ("args for filesize checked, sending %d\n", *(int *)(f->esp + 4));
      f->eax = filesize (*(int *)(f->esp + 4));
      //ASSERT(false);
      if (DEBUG)
        printf ("filesize: %d\n", f->eax);
      break;
    }
    case SYS_READ:
    { 
      if (DEBUG)
        printf ("SYS_READ signal\n");
      arg_error_check (f->esp,3);
      int fd = *(int*)(f->esp+4);
      if ( fd == STDOUT_FILENO || fd_to_file_ptr (fd) == NULL)
      {
          if (DEBUG)
              printf ("bad FD\n");
          f->eax = SYSCALL_ERROR;
          exit (SYSCALL_ERROR);
      }

      char * buffer = *(char**)(f->esp+8);
       //check if buffer address is valid
      if (buffer == NULL || !is_user_vaddr (buffer) || !is_paged (buffer))
      {
          if (DEBUG)
              printf ("buffer is bad\n");
          f->eax = SYSCALL_ERROR;
          exit (SYSCALL_ERROR);
      }
     
      f->eax = read (*(int*)(f->esp+4), buffer, *(unsigned*)(f->esp+12));
      break;
    }
    case SYS_WRITE: {
      if (DEBUG)
          printf ("SYS_WRITE signal\n");
      arg_error_check (f->esp,3);
      int fd = *(int*)(f->esp+4);
      char ** cp = (char*)(f->esp+8);
      if (!is_user_and_mapped(*cp))
      {
          if (DEBUG)
            printf ("\n");
          f->eax = SYSCALL_ERROR;
          exit (SYSCALL_ERROR);
      }

      int char_count = *(int*)(f->esp+12);

      f->eax = write (fd, *cp, char_count);
      break;
    }
    case SYS_SEEK:
    { 
      if (DEBUG)
        printf ("SYS_SEEK signal\n");
      arg_error_check (f->esp,2);

      seek (*(int*)(f->esp+4), *(unsigned*)(f->esp+8));
      break;
    }
    case SYS_TELL:
    { 
      if (DEBUG)
        printf ("SYS_TELL signal\n");
      arg_error_check (f->esp,1);
      f->eax = tell(*(int*)(f->esp+4));
      break;
    }
    case SYS_CLOSE:
    { 
      if (DEBUG)
        printf ("SYS_CLOSE signal\n");
      arg_error_check (f->esp,1);
      break;
    }
    default:
      if (DEBUG)
        printf ("ERROR: uncaught exception");
  } // end switch

  if (DEBUG)
    printf ("syscall thread exit...\n");
}
// halt:
// what it does: halts program
// input: void
// returns: void
void halt (void)
{
  shutdown_power_off();
}

// exit:
// what it does: exits user process
// input: exit status
// returns: void
void exit (int status)
{
  //set current program's status to new status
  struct thread_child* child_struct_ptr  = list_entry (thread_current()->child_list_elem, struct thread_child, elem);
  child_struct_ptr->exit_status = status;
  if (DEBUG)
    printf ("child %s exited with status %d\n", child_struct_ptr->child_pointer->name, child_struct_ptr->exit_status);
  printf ("%s: exit(%d)\n", child_struct_ptr->child_pointer->name, child_struct_ptr->exit_status);
  
  /*
  if (child_struct_ptr->parent_waiting)
  {
    if(DEBUG){
      printf("child %s sema'ing up on parent %s\n", child_struct_ptr->child_pointer->name, child_struct_ptr->child_pointer->parent->name);
    }
    child_struct_ptr->parent_waiting = 0;
    sema_up (&child_struct_ptr->child_pointer->parent->sema);
  }*/

  thread_exit();
}

// exec:
// what it does: executes a program in user space
// input: cmd_line - pointer to command line string to be executed
// returns: pid of executed process
pid_t exec (const char *cmd_line)
{
  if(!is_user_and_mapped(cmd_line))
    return SYSCALL_ERROR;
/*
  // hacky test, i dont like it:
  // get file name
  char filename[15]; // max filename size
  int i = 0;
  while(cmd_line[i] != ' '){
    filename[i] = cmd_line[i];
    ++i;
    if(i==14)
      break;
  }
  filename[i]= 0;
  //printf("---%s\n", filename);
  if(open(filename) != SYSCALL_ERROR)
    printf("");//close(cmd_line); // doesntwork yet :C
  else{
    if(DEBUG)
      printf("%s ERROR!!!!!",cmd_line);
    return SYSCALL_ERROR;
  }
  // end hacky test*/

  if (DEBUG)
  {
    printf ("exec'ing %s\n", cmd_line);
  }

  pid_t pid = process_execute (cmd_line);

  if(DEBUG)
    printf("EXEC: sema'ing down on: %s\n",thread_current()->name);
  struct thread_child* child_thread_ptr = get_child_by_tid (pid);
  child_thread_ptr->parent_waiting = 1;

  sema_down (&thread_current()->load_sema);
  if (DEBUG)
  {
    printf ("EXEC: pid is %d, exit status %d\n", pid, child_thread_ptr->exit_status);
  }
  

  //if(DEBUG)
    //printf("EXEC: %s exit status: %d \n", child_thread_ptr->child_pointer->parent->name, child_thread_ptr->exit_status);
  if(child_thread_ptr->exit_status == SYSCALL_ERROR)
    return SYSCALL_ERROR;
  //wait(pid);
  return pid;
}

// wait:
// what it does: waits for a process to finish
// input: pid - identifier of process to wait for
// returns: -1 on failure, exit status on success
int wait (pid_t pid)
{
  if (DEBUG)
    printf ("wait called on PID %d\n", pid);
  // fail cases:
  // -- pid not child:
  // struct thread* child_ptr = get_child_by_tid(pid);

  // if(child_ptr == NULL){
  //   if(DEBUG)
  //     printf("child pointer is bad\n");
  //   return SYSCALL_ERROR;    
  // }

  // if(DEBUG)
  //   printf("thread %p: %s gotten\n", child_ptr, child_ptr->name);

  // struct thread_child* thread_cp = get_child_struct_by_child(child_ptr);

   /* 
  // is already waiting
  printf("OHNOES!!!!!!!!!    %p\n", thread_cp);
  if(thread_cp->parent_waiting != 0){
    if(DEBUG)
      printf("already waiting\n");
    return SYSCALL_ERROR;
  }*/

  // sema down -----
  //sema_down(&thread_current ()-> sema);
  return process_wait (pid);
}
// create:
// what it does: creates a file in the filesystem
// input: file - name of file to create
//        initial_size - starting size of file
// returns: boolean representing success
bool create (const char *file, unsigned initial_size)
{
  if (DEBUG)
    printf ("file ptr: %p valid? %d\n",file, is_paged (file));
  // check for valid file name in memory
  if (file == NULL || !is_paged (file))
    exit (SYSCALL_ERROR);
  if (DEBUG)
    printf ("sema-downing in create...   ");
  // synchronize
  sema_down (&filesys_sema);
  if (DEBUG)
    printf ("   ... success!\n");
  bool created = filesys_create (file, initial_size);

  if (DEBUG)
    printf ("sema up-ing....   ");

  sema_up (&filesys_sema);
  if (DEBUG)
    printf ("   ... success!\n");

  return created;
}
// remove:
// what it does: removes a file from the filesystem
// input: file - name of file to remove
// returns: boolean representing success
bool remove (const char *file)
{
  if (DEBUG)
    printf ("sema-downing in remove...   ");

  sema_down (&filesys_sema);
  if (DEBUG)
    printf ("   ... success!\n");
  // invoke file system kernel functions
  bool removed = filesys_remove (file);

  if (DEBUG)
    printf ("sema up-ing....   ");

  sema_up (&filesys_sema);
  if (DEBUG)
    printf ("   ... success!\n");

  return removed;
}
// open:
// what it does: opens a file in the filesystem
// input: file - name of file to open
// returns: file descriptor
int open (const char *file)
{
  if (DEBUG)
    printf ("sema downing on open\n");
  sema_down (&filesys_sema);
  if (DEBUG)
    printf ("   ... success!\n");
  
  //check if first character is null
  if (file == NULL || *file == NULL){
    sema_up (&filesys_sema);
    return SYSCALL_ERROR;
  }

  struct file* opened_file = filesys_open (file);

  if (opened_file == NULL)
  {
    if (DEBUG)
      printf ("filesystem open error\n");
    sema_up (&filesys_sema);
    return SYSCALL_ERROR;
  }
  // get new page, place file struct in it to avoid deallocation
  struct thread_file* thread_file_ptr = palloc_get_page (PAL_ZERO);
  thread_file_ptr->fd = get_file_descriptor (file);
  thread_file_ptr->file_ptr = opened_file;
  file_descriptors[thread_file_ptr->fd-2] = thread_file_ptr->file_ptr;
  if (DEBUG)
    printf ("gave fd %d to file %s \n", thread_file_ptr->fd, file);
  list_push_back (&thread_current ()->open_files, &thread_file_ptr->elem);
  if (DEBUG)
    printf ("added %p to open file list\n", opened_file);
  if (DEBUG)
    printf ("sema up-ing....   ");

  sema_up (&filesys_sema);
  if (DEBUG)
    printf ("   ... success!\n");

  return thread_file_ptr->fd;
}

// filesize:
// what it does: gets the size of a file in the filesystem
// input: fd - file descriptor
// returns: size in bytes of file
int filesize (int fd)
{
  if (DEBUG)
    printf ("checking fd %d\n", fd);

  // atomic access
  sema_down (&filesys_sema);

  // ensure file descriptor isnt STDIN or STDOUT
  if (fd < 2)
  {
    if (DEBUG)
      printf ("wrong file descriptor for filesize\n");
    return SYSCALL_ERROR;
  }

  struct file* fp = fd_to_file_ptr (fd);

  if (DEBUG)
      printf ("file pointer %p gotten\n", fp);
  // check for valid file
  if (fp == NULL)
  {
    if (DEBUG)
      printf ("file pointer is null\n");
    sema_up (&filesys_sema);
    return SYSCALL_ERROR;
  }
  // invoke kernel call
  int filesize = file_length (fp);
  // release atomic access
  sema_up (&filesys_sema);
  return filesize;
}

// read:
// what it does: reads from a file, places into buffer
// input: fd - file descriptor
//        buffer - address of memory to read into
//        length - number of bytes to read
// returns: number of bytes read
int read (int fd, void *buffer, unsigned length)
{
  if (DEBUG)
    printf ("attempting to read!\n");

  // if the file descriptor is standard in
  if (fd == STDIN_FILENO)
  {
    unsigned * usp = (unsigned*)buffer;
    unsigned i = 0;
    for(i; i < length; ++i)
    {
      usp[i] = input_getc ();
    }
    return length;
  }
  // otherwise read from file system
  sema_down (&filesys_sema);
  struct file* file_ptr = fd_to_file_ptr (fd);
  if (file_ptr == NULL)
  {
    sema_up (&filesys_sema);
    return SYSCALL_ERROR;
  }
  // everything is validated, read the file
  int size = file_read (file_ptr, buffer, length);
  sema_up (&filesys_sema);

  return size;
}
// write:
// what it does: writes to a file
// input: fd - file descriptor
//        buffer - address of data to be written to file
//        size - bytes to write
// returns: bytes written
int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
    if (DEBUG)
      printf ("printing to stdout\n");
    putbuf ((char*)buffer, size);
    return size;
  }
  else 
  {
    // atomically access file system
    if (DEBUG)
    printf ("file descriptor %d\n", fd);

    sema_down (&filesys_sema);
    struct file* file_ptr = fd_to_file_ptr (fd);
    if (DEBUG)
      printf ("fp gotten == %p\n", file_ptr);
    if (file_ptr == NULL)
    {
      if (DEBUG)
        printf ("file descriptor is not matched to fd\n");
      sema_up (&filesys_sema);
      return SYSCALL_ERROR;
    }
    // everything validated, write
    int written = file_write (file_ptr, buffer, size);
    sema_up (&filesys_sema);
    if (DEBUG)
      printf ("returning %d written bytes\n", written);
    return written;
  }
}

// seek:
// what it does: changes next byte to be read/written
// input: fd - file descriptor
//        position - location to change to
// returns: void
void seek (int fd, unsigned position)
{
	struct file* file_ptr = fd_to_file_ptr (fd);

	if (file_ptr == NULL)
	  exit(SYSCALL_ERROR);
	sema_down(&filesys_sema);
	file_seek (file_ptr, position);
	sema_up(&filesys_sema);
}
// tell:
// what it does: gets position of next byte in byte stream
// input: fd - file descriptor
// returns: position of next byte
unsigned tell (int fd)
{
	struct file* file_ptr = fd_to_file_ptr (fd);

	if (file_ptr == NULL)
	  exit(SYSCALL_ERROR);
	sema_down(&filesys_sema);
	unsigned rval = file_tell (file_ptr);
	sema_up(&filesys_sema);
  return rval;
}
// close:
// what it does: closes an open file
// input: fd - file descriptor
// returns: void
void close (int fd)
{
	// unimplemented
    //ASSERT(false); // to speed up failure
  file_close(fd_to_file_ptr(fd));
}

// HELPER FUNCTIONS---------------------------

// arg_error_check:
// what it does: ensures the arguments given are in user space
// input: _esp - stack pointer
//        arg_width - how far the arguments go into the stack
// returns: void
void arg_error_check (void* _esp, int arg_width)
{
  if (!is_user_vaddr (_esp+4*arg_width))
  {
    if (DEBUG)
      printf ("memory error! arg_width will leave user space\n");
    exit (SYSCALL_ERROR);
  }
}
// is_paged:
// what it does: checks if a memory address is currently paged
// input: addr - address to check
// returns: result of check-- is it in page directory?
bool is_paged (void* addr)
{
  return !(pagedir_get_page (thread_current ()->pagedir,addr) == NULL);
}
// get_file_descriptor:
// what it does: gets a file descriptor from a file pointer
// input: file_ptr - pointer to the actual file
// returns: file descriptor
int get_file_descriptor (char* file_ptr)
{
  int i=0;
  for(i; i < 128; ++i)
  {
    if (file_descriptors[i] == NULL)
      {
        file_descriptors[i] = file_ptr;
          return i+2;
      }
  }

  return 0;
}
// fd_to_file_ptr:
// what it does: converts file descriptor to file pointer
// input: fd - file descriptor
// returns: pointer to file
struct file * fd_to_file_ptr (int fd)
{
  if (fd < 2 || fd > 129)
    return NULL;
  struct file * result = file_descriptors[fd-2];

  return result;
}
// is_user_mapped:
// what it does: checks if an address is paged, and is in user space
// input: addr - address to check
// returns: if it passed the check
bool is_user_and_mapped (void* addr)
{
  return is_user_vaddr (addr) && is_paged (addr);
}