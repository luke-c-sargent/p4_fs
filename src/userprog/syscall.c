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
#include "filesys/inode.h"
#include "filesys/directory.h"


#define SYSCALL_ERROR -1
#define DEBUG 0

struct filesys_sema;

void arg_error_check (void* _esp, int arg_width);
bool is_paged (void* addr);
int get_file_descriptor (char* file_ptr);
struct file * fd_to_file_ptr (int fd);
bool is_user_and_mapped (void* addr);
uint32_t arg_array_count(char** aa);

/* filesys: directory system calls */
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
char** parse_path(const char* in);

bool is_absolute(const char* path);
block_sector_t navigate_path(uint32_t args, char** parse_array, block_sector_t temp_dir);
//-----------------------------------------------
static void syscall_handler (struct intr_frame *);
#define DEBUGMSG(...) if(DEBUG){printf(__VA_ARGS__);}

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
      f->eax = tell (*(int*)(f->esp+4));
      break;
    }
    case SYS_CLOSE:
    { 
      if (DEBUG)
        printf ("SYS_CLOSE signal\n");
      arg_error_check (f->esp,1);
      break;
    }
    case SYS_CHDIR:                 /* Change the current directory. */
    {
      if (DEBUG)
        printf ("SYS_CHDIR signal\n");
      arg_error_check (f->esp,1);
      f->eax = chdir (*(char**)(f->esp + 4));
      break;
    }                  
    case SYS_MKDIR:                  /* Create a directory. */
    {
      if (DEBUG)
        printf ("SYS_MKDIR signal\n");
      arg_error_check (f->esp,1);
      f->eax = mkdir (*(char**)(f->esp + 4));
      break;
    }
    case SYS_READDIR:                /* Reads a directory entry. */
    {
      if (DEBUG)
        printf ("SYS_READDIR signal\n");
      arg_error_check (f->esp,2);

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

      f->eax = readdir (fd, buffer);
      break;
    }
    case SYS_ISDIR:                  /* Tests if a fd represents a directory. */
    {
      if (DEBUG)
        printf ("SYS_ISDIR signal\n");
      arg_error_check (f->esp,1);
      f->eax = isdir (*(int*)(f->esp+4));
      break;
    }
    case SYS_INUMBER:                /* Returns the inode number for a fd. */
    {
      if (DEBUG)
        printf ("SYS_INUMBER signal\n");
      arg_error_check (f->esp,1);
      f->eax = inumber (*(int*)(f->esp+4));
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
  DEBUGMSG("EXEC\n");
  if(!is_user_and_mapped(cmd_line))
    return SYSCALL_ERROR;

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

  return process_wait (pid);
}
// create:
// what it does: creates a file in the filesystem
// input: file - name of file to create
//        initial_size - starting size of file
// returns: boolean representing success
bool create (const char *file, unsigned initial_size)
{
  DEBUGMSG("CREATE\n");
  // check for valid file name in memory
  if (file == NULL || !is_paged (file))
    exit (SYSCALL_ERROR);

  if(!(*file))
    return false;
  sema_down (&filesys_sema);
  struct thread* curr_thread = thread_current();
  
  // old directory
  //struct dir* old_dir = sector_to_dir(curr_thread->cwd_i);
  block_sector_t old_cwd_i = curr_thread->cwd_i;
  DEBUGMSG("CREATE CWD_I: %d\n", old_cwd_i);
  //struct dir* temp_dir = old_dir;
  if(is_absolute(file))
   curr_thread->cwd_i = ROOT_DIR_SECTOR;

 // set new cwd
  char** parse_array = parse_path(file);
  uint32_t args = 0;
  if(parse_array)
    args = arg_array_count(parse_array);

  if(args>1)
  {
    {
      curr_thread->cwd_i =  navigate_path( args, parse_array, curr_thread->cwd_i);
      DEBUGMSG("CREATE NEW CWD %d\n", curr_thread->cwd_i);
    }
    DEBUGMSG("CREATING FILE %s at sector %d \n", parse_array[args-1], curr_thread->cwd_i);
    if(!filesys_create(parse_array[args-1], initial_size, false)){
      DEBUGMSG("create filesys_create failed\n");
      curr_thread->cwd_i = old_cwd_i;
      sema_up (&filesys_sema);
      free_parse_path(parse_array);
      return false;
    }
    curr_thread->cwd_i = old_cwd_i;
    sema_up (&filesys_sema);
    free_parse_path(parse_array);
    return true;
  }
  else 
  {
    if (DEBUG)
    printf ("file ptr: %p valid? %d\n",file, is_paged (file));
    if (DEBUG)
      printf ("sema-downing in create...   ");
    // synchronize
    // sema_down (&filesys_sema);
    if (DEBUG)
      printf ("   ... success!\n");
    bool created = filesys_create (file, initial_size, false);

    if (DEBUG)
      printf ("sema up-ing....   ");

    sema_up (&filesys_sema);
    if (DEBUG)
      printf ("   ... success!\n");
    free_parse_path(parse_array);
    return created;
  }

}
// remove:
// what it does: removes a file from the filesystem
// input: file - name of file to remove
// returns: boolean representing success
bool remove (const char *file)
{
  DEBUGMSG("REMOVE\n");
  sema_down (&filesys_sema);
  // -----------------------------------------------------
  struct thread* curr_thread = thread_current();
  
 // old directory
  block_sector_t old_cwd_i = curr_thread->cwd_i;
  DEBUGMSG("REMOVE CWD_I: %d\n", old_cwd_i);

  if(is_absolute(file))
   curr_thread->cwd_i = ROOT_DIR_SECTOR;

 // set new cwd
  char** parse_array = parse_path(file);
  uint32_t args = 0;
  if(parse_array)
    args = arg_array_count(parse_array);

  if(args>1)
  {
    
    curr_thread->cwd_i =  navigate_path( args, parse_array, curr_thread->cwd_i);
    DEBUGMSG("REMOVE NEW CWD %d\n", curr_thread->cwd_i);
    
    DEBUGMSG("REMOVING FILE %s at sector %d \n", parse_array[args-1], curr_thread->cwd_i);
    if(!filesys_remove(parse_array[args-1]))
    {
      DEBUGMSG("remove filesys_create failed\n");
      curr_thread->cwd_i = old_cwd_i;
      sema_up (&filesys_sema);
      free_parse_path (parse_array);
      return false;
    }
    curr_thread->cwd_i = old_cwd_i;
    sema_up (&filesys_sema);
    free_parse_path (parse_array);
    return true;
  }
  // ------------------------------------------------------
  //else
  if (DEBUG)
    printf ("sema-downing in remove...   ");
  // sema_down (&filesys_sema);
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
  //--------------------------------------------------
  struct thread* curr_thread = thread_current();
  struct file* opened_file = 0;
 // old directory
  block_sector_t old_cwd_i = curr_thread->cwd_i;
  DEBUGMSG("OPEN CWD_I: %d\n", old_cwd_i);

  if(is_absolute(file))
   curr_thread->cwd_i = ROOT_DIR_SECTOR;

 // set new cwd
  char** parse_array = parse_path(file);
  uint32_t args = 0;
  if(parse_array)
    args = arg_array_count(parse_array);

  if(args>1)
  {
    {
      curr_thread->cwd_i =  navigate_path( args, parse_array, curr_thread->cwd_i);
      DEBUGMSG("OPEN NEW CWD %d\n", curr_thread->cwd_i);
    }
    DEBUGMSG("OPEN FILE %s at sector %d \n", parse_array[args-1], curr_thread->cwd_i);
    opened_file = filesys_open(parse_array[args-1]);
    if(!opened_file){
      DEBUGMSG("create filesys_create failed\n");
      curr_thread->cwd_i = old_cwd_i;
      sema_up (&filesys_sema);
      free_parse_path(parse_array);
      return false;
    }
    curr_thread->cwd_i = old_cwd_i;
    free_parse_path(parse_array);
  }
  else
    opened_file = filesys_open (file);

  //--------------------------------------------------

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
  DEBUGMSG("WRITE\n");
  if (fd == STDOUT_FILENO)
  {
    if (DEBUG)
      printf ("printing to stdout\n");
    putbuf ((char*)buffer, size);
    return size;
  }
  else 
  {
    if(isdir (fd))
      return SYSCALL_ERROR;
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
    // if(!written)
    //   return SYSCALL_ERROR;
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
	DEBUGMSG("SEEK\n");
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
  DEBUGMSG("TELL\n");
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
  DEBUGMSG("CLOSE\n");
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

// Changes the current working directory of the process to dir,
// which may be relative or absolute. Returns true if successful,
// false on failure.

bool chdir (const char *dir)
{
  DEBUGMSG("CHDIR\n");
  if (dir == NULL || !is_paged (dir))
    exit (SYSCALL_ERROR);

  if(!(*dir))
    return false;
  sema_down (&filesys_sema);
  struct thread* curr_thread = thread_current();
  char** parse_array = parse_path(dir);
 // old directory
  block_sector_t old_cwd_i = curr_thread->cwd_i;

  // struct inode* temp_inode;
  if(is_absolute(dir))
   curr_thread->cwd_i = ROOT_DIR_SECTOR;

 // set new cwd
  uint32_t args = 0;
  if(parse_array)
    args = arg_array_count(parse_array);

  DEBUGMSG("chdir: Before if(args>0)\n");
  DEBUGMSG("CHDIR OLD CWD = %d\n", curr_thread->cwd_i);
  if(args>0)
  {
    curr_thread->cwd_i = navigate_path( args+1, parse_array, curr_thread->cwd_i);
    DEBUGMSG("CHDIR NEW CWD = %d\n", curr_thread->cwd_i);
    if(curr_thread->cwd_i == NULL)
    {
      curr_thread->cwd_i = old_cwd_i;
      sema_up (&filesys_sema);
      free_parse_path(parse_array);
      return false;
    }
    sema_up (&filesys_sema);
    free_parse_path(parse_array);
    return true;
  }
  sema_up (&filesys_sema);
  free_parse_path(parse_array);
  return false;
}
/* mkdir
  what it does: makes a directory
  what it takes: the name of the directory with path
  what it returns: boolean representing success
*/
bool mkdir (const char *dir)
{
  DEBUGMSG("MKDIR\n");
  if (dir == NULL || !is_paged (dir))
    exit (SYSCALL_ERROR);

  if(!(*dir))
    return false;
  sema_down (&filesys_sema);
  struct thread* curr_thread = thread_current ();
  char** parse_array = parse_path (dir);
 // old directory
  block_sector_t old_cwd_i = curr_thread->cwd_i;
  DEBUGMSG("MKDIR CWD: %d\n", old_cwd_i);
  //Checking if absolute or relative path
  if(is_absolute(dir))
   curr_thread->cwd_i = ROOT_DIR_SECTOR;

 // Counts number of directories to transfer in path
  uint32_t args = 0;
  if(parse_array)
    args = arg_array_count(parse_array);

  if(args>1)
  {
    curr_thread->cwd_i = navigate_path( args, parse_array, curr_thread->cwd_i);
    DEBUGMSG("MKDIR NEW CWD: %d\n", curr_thread->cwd_i);
  }
  if(!filesys_create(parse_array[args-1], 0, true))
  {
    DEBUGMSG("mkdir filesys_create failed\n");
    curr_thread->cwd_i = old_cwd_i;
    sema_up (&filesys_sema);
    free_parse_path (parse_array);
    return false;
  }
  if(old_cwd_i)
    curr_thread->cwd_i = old_cwd_i;
  sema_up (&filesys_sema);
  free_parse_path (parse_array);
  return true;
}
/* readdir
  what it does: Reads a directory entry from file descriptor fd, which must represent 
    a directory. If successful, stores the null-terminated file name in name, which must 
    have room for READDIR_MAX_LEN + 1 bytes, and returns true. If no entries are left in 
    the directory, returns false.
  what it takes: file descriptor, name buffer
  what it returns: a bool that represents success
*/
bool readdir (int fd, char *name)
{
  DEBUGMSG("READDIR\n");
  if (name == NULL || !is_paged (name))
    exit (SYSCALL_ERROR);

  ASSERT (false);
  return false;
}

/* isdir
  what it does: checks if a file is a directory
  what it takes: file descriptor
  what it returns: a bool representing success
*/
bool isdir (int fd)
{
  sema_down (&filesys_sema);
  struct file *temp_file = fd_to_file_ptr(fd);
  if(temp_file == NULL){
    sema_up (&filesys_sema);
    exit(SYSCALL_ERROR);
  }
  struct inode *temp_inode = file_get_inode(temp_file);
  if(temp_inode == NULL){
    sema_up (&filesys_sema);
    exit(SYSCALL_ERROR);
  }
  int result = inode_get_is_dir (temp_inode);
  sema_up (&filesys_sema);
  return (bool) result;
}

/* inumber
  what it does: gets an inode number from a file descriptor
  what it takes: file descriptor
  what it returns: a bool representing success
*/
int inumber (int fd)
{
  sema_down (&filesys_sema);
  DEBUGMSG("1\n");
  struct file *temp_file = fd_to_file_ptr(fd);
  
  if(temp_file == NULL) {
    sema_up (&filesys_sema);
    exit(SYSCALL_ERROR);
  }
  DEBUGMSG("2\n");
  struct inode *temp_inode = file_get_inode(temp_file);
  if(temp_inode == NULL){
    sema_up (&filesys_sema);
    exit(SYSCALL_ERROR);
  }
  DEBUGMSG("3\n");
  block_sector_t result = inode_get_inumber(temp_inode);
  sema_up (&filesys_sema);
  return (int) result;
}

// returns a parsed path that ends in two null values.
/* examples: 
  /a/b/c-> a null b null c null null
  foo/bar/wat = foo null bar null wat null null

  double nulls are used to detect end of arguments
*/
char** parse_path(const char* in)
{ 
  
  if(in[0]==NULL)
  {
    DEBUGMSG("in[0] is null\n");
    return NULL;
  }

  size_t pathsize = strlen(in);
  char* out;
  // FREE THE BELOW
  out = calloc (1, pathsize+2); // REMEMBER TO FREE
  // FREE THE ABOVE
  strlcpy(out, in, pathsize+2);

  char *token, *save_ptr;
  int indexer = 0;
  int length;
  uint32_t arg_count=0;
  for (token = strtok_r (out, "/", &save_ptr); token != NULL;
    token = strtok_r (NULL, "/", &save_ptr))
  {
    length = strlen(token);

    strlcpy (out + indexer, token, length+1);
    ++arg_count;
    indexer += length + 1;
  }
  if(DEBUG){hex_dump(out,out,16,1);}

  char** arg_array = (char**)calloc(1, sizeof(char*)*(arg_count+1)); 
  int i = 1;
  int index=0;
  arg_array[0] = out;
  DEBUGMSG("arg_count=%d\n", arg_count);
  for( i; i < arg_count; ++i )
  {
    DEBUGMSG("i= %d\n",i);
    while(out[index]!=NULL)
    {
      DEBUGMSG("index=%d\n",index);
      index++;
    }
    DEBUGMSG("zero at %d\n",index);
    index++;
    arg_array[i]=&out[index];
    if(DEBUG){printf("!!!%s\n",arg_array[i]);}
  }
  if(DEBUG)
  {
    i=0;
    while(arg_array[i])
    {
      printf("aa[%d]=%s\n", i, arg_array[i]);
      ++i;
    }
  }
  return arg_array;
}

/* free_parse_path
what it does: frees allocated memory for argument parsing
what it takes: parsed argument
what it returns: nothing
*/
void free_parse_path(char** aa)
{
  free(aa[0]);
  free(aa);
}

/* arg_array_count
what it does: counts arguments
what it takes: parsed argument
what it returns: argument count
*/
uint32_t arg_array_count(char** aa)
{
  uint32_t i=0;
  uint32_t count=0;
  while(aa[i]){
    ++count;
    ++i;
  }
  DEBUGMSG("arg_array count = %d\n", count);
  return count;
}

/* is_absolute
what it does: checks if path is absolute
what it takes: a path
what it returns: boolean representing absolute path or not
*/
bool 
is_absolute(const char* path)
{
  return path[0] == '/';
}

/* navigate_path
what it does: navigates a parsed path
what it takes: number of arguments, parsed array, and sector to start navigation from
what it returns: block sector where the requested directory lives
*/
block_sector_t 
navigate_path(uint32_t args, char** parse_array, block_sector_t dir_sector)
{
  int idx=0;
  while(parse_array[idx])
  {
    DEBUGMSG ("ARGS: %s\n", parse_array[idx]);
    ++idx;
  }
  DEBUGMSG("~~~~~~~~~~~~~~~~~~~~~~~~\nNAVIGATE: from %d ", dir_sector);
  struct inode** temp_inode;
  uint32_t directory_count = args -1;
  uint32_t i = 0;
  struct dir* temp_dir = sector_to_dir(dir_sector);
  for(i; i < directory_count; ++i)
  {

    if(!dir_lookup(temp_dir, parse_array[i], &temp_inode))
    {
      return NULL;
    }
    temp_dir = dir_open (temp_inode);
    DEBUGMSG("to %d ", dir_to_sector(temp_dir));
  }
  DEBUGMSG("\n");
  if(!temp_dir)
  {
    return NULL;
  }
  return dir_to_sector(temp_dir);
}

/* sector_to_dir
what it does: translates a sector number to a directory pointer
what it takes: a sector number
what it returns: a directory pointer
*/
struct dir* sector_to_dir(block_sector_t in)
{
  return dir_open(inode_open(in));
}

/* dir_to_sector
what it does: translates a directory pointer to a a sector number
what it takes: a directory pointer
what it returns: a sector number
*/
block_sector_t dir_to_sector(struct dir* dir)
{
  return inode_get_inumber(dir_get_inode(dir));
}