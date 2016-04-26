#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//-------------------------------------------------------
#define ENTRIES 128 //sqrt of number of blocks needed
#define HALF_ENTRY 64
#define DIRECT_PTRS 124
#define ERROR_CODE -1
#define MAX_DATA_SECTORS 16384// 8MB

//-------------------------------------------------------

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
    //block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    //uint32_t unused[125];               /* Not used. */
    block_sector_t  direct[DIRECT_PTRS];  // 124 direct pointers
    // will equal block sector size bytes 
    block_sector_t single_indirection;      /* sector where single indirection block lives */
    block_sector_t dbl_indirection;         /* sector where double indirection block lives */
    //total number of direct pointers will be entries*entries
};

  //------------------------------------------------------
struct indirect
{
    // will equal block sector size bytes
  block_sector_t indices[ENTRIES];
};

struct dbl_indirect
{
    // will equal block sector size bytes
  block_sector_t indices[ENTRIES]; 
}
  //------------------------------------------------------

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
{
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
   static block_sector_t
   byte_to_sector (const struct inode *inode, off_t pos) 
   {
    ASSERT (inode != NULL);
  /*if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1; */
  //-----------------------------------------------------------
    ASSERT (pos >= 0);
    //determine which block number
  size_t sectors = pos / BLOCK_SECTOR_SIZE;

  if (sectors < DIRECT_PTRS)
    return inode->data.direct[sectors];
  else if (sectors < (DIRECT_PTRS + ENTRIES)) // else if it requires single indirection
  {
    block_sector_t single_indr = inode->data.single_indirection;
    // read the singly indirect table to memory
    return NULL; // return sector
  } else if (sectors < (DIRECT_PTRS + ENTRIES + ENTRIES*ENTRIES)) {// if indexed by double indirection
    block_sector_t dbl_indr = inode->data.dbl_indirection;
    // read double indirect ptr
    // read single indirect ptr
    return NULL; // return sector
  } else { // otherwise the sector offset is too big
    return ERROR_CODE;
  }

    if(result == NULL) // if the entry was empty
      return ERROR_CODE;

    return result;
  //-----------------------------------------------------------
  }

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
  static struct list open_inodes;

/* Initializes the inode module. */
  void
  inode_init (void) 
  {
    list_init (&open_inodes);
  }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
   bool
   inode_create (block_sector_t sector, off_t length)
   {
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
    ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    disk_inode = calloc (1, sizeof *disk_inode);
    
    if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length); // number of sectors to allocate
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      // determine number of required inodes
      uint32_t inode_count = 0;
      uint32_t doubly_indr = 0;
      uint32_t singly_indr = 0;
      if(sectors <= DIRECT_PTRS)
        inode_count = 1; // just this inode is enough
      else if( sectors <= (DIRECT_PTRS + ENTRIES))
        inode_count = 2; // need this inode, and a singly indirect table
      else{
        uint32_t remain = sectors - (DIRECT_PTRS + ENTRIES);
        doubly_indr = (remain + MAX_DATA_SECTORS - 1) / (MAX_DATA_SECTORS); // this never happens, max file size is 8MB
        ASSERT(doubly_indr == 1);
        singly_indr = (remain + ENTRIES -1) / ENTRIES;
        inode_count = 2 + doubly_indr + singly_indr;// need this inode, a singly indirect, a doubly indirect, then an additional
      }
      block_sector_t start_sector;
      // two cases: 
          // CASE 1: every inode required fits:
      if ( free_map_allocate (inode_count + sectors, &start_sector) )
      {
          // allocate master
          
          // allocate 124 direct data blocks
          // allocate singly indirect inode
          // allocate 128 direct data blocks
          // allocate doubly
          // allocate as many (singly block + 128 data blocks) as necessary
      }
      else 
      {
        // do it incrementally in a for loop
      }
      // 


      /*if (free_map_allocate (sectors, &start_sector))
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->start + i, zeros);
            }
          success = true; 
        } */
          free (disk_inode);
        }
        return success;
      }

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
   struct inode *
   inode_open (block_sector_t sector)
   {
    struct list_elem *e;
    struct inode *inode;

  /* Check whether this inode is already open. */
    for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
     e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
      {
        inode_reopen (inode);
        return inode; 
      }
    }

  /* Allocate memory. */
    inode = malloc (sizeof *inode);
    if (inode == NULL)
      return NULL;

  /* Initialize. */
    list_push_front (&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    block_read (fs_device, inode->sector, &inode->data);
    return inode;
  }

/* Reopens and returns INODE. */
  struct inode *
  inode_reopen (struct inode *inode)
  {
    if (inode != NULL)
      inode->open_cnt++;
    return inode;
  }

/* Returns INODE's inode number. */
  block_sector_t
  inode_get_inumber (const struct inode *inode)
  {
    return inode->sector;
  }

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
   void
   inode_close (struct inode *inode) 
   {
  /* Ignore null pointer. */
    if (inode == NULL)
      return;

  /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed) 
      {
        free_map_release (inode->sector, 1);
        free_map_release (inode->data.start,
          bytes_to_sectors (inode->data.length)); 
      }

      free (inode); 
    }
  }

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
  void
  inode_remove (struct inode *inode) 
  {
    ASSERT (inode != NULL);
    inode->removed = true;
  }

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
   off_t
   inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
   {
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
      {
          /* Read full sector directly into caller's buffer. */
        block_read (fs_device, sector_idx, buffer + bytes_read);
      }
      else 
      {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
        if (bounce == NULL) 
        {
          bounce = malloc (BLOCK_SECTOR_SIZE);
          if (bounce == NULL)
            break;
        }
        block_read (fs_device, sector_idx, bounce);
        memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
      }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
    free (bounce);

    return bytes_read;
  }

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
   off_t
   inode_write_at (struct inode *inode, const void *buffer_, off_t size,
    off_t offset) 
   {
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;

    if (inode->deny_write_cnt)
      return 0;

    while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
      {
          /* Write full sector directly to disk. */
        block_write (fs_device, sector_idx, buffer + bytes_written);
      }
      else 
      {
          /* We need a bounce buffer. */
        if (bounce == NULL) 
        {
          bounce = malloc (BLOCK_SECTOR_SIZE);
          if (bounce == NULL)
            break;
        }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
             if (sector_ofs > 0 || chunk_size < sector_left) 
              block_read (fs_device, sector_idx, bounce);
            else
              memset (bounce, 0, BLOCK_SECTOR_SIZE);
            memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
            block_write (fs_device, sector_idx, bounce);
          }

      /* Advance. */
          size -= chunk_size;
          offset += chunk_size;
          bytes_written += chunk_size;
        }
        free (bounce);

        return bytes_written;
      }

/* Disables writes to INODE.
   May be called at most once per inode opener. */
      void
      inode_deny_write (struct inode *inode) 
      {
        inode->deny_write_cnt++;
        ASSERT (inode->deny_write_cnt <= inode->open_cnt);
      }

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
   void
   inode_allow_write (struct inode *inode) 
   {
    ASSERT (inode->deny_write_cnt > 0);
    ASSERT (inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
  }

/* Returns the length, in bytes, of INODE's data. */
  off_t
  inode_length (const struct inode *inode)
  {
    return inode->data.length;
  }
