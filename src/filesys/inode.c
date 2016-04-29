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
#define DEBUG 0

#define ENTRIES 128 //sqrt of number of blocks needed
#define HALF_ENTRY 64
#define DIRECT_PTRS 124
#define ERROR_CODE -1
#define MAX_DATA_SECTORS 16384// 8MB
#define DEBUGMSG(...) if(DEBUG){printf(__VA_ARGS__);}
//-------------------------------------------------------

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
    //block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */

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
};
// FN DECLARATIONS
//-----------------------------------------------------------------
void inode_create_helper(uint32_t inode_blocks, uint32_t data_blocks, char* zeros, struct inode_disk* ram_inode );
void contiguous(uint32_t start, uint32_t inode_blocks, uint32_t data_blocks, char* zeros, struct inode_disk* master_inode );
void write_inode_to_sector(struct inode_disk* ram_inode, block_sector_t idx);

//-----------------------------------------------------------------


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

  ASSERT (pos >= 0);
  //determine which block number
  size_t sectors = pos / BLOCK_SECTOR_SIZE;

  DEBUGMSG("byte_to_sector converting pos %d\n", pos);
  if (sectors < DIRECT_PTRS)
    return inode->data.direct[sectors];
  else if (sectors < (DIRECT_PTRS + ENTRIES)) // else if it requires single indirection
  {
    
    block_sector_t single_indr = inode->data.single_indirection;
    DEBUGMSG("byte_to_sector single table at sector %d\n",single_indr);
    // read the singly indirect table to memory
    struct indirect* indirect_buff = calloc(1, sizeof(struct indirect));
    block_read (fs_device, single_indr, indirect_buff); 
    block_sector_t result = indirect_buff->indices[sectors-DIRECT_PTRS];
    free(indirect_buff);
    return result; // return sector
  } else if (sectors < (DIRECT_PTRS + ENTRIES + ENTRIES*ENTRIES)) {// if indexed by double indirection
    uint32_t dbl_sectors = sectors - (DIRECT_PTRS + ENTRIES);
    uint32_t idx_into_double = dbl_sectors / ENTRIES;
    uint32_t idx_into_single = dbl_sectors % ENTRIES;

    block_sector_t dbl_indr = inode->data.dbl_indirection;
    struct indirect* db_indirect = calloc(1, sizeof(struct indirect));
    block_read (fs_device, dbl_indr, db_indirect);
    block_sector_t single_indr = db_indirect->indices[idx_into_double];
    free(db_indirect);

    struct indirect* indirect_buff = calloc(1, sizeof(struct indirect));
    block_read (fs_device, single_indr, &indirect_buff);
    block_sector_t result = indirect_buff->indices[idx_into_single];
    free(indirect_buff);
    return result; // return sector

  } else { // otherwise the sector offset is too big
    return ERROR_CODE;
  }
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
    static char zeros[BLOCK_SECTOR_SIZE];
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT (length >= 0);

    DEBUGMSG("Creating file of size %d starting at sector %d\n",length, sector);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
    ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    disk_inode = calloc (1, sizeof *disk_inode);
    
    if (disk_inode != NULL)
    {
      size_t data_sectors = bytes_to_sectors (length); // number of sectors to allocate
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      // determine number of required inodes
      
      uint32_t inode_count = 0;
      uint32_t doubly_indr = 0;
      uint32_t singly_indr = 0;
      
      if(data_sectors <= DIRECT_PTRS)
        inode_count = 0; // just this inode is enough
      else if( data_sectors <= (DIRECT_PTRS + ENTRIES))
        inode_count = 1; // need this inode, and a singly indirect table
      else{
        uint32_t remain = data_sectors - (DIRECT_PTRS + ENTRIES);
        doubly_indr = (remain + MAX_DATA_SECTORS - 1) / (MAX_DATA_SECTORS); 
        ASSERT(doubly_indr == 1);// if this fails, max filesize was too big
        singly_indr = (remain + ENTRIES - 1) / ENTRIES;
        inode_count = 1 + doubly_indr + singly_indr;// need this inode, a singly indirect, a doubly indirect, then an additional
      }
      if(length)
        inode_create_helper(inode_count, data_sectors, zeros, disk_inode );
      //write master inode to disk, free memory
      DEBUGMSG("Writing master inode to sector %d\n",sector);
      write_inode_to_sector(disk_inode, sector);
      free(disk_inode);
      success = true;
      DEBUGMSG( "returning true!\n");
      return success;
    }
    else
      DEBUGMSG("OH SHIT NULL INODE_DISK!\n");
    return success;
  }

/*      // two cases: 
          // CASE 1: every inode required fits:
      uint32_t blocks_left = inode_count + data_sectors;   // Total blocks/sectors to write to disk
      static char zeros[BLOCK_SECTOR_SIZE];
      block_sector_t start = 0;
      if ( free_map_allocate (blocks_left, &current_sector) )
      {
          start = current_sector;
          // allocate master in current_sector
          uint32_t direct_blocks = DIRECT_PTRS;
          ++current_sector;
          uint32_t index = 0;
          while(blocks_left && direct_blocks)
          {
            // write zeroes to directly mapped blocks
            block_write (fs_device, current_sector, zeros);
            // update stuff
            disk_inode.direct[index] = current_sector;
            --blocks_left;
            --direct_blocks;
            ++current_sector;
            ++index;
          }
          if(blocks_left){
            //next entry will be singly indirect inode
            disk_inode.single_indirection = current_sector;
            ++current_sector;
            --blocks_left;
            if(blocks_left > ENTRIES)
              disk_inode.doubly_indr = current_sector + ENTRIES;
            // create RAM single_indirection inode struct singly_whatever
          }
          // WRITE MAIN INODE TO DISK, ZERO MEMORY, USE AS SINGLY INDIRECT
          block_write (fs_device, start, disk_inode);
          free (disk_inode);

          struct indirect disk_indr = calloc(1, sizeof indirect);

          uint32_t singly_blocks = ENTRIES;
          index = 0;
          while(blocks_left && singly_blocks) // populate single indirection table
          {
            // fill in de singly indirect thing
            //if(bool) {current_Sector = allocate}
            //else (++current_Sector)
            disk_indr[index] = current_sector;
            
            block_write (fs_device, current_sector, zeros);
            --blocks_left;
            --singly_blocks;
            //++current_sector;
            ++index;
          }
            // update ram
            // write to disk
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
                //update buffer
            }
          success = true; 
        } 
          
          //free (disk_inode);
        }
        return success;
      }*/
/*
  // ---------------------------- added function for getting and setting table entry
  static block_sector_t*
  byte_to_entry ( const struct inode *inode, off_t pos ){
    ASSERT(inode != NULL);
    // inode data length:
    uint32_t data_length = inode->data_length;

    if (pos < DIRECT_PTRS){
      DEBUGMSG("direct_blocks[%d]\n", pos%DIRECT_PTRS);
      return &inode.data.direct[pos%DIRECT_PTRS];
    }
    else if (pos < (DIRECT_PTRS + ENTRIES)) // else if it requires single indirection
    {
      uint32_t idx_dir=(pos-DIRECT_PTRS)%ENTRIES;

      DEBUGMSG("single_indr[%d]\n", idx_dir);

      return = &inode->data.single_indirection[idx_dir];
      // read the singly indirect table to memory
    } else if (pos < (DIRECT_PTRS + ENTRIES + ENTRIES*ENTRIES)) {// if indexed by double indirection
      uint32_t doub_idx = (pos - (DIRECT_PTRS + ENTRIES))/(ENTRIES);
      uint32_t sing_idx = (pos - (DIRECT_PTRS + ENTRIES))%(ENTRIES);
      return &inode->data.dbl_indirection[idx];
      // read double indirect ptr
      // read single indirect ptr
      return NULL; // return sector
    } else { // otherwise the sector offset is too big
      return ERROR_CODE;
    }
  }*/

  void
  inode_create_helper(uint32_t inode_blocks, uint32_t data_blocks, char* zeros, struct inode_disk* ram_inode )
  {
    block_sector_t index = 0;
    DEBUGMSG("allocating %d blocks ", inode_blocks + data_blocks);
    if (free_map_allocate(inode_blocks + data_blocks, &index))
    {
      DEBUGMSG("contiguously starting at %d\n", index);
      contiguous(index, inode_blocks, data_blocks, zeros, ram_inode);
    } else
    {
      DEBUGMSG("NO CONTIGUOUS BLOCK TO PLAY WITH\n");
    }
  }

  void contiguous(uint32_t start, uint32_t inode_blocks, uint32_t data_blocks, char* zeros, struct inode_disk* master_inode )
  {
    // since everything is linear, create master table
    uint32_t data_blocks_left = data_blocks;
    
    uint32_t current_idx=0;// the master will be written to the start
    // direct blocks
    
    DEBUGMSG("Start: %d Inode_blocks: %d data_blocks: %d\n", start, inode_blocks, data_blocks);
    
    uint32_t i = 0;
    for(i; i < DIRECT_PTRS; ++i)
    {
      DEBUGMSG("writing zero data to sector %d\n", start+current_idx);
      //write to disk
      write_inode_to_sector(zeros, start+current_idx);

      // set value in direct entry
      DEBUGMSG("setting in direct[%d]=%d\n", i, start+current_idx);
      master_inode->direct[i]=start+current_idx;

      current_idx++;
      --data_blocks_left;
      if(!data_blocks_left)
        break;
    }

    //direct filled in, calc singly and doubly
    if(data_blocks > DIRECT_PTRS)
      master_inode->single_indirection = start + DIRECT_PTRS;
      if(data_blocks > (DIRECT_PTRS+ENTRIES))
        master_inode->dbl_indirection = master_inode->single_indirection + ENTRIES + 1;

    if(!data_blocks_left){// only direct, and they've all been allocated
        DEBUGMSG("no more data blocks left, quitting early!\n");
        return;
    }

    //128 entries
    struct indirect* indr = (struct indirect*)calloc(1,sizeof(struct indirect));

    DEBUGMSG("sizeof indr %d\n", sizeof(struct indirect));
    ASSERT(sizeof(struct indirect)/4 == ENTRIES);
    block_sector_t single_ptr= start+current_idx;
    ++current_idx;

    //on to first singly

    i = 0;
    for(i; i< ENTRIES; ++i){
      //populate single
      DEBUGMSG("setting sector %d in single[%d]\n", start+current_idx, i);
      write_inode_to_sector(zeros, start+current_idx);
      indr->indices[i]=start+current_idx;
      ++current_idx;
      --data_blocks_left;
      if(!data_blocks_left){
        DEBUGMSG("breaking early whoop!!\n");
        break;
      }
    }
    DEBUGMSG("writing single indr table to disk at sector %d\n", single_ptr);
    //write single to disk
    i=0;
    if (DEBUG)
    {
      while (i < ENTRIES)
      {
        printf("(%d: [%d])",i, indr->indices[i]);
        ++i;
      }
      printf("\n");
    }
    write_inode_to_sector(indr, single_ptr);
    free(indr);

    if(!data_blocks_left){// only direct, and they've all been allocated
        DEBUGMSG("no more data blocks left, quitting early!\n");
        return;
    }

    //doubly
    struct indirect* db_indr= calloc(1,sizeof(struct indirect));
    block_sector_t double_ptr= current_idx;
    ++current_idx;
    i=0;
    for(i; i < ENTRIES*ENTRIES; ++i)
    {
      if(!(i%ENTRIES)){ // if it requires creating a single_indirection
        block_sector_t single_idx = current_idx; // move index forward, this is where single 
        ++current_idx;
        db_indr->indices[i/ENTRIES]=single_idx;
        indr= calloc(1,sizeof(struct indirect));
      }
      DEBUGMSG("db:writing single indr table to disk at sector %d\n", single_ptr);
      write_inode_to_sector(zeros, start+current_idx);

      

      indr->indices[i%ENTRIES] = start+current_idx;
      ++current_idx;
      --data_blocks_left;

      if(!data_blocks_left)
      { // if its an early out, write and quit
        write_inode_to_sector(db_indr, start + double_ptr);
        write_inode_to_sector(indr, start + single_ptr);
        break;
      }
      else if(i%ENTRIES == ENTRIES-1) // after this write single
      {
        write_inode_to_sector(indr, start + single_ptr);
        free(indr);
      } 
    }
    free(indr);
    free(db_indr);
    ASSERT(!data_blocks_left);
  }

  void write_inode_to_sector(struct inode_disk* ram_inode, block_sector_t idx){
    DEBUGMSG("write_inode_to_sector %d\n", idx);
    block_write (fs_device, idx, ram_inode);
  }


/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
   struct inode *
   inode_open (block_sector_t sector)
   {
    //----------------------------------------
    DEBUGMSG("Attempting to open file system inode at sector %d\n", sector);
    //----------------------------------------
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
    DEBUGMSG("inode not already open...");

  /* Allocate memory. */
    inode = malloc (sizeof *inode);
    if (inode == NULL)
      return NULL;
    DEBUGMSG("memory malloc'd...");

  /* Initialize. */
    list_push_front (&open_inodes, &inode->elem);
    DEBUGMSG("pushed to list...\n");
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    DEBUGMSG("attempting to read master sector %d\n", inode->sector);

    block_read (fs_device, inode->sector, &inode->data);
    DEBUGMSG("read block\n");
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
        ASSERT(false);
        /*free_map_release (inode->sector, 1);
        free_map_release (inode->data.start,
          bytes_to_sectors (inode->data.length)); */
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
    //--------------------------------------------------------------------------
    //ASSERT(false);
    //--------------------------------------------------------------------------

    /* A read starting from a position past EOF returns no bytes. */
    if(offset > inode->data.length)
      return 0;

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
    off_t eof = inode->data.length;   //end-of-file in bytes
    if (inode->deny_write_cnt)
      return 0;

    /* Writing at a position past EOF extends the file to the position 
    being written, and any gap between the previous EOF and the start
    of the write must be filled with zeros.  */

    if((offset + size) > eof)
    {
      size_t blocks_needed = (size_t) (((offset + size)/BLOCK_SECTOR_SIZE + 1) - (eof/BLOCK_SECTOR_SIZE + 1));
      DEBUGMSG("blocks_needed: %d\n", blocks_needed);
      block_sector_t index; 
      int i;
      for(i = 0; i < blocks_needed; ++i)
      {
        if(!free_map_allocate(1, &index))   //allocate one sector at a time;
          ASSERT(false); //whole file system full
        
      }
    }
    else 
    {
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
