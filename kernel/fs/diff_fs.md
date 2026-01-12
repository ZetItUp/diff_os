# DifferentOS Filesystem 
### DiffFS - A tiny filesystem for the OS DifferentOS

**Author:** ZetItUp
**Date:** 2026/01/12

---

### Table of Contents
1. [Introduction](#introduction)
2. [Disk Layout](#disk-layout)
3. [Entry Types](#entry-types)

---

### Introduction

This document describes the design and implementation of DiffFS.
DiffFS is a simple, block-based filesystem for the DifferentOS operating system. It is designed to be deterministic, easy to understand, and easy to extend. The filesystem is not feature complete or POSIX-compliant. 

What the goal with the filesystem is:
- Clear on-disk layout
- Predictable behavior
- Minimal implementation complexity
- Forward compatibility

The filesystem uses a fixed-size superblock, a linear file table for metadata, and contiguous block allocation for file data. Files and directories are represented through file table entries, with hierarchical structure using parent identifiers.

As of writing the filesystem does not allow multi-task writing/reading. It does not use a journaling system, and it lacks permission control, access control or any crash recovery.

This document explains the filesystem layout, metadata structures, path resolutions and supported filesystem operations.

---

### Disk Layout

DiffFS organizes the disk into sectors of 512 bytes each. The first sectors contains metadata-structures describing the filesystems content.

##### Structure Overview

| Region              | Start Sector | Size (sectors)                | Notes                          |
|---------------------|--------------|-------------------------------|--------------------------------|
| Superblock          | 0            | 1                             | 512 bytes                      |
| File Table          | N            | file_table_size               | File and directory metadata    |
| File Table Bitmap   | M            | file_table_bitmap_size        | Allocation map for file table  |
| Sector Bitmap       | J            | sector_bitmap_size            | Data block allocation map      |
| File Data           | K            | Remaining                     | File contents                  |



##### Superblock

The superblock is always in sector 0 and has a size of 512 bytes. It contains the filesystems metadata and pointers to other structures.

| Offset | Size (bytes) | Field                     | Description                                   |
|--------|--------------|---------------------------|-----------------------------------------------|
| 0x00   | 4            | magic                     | Magic number: 0x44494646 ("DIFF")              |
| 0x04   | 4            | version                   | Filesystem version                            |
| 0x08   | 4            | total_sectors             | Total number of sectors on the disk           |
| 0x0C   | 4            | file_table_sector         | Starting sector of the File Table             |
| 0x10   | 4            | file_table_size           | Number of sectors used by the File Table      |
| 0x14   | 4            | file_table_bitmap_sector  | Starting sector of the File Table Bitmap      |
| 0x18   | 4            | file_table_bitmap_size    | Number of sectors for the File Table Bitmap   |
| 0x1C   | 4            | sector_bitmap_sector      | Starting sector of the Sector Bitmap          |
| 0x20   | 4            | sector_bitmap_size        | Number of sectors for the Sector Bitmap       |
| 0x24   | 4            | root_dir_id               | Entry ID of the root directory                |
| 0x28   | 4            | feature_flags             | Feature flags (e.g. symbolic link support)    |
| 0x2C   | 480          | reserved                  | Reserved for future use                       |

#### Feature Flags

- **DIFF_FEATURE_SYMLINKS** (`0x00000001`)  
  Enables support for symbolic links.

#### File Table
File Table contains all file and directory entries (<code>FileEntry</code>). The table supports a maximum of 256 entries (<code>MAX_FILES</code>).
File Table is stored on disk starting from <code>file_table_sector</code> and spans <code>file_table_size</code> sectors.

#### File Table Bitmap
Bitmap which keeps track of which <code>FileEntry</code>-posts are available:
- Bit 0 = Entry 0 is taken
- Bit 1 = Entry 1 is taken
- and so on

Each byte represents 8 entries.

#### Sector Bitmap
Bitmap which keeps track of the sectors that are allocated for file data:
- Bit N = 1: Sector N is busy
- Bit N = 0: Sector N is free
Size is depending on <code>total_sectors</code>

#### File Data
The remaining sectors are used for actual file data. Files are allocated in contiguous blocks of sectors, where <code>start_sector</code> and <code>sector_count</code> in the <code>FileEntry</code> structure point to the file's data.

#### FileEntry Structure
Each file, directory or symbolic link in the filesystem is represented by a <code>FileEntry</code> structure stored in the File Table.

| Offset | Size (bytes) | Field               | Description                                 |
|--------|--------------|---------------------|---------------------------------------------|
| 0x000  | 4            | entry_id            | Unique identifier for this entry (1-based)  |
| 0x004  | 4            | parent_id           | Entry ID of the parent directory            |
| 0x008  | 4            | type                | Entry type (see below)                      |
| 0x00C  | 256          | filename            | Null-terminated filename                    |
| 0x10C  | 48           | data                | Union: file data or symlink target          |
| 0x13C  | 4            | created_timestamp   | Creation timestamp                          |
| 0x140  | 4            | modified_timestamp  | Last modification timestamp                 |
| 0x144  | 20           | reserved            | Reserved for future use                     |

**Total Size:** 344 bytes per entry.

#### Entry Type Values
The <code>type</code> field indicates what kind of entry this is:
| Value | Name              | Description           |
|-------|-------------------|-----------------------|
| 0     | ENTRY_TYPE_INVALID| Unused / deleted entry|
| 1     | ENTRY_TYPE_FILE   | Regular file          |
| 2     | ENTRY_TYPE_DIR    | Directory             |
| 3     | ENTRY_TYPE_SYMLINK| Symbolic link         |

#### Data Union
The <code>data</code> field is a union that holds different information depending on the entry type:

#### For files and directories (`ENTRY_TYPE_FILE`, `ENTRY_TYPE_DIR`)

| Offset | Size (bytes) | Field            | Description                               |
|--------|--------------|------------------|-------------------------------------------|
| 0x00   | 4            | start_sector     | First sector of file data on disk         |
| 0x04   | 4            | sector_count     | Number of contiguous sectors allocated    |
| 0x08   | 4            | file_size_bytes  | Actual file size in bytes                 |
#### For symbolic links (`ENTRY_TYPE_SYMLINK`)

| Offset | Size (bytes) | Field  | Description                      |
|--------|--------------|--------|----------------------------------|
| 0x00   | 48           | target | Null-terminated target path      |

#### Parent-Child Relationships
Directories form a tree structure through the <code>parent_id</code> field:
- The root directory has <code>parent_id = 0</code>
- All other entries have <code>parent_id</code> set to their parent directory's <code>entry_id</code>
- Directory listings are built by scanning the <code>FileTable</code> for entries with matching <code>parent_id</code>

#### Limitations
**Maximum filename length:** 256 bytes
**Maximum symlink target:** 48 bytes
**Maximum file entries:** 256
Files must be stored in contiguous sectors, since there is no fragmentation support.

### Entry Types

DiffFS supports three types of entries: regular files, directories and symbolic links. Each type uses the same <code>FileEntry</code> structure but interprets the <code>data</code> union differently.

#### Regular Files (<code>ENTRY_TYPE_FILE</code>)
Regular files store arbitrary binary data on disk. The file's content is stored in a contiguous block of sectors.

**Key fields:**
<code>data.file.start_sector</code> - LBA of the first sector containing the file data
<code>data.file.sector_count</code> - Number of sectors allocated (capacity = sector_count x 512)
<code>data.file.file_size_bytes</code> - Actual file size

**Example:**
<ul>
<code>
<li>FileEntry</li>
<li>{</li>
<ul>
<li>entry_id: 5</li>
<li>parent_id: 1</li>
<li>type: ENTRY_TYPE_FILE</li>
<li>filename: "my_file.txt"</li>
<li>data.file:</li>
<ul>
<li>start_sector: 128</li>
<li>sector_count: 64 // 32 KB Allocated</li>
<li>file_size_bytes: 31744 // 31 KB Actual size</li>
</ul>
</ul>}</li>
</code>
</ul>

**Reading a file:**
<ol>
<li>Locate the <code>FileEntry</code> by path</li>
<li>Read <code>sector_count</code> sectors starting at <code>start_sector</code></li>
<li>Truncate result to <code>file_size_bytes</code></li>
</ol>

#### Directories (<code>ENTRY_TYPE_DIR</code>)
Directories are containers that group files and subdirectories. DiffFS does not store directory contents in separate data blocks, the hierarchy is encoded entirely through <code>parent_id</code> relationships in the <code>FileTable</code>.

**Listing directory contents:**
To list all entries in a directory with <code>entry_id = N</code>:
<ol>
<li>Scan the entire <code>FileTable</code>
<li>Collect all entries where <code>parent_id == N</code>
<li>Filter out <code>ENTRY_TYPE_INVALID</code> entries
</ol>

<code>
// Pseudocode for directory listing
for (int i = 0; i < MAX_FILES; i++) 
{
    FileEntry *entry = &file_table->entries[i];

    if (entry->type != ENTRY_TYPE_INVALID && entry->parent_id == directory_id) 
    {
        // This entry is a child of the directory
    }
}
</code>

**Root directory:**
The root directory's <code>entry_id</code> is stored in <code>superblock.root_dir_id</code>. Its <code>parent_id</code> is either 0 or equal to its own <code>entry_id</code>.


#### Symbolic links (<code>ENTRY_TYPE_SYMLINK</code>)
Symbolic links (symlinks) are special entries that point to another path. When accessed, the filesystem can resolve the symlink to its target.

**Example:**
<ul>
<code>
<li>FileEntry</li>
<li>{</li>
<ul>
<li>entry_id: 12</li>
<li>parent_id: 1</li>
<li>type: ENTRY_TYPE_SYMLINK</li>
<li>filename: "my_exl"</li>
<li>data.symlink:</li>
<ul>
<li>target: "/system/exls/some.exl"</li>
</ul>
</ul>}</li>
</code>
</ul>

**Symlink behavior:**
- Symbol link target can be absolute (<code>/system/exls</code>) or relative (<code>../shared</code>).
- Maximum target length is 47 characters (stored inline, no extra disk space).
- Requires <code>DIFF_FEATURE_SYMLINKS</code> flag in <code>superblock</code>.

**Operations**
| Function                                | Description                           |
|-----------------------------------------|---------------------------------------|
| filesystem_symlink(target, linkpath)    | Create a new symbolic link            |
| filesystem_readlink(path, buf, size)    | Read symlink target into buffer       |
| filesystem_is_symlink(path)             | Check if the path is a symbolic link  |


#### Types Comparison
| Feature                | File | Directory | Symlink |
|------------------------|------|-----------|---------|
| Stores data on disk    | Yes  | No        | No      |
| Has children           | No   | Yes       | No      |
| Uses start_sector      | Yes  | No        | No      |
| Uses sector_count      | Yes  | No        | No      |
| Uses file_size_bytes   | Yes  | No        | No      |
| Uses target            | No   | No        | Yes     |
| Max name length        | 255  | 255       | 255     |
| Max content / target   | 2³² bytes | N/A | 47 chars |
