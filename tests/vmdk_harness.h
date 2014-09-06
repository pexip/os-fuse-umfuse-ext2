/**
 * Copyright (c) 2014 Pexip AS <packaging@pexip.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the fuse-ext2
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef FUSEEXT2_TEST_VMDK_HARNESS_H
#define FUSEEXT2_TEST_VMDK_HARNESS_H

#include <inttypes.h>

#define BYTES_PER_SECTOR 512

/* Grain size is 64k */
#define GRAIN_SIZE 65536
/* Grain tables cover 32MB */
#define GT_COVERAGE (32 * 1024 * 1024)

/* Describe a block in a disk */
struct block_descriptor {
	uint64_t lba; /* must be a multiple of grain size */
	uint32_t size; /* compressed (i.e. <= grain size) */
	uint8_t fill; /* value to fill block with */
	/* The 2 raised to the power of the fill value 
	 * defines the size of the block when recompressed
	 * (i.e. a fill value of 10 implies a compressed 
	 * size of 1024 bytes) */
};

/* Describe a disk */
struct disk_descriptor {
	uint64_t capacity; /* in bytes */
	uint32_t nblocks; /* number of allocated blocks */
	struct block_descriptor blocks[]; /* block descriptions */
};

/* Build a disk into a memory buffer, returning size of disk */
uint8_t *
build_disk(const struct disk_descriptor *desc, uint64_t *disk_size);


#endif
