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

#include <string.h>
#include <unistd.h>

#include <zlib.h>

#include "fuse-ext2.h"

#ifdef UNITTEST
  extern errcode_t test_ext2fs_get_mem(unsigned long size, void *ptr);
  extern errcode_t test_ext2fs_free_mem(void *ptr);
  extern ext2_loff_t test_ext2fs_llseek(int fd, ext2_loff_t offset, int whence);
  extern int test_ext2fs_open_file(const char *pathname,
		  		   int flags, mode_t mode);
  extern int test_close(int fd);
  extern ssize_t test_read(int fd, void *buf, size_t count);
  extern ssize_t test_write(int fd, const void *buf, size_t count);
  extern int test_fsync(int fd);
  extern int test_ftruncate(int fd, off_t length);
  extern int test_compress(Bytef *dest, uLongf *destLen,
		  	   const Bytef *source, uLong sourceLen);
  extern int test_uncompress(Bytef *dest, uLongf *destLen,
		  	     const Bytef *source, uLong sourceLen);

  #define ext2fs_get_mem   test_ext2fs_get_mem
  #define ext2fs_free_mem  test_ext2fs_free_mem
  #define ext2fs_llseek    test_ext2fs_llseek
  #define ext2fs_open_file test_ext2fs_open_file
  #define close            test_close
  #define read             test_read
  #define write            test_write
  #define fsync            test_fsync
  #define ftruncate        test_ftruncate
  #define compress         test_compress
  #define uncompress       test_uncompress
#endif

#define EXT2_ET_MAGIC_VMDK_IO_CHANNEL 0x766d6400
#define EXT2_ET_BAD_VMDK 0x766d6401

#define EXT2_CHECK_MAGIC(struct, code) \
	          if ((struct)->magic != (code)) return (code)

#define BYTES_PER_SECTOR 512

/* Assumes power of 2 */
#define SECTOR_ALIGN(x) (((x) + BYTES_PER_SECTOR - 1) & ~(BYTES_PER_SECTOR - 1))

#define min(a, b) ((a) < (b) ? (a) : (b))

struct vmdk_sparse_extent_header {
	uint32_t magic;
	uint32_t version;
	uint32_t flags;
	uint64_t capacity;
	uint64_t grain_size;
	uint64_t descriptor_offset;
	uint64_t descriptor_size;
	uint32_t num_gtes_per_gt;
	uint64_t rgd_offset;
	uint64_t gd_offset;
	uint64_t overhead;
	uint8_t unclean_shutdown;
	char single_end_line_char;
	char non_end_line_char;
	char double_end_line_char1;
	char double_end_line_char2;
	uint16_t compress_algorithm;
	uint8_t pad[433];
} __attribute__((__packed__));

struct vmdk_grain_marker {
	uint64_t lba;
	uint32_t size;
} __attribute__((__packed__));

enum vmdk_marker_type {
	VMDK_MARKER_TYPE_EOS    = 0,
	VMDK_MARKER_TYPE_GT     = 1,
	VMDK_MARKER_TYPE_GD     = 2,
	VMDK_MARKER_TYPE_FOOTER = 3
};

struct vmdk_marker {
	uint64_t num_sectors;
	uint32_t size;
	uint32_t type;
	uint8_t pad[496];
} __attribute__((__packed__));

struct vmdk_modified_grain {
	struct vmdk_modified_grain *next;
	uint64_t lba;

	ext2_loff_t old_location;
	ext2_loff_t new_location;
	ext2_loff_t old_size;
	ext2_loff_t new_size;
	uint64_t bytes_following;
	int gt_follows : 1,
	    moved      : 1,
	    written    : 1;

	uint8_t data[0];
};

struct vmdk_gap {
	struct vmdk_gap *next;

	ext2_loff_t orig_location;
	ext2_loff_t location;
	ext2_loff_t orig_size;
	ext2_loff_t size;
};

struct vmdk_private_data {
	int magic;
	int dev;
	int flags;
	ext2_loff_t offset;
	struct struct_io_stats io_stats;

	ext2_loff_t initial_extent;
	ext2_loff_t max_lba;

	ext2_loff_t data_start;
	ext2_loff_t grain_coverage;
	uint8_t *grain;
	uint8_t *compressed_buf;

	ext2_loff_t grain_table_coverage;
	ext2_loff_t grain_table_size;
	uint32_t *grain_table;

	ext2_loff_t gd_entries;
	uint32_t *grain_directory;

	struct vmdk_modified_grain *change_list;
};

static struct struct_io_manager struct_vmdk_manager;
io_manager vmdk_io_manager = &struct_vmdk_manager;


static errcode_t
vmdk_raw_read(struct vmdk_private_data *data, ext2_loff_t offset,
	      ssize_t count, void *buf)
{
	ssize_t bytes_read;

	if (ext2fs_llseek(data->dev, offset, SEEK_SET) != offset) {
		return errno;
	}

	bytes_read = read(data->dev, buf, count);
	if (bytes_read != count) {
		return EXT2_ET_SHORT_READ;
	}

	return 0;
}

static errcode_t
vmdk_raw_write(struct vmdk_private_data *data, ext2_loff_t offset,
	       ssize_t count, const void *buf)
{
	ssize_t bytes_written;

	if (ext2fs_llseek(data->dev, offset, SEEK_SET) != offset) {
		return errno;
	}

	bytes_written = write(data->dev, buf, count);
	if (bytes_written != count) {
		return EXT2_ET_SHORT_WRITE;
	}

	return 0;
}

static errcode_t
vmdk_ensure_eos(struct vmdk_private_data *data)
{
	static const char eos_marker[BYTES_PER_SECTOR];

	int retval = 0;
	char buf[BYTES_PER_SECTOR];

	retval = vmdk_raw_read(data, data->initial_extent - sizeof(buf),
			       sizeof(buf), buf);
	if (retval == 0 && memcmp(buf, eos_marker, sizeof(eos_marker)) != 0) {
		retval = EXT2_ET_BAD_VMDK;
	}

	return retval;
}

static errcode_t
vmdk_parse_footer(struct vmdk_private_data *data)
{
	int retval = 0;
	ext2_loff_t pos, sectors_per_gt, grain_directory_size;
	struct vmdk_sparse_extent_header footer;

	data->initial_extent = ext2fs_llseek(data->dev, 0, SEEK_END);
	if (data->initial_extent == (ext2_loff_t) -1) {
		return errno;
	}

	retval = vmdk_ensure_eos(data);
	if (retval) {
		return retval;
	}
	
	pos = data->initial_extent - BYTES_PER_SECTOR - sizeof(footer);
	retval = vmdk_raw_read(data, pos, sizeof(footer), &footer);
	if (retval) {
		return retval;
	}

	data->max_lba = (ext2_loff_t) (footer.capacity * BYTES_PER_SECTOR);

	/* Compute the location of the first grain in the image */
	data->data_start = footer.overhead + 1; /* skip overhead and header */
	if (footer.descriptor_offset > 0) {
		data->data_start += footer.descriptor_size;
	}
	data->data_start *= BYTES_PER_SECTOR; /* convert to bytes */

	data->grain_coverage = footer.grain_size * BYTES_PER_SECTOR;
	retval = ext2fs_get_mem(data->grain_coverage, &data->grain);
	if (retval) {
		return retval;
	}

	retval = ext2fs_get_mem(compressBound(data->grain_coverage),
				&data->compressed_buf);
	if (retval) {
		ext2fs_free_mem(&data->grain);
		return retval;
	}

	data->grain_table_size = footer.num_gtes_per_gt * sizeof(uint32_t);
	retval = ext2fs_get_mem(data->grain_table_size, &data->grain_table);
	if (retval) {
		ext2fs_free_mem(&data->compressed_buf);
		ext2fs_free_mem(&data->grain);
		return retval;
	}

	sectors_per_gt = footer.num_gtes_per_gt * footer.grain_size;
	data->grain_table_coverage = sectors_per_gt * BYTES_PER_SECTOR;

	data->gd_entries = (footer.capacity + sectors_per_gt - 1) /
			   sectors_per_gt;
	grain_directory_size = data->gd_entries * sizeof(uint32_t);
	retval = ext2fs_get_mem(grain_directory_size, &data->grain_directory);
	if (retval) {
		ext2fs_free_mem(&data->grain_table);
		ext2fs_free_mem(&data->compressed_buf);
		ext2fs_free_mem(&data->grain);
		return retval;
	}

	pos = footer.gd_offset * BYTES_PER_SECTOR;
	retval = vmdk_raw_read(data, pos, grain_directory_size,
			       data->grain_directory);
	if (retval) {
		ext2fs_free_mem(&data->grain_directory);
		ext2fs_free_mem(&data->grain_table);
		ext2fs_free_mem(&data->compressed_buf);
		ext2fs_free_mem(&data->grain);
		return retval;
	}

	return retval;
}

static void
vmdk_reverse_change_list(struct vmdk_private_data *data)
{
	struct vmdk_modified_grain *grain, *prev = NULL, *next;

	for (grain = data->change_list; grain != NULL; grain = next) {
		next = grain->next;
		grain->next = prev;
		prev = grain;
	}
	data->change_list = prev;
}

static void
vmdk_destroy_change_list(struct vmdk_private_data *data)
{
	struct vmdk_modified_grain *victim;

	while (data->change_list != NULL) {
		victim = data->change_list;
		data->change_list = victim->next;

		ext2fs_free_mem(&victim);
	}
}

static void
vmdk_insert_modified_grain(struct vmdk_private_data *data,
			   struct vmdk_modified_grain *grain)
{
	struct vmdk_modified_grain *list = data->change_list;
	struct vmdk_modified_grain *prev = NULL;

	while (list != NULL && list->lba < grain->lba) {
		prev = list;
		list = list->next;
	}

	if (prev == NULL) {
		grain->next = data->change_list;
		data->change_list = grain;
	} else {
		grain->next = prev->next;
		prev->next = grain;
	}
}

static errcode_t
vmdk_create_modified_grain(struct vmdk_private_data *data,
			   ext2_loff_t lba,
			   struct vmdk_modified_grain **result)
{
	errcode_t retval = 0;
	struct vmdk_modified_grain *grain;

	retval = ext2fs_get_mem(data->grain_coverage + 
				sizeof(struct vmdk_modified_grain),
				&grain);
	if (retval) {
		return retval;
	}

	memset(grain, 0,
	       data->grain_coverage + sizeof(struct vmdk_modified_grain));
	grain->lba = lba;

	vmdk_insert_modified_grain(data, grain);

	*result = grain;

	return retval;
}

static struct vmdk_modified_grain *
vmdk_find_modified_grain(struct vmdk_modified_grain *list,
			 ext2_loff_t grain_size, uint64_t lba)
{
	while (list != NULL) {
		if (list->lba <= lba && lba < list->lba + grain_size) {
			break;
		}
		list = list->next;
	}

	return list;
}

static errcode_t
vmdk_read_grain(struct vmdk_private_data *data, ext2_loff_t lba,
		ext2_loff_t *grain_base)
{
	ext2_loff_t pos;
	unsigned long grainlen = (unsigned long) data->grain_coverage;
	errcode_t retval = 0;
	const struct vmdk_modified_grain *grain;
	struct vmdk_grain_marker marker;

	/* Compute grain base from lba */
	*grain_base = (lba / data->grain_coverage) * data->grain_coverage;

	/* Search change list first */
	grain = vmdk_find_modified_grain(data->change_list,
					 data->grain_coverage, lba);
	if (grain != NULL) {
		memcpy(data->grain, grain->data, data->grain_coverage);
		//assert(*grain_base == (ext2_loff_t) grain->lba);
		return retval;
	}

	pos = data->grain_directory[lba / data->grain_table_coverage];
	if (pos <= 1) {
		/* Entire grain table is empty */
		memset(data->grain, 0, data->grain_coverage);
		return retval;
	}

	retval = vmdk_raw_read(data, pos * BYTES_PER_SECTOR,
			       data->grain_table_size, data->grain_table);
	if (retval) {
		return retval;
	}

	pos = data->grain_table[(lba % data->grain_table_coverage) /
				data->grain_coverage];
	if (pos <= 1) {
		/* Grain is not present */
		memset(data->grain, 0, data->grain_coverage);
		return retval;
	}

	retval = vmdk_raw_read(data, pos * BYTES_PER_SECTOR,
			       sizeof(marker), &marker);
	if (retval) {
		return retval;
	}

	retval = vmdk_raw_read(data, pos * BYTES_PER_SECTOR + sizeof(marker),
			       marker.size, data->compressed_buf);
	if (retval) {
		return retval;
	}

	if (uncompress(data->grain, &grainlen, data->compressed_buf,
		       marker.size) != Z_OK) {
		return EXT2_ET_BAD_VMDK;
	}

	//assert(*grain_base == (ext2_loff_t) marker.lba * BYTES_PER_SECTOR);

	return retval;
}

static errcode_t
vmdk_write_grain(struct vmdk_private_data *data, ext2_loff_t lba)
{
	errcode_t retval = 0;
	struct vmdk_modified_grain *grain;

	grain = vmdk_find_modified_grain(data->change_list,
					 data->grain_coverage, lba);
	if (grain == NULL) {
		retval = vmdk_create_modified_grain(data, lba, &grain);
		if (retval) {
			return retval;
		}
	}

	memcpy(grain->data, data->grain, data->grain_coverage);

	return retval;
}

static void
vmdk_destroy_gap_list(struct vmdk_gap *gap_list)
{
	while (gap_list != NULL) {
		struct vmdk_gap *gap = gap_list;
		gap_list = gap_list->next;
		ext2fs_free_mem(&gap);
	}
}

#define CURRENT_SIZE_NEW_GRAIN_TABLE ((uint32_t) -1)
#define CURRENT_SIZE_NEW_GRAIN       ((uint32_t) -2)

static errcode_t
vmdk_compute_grain_location(struct vmdk_private_data *data,
			    const struct vmdk_modified_grain *grain,
			    ext2_loff_t *location,
			    uint32_t *current_size)
{
	ext2_loff_t gtpos, pos;
	int64_t index;
	const int64_t num_gt_entries = data->grain_table_size /
				       sizeof(uint32_t);
	errcode_t retval = 0;
	struct vmdk_grain_marker marker;

	index = grain->lba / data->grain_table_coverage;
	gtpos = data->grain_directory[index];
	if (gtpos <= 1) {
		/* No grain table: need to create one */

		/* Search backwards in grain directory to find 
		 * preceding in-use entry (if any) */
		while (--index >= 0) {
			gtpos = data->grain_directory[index];
			if (gtpos > 1) {
				/* Found it */
				*location = gtpos * BYTES_PER_SECTOR +
					    data->grain_table_size;
				*current_size = CURRENT_SIZE_NEW_GRAIN_TABLE;
				return retval;
			}
		}

		/* No previous in-use entry, so must be at 
		 * the start of the disk */
		*location = data->data_start;
		*current_size = CURRENT_SIZE_NEW_GRAIN_TABLE;
		return retval;
	}

	retval = vmdk_raw_read(data, gtpos * BYTES_PER_SECTOR,
			       data->grain_table_size, data->grain_table);
	if (retval) {
		return retval;
	}

	index = (grain->lba % data->grain_table_coverage) /
		data->grain_coverage;
	pos = data->grain_table[index];
	if (pos <= 1) {
		/* No existing grain: need to create one */

		/* Search forwards in grain table to find
		 * subsequent in-use entry (in any) */
		while (++index < num_gt_entries) {
			pos = data->grain_table[index];
			if (pos > 1) {
				/* Found it */
				*location = pos * BYTES_PER_SECTOR;
				*current_size = CURRENT_SIZE_NEW_GRAIN;
				return retval;
			}
		}

		/* No subsequent entry: insert before grain table */
		*location = (gtpos - 1) * BYTES_PER_SECTOR; /* -1 for marker */
		*current_size = CURRENT_SIZE_NEW_GRAIN;
		return retval;
	}

	/* Existing grain: read its size */
	retval = vmdk_raw_read(data, pos * BYTES_PER_SECTOR,
			       sizeof(marker), &marker);
	if (retval) {
		return retval;
	}

	*location = pos * BYTES_PER_SECTOR;
	*current_size = marker.size;

	return retval;
}

static errcode_t
vmdk_prepare_change_list_for_write(struct vmdk_private_data *data,
				   ext2_loff_t file_extent,
				   ext2_loff_t *accumulated_change,
				   struct vmdk_gap **gaps)
{
	struct vmdk_gap *gap_list = NULL, *gap_last = NULL;
	struct vmdk_modified_grain *grain, *prev = NULL;
	errcode_t retval = 0;
	ext2_loff_t total_change = 0;

	for (grain = data->change_list; grain != NULL; grain = grain->next) {
		uint32_t size;
		unsigned long new_size = compressBound(data->grain_coverage);

		/* Work out where grain would live, if nothing changed */
		retval = vmdk_compute_grain_location(data, grain,
						     &grain->old_location,
						     &size);
		if (retval) {
			goto error;
		}

		/* Compress the new grain data */
		if (compress(data->compressed_buf, &new_size,
			     grain->data, data->grain_coverage) != Z_OK) {
			retval = EXT2_ET_SHORT_WRITE;
			goto error;
		}

		/* Compute original size of grain */
		if (size == CURRENT_SIZE_NEW_GRAIN_TABLE) {
			/* Need a new grain table; flag this */
			grain->gt_follows = 1;

			if (prev != NULL && prev->gt_follows != 0 && 
			    (prev->lba / data->grain_table_coverage) == 
			    (grain->lba / data->grain_table_coverage)) {
				/* Last grain shares this new grain table.
				 * Clear its flag, as this grain owns it. */
				prev->gt_follows = 0;
			}

			grain->old_size = 0;
		} else if (size == CURRENT_SIZE_NEW_GRAIN) {
			grain->old_size = 0;
		} else {
			grain->old_size = SECTOR_ALIGN(size + 
					    sizeof(struct vmdk_grain_marker));
		}

		/* Compute new size of grain */
		grain->new_size = SECTOR_ALIGN(new_size +
					       sizeof(struct vmdk_grain_marker));

		/* If the previous grain will emit a grain table after itself,
		 * update the total change to take account of this. */
		if (prev != NULL && prev->gt_follows != 0) {
			total_change += data->grain_table_size + 
					sizeof(struct vmdk_marker);
		}

		/* Work out where we want to put this grain */
		grain->new_location = grain->old_location + total_change;

		/* Compute the amount of data between this grain and the 
		 * previous modification (if any) */
		if (prev != NULL) {
			prev->bytes_following = grain->old_location -
				(prev->old_location + prev->old_size);
		}

		/* Update total_change to take account of the new size 
		 * of this grain */
		total_change += grain->new_size - grain->old_size;

		/* Create new gap for grain (if necessary) */
		if (gap_last == NULL || gap_last->orig_location + 
		    gap_last->orig_size != grain->old_location) {
			struct vmdk_gap *gap;

			retval = ext2fs_get_mem(sizeof(struct vmdk_gap),
						&gap);
			if (retval) {
				goto error;
			}

			gap->orig_location = gap->location = 
					grain->old_location;
			gap->orig_size = gap->size = 0;
			gap->next = NULL;

			if (gap_last == NULL) {
				gap_last = gap_list = gap;
			} else {
				gap_last->next = gap;
				gap_last = gap;
			}
		}

		/* Extend gap to reflect grain */
		gap_last->orig_size += grain->old_size;
		gap_last->size += grain->old_size;

		prev = grain;
	}

	/* Ensure we calculate the amount of data after the final grain */
	if (prev != NULL) {
		prev->bytes_following =	file_extent - 
			(prev->old_location + prev->old_size);
	}

	/* Ensure total_change reflects any new grain table
	 * created by the final grain. */
	if (prev != NULL && prev->gt_follows != 0) {
		total_change += data->grain_table_size +
				sizeof(struct vmdk_marker);
	}

	if (total_change > 0) {
		/* Disk is growing: add dummy gap after end of file */
		if (prev != NULL) {
			struct vmdk_gap *gap;

			retval = ext2fs_get_mem(sizeof(struct vmdk_gap), &gap);
			if (retval) {
				goto error;
			}

			gap->orig_location = gap->location = 
				(prev->old_location + prev->old_size + 
				 prev->bytes_following);
			gap->orig_size = gap->size = total_change;
			gap->next = NULL;

			if (gap_last == NULL) {
				gap_last = gap_list = gap;
			} else {
				gap_last->next = gap;
				gap_last = gap;
			}
		}
	}

	*accumulated_change = total_change;
	*gaps = gap_list;

error:
	if (retval) {
		/* Something bad happened: clean up */
		vmdk_destroy_gap_list(gap_list);

		*accumulated_change = 0;
		*gaps = NULL;
	}

	return retval;
}

static errcode_t
vmdk_shift_data(struct vmdk_private_data *data, ext2_loff_t whence,
		ext2_loff_t num_bytes, ext2_loff_t shift)
{
	errcode_t retval = 0;
	ext2_loff_t readpos, writepos, remaining, bytes_to_read;
	uint8_t buffer[64 * 1024];

	assert(num_bytes > 0);

	remaining = num_bytes;
	bytes_to_read = min(num_bytes, sizeof(buffer));

	if (shift < 0) {
		/* Shrinking: start at bottom and move up */
		readpos = whence;
		writepos = whence + shift;
	} else {
		/* Growing: start at top and move down */
		readpos = whence + num_bytes;
		writepos = whence + shift + num_bytes;
	}

	do {
		if (shift >= 0) {
			/* Growing: update read/write positions */
			readpos -= bytes_to_read;
			writepos -= bytes_to_read;
		}

		retval = vmdk_raw_read(data, readpos, bytes_to_read, &buffer);
		if (retval) {
			return retval;
		}

		retval = vmdk_raw_write(data, writepos, bytes_to_read, buffer);
		if (retval) {
			return retval;
		}
		
		if (shift < 0) {
			/* Shrinking: update read/write positions */
			readpos += bytes_to_read;
			writepos += bytes_to_read;
		}

		remaining -= bytes_to_read;
		bytes_to_read = min(remaining, sizeof(buffer));
	} while (remaining > 0);

	return retval;
}

static void
vmdk_find_gaps_for_grain(const struct vmdk_modified_grain *grain,
			 struct vmdk_gap *gap_list,
			 struct vmdk_gap **before,
			 struct vmdk_gap **after)
{
	struct vmdk_gap *gap, *b = NULL;

	for (gap = gap_list; gap != NULL; gap = gap->next) {
		if (grain->old_location >= gap->orig_location &&
				(grain->old_location + grain->old_size) <= 
				(gap->orig_location + gap->orig_size)) {
			b = gap;
		} else if (b != NULL) {
			*before = b;
			*after = gap;
			return;
		}
	}

	if (b == NULL) {
		*before = NULL;
		*after = gap_list;
	} else {
		*before = b;
		*after = NULL;
	}
}

static errcode_t
vmdk_try_move_data(struct vmdk_private_data *data,
		   struct vmdk_modified_grain *grain, struct vmdk_gap *gap_list)
{
	errcode_t retval = 0;
	ext2_loff_t shift = grain->new_location - grain->old_location;
	ext2_loff_t diff = grain->new_size - grain->old_size;
	ext2_loff_t mv = shift + diff;
	struct vmdk_gap *before, *after;

	if (grain->moved != 0) {
		return retval;
	}

	if (grain->gt_follows != 0) {
		/* Adjust mv to account for new grain table */
		mv += data->grain_table_size + sizeof(struct vmdk_marker);
	}

	if (mv == 0 || grain->bytes_following == 0) {
		/* Nothing to move; set flag and skip */
		grain->moved = 1;
		return retval;
	}

	vmdk_find_gaps_for_grain(grain, gap_list, &before, &after);

	if (mv < 0) {
		/* Trailing data needs moving earlier in file */
		assert(before != NULL);
		/* Signs are backwards in here, as mv is negative */
		if (before->size + mv >= 0) {
			/* There is space for the move, perform it */
			retval = vmdk_shift_data(data, 
						 grain->old_location +
						 	grain->old_size,
						 grain->bytes_following,
						 mv);
			if (retval) {
				return retval;
			}

			/* Update gaps to reflect shift */
			before->size += mv;
			if (after != NULL) {
				after->location += mv;
				after->size -= mv;
			}

			/* Flag that the data has moved */
			grain->moved = 1;
		}
	} else if (mv > 0) {
		/* Trailing data needs moving later in file */
		assert(after != NULL);
		if (after->size - mv >= 0) {
			/* There is space for the move, perform it */
			retval = vmdk_shift_data(data,
						 grain->old_location +
						 	grain->old_size,
						 grain->bytes_following,
						 mv);
			if (retval) {
				return retval;
			}

			/* Update gaps to reflect shift */
			after->location += mv;
			after->size -= mv;
			if (before != NULL) {
				before->size += mv;
			}

			/* Flag that the data has moved */
			grain->moved = 1;
		}
	}

	return retval;
}

static errcode_t
vmdk_write_grain_to_disk(struct vmdk_private_data *data,
			 const struct vmdk_modified_grain *grain)
{
	static const uint8_t pad[512];
	errcode_t retval = 0;
	ssize_t padlen;
	unsigned long size = compressBound(data->grain_coverage);
	struct vmdk_grain_marker marker;

	/* Compress the grain data */
	if (compress(data->compressed_buf, &size,
		     grain->data, data->grain_coverage) != Z_OK) {
		return EXT2_ET_SHORT_WRITE;
	}

	assert(SECTOR_ALIGN(size + sizeof(marker)) == grain->new_size);

	/* Emit the grain to its location */

	marker.lba = grain->lba / BYTES_PER_SECTOR;
	marker.size = (uint32_t) size;

	retval = vmdk_raw_write(data, grain->new_location,
				sizeof(marker), &marker);
	if (retval) {
		return retval;
	}

	retval = vmdk_raw_write(data, grain->new_location + sizeof(marker),
				size, data->compressed_buf);
	if (retval) {
		return retval;
	}

	padlen = grain->new_size - sizeof(marker) - size;
	if (padlen > 0) {
		retval = vmdk_raw_write(data,
					grain->new_location +
					    sizeof(marker) + size,
					padlen,
					pad);
		if (retval) {
			return retval;
		}
	}

	return retval;
}

static errcode_t
vmdk_try_write_data(struct vmdk_private_data *data,
		    struct vmdk_modified_grain *grain,
		    struct vmdk_gap *gap_list)
{
	struct vmdk_gap *gap;
	ext2_loff_t size;
	errcode_t retval = 0;

	/* Compute space required to store grain */
	size = grain->new_size;
	if (grain->gt_follows != 0) {
		/* Allow for trailing grain table */
		size += data->grain_table_size + sizeof(struct vmdk_marker);
	}

	/* Search for gap into which grain fits */
	for (gap = gap_list; gap != NULL; gap = gap->next) {
		if (grain->new_location >= gap->location) {
			if (grain->new_location + size <= 
					gap->location + gap->size) {
				/* Found it: emit grain */
				retval = vmdk_write_grain_to_disk(data, grain);
				if (retval) {
					return retval;
				}

				/* Update gap size/location */
				gap->size -= size;
				if (grain->new_location == gap->location) {
					gap->location = grain->new_location + 
							size;
				}

				/* Flag that this grain has been written out */
				grain->written = 1;

				break;
			}
		} else {
			break;
		}
	}

	return retval;
}

static errcode_t
vmdk_emit_change_list(struct vmdk_private_data *data, struct vmdk_gap *gap_list)
{
	struct vmdk_modified_grain *grain;
	errcode_t retval = 0;
	int work_to_do = 1;

	while (work_to_do) {
		work_to_do = 0;

		for (grain = data->change_list; grain != NULL;
				grain = grain->next) {
			if (grain->written == 0) {
				retval = vmdk_try_move_data(data,
							    grain,
							    gap_list);
				if (retval) {
					return retval;
				}

				if (grain->moved != 0) {
					retval = vmdk_try_write_data(data,
								     grain,
								     gap_list);
					if (retval) {
						return retval;
					}
				}

				if (grain->written == 0) {
					work_to_do = 1;
				}
			}
		}
	}

	return retval;
}

static errcode_t
vmdk_update_metadata_for_modified_grains(struct vmdk_private_data *data)
{
	errcode_t retval = 0;
	struct vmdk_modified_grain *grain;

	/* Ensure new grain tables are initialised */
	for (grain = data->change_list; grain != NULL; grain = grain->next) {
		int gdindex = grain->lba / data->grain_table_coverage;

		if (grain->gt_follows != 0) {
			struct vmdk_marker gtmarker;
			ext2_loff_t gtpos = grain->new_location +
					    grain->new_size;

			memset(&gtmarker, 0, sizeof(gtmarker));
			gtmarker.type = VMDK_MARKER_TYPE_GT;
			gtmarker.num_sectors = data->grain_table_size / 
					       BYTES_PER_SECTOR;

			retval = vmdk_raw_write(data, gtpos,
						sizeof(gtmarker), &gtmarker);
			if (retval) {
				return retval;
			}

			memset(data->grain_table, 0, data->grain_table_size);
			retval = vmdk_raw_write(data, gtpos + sizeof(gtmarker),
						data->grain_table_size,
						data->grain_table);
			if (retval) {
				return retval;
			}

			data->grain_directory[gdindex] =
					(gtpos + sizeof(gtmarker)) / BYTES_PER_SECTOR;

		}
	}

	/* Ensure grain table entries are up-to-date */
	for (grain = data->change_list; grain != NULL; grain = grain->next) {
		int gdindex = grain->lba / data->grain_table_coverage;
		ext2_loff_t pos = data->grain_directory[gdindex];
		assert(pos > 1);

		retval = vmdk_raw_read(data, pos * BYTES_PER_SECTOR,
				       data->grain_table_size,
				       data->grain_table);
		if (retval) {
			return retval;
		}

		data->grain_table[(grain->lba % data->grain_table_coverage) /
				  data->grain_coverage] = 
					grain->new_location / BYTES_PER_SECTOR;

		retval = vmdk_raw_write(data, pos * BYTES_PER_SECTOR,
					data->grain_table_size,
					data->grain_table);
		if (retval) {
			return retval;
		}
	}

	return retval;
}

static void
vmdk_update_mv_and_grain(struct vmdk_private_data *data,
			 struct vmdk_modified_grain **grain,
			 ext2_loff_t *mv)
{
	struct vmdk_modified_grain *next = *grain;

	/* Grain points at the next modification.
	 * Ensure we coalesce adjacent changes. */
	while (next != NULL && next->old_location == (*grain)->old_location) {
		*mv += next->new_size - next->old_size;
		if (next->gt_follows != 0) {
			*mv += data->grain_table_size +
			       sizeof(struct vmdk_marker);
		}
		next = next->next;
	}
	*grain = next;

	/* MV must be a multiple of the sector size */
	assert(((*mv / BYTES_PER_SECTOR) * BYTES_PER_SECTOR) == *mv);
}

static ext2_loff_t
vmdk_mv_for_gt(struct vmdk_private_data *data,
	       const struct vmdk_modified_grain *grain,
	       ext2_loff_t max_lba)
{
	ext2_loff_t mv = 0;

	while (grain != NULL && grain->lba < max_lba) {
		mv += grain->new_size - grain->old_size;
		if (grain->gt_follows != 0) {
			mv += data->grain_table_size +
			      sizeof(struct vmdk_marker);
		}
		grain = grain->next;
	}

	return mv;
}

static errcode_t
vmdk_update_metadata(struct vmdk_private_data *data)
{
	ext2_loff_t gdindex, mv = 0;
	struct vmdk_modified_grain *grain = data->change_list;
	errcode_t retval = 0;

	assert(grain != NULL);

	/* Update all extant grain tables */
	for (gdindex = 0; gdindex < data->gd_entries; gdindex++) {
		ext2_loff_t gtpos, gtindex;

		gtpos = data->grain_directory[gdindex] * BYTES_PER_SECTOR;
		if (gtpos <= BYTES_PER_SECTOR) {
			/* Unused grain directory entry: skip */
			continue;
		}

		/* Compute/store new grain table location */
		gtpos += mv + vmdk_mv_for_gt(data, grain,
				data->grain_table_coverage * (gdindex + 1));
		data->grain_directory[gdindex] = gtpos / BYTES_PER_SECTOR;

		/* Read grain table */
		retval = vmdk_raw_read(data, gtpos,
				       data->grain_table_size,
				       data->grain_table);
		if (retval) {
			return retval;
		}

		/* Process all grains in table */
		for (gtindex = 0; 
		     gtindex < data->grain_table_size / sizeof(uint32_t);
		     gtindex++) {
			ext2_loff_t gpos;

			gpos = data->grain_table[gtindex] * BYTES_PER_SECTOR;
			if (gpos <= BYTES_PER_SECTOR) {
				/* Unused grain table entry: skip */
				continue;
			}

			/* Update mv and grain, if needed */
			if (grain != NULL && gpos >= grain->old_location) {
				vmdk_update_mv_and_grain(data, &grain, &mv);
			}

			gpos += mv;
			data->grain_table[gtindex] = gpos / BYTES_PER_SECTOR;
		}

		/* Write out the updated grain table */
		retval = vmdk_raw_write(data, gtpos,
					data->grain_table_size,
					data->grain_table);
		if (retval) {
			return retval;
		}
	}

	return retval;
}

static errcode_t
vmdk_update_disk_metadata(struct vmdk_private_data *data,
			  ext2_loff_t amount_to_move)
{
	errcode_t retval;
	ext2_loff_t file_extent;
	struct vmdk_sparse_extent_header footer;

	file_extent = ext2fs_llseek(data->dev, 0, SEEK_END);
	if (file_extent == (ext2_loff_t) -1) {
		return errno;
	}

	retval = vmdk_raw_read(data,
			       file_extent - BYTES_PER_SECTOR - sizeof(footer),
			       sizeof(footer), &footer);
	if (retval) {
		return retval;
	}

	footer.gd_offset += (amount_to_move / BYTES_PER_SECTOR);

	/* Update extant grain tables */
	retval = vmdk_update_metadata(data);
	if (retval) {
		return retval;
	}

	/* Create new grain tables */
	retval = vmdk_update_metadata_for_modified_grains(data);
	if (retval) {
		return retval;
	}

	/* Write out the updated grain directory */
	retval = vmdk_raw_write(data, footer.gd_offset * BYTES_PER_SECTOR,
				data->gd_entries * sizeof(uint32_t),
				data->grain_directory);
	if (retval) {
		return retval;
	}

	/* And the updated footer */
	retval = vmdk_raw_write(data,
				file_extent - BYTES_PER_SECTOR - sizeof(footer),
				sizeof(footer), &footer);
	if (retval) {
		return retval;
	}

	return retval;
}

static errcode_t
vmdk_write_change_list(struct vmdk_private_data *data)
{
	struct vmdk_gap *gap_list;
	ext2_loff_t amount_to_move, file_extent;
	errcode_t retval = 0;

	if (data->change_list == NULL) {
		return retval;
	}

	file_extent = ext2fs_llseek(data->dev, 0, SEEK_END);
	if (file_extent == (ext2_loff_t) -1) {
		return errno;
	}

	retval = vmdk_prepare_change_list_for_write(data,
						    file_extent,
						    &amount_to_move,
						    &gap_list);
	if (retval) {
		vmdk_destroy_gap_list(gap_list);
		return retval;
	}

	/* Amount to move must be a multiple of the sector size */
	assert(((amount_to_move / BYTES_PER_SECTOR) * BYTES_PER_SECTOR) ==
	       amount_to_move);

	/* From this point onward, we will modify the actual disk contents.
	 * If anything goes wrong, the disk will be corrupted. */

	if (amount_to_move > 0) {
		/* Disk is growing: reverse change list as it's almost
		 * certainly more efficient to process it backwards */
		vmdk_reverse_change_list(data);
	}

	retval = vmdk_emit_change_list(data, gap_list);
	if (retval) {
		vmdk_destroy_gap_list(gap_list);
		return retval;
	}

	vmdk_destroy_gap_list(gap_list);

	/* Truncate file to new size */
	retval = ftruncate(data->dev, file_extent + amount_to_move);
	if (retval == (ext2_loff_t) -1) {
		return errno;
	}

	if (amount_to_move > 0) {
		/* Change list is backwards (see above), but the
		 * metadata manipulation requires it to be forwards.
		 * So, reverse it again here. */
		vmdk_reverse_change_list(data);
	}

	retval = vmdk_update_disk_metadata(data, amount_to_move);
	if (retval) {
		return retval;
	}

	return retval;
}


static errcode_t
vmdk_open(const char *name, int flags, io_channel *channel)
{
	io_channel io = NULL;
	struct vmdk_private_data *data = NULL;
	int open_flags;
	errcode_t retval;

	if (name == NULL) {
		return EXT2_ET_BAD_DEVICE_NAME;
	}

	retval = ext2fs_get_mem(sizeof(struct struct_io_channel), &io);
	if (retval) {
		return retval;
	}
	memset(io, 0, sizeof(struct struct_io_channel));

	retval = ext2fs_get_mem(sizeof(struct vmdk_private_data), &data);
	if (retval) {
		ext2fs_free_mem(&io);
		return retval;
	}
	memset(data, 0, sizeof(struct vmdk_private_data));
	data->magic = EXT2_ET_MAGIC_VMDK_IO_CHANNEL;
	data->flags = flags;
	data->io_stats.num_fields = 2;

	retval = ext2fs_get_mem(strlen(name)+1, &io->name);
	if (retval) {
		ext2fs_free_mem(&data);
		ext2fs_free_mem(&io);
		return retval;
	}

	strcpy(io->name, name);
	io->magic = EXT2_ET_MAGIC_IO_CHANNEL;
	io->manager = vmdk_io_manager;
	io->private_data = data;
	io->block_size = 512;
	io->read_error = 0;
	io->write_error = 0;
	io->refcount = 1;

	open_flags = (flags & IO_FLAG_RW) ? O_RDWR : O_RDONLY;
	/** \todo exclusive/direct IO? */
	data->dev = ext2fs_open_file(io->name, open_flags, 0);
	if (data->dev < 0) {
		ext2fs_free_mem(&io->name);
		ext2fs_free_mem(&data);
		ext2fs_free_mem(&io);
		return errno;
	}

	retval = vmdk_parse_footer(data);
	if (retval) {
		close(data->dev);
		ext2fs_free_mem(&io->name);
		ext2fs_free_mem(&data);
		ext2fs_free_mem(&io);
		return retval;
	}

	*channel = io;
	return 0;
}

static errcode_t
vmdk_flush(io_channel channel)
{
	struct vmdk_private_data *data;
	errcode_t retval = 0;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	/* Reconstruct VMDK */
	retval = vmdk_write_change_list(data);
	fsync(data->dev);
	vmdk_destroy_change_list(data);

	return retval;
}

static errcode_t
vmdk_close(io_channel channel)
{
	struct vmdk_private_data *data;
	errcode_t retval = 0;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	if (--channel->refcount > 0) {
		return 0;
	}

	retval = vmdk_flush(channel);

	if (close(data->dev) < 0) {
		retval = errno;
	}

	ext2fs_free_mem(&data->compressed_buf);
	ext2fs_free_mem(&data->grain_directory);
	ext2fs_free_mem(&data->grain_table);
	ext2fs_free_mem(&data->grain);

	ext2fs_free_mem(&channel->name);
	ext2fs_free_mem(&channel->private_data);
	ext2fs_free_mem(&channel);

	return retval;
}

static errcode_t
vmdk_set_blksize(io_channel channel, int blksize)
{
	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);

	channel->block_size = blksize;

	return 0;
}

static errcode_t
vmdk_set_option(io_channel channel, const char *option, const char *arg)
{
	struct vmdk_private_data *data;
	unsigned long long offset;
	char *end;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	if (strcmp(option, "offset") == 0 && arg != NULL) {
		offset = strtoull(arg, &end, 0);
		if (*end == '\0' && (ext2_loff_t) offset >= 0) {
			data->offset = offset;
			return 0;
		}
	}

	return EXT2_ET_INVALID_ARGUMENT;
}

static errcode_t
vmdk_get_stats(io_channel channel, io_stats *stats)
{
	struct vmdk_private_data *data;
	errcode_t retval = 0;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	if (stats != NULL) {
		*stats = &data->io_stats;
	}

	return retval;
}

static errcode_t
vmdk_read_blk64(io_channel channel, unsigned long long block, int count,
		void *bufv)
{
	struct vmdk_private_data *data;
	errcode_t retval = 0;
	ssize_t size, remaining;
	ext2_loff_t lba;
	unsigned char *buf = bufv;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	size = remaining = (count < 0) ? -count : count * channel->block_size;
	lba = ((ext2_loff_t) block * channel->block_size) + data->offset;
	if (lba + size > data->max_lba) {
		return EXT2_ET_LLSEEK_FAILED;
	}

	while (remaining > 0) {
		ext2_loff_t grain_base, grain_offset, bytes_from_grain;

		retval = vmdk_read_grain(data, lba, &grain_base);
		if (retval) {
			memset(buf, 0, remaining);
			if (channel->read_error != NULL) {
				retval = channel->read_error(channel, block,
							     count, bufv,
							     size,
							     size - remaining,
							     retval);
			}

			break;
		}

		grain_offset = lba - grain_base;
		bytes_from_grain = min(data->grain_coverage - grain_offset,
				       remaining);

		memcpy(buf, data->grain + grain_offset, bytes_from_grain);

		buf += bytes_from_grain;
		lba += bytes_from_grain;
		remaining -= bytes_from_grain;
	}

	return retval;
}

static errcode_t
vmdk_write_blk64(io_channel channel, unsigned long long block, int count,
		 const void *bufv)
{
	struct vmdk_private_data *data;
	errcode_t retval = 0;
	ssize_t size, remaining = 0;
	ext2_loff_t lba;
	const unsigned char *buf = bufv;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	size = remaining = (count < 0) ? -count : count * channel->block_size;
	lba = ((ext2_loff_t) block * channel->block_size) + data->offset;

	while (remaining > 0) {
		ext2_loff_t grain_base, grain_offset, bytes_from_grain;

		retval = vmdk_read_grain(data, lba, &grain_base);
		if (retval) {
			if (channel->write_error != NULL) {
				retval = channel->write_error(channel, block,
							      count, bufv,
							      size,
							      size - remaining,
							      retval);
			}

			break;
		}

		grain_offset = lba - grain_base;
		bytes_from_grain = min(data->grain_coverage - grain_offset,
				       remaining);

		memcpy(data->grain + grain_offset, buf, bytes_from_grain);

		retval = vmdk_write_grain(data, grain_base);
		if (retval) {
			if (channel->write_error != NULL) {
				retval = channel->write_error(channel, block,
							      count, bufv,
							      size,
							      size - remaining,
							      retval);
			}

			break;
		}

		buf += bytes_from_grain;
		lba += bytes_from_grain;
		remaining -= bytes_from_grain;
	}

	return retval;
}

static errcode_t
vmdk_write_byte(io_channel channel, unsigned long offset, int size,
	        const void *bufv)
{
	struct vmdk_private_data *data;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	/** \todo Consider implementing this */

	return EXT2_ET_UNIMPLEMENTED;
}

static errcode_t
vmdk_discard(io_channel channel, unsigned long long block, 
	     unsigned long long count)
{
	struct vmdk_private_data *data;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_VMDK_IO_CHANNEL);

	/** \todo Consider being more intelligent handling discards */

	return EXT2_ET_UNIMPLEMENTED;
}

static errcode_t
vmdk_read_blk(io_channel channel, unsigned long block, int count, void *data)
{
	return vmdk_read_blk64(channel, block, count, data);
}

static errcode_t
vmdk_write_blk(io_channel channel, unsigned long block, int count,
	       const void *data)
{
	return vmdk_write_blk64(channel, block, count, data);
}


static struct struct_io_manager struct_vmdk_manager = {
	EXT2_ET_MAGIC_IO_MANAGER,
	"VMDK IO manager",
	vmdk_open,
	vmdk_close,
	vmdk_set_blksize,
	vmdk_read_blk,
	vmdk_write_blk,
	vmdk_flush,
	vmdk_write_byte,
	vmdk_set_option,
	vmdk_get_stats,
	vmdk_read_blk64,
	vmdk_write_blk64,
	vmdk_discard,
};

int
vmdk_probe(const char *path)
{
	int fd;
	char buf[4];
	int retval = 0;
       
	fd = ext2fs_open_file(path, O_RDONLY, 0);
	if (fd >= 0) {
		if (read(fd, buf, sizeof(buf)) == sizeof(buf) &&
		    memcmp(buf, "KDMV", sizeof(buf)) == 0) {
			retval = 1;
		}
		close(fd);
	}

	return retval;
}
