#include <string.h>
#include <unistd.h>

#include <zlib.h>

#include "fuse-ext2.h"

#define EXT2_ET_MAGIC_VMDK_IO_CHANNEL 0x766d6400
#define EXT2_ET_BAD_VMDK 0x766d6401

#define EXT2_CHECK_MAGIC(struct, code) \
	          if ((struct)->magic != (code)) return (code)

#define BYTES_PER_SECTOR 512

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

struct vmdk_modified_grain {
	struct vmdk_modified_grain *next;
	uint64_t lba;
	uint8_t data[0];
};

struct vmdk_private_data {
	int magic;
	int dev;
	int flags;
	ext2_loff_t offset;
	struct struct_io_stats io_stats;

	ext2_loff_t initial_extent;
	ext2_loff_t max_lba;

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
	int retval = 0;
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
	/** \todo mmap instead? */
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

	/** \todo reconstruct vmdk */

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
