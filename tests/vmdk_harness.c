#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmdk_harness.h"

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

struct vmdk_marker {
	uint64_t num_sectors;
	uint32_t size;
	uint32_t type;
	uint8_t pad[496];
} __attribute__((__packed__));

static struct vmdk_sparse_extent_header *
make_header(uint64_t capacity)
{
	struct vmdk_sparse_extent_header *header;

	header = calloc(1, sizeof(struct vmdk_sparse_extent_header));
	if (header != NULL) {
		header->magic = 0x564d444b;
		header->version = 3;
		header->flags = (1 << 17) | (1 << 16) | (1 << 0);
		header->capacity = capacity / BYTES_PER_SECTOR;
		header->grain_size = 128;
		header->descriptor_offset = 1;
		header->descriptor_size = 1;
		header->num_gtes_per_gt = 512;
		header->rgd_offset = 0;
		header->gd_offset = (uint64_t) -1;
		header->overhead = 0; //128;
		header->unclean_shutdown = 0;
		header->single_end_line_char = '\n';
		header->non_end_line_char = ' ';
		header->double_end_line_char1 = '\r';
		header->double_end_line_char2 = '\n';
		header->compress_algorithm = 1;
	}

	return header;
}

static uint8_t *
make_descriptor(uint64_t capacity)
{
	uint8_t *desc;
	size_t capacity_s, cylinders;

	desc = calloc(1, BYTES_PER_SECTOR);
	if (desc == NULL) {
		return desc;
	}

	capacity_s = (capacity + (BYTES_PER_SECTOR - 1)) / BYTES_PER_SECTOR;
	cylinders = (capacity_s + (63 * 255 - 1)) / (63 * 255);

	snprintf((char *) desc,
		 BYTES_PER_SECTOR,
		 "# Disk DescriptorFile\n"
		 "version=1\n"
		 "CID=3ed88b4d\n"
		 "parentCID=ffffffff\n"
		 "createType=\"streamOptimized\"\n"
		 "\n"
		 "# Extent description\n"
		 "RDONLY %zd SPARSE \"generated-stream.vmdk\"\n"
		 "\n"
		 "# The Disk Data Base\n"
		 "#DDB\n"
		 "\n"
		 "ddb.adapterType = \"lsilogic\"\n"
		 "ddb.encoding = \"UTF-8\"\n"
		 "ddb.geometry.sectors = \"63\"\n"
		 "ddb.geometry.heads = \"255\"\n"
		 "ddb.geometry.cylinders = \"%zd\"\n"
		 "ddb.virtualHWVersion = \"4\"\n",
		 capacity_s,
		 cylinders); 

	return desc;
}

uint8_t *
build_disk(const struct disk_descriptor *desc, uint64_t *disk_size)
{
	struct vmdk_marker marker = { 0 };
	struct vmdk_grain_marker gmarker = { 0 };
	struct vmdk_sparse_extent_header *header;
	uint8_t *descriptor;
	uint8_t *rawdisk, *diskp;
	uint32_t *gd, *gt;
	uint64_t extent, gcoverage, gtcoverage, gtsize, gdsize, gtbase;
	uint32_t block_index;

	header = make_header(desc->capacity);
	if (header == NULL) {
		return NULL;
	}

	descriptor = make_descriptor(desc->capacity);
	if (descriptor == NULL) {
		free(header);
		return NULL;
	}

	gcoverage = header->grain_size * BYTES_PER_SECTOR;
	gtcoverage = header->num_gtes_per_gt * gcoverage;
	gtsize = header->num_gtes_per_gt * sizeof(uint32_t);
	gdsize = ((header->capacity * BYTES_PER_SECTOR + gtcoverage - 1) /
		  gtcoverage) * sizeof(uint32_t);

	#define ROUND(x) ((((x) + BYTES_PER_SECTOR - 1) / \
			  BYTES_PER_SECTOR) * BYTES_PER_SECTOR)

	/* Compute how much space we need */
	extent = 2 * BYTES_PER_SECTOR; /* header + descriptor */
	for (block_index = 0, gtbase = 0;
	     block_index < desc->nblocks;
	     block_index++) {
		if (desc->blocks[block_index].lba >= gtbase) {
			/* New grain table needed */
			extent += ROUND(gtsize) + sizeof(struct vmdk_marker);

			/* Skip empty grain tables */
			while (gtbase <= desc->blocks[block_index].lba) {
				gtbase += gtcoverage;
			}
		}

		/* Add on size of block */
		extent += ROUND(sizeof(struct vmdk_grain_marker) + 
				desc->blocks[block_index].size);
	}
	/* Add on size of grain directory */
	extent += ROUND(gdsize) + sizeof(struct vmdk_marker);
	extent += 3 * BYTES_PER_SECTOR; /* footer marker, footer, EOS */

	gt = calloc(1, gtsize);
	if (gt == NULL) {
		free(descriptor);
		free(header);
		return NULL;
	}

	gd = calloc(1, gdsize);
	if (gd == NULL) {
		free(gt);
		free(descriptor);
		free(header);
		return NULL;
	}

	/* Build the disk */
	diskp = rawdisk = calloc(1, extent);
	if (rawdisk == NULL) {
		free(gd);
		free(gt);
		free(descriptor);
		free(header);
		return NULL;
	}

	/* Emit header and descriptor */
	memcpy(diskp, header, sizeof(struct vmdk_sparse_extent_header));
	diskp += sizeof(struct vmdk_sparse_extent_header);
	memcpy(diskp, descriptor, BYTES_PER_SECTOR);
	diskp += BYTES_PER_SECTOR;

	marker.num_sectors = ROUND(gtsize) / BYTES_PER_SECTOR;
	marker.size = 0;
	marker.type = 1; /* Grain table */

	/* Emit blocks */
	for (block_index = 0, gtbase = 0;
	     block_index < desc->nblocks;
	     block_index++) {
		if (desc->blocks[block_index].lba >= gtbase) {
			/* New grain table needed */
			if (block_index > 0) {
				/* Record location in grain directory */
				gd[desc->blocks[block_index - 1].lba /
				   gtcoverage] = (diskp +
						  sizeof(struct vmdk_marker) -
						  rawdisk) /
						 BYTES_PER_SECTOR;

				/* Emit current grain table */
				memcpy(diskp, &marker,
				       sizeof(struct vmdk_marker));
				diskp += sizeof(struct vmdk_marker);
				memcpy(diskp, gt, gtsize);
				diskp += ROUND(gtsize);

				memset(gt, 0, gtsize);
			}

			/* Skip empty grain tables */
			while (gtbase <= desc->blocks[block_index].lba) {
				gtbase += gtcoverage;
			}
		}

		/* Record block location in grain table */
		gt[(desc->blocks[block_index].lba % gtcoverage) /
		   gcoverage] = (diskp - rawdisk) / BYTES_PER_SECTOR;

		/* Emit block */
		gmarker.lba = desc->blocks[block_index].lba / BYTES_PER_SECTOR;
		gmarker.size = desc->blocks[block_index].size;
		memcpy(diskp, &gmarker, sizeof(struct vmdk_grain_marker));
		memset(diskp + sizeof(struct vmdk_grain_marker), 
		       desc->blocks[block_index].fill,
		       desc->blocks[block_index].size);
		diskp += ROUND(sizeof(struct vmdk_grain_marker) + 
				desc->blocks[block_index].size);
	}

	if (block_index > 0) {
		/* Record final grain table location in grain directory */
		gd[desc->blocks[block_index - 1].lba / gtcoverage] = 
				(diskp + sizeof(struct vmdk_marker) - rawdisk) /
				BYTES_PER_SECTOR;

		/* Emit final grain table */
		memcpy(diskp, &marker, sizeof(struct vmdk_marker));
		diskp += sizeof(struct vmdk_marker);
		memcpy(diskp, gt, gtsize);
		diskp += ROUND(gtsize);
	}

	/* Emit grain directory marker */
	marker.num_sectors = ROUND(gdsize) / BYTES_PER_SECTOR;
	marker.size = 0;
	marker.type = 2; /* Grain directory */
	memcpy(diskp, &marker, sizeof(struct vmdk_marker));
	diskp += sizeof(struct vmdk_marker);

	/* Record grain directory location in footer */
	header->gd_offset = (diskp - rawdisk) / BYTES_PER_SECTOR;

	/* Emit grain directory */
	memcpy(diskp, gd, gdsize);
	diskp += ROUND(gdsize);

	/* Emit footer marker */
	marker.num_sectors = 1;
	marker.size = 0;
	marker.type = 3; /* Footer */
	memcpy(diskp, &marker, sizeof(struct vmdk_marker));
	diskp += sizeof(struct vmdk_marker);

	/* Emit footer */
	memcpy(diskp, header, sizeof(struct vmdk_sparse_extent_header));
	diskp += sizeof(struct vmdk_sparse_extent_header);

	/* Emit EOS marker */
	marker.num_sectors = 0;
	marker.size = 0;
	marker.type = 0;
	memcpy(diskp, &marker, sizeof(struct vmdk_marker));
	diskp += sizeof(struct vmdk_marker);

	assert(diskp - rawdisk == extent);

	/* Clean up */
	free(gd);
	free(gt);
	free(descriptor);
	free(header);

	*disk_size = extent;
	return rawdisk;
}


