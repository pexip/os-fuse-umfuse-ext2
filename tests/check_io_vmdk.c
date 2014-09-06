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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#include <zlib.h>

#include <ext2fs/ext2fs.h>
#include "fuse-ext2.h"

#include "vmdk_harness.h"

#define min(a,b) ((a) < (b) ? (a) : (b))

typedef struct file_s {
	uint8_t *buf;
	uint64_t len;

	ext2_loff_t cursor;

	io_channel channel;
} file_t;

static file_t *test_file;


static const struct disk_descriptor simple_disk_descriptor = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 1,
	.blocks = {
		{ 0, 1024, 10 },
	}
};

static const struct disk_descriptor simple_disk_descriptor_small = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 1,
	.blocks = {
		{ 0, 512, 9 },
	}
};

static const struct disk_descriptor simple_disk_descriptor_large = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 1,
	.blocks = {
		{ 0, 2048, 11 },
	}
};

static const struct disk_descriptor simple_disk_descriptor_2 = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 2,
	.blocks = {
		{          0, 1024, 10 },
		{ GRAIN_SIZE, 2048, 11 },
	}
};

static const struct disk_descriptor simple_disk_descriptor_2_sparse = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 2,
	.blocks = {
		{           0, 1024, 10 },
		{ GT_COVERAGE, 2048, 11 },
	}
};

static const struct disk_descriptor empty_disk_descriptor = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 0,
	.blocks = {}
};

static const struct disk_descriptor high_disk_descriptor = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 1,
	.blocks = {
		{ GT_COVERAGE + GRAIN_SIZE, 2048, 11 },
	}
};

static const struct disk_descriptor high_disk_descriptor_2 = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 2,
	.blocks = {
		{              GT_COVERAGE, 1024, 10 },
		{ GRAIN_SIZE + GT_COVERAGE, 2048, 11 },
	}
};

static const struct disk_descriptor high_disk_descriptor_3 = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 3,
	.blocks = {
		{                        0, 1024, 10 },
		{              GT_COVERAGE, 1024, 10 },
		{ GRAIN_SIZE + GT_COVERAGE, 2048, 11 },
	}
};

static const struct disk_descriptor complex_disk_descriptor = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 7,
	.blocks = {
		{                 GT_COVERAGE, 8192, 13 },
		{    GRAIN_SIZE + GT_COVERAGE,  512,  9 },
		{  2*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{  4*GRAIN_SIZE + GT_COVERAGE, 2048, 11 },
		{  8*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{ 16*GRAIN_SIZE + GT_COVERAGE, 4096, 12 },
		{ 32*GRAIN_SIZE + GT_COVERAGE,  512,  9 },
	}
};

static const struct disk_descriptor complex_disk_descriptor_modified = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 9,
	.blocks = {
		{                           0,  256,  8 },
		{                 GT_COVERAGE,  256,  8 },
		{    GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{  2*GRAIN_SIZE + GT_COVERAGE,  512,  9 },
		{  3*GRAIN_SIZE + GT_COVERAGE,  512,  9 },
		{  4*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{  8*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{ 16*GRAIN_SIZE + GT_COVERAGE, 2048, 11 },
		{ 32*GRAIN_SIZE + GT_COVERAGE,  512,  9 },
	}
};

static const struct disk_descriptor complex_disk_descriptor_move_write = {
	.capacity = 2 * GT_COVERAGE,
	.nblocks = 7,
	.blocks = {
		{                 GT_COVERAGE, 8192, 13 },
		{    GRAIN_SIZE + GT_COVERAGE, 4096, 12 },
		{  2*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{  4*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{  8*GRAIN_SIZE + GT_COVERAGE, 1024, 10 },
		{ 16*GRAIN_SIZE + GT_COVERAGE, 2048, 11 },
		{ 32*GRAIN_SIZE + GT_COVERAGE,  256,  8 },
	}
};


errcode_t
test_ext2fs_get_mem(unsigned long size, void *ptr)
{
	void **pptr = (void **) ptr;
	*pptr = malloc(size);
	if (*pptr == NULL)
		return EXT2_ET_NO_MEMORY;
	return 0;
}

errcode_t
test_ext2fs_free_mem(void *ptr)
{
	void **pptr = (void **) ptr;
	free(*pptr);
	*pptr = NULL;
	return 0;
}

ext2_loff_t
test_ext2fs_llseek(int fd, ext2_loff_t offset, int whence)
{
	ext2_loff_t pos;

	if (fd != 0) {
		errno = EBADF;
		return (ext2_loff_t) -1;
	}

	switch (whence) {
	case SEEK_SET:
		pos = offset;
		break;
	case SEEK_CUR:
		pos = test_file->cursor + offset;
		break;
	case SEEK_END:
		pos = test_file->len + offset;
		break;
	default:
		errno = EINVAL;
		return (ext2_loff_t) -1;
	}

	if (pos < 0) {
		errno = EINVAL;
		return (ext2_loff_t) -1;
	}

	test_file->cursor = pos;

	return pos;
}

int
test_ext2fs_open_file(const char *pathname, int flags, mode_t mode)
{
	if (test_file == NULL) {
		return -1;
	}

	return 0;
}

int
test_close(int fd)
{
	ck_assert_int_eq(fd, 0);
	return 0;
}

int
test_fsync(int fd)
{
	ck_assert_int_eq(fd, 0);
	return 0;
}

ssize_t
test_read(int fd, void *buf, size_t count)
{
	size_t len;
	
	if (test_file->cursor >= test_file->len) {
		return 0;
	}

	len = min(count, test_file->len - test_file->cursor);

	ck_assert_int_eq(fd, 0);
	if (len > 0) {
		memcpy(buf, test_file->buf + test_file->cursor, len);
		test_file->cursor += len;
	}

	return len;
}

ssize_t
test_write(int fd, const void *buf, size_t count)
{
	ck_assert_int_eq(fd, 0);

	if (count < 0 || buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (test_file->cursor + count > test_file->len) {
		uint8_t *temp = realloc(test_file->buf, test_file->cursor + count);
		if (temp == NULL) {
			errno = ENOSPC;
			return -1;
		}
		memset(temp + test_file->len, 0,
		       test_file->cursor + count - test_file->len);
		test_file->len = test_file->cursor + count;
		test_file->buf = temp;
	}

	memcpy(test_file->buf + test_file->cursor, buf, count);
	test_file->cursor += count;

	return count;
}

int
test_ftruncate(int fd, off_t length)
{
	uint8_t *temp;

	ck_assert_int_eq(fd, 0);

	if (length < 0) {
		errno = EINVAL;
		return -1;
	}

	temp = realloc(test_file->buf, length);
	if (temp == NULL) {
		errno = EIO;
		return -1;
	}

	if (length > test_file->len) {
		memset(temp + test_file->len, 0, length - test_file->len);
	}

	test_file->len = length;
	test_file->buf = temp;

	return 0;
}


int
test_compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
{
	if (*destLen < (1 << source[0])) {
		return Z_BUF_ERROR;
	}

	memset(dest, source[0], (1 << source[0]));
	*destLen = (1 << source[0]);

	return Z_OK;
}

int
test_uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
{
	memset(dest, source[0], *destLen);

	return Z_OK;
}


START_TEST(test_io_vmdk_probe_no_file)
{
	int result = vmdk_probe("/does/not/exist");
	ck_assert_int_eq(result, 0);
}
END_TEST


static void
setup_simple_context(void)
{
	test_file = calloc(1, sizeof(file_t));
	fail_unless(test_file != NULL, "Failed allocating test file.");
}

static void
teardown_simple_context(void)
{
	if (test_file->buf != NULL) {
		free(test_file->buf);
	}
	free(test_file);
	test_file = NULL;
}

static void
set_buffer_contents(const char *data, uint64_t len)
{
	if (test_file->buf != NULL) {
		free(test_file->buf);
	}
	test_file->len = len;
	test_file->buf = malloc(len);
	fail_unless(test_file->buf != NULL, "Failed allocating file buffer.");
	memcpy(test_file->buf, data, len);
}

START_TEST(test_io_vmdk_probe_short_read)
{
	int result = vmdk_probe("/path/to/file");
	ck_assert_int_eq(result, 0);
}
END_TEST

START_TEST(test_io_vmdk_probe_bad_header)
{
	int result;

	set_buffer_contents("VMDX", 4);

	result = vmdk_probe("/path/to/file");
	ck_assert_int_eq(result, 0);
}
END_TEST

START_TEST(test_io_vmdk_probe_successful)
{
	int result;

	set_buffer_contents("KDMV", 4);

	result = vmdk_probe("/path/to/file");
	ck_assert_int_eq(result, 1);
}
END_TEST


START_TEST(test_io_vmdk_open_close)
{
	io_channel channel;
	errcode_t err;

	test_file->buf = build_disk(&simple_disk_descriptor, &test_file->len);
	fail_unless(test_file->buf != NULL, "Failed creating test file.");

	err = vmdk_io_manager->open("/path/to/file", 0, &channel);
	ck_assert_int_eq(err, 0);

	err = channel->manager->close(channel);
	ck_assert_int_eq(err, 0);
}
END_TEST


static void
setup_disk_context(const struct disk_descriptor *desc)
{
	errcode_t err;

	setup_simple_context();

	test_file->buf = build_disk(desc, &test_file->len);
	fail_unless(test_file->buf != NULL, "Failed creating test file.");

	err = vmdk_io_manager->open("/path/to/file", IO_FLAG_RW, 
				    &test_file->channel);
	ck_assert_int_eq(err, 0);
}

static void
teardown_disk_context(void)
{
	errcode_t err;

	err = test_file->channel->manager->close(test_file->channel);
	ck_assert_int_eq(err, 0);

	teardown_simple_context();
}

static void
setup_simple_disk_context(void)
{
	setup_disk_context(&simple_disk_descriptor);
}

static void
assert_buffer_contents(const uint8_t *buf, size_t len, uint8_t c)
{
	while (len > 0) {
		ck_assert_int_eq(buf[len-1], c);
		len--;
	}
}

static void
assert_disk_matches(const struct disk_descriptor *control)
{
	uint8_t *buf;
	uint64_t len;
	int result;

	buf = build_disk(control, &len);
	fail_unless(buf != NULL, "Failed creating control.");

	ck_assert_int_eq(test_file->len, len);
	result = memcmp(test_file->buf, buf, len);
#ifdef DUMP_MISMATCHED_FILES
	if (result != 0) {
		FILE *fp;

		fp = fopen("a", "w");
		fwrite(test_file->buf, 1, test_file->len, fp);
		fclose(fp);

		fp = fopen("b", "w");
		fwrite(buf, 1, len, fp);
		fclose(fp);
	}
#endif
	ck_assert_int_eq(result, 0);

	free(buf);
}

START_TEST(test_io_vmdk_basic_read)
{
	uint8_t buf[512];
	errcode_t err;

	err = test_file->channel->manager->read_blk64(test_file->channel,
						      0,
						      1,
						      &buf);
	ck_assert_int_eq(err, 0);

	assert_buffer_contents(buf, sizeof(buf), 10);
}
END_TEST

START_TEST(test_io_vmdk_basic_write)
{
	uint8_t buf[512], fill;
	errcode_t err;

	for (fill = 9; fill <= 10; fill++) {
		memset(buf, fill, sizeof(buf));

		err = test_file->channel->manager->write_blk64(
				test_file->channel,
				0,
				1,
				&buf);
		ck_assert_int_eq(err, 0);

		memset(buf, 0, sizeof(buf));

		err = test_file->channel->manager->read_blk64(
				test_file->channel,
				0,
				1,
				&buf);
		ck_assert_int_eq(err, 0);

		assert_buffer_contents(buf, sizeof(buf), fill);
	}
}
END_TEST

static void
modify_block(uint64_t lba, uint8_t fill)
{
	uint8_t buf[512];
	errcode_t err;

	memset(buf, fill, sizeof(buf));

	err = test_file->channel->manager->write_blk64(
			test_file->channel,
			lba / BYTES_PER_SECTOR,
			1,
			&buf);
	ck_assert_int_eq(err, 0);
}

static void
flush_and_assert(const struct disk_descriptor *desc)
{
	errcode_t err;

	err = test_file->channel->manager->flush(test_file->channel);
	ck_assert_int_eq(err, 0);

	assert_disk_matches(desc);
}

START_TEST(test_io_vmdk_basic_flush)
{
	modify_block(0, 10);
	flush_and_assert(&simple_disk_descriptor);
}
END_TEST

START_TEST(test_io_vmdk_basic_shrink)
{
	modify_block(0, 9);
	flush_and_assert(&simple_disk_descriptor_small);
}
END_TEST

START_TEST(test_io_vmdk_basic_grow)
{
	modify_block(0, 11);
	flush_and_assert(&simple_disk_descriptor_large);
}
END_TEST

START_TEST(test_io_vmdk_basic_insert)
{
	modify_block(GRAIN_SIZE, 11);
	flush_and_assert(&simple_disk_descriptor_2);
}
END_TEST

START_TEST(test_io_vmdk_basic_insert_and_modify)
{
	modify_block(0, 10);
	modify_block(GRAIN_SIZE, 11);
	flush_and_assert(&simple_disk_descriptor_2);
}
END_TEST

START_TEST(test_io_vmdk_basic_insert_sparse)
{
	modify_block(GT_COVERAGE, 11);
	flush_and_assert(&simple_disk_descriptor_2_sparse);
}
END_TEST

START_TEST(test_io_vmdk_block_size)
{
	uint8_t buf[1024];
	errcode_t err;

	memset(buf, 0, sizeof(buf));
	err = test_file->channel->manager->read_blk64(test_file->channel,
						      0,
						      1,
						      &buf);
	ck_assert_int_eq(err, 0);
	assert_buffer_contents(buf, 512, 10);
	assert_buffer_contents(buf + 512, 512, 0);

	err = test_file->channel->manager->set_blksize(test_file->channel,
						       sizeof(buf));
	ck_assert_int_eq(err, 0);

	memset(buf, 0, sizeof(buf));
	err = test_file->channel->manager->read_blk64(test_file->channel,
						      0,
						      1,
						      &buf);
	ck_assert_int_eq(err, 0);
	assert_buffer_contents(buf, sizeof(buf), 10);
}
END_TEST

START_TEST(test_io_vmdk_unimplemented_api)
{
	io_stats stats;
	errcode_t err;

	err = test_file->channel->manager->get_stats(test_file->channel,
						     &stats);
	ck_assert_int_eq(err, 0);

	err = test_file->channel->manager->write_byte(test_file->channel,
						      0,
						      1,
						      NULL);
	ck_assert_int_eq(err, EXT2_ET_UNIMPLEMENTED);

	err = test_file->channel->manager->discard(test_file->channel,
						   0,
						   1);
	ck_assert_int_eq(err, EXT2_ET_UNIMPLEMENTED);
}
END_TEST


static void
setup_empty_disk_context(void)
{
	setup_disk_context(&empty_disk_descriptor);
}

START_TEST(test_io_vmdk_empty_read)
{
	uint8_t buf[512];
	errcode_t err;

	err = test_file->channel->manager->read_blk64(test_file->channel,
						      0,
						      1,
						      &buf);
	ck_assert_int_eq(err, 0);

	assert_buffer_contents(buf, sizeof(buf), 0);
}
END_TEST

START_TEST(test_io_vmdk_empty_write)
{
	uint8_t buf[512];
	errcode_t err;

	modify_block(0, 10);

	err = test_file->channel->manager->read_blk64(test_file->channel,
						      0,
						      1,
						      &buf);
	ck_assert_int_eq(err, 0);

	assert_buffer_contents(buf, sizeof(buf), 10);

	modify_block(GRAIN_SIZE, 11);
	flush_and_assert(&simple_disk_descriptor_2);
}
END_TEST


static void
setup_high_disk_context(void)
{
	setup_disk_context(&high_disk_descriptor);
}

START_TEST(test_io_vmdk_insert_before)
{
	modify_block(GT_COVERAGE, 10);
	flush_and_assert(&high_disk_descriptor_2);
}
END_TEST

START_TEST(test_io_vmdk_new_gt_and_insert)
{
	modify_block(0, 10);
	modify_block(GT_COVERAGE, 10);
	flush_and_assert(&high_disk_descriptor_3);
}
END_TEST

START_TEST(test_io_vmdk_nonzero_offset)
{
	uint8_t buf[512];
	errcode_t err;

	snprintf((char *) &buf, sizeof(buf), "%u", GT_COVERAGE + GRAIN_SIZE);

	err = test_file->channel->manager->set_option(test_file->channel,
						      "offset",
						      (char *) &buf);
	ck_assert_int_eq(err, 0);

	memset(buf, 0, sizeof(buf));
	err = test_file->channel->manager->read_blk64(test_file->channel,
						      0,
						      1,
						      &buf);
	ck_assert_int_eq(err, 0);
	assert_buffer_contents(buf, sizeof(buf), 11);
}
END_TEST

static void
setup_complex_disk_context(void)
{
	setup_disk_context(&complex_disk_descriptor);
}

START_TEST(test_io_vmdk_complex)
{
	/* A combination of new grains, new grain tables, 
	 * and grains growing and shrinking. */
	modify_block(                          0,  8);
	modify_block(                GT_COVERAGE,  8);
	modify_block(   GRAIN_SIZE + GT_COVERAGE, 10);
	modify_block( 2*GRAIN_SIZE + GT_COVERAGE,  9);
	modify_block( 3*GRAIN_SIZE + GT_COVERAGE,  9);
	modify_block( 4*GRAIN_SIZE + GT_COVERAGE, 10);
	modify_block(16*GRAIN_SIZE + GT_COVERAGE, 11);
	modify_block(32*GRAIN_SIZE + GT_COVERAGE,  9);

	flush_and_assert(&complex_disk_descriptor_modified);
}
END_TEST

START_TEST(test_io_vmdk_move_write_dependency)
{
	/* The first modification here will be serialised last, 
	 * because it relies on the subsequent modifications to 
	 * be processed for there to be space in the output disk 
	 * image. */
	modify_block(   GRAIN_SIZE + GT_COVERAGE, 12);
	modify_block( 4*GRAIN_SIZE + GT_COVERAGE, 10);
	modify_block(16*GRAIN_SIZE + GT_COVERAGE, 11);
	modify_block(32*GRAIN_SIZE + GT_COVERAGE,  8);
	flush_and_assert(&complex_disk_descriptor_move_write);
}
END_TEST


static void
test_io_vmdk_create_suite(SRunner *sr)
{
	Suite *s = suite_create("VMDK IO tests");
	TCase *tc;
       
	tc = tcase_create("Context-free");
	tcase_add_test(tc, test_io_vmdk_probe_no_file);
	suite_add_tcase(s, tc);

	tc = tcase_create("Simple context");
	tcase_add_checked_fixture(tc,
				  setup_simple_context,
				  teardown_simple_context);
	tcase_add_test(tc, test_io_vmdk_probe_short_read);
	tcase_add_test(tc, test_io_vmdk_probe_bad_header);
	tcase_add_test(tc, test_io_vmdk_probe_successful);
	tcase_add_test(tc, test_io_vmdk_open_close);
	suite_add_tcase(s, tc);

	tc = tcase_create("Simple disk context");
	tcase_add_checked_fixture(tc,
				  setup_simple_disk_context,
				  teardown_disk_context);
	tcase_add_test(tc, test_io_vmdk_basic_read);
	tcase_add_test(tc, test_io_vmdk_basic_write);
	tcase_add_test(tc, test_io_vmdk_basic_flush);
	tcase_add_test(tc, test_io_vmdk_basic_shrink);
	tcase_add_test(tc, test_io_vmdk_basic_grow);
	tcase_add_test(tc, test_io_vmdk_basic_insert);
	tcase_add_test(tc, test_io_vmdk_basic_insert_and_modify);
	tcase_add_test(tc, test_io_vmdk_basic_insert_sparse);
	tcase_add_test(tc, test_io_vmdk_block_size);
	tcase_add_test(tc, test_io_vmdk_unimplemented_api);
	suite_add_tcase(s, tc);

	tc = tcase_create("Empty disk context");
	tcase_add_checked_fixture(tc,
				  setup_empty_disk_context,
				  teardown_disk_context);
	tcase_add_test(tc, test_io_vmdk_empty_read);
	tcase_add_test(tc, test_io_vmdk_empty_write);
	suite_add_tcase(s, tc);

	tc = tcase_create("High disk context");
	tcase_add_checked_fixture(tc,
				  setup_high_disk_context,
				  teardown_disk_context);
	tcase_add_test(tc, test_io_vmdk_insert_before);
	tcase_add_test(tc, test_io_vmdk_new_gt_and_insert);
	tcase_add_test(tc, test_io_vmdk_nonzero_offset);
	suite_add_tcase(s, tc);

	tc = tcase_create("Complex disk context");
	tcase_add_checked_fixture(tc,
				  setup_complex_disk_context,
				  teardown_disk_context);
	tcase_add_test(tc, test_io_vmdk_complex);
	tcase_add_test(tc, test_io_vmdk_move_write_dependency);
	suite_add_tcase(s, tc);

	srunner_add_suite(sr, s);
}

int
main(void)
{
	int failed_count;
	SRunner *sr;

	sr = srunner_create(suite_create("VMDK IO layer tests"));

	test_io_vmdk_create_suite(sr);

	srunner_run_all(sr, CK_VERBOSE);
	failed_count = srunner_ntests_failed(sr);

	srunner_free(sr);

	return (failed_count == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
