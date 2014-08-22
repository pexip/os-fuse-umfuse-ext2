TESTS_ENVIRONMENT = 

if HAVE_VALGRIND
TESTS_ENVIRONMENT += \
	$(VALGRIND_PATH) -q --error-exitcode=1 \
	--tool=memcheck --leak-check=full --trace-children=yes \
	--leak-resolution=high --num-callers=10
check-valgrind: check
else
check-valgrind:
	@true
endif

if HAVE_CHECK
AM_CPPFLAGS = -I$(top_srcdir)/fuse-ext2

TESTS = check_io_vmdk

check_PROGRAMS = \
	check_io_vmdk

check_io_vmdk_SOURCES = \
	check_io_vmdk.c \
	$(top_srcdir)/fuse-ext2/io_vmdk.c
check_io_vmdk_CFLAGS = \
	-Wall @CHECK_CFLAGS@ @GCOV_CFLAGS@
check_io_vmdk_LDADD = \
	-lz @CHECK_LIBS@ @GCOV_LIBS@

endif
