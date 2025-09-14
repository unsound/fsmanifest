/*-
 * fsmanifest.c - Tool generating metadata / content manifests for file trees.
 *
 * Copyright (c) 2023 Erik Larsson
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__APPLE__) || defined(__DARWIN__)
#define IS_MACOS 1
#else
#define IS_MACOS 0
#endif

#if defined(__linux__)
#define IS_LINUX 1
#else
#define IS_LINUX 0
#endif

#if defined(__FreeBSD__)
#define IS_BSD 1
#else
#define IS_BSD 0
#endif

#if (defined(sun) || defined(__sun)) && (defined(__SVR4) || defined(__svr4__))
#define IS_SOLARIS 1
#else
#define IS_SOLARIS 0
#endif

/* Headers - C standard library */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Headers - POSIX / UNIX */
#include <dirent.h>
#include <grp.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#if IS_BSD
#include <sys/extattr.h>
#endif
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#if IS_SOLARIS
#include <sys/statvfs.h>
#endif
#if IS_LINUX || IS_SOLARIS
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#endif
#if IS_LINUX || IS_MACOS
#include <sys/xattr.h>
#endif

/* Headers - macOS */
#if IS_MACOS
#include <CommonCrypto/CommonDigest.h>
#endif

/* Headers - OpenSSL */
#if !IS_MACOS
#include <openssl/evp.h>
#if 0
#include <openssl/types.h>
#endif
#endif

#ifndef SHOW_ALL_FIELDS
#define SHOW_ALL_FIELDS 0
#endif

#if IS_LINUX || IS_SOLARIS || IS_BSD
#define st_atimespec st_atim
#define st_mtimespec st_mtim
#define st_ctimespec st_ctim
#define O_SYMLINK O_NOFOLLOW
#endif

#if IS_SOLARIS
#define statfs statvfs
#endif

typedef struct queue_item queue_item;
struct queue_item {
	queue_item *parent_item;
	char *name;
	size_t name_length;
	int fd;
	size_t refcount;
	queue_item *next_item;
};

/**
 * Print a partial line with no line ending.
 */
#define print(fmt, ...) \
	fprintf(stdout, fmt, ##__VA_ARGS__)

/**
 * Print one formatted line.
 */
#define println(fmt, ...) \
	fprintf(stdout, fmt "\n", ##__VA_ARGS__)

/**
 * Print a partial line with indented prefix and no line ending.
 */
#define printi(fmt, ...) \
	fprintf(stdout, "\t" fmt, ##__VA_ARGS__)

/**
 * Print one formatted line, indented.
 */
#define printlni(fmt, ...) \
	printi(fmt "\n", ##__VA_ARGS__)

/**
 * Print one formatted line, indented twice.
 */
#define printlnii(fmt, ...) \
	fprintf(stdout, "\t\t" fmt "\n", ##__VA_ARGS__)

/**
 * Print one formatted line, indented thrice.
 */
#define printlniii(fmt, ...) \
	fprintf(stdout, "\t\t\t" fmt "\n", ##__VA_ARGS__)

#define print_error(fmt, ...) \
	fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define print_perror(err, fmt, ...) \
	fprintf(stderr, fmt ": %s (%d)\n", ##__VA_ARGS__, strerror(err), err)

static int queue_item_create(
		queue_item *parent_item,
		const char *name,
		queue_item **out_item)
{
	int err = 0;
	queue_item *item = NULL;

	item = malloc(sizeof(queue_item));
	if(!item) {
		print_perror(errno, "Memory allocation error");
		err = (err = errno) ? errno : ENOMEM;
		goto out;
	}

	memset(item, 0, sizeof(*item));
	item->name = strdup(name);
	if(!item->name) {
		print_perror(errno, "Error duplicating name");
		goto out;
	}

	if(parent_item) {
		++parent_item->refcount;
	}
	item->parent_item = parent_item;
	item->name_length = strlen(name);
	item->fd = -1,
	item->refcount = 1;
	*out_item = item;
	item = NULL;
out:
	if(item) {
		if(item->name) {
			free(item->name);
		}

		free(item);
	}
	return err;
}

static void queue_item_release(queue_item **item)
{
	if((*item)->refcount && --(*item)->refcount) {
		return;
	}

	if((*item)->parent_item) {
		/* Note: Recursive release. Might be better off queued. */
		queue_item_release(&(*item)->parent_item);
	}

	if((*item)->fd != -1) {
		close((*item)->fd);
		(*item)->fd = -1;
	}

	if((*item)->name) {
		free((*item)->name);
	}

	free(*item);
	*item = NULL;
}

static int queue_item_open(
		queue_item *item,
		const char *item_path,
		int flags)
{
	int err = 0;

	item->fd =
#ifdef HAVE_OPENAT
		item->parent_item ?
		openat(item->parent_item->fd, item->name, flags) :
#endif
		open(item_path, flags);
#if IS_LINUX
	if(item->fd == -1) {
		item->fd =
#ifdef HAVE_OPENAT
			item->parent_item ?
			openat(item->parent_item->fd, item->name,
			flags | O_PATH) :
#endif
			open(item_path, flags | O_PATH);
	}
#endif
	if(item->fd == -1) {
		err = (err = errno) ? err : EIO;
	}

	return err;
}

static ssize_t queue_item_listxattr(
		queue_item *item,
		const char *item_path,
#if IS_BSD
		int namespace,
#endif
		char *xattr_list,
		size_t xattr_list_size)
{
#if IS_MACOS || IS_LINUX
	return (item->fd != -1) ?
		flistxattr(
			item->fd,
			xattr_list,
			xattr_list_size
#if IS_MACOS
			, 0
#endif
			) :
		listxattr(
			item_path,
			xattr_list,
			xattr_list_size
#if IS_MACOS
			, 0
#endif
			);
#elif IS_BSD
	ssize_t ret;

	ret = (item->fd != -1) ?
		extattr_list_fd(
			item->fd,
			namespace,
			xattr_list,
			xattr_list_size) :
		extattr_list_link(
			item_path,
			namespace,
			xattr_list,
			xattr_list_size);
	if(ret > 0 && xattr_list) {
		/* The FreeBSD xattr list format is different from the
		 * Linux/macOS/Solaris format. It leads each entry with a length
		 * byte and doesn't NULL-terminate each string. Luckily for us
		 * we can easily transform it in place to the Linux format by
		 * shifting the entry back by one byte and write a NULL
		 * terminator in the last byte. This avoids a lot of custom code
		 * paths for FreeBSD. */
		ssize_t i = 0;
		while(i < ret) {
			char *const entry = &xattr_list[i];
			const unsigned char length = *((unsigned char*) entry);

			print_error("Got %hhu-byte xattr entry: %.*s...",
				length, length, &entry[1]);

			memmove(&entry[0], &entry[1], length);
			entry[length] = '\0';

			i += 1 + length;
		}
	}

	return ret;
#elif IS_SOLARIS
	int err = 0;
	ssize_t res = 0;
	int xattr_fd = -1;
	DIR *xattr_dirp = NULL;
	struct dirent *xattr_dp = NULL;

	if(item->fd != -1) {
		xattr_fd = openat(item->fd, ".", O_RDONLY | O_XATTR);
	}
	else {
		xattr_fd = attropen(item_path, ".", O_RDONLY | O_NOFOLLOW);
	}
	if(xattr_fd == -1) {
		err = (err = errno) ? err : EIO;
		goto out;
	}

	/* There doesn't seem to be a way of querying the size of the list of
	 * extended attributes in Solaris without actually reading the list. */

	xattr_dirp = fdopendir(xattr_fd);
	if(!xattr_dirp) {
		err = (err = errno) ? err : EIO;
		goto out;
	}

	errno = 0;
	while((xattr_dp = readdir(xattr_dirp))) {
		const size_t name_length = strlen(xattr_dp->d_name);

		if(xattr_dp->d_name[0] == '.' && (xattr_dp->d_name[1] == '\0' ||
			(xattr_dp->d_name[1] == '.' &&
			xattr_dp->d_name[2] == '\0')))
		{
			/* Skip over '.' and '..' entries. */
			continue;
		}

		if(xattr_list_size) {
			size_t copy_length;
			if(xattr_list_size - (size_t) res < (name_length + 1)) {
				copy_length =
					(size_t) (xattr_list_size -
					(size_t) res);
			}
			else {
				copy_length = name_length + 1;
			}

			memcpy(&xattr_list[res], xattr_dp->d_name, copy_length);
			res += copy_length;
		}
		else {
			res += name_length + 1;
		}

		errno = 0;
	}

	if(errno) {
		err = errno;
		goto out;
	}
out:
	if(xattr_dirp != NULL) {
		closedir(xattr_dirp);
	}
	else if(xattr_fd != -1) {
		close(xattr_fd);
	}

	if(err) {
		errno = err;
	}

	return err ? -1 : res;
#endif /* IS_MACOS || IS_LINUX ... IS_BSD ... IS_SOLARIS */
}

static ssize_t queue_item_getxattr(
		queue_item *item,
		const char *item_path,
#if IS_BSD
		int namespace,
#endif
		const char *name,
		char *value,
		size_t size)
{
#if IS_MACOS || IS_LINUX
	return (item->fd != -1) ?
		fgetxattr(
			item->fd,
			name,
			value,
			size
#if IS_MACOS
			, 0, 0
#endif
			) :
		getxattr(
			item_path,
			name,
			value,
			size
#if IS_MACOS
			, 0, 0
#endif
			);
#elif IS_BSD
	return (item->fd != -1) ?
		extattr_get_fd(
			item->fd,
			namespace,
			name,
			value,
			size) :
		extattr_get_link(
			item_path,
			namespace,
			name,
			value,
			size);
#elif IS_SOLARIS
	int err = 0;
	ssize_t res = 0;
	int xattr_fd = -1;

	if(item->fd != -1) {
		xattr_fd = openat(item->fd, name, O_RDONLY | O_XATTR);
	}
	else {
		xattr_fd = attropen(item_path, name, O_RDONLY);
	}
	if(xattr_fd == -1) {
		err = (err = errno) ? err : EIO;
		goto out;
	}

	if(!size) {
		struct stat stbuf;

		memset(&stbuf, 0, sizeof(stbuf));

		if(fstat(xattr_fd, &stbuf)) {
			err = (err = errno) ? err : EIO;
			goto out;
		}

		res = (ssize_t) stbuf.st_size;
	}
	else {
		res = read(xattr_fd, value, size);
		if(res < 0) {
			err = (err = errno) ? err : EIO;
			goto out;
		}
	}
out:
	if(xattr_fd != -1) {
		close(xattr_fd);
	}

	if(err) {
		errno = err;
	}

	return err ? -1 : res;
#endif /* IS_MACOS || IS_LINUX ... IS_BSD ... IS_SOLARIS */
}

static int compare_queue_items(const void *_a, const void *_b)
{
	const queue_item *a = *((const queue_item**) _a);
	const queue_item *b = *((const queue_item**) _b);

	return strcmp(a->name, b->name);
}

#if IS_MACOS
typedef CC_SHA512_CTX sha512_context;
#else
typedef EVP_MD_CTX* sha512_context;
#endif

static int sha512_init(sha512_context *ctx)
{
#if IS_MACOS
	CC_SHA512_Init(ctx);
#else
	const EVP_MD *digest = NULL;

#if 1
	digest = EVP_sha512();
#else
	digest = EVP_get_digestbyname("sha512");
#endif
	if(!digest) {
		return ENOTSUP;
	}

	*ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(*ctx, digest, NULL);
#endif
	return 0;
}

static int sha512_update(sha512_context *ctx, const char *data, size_t length)
{
#if IS_MACOS
	CC_SHA512_Update(ctx, data, length);
#else
	if(!EVP_DigestUpdate(*ctx, data, length)) {
		return EIO; /* ...? There's no plausible failure mode here. */
	}
#endif

	return 0;
}

static int sha512_finalize(sha512_context *ctx, unsigned char hash[64])
{
#if IS_MACOS
	CC_SHA512_Final(hash, ctx);
#else
	unsigned int len = 0;

	if(!EVP_DigestFinal_ex(*ctx, hash, &len)) {
		return EIO; /* ...? There's no plausible failure mode here. */
	}
	else if(len != 64) {
		return EIO;
	}

	EVP_MD_CTX_destroy(*ctx);
	*ctx = NULL;
#endif

	return 0;
}

static int compare_strings(const void *_a, const void *_b)
{
	char *a = *((char**) _a);
	char *b = *((char**) _b);

	return strcmp(a, b);
}

static int build_path(queue_item *item, char **out_path)
{
	int err = 0;
	char *path = NULL;
	size_t path_length = 0;
	size_t path_size = 4096;
	queue_item *cur_item = item;

	path = malloc(path_size);
	if(!path) {
		err = (err = errno) ? err : ENOMEM;
		goto out;
	}

	while(cur_item) {
		size_t name_length = cur_item->name_length;

		/* Trim trailing '/':es from root item. */
		if(!cur_item->parent_item) {
			while(name_length &&
				cur_item->name[name_length - 1] == '/')
			{
				--name_length;
			}
		}

		if(path_size - path_length < name_length + 2) {
			/* Expand 'path'. */
			char *new_path;

			path_size =
				MAX(path_size ? path_size * 2 : 4096,
				path_length + name_length + 2);
			new_path = realloc(path, path_size);
			if(!new_path) {
				err = (err = errno) ? err : ENOMEM;
				goto out;
			}

			path = new_path;
		}

		/* Note: Inefficient... should iterate from bottom to top but
		 * need a stack for that (we could recurse...). */
		if(path_length) {
			memmove(&path[name_length + 1], path, path_length + 1);
		}
		else {
			path[name_length + 2] = '\0';
		}

		snprintf(path, name_length + 1, "%s", cur_item->name);
		if(path_length || (!cur_item->parent_item && !name_length)) {
			path[name_length] = '/';
			path_length += name_length + 1;
		}
		else {
			path_length += name_length;
		}

		cur_item = cur_item->parent_item;
	}

	/* Shrink 'path' down to actual size. */
	if(path_length < path_size - 1) {
		char *new_path;

		new_path = realloc(path, path_length + 1);
		if(!new_path) {
			err = (err = errno) ? err : ENOMEM;
			goto out;
		}

		path = new_path;
		path_size = path_length + 1;
	}

	*out_path = path;
out:
	if(err && path) {
		free(path);
	}

	return err;
}

static const char* get_modestring(mode_t m)
{
	static char s[11];

	switch(m & S_IFMT) {
	case S_IFIFO:
		s[0] = 'p';
		break;
	case S_IFCHR:
		s[0] = 'c';
		break;
	case S_IFDIR:
		s[0] = 'd';
		break;
	case S_IFBLK:
		s[0] = 'b';
		break;
	case S_IFREG:
		s[0] = '-';
		break;
	case S_IFLNK:
		s[0] = 'l';
		break;
	case S_IFSOCK:
		s[0] = 's';
		break;
#ifdef S_IFWHT
	case S_IFWHT:
		s[0] = 'w';
		break;
#endif
	default:
		s[0] = '?';
	}
	s[1] = (m & 0400) ? 'r' : '-';
	s[2] = (m & 0200) ? 'w' : '-';
	s[3] = (m & 0100) ? (m & 04000 ? 's' : 'x') : (m & 04000 ? 'S' : '-');
	s[4] = (m & 0040) ? 'r' : '-';
	s[5] = (m & 0020) ? 'w' : '-';
	s[6] = (m & 0010) ? (m & 02000 ? 's' : 'x') : (m & 02000 ? 'S' : '-');
	s[7] = (m & 0004) ? 'r' : '-';
	s[8] = (m & 0002) ? 'w' : '-';
	s[9] = (m & 0001) ? (m & 01000 ? 't' : 'x') : (m & 01000 ? 'T' : '-');
	s[10] = '\0';

	return s;
}

static const char* get_ctime(time_t t)
{
	char *ctime_string = ctime(&t);
	ctime_string[strlen(ctime_string) - 1] = '\0';
	return ctime_string;
}

static int matches_mountpoint(
		const struct statfs *const mountinfo,
		const char *const cur_path,
		int *out_is_mountpoint)
{
	int err = 0;
	struct statfs stbuf;

	memset(&stbuf, 0, sizeof(stbuf));

	if(statfs(cur_path, &stbuf)) {
		print_perror(errno, "Error while getting statfs info for "
			"directory");
		err = (err = errno) ? err : EIO;
		goto out;
	}

	*out_is_mountpoint =
		memcmp(&mountinfo->f_fsid, &stbuf.f_fsid, sizeof(stbuf.f_fsid))
		? 1 : 0;
out:
	return err;
}

int main(int argc, char** argv)
{
	static const int open_flags = O_RDONLY | O_NONBLOCK | O_SYMLINK;
#if IS_BSD
	const int namespaces[2] = {
		EXTATTR_NAMESPACE_USER,
		EXTATTR_NAMESPACE_SYSTEM,
	};
#endif

	int ret = (EXIT_FAILURE);
	int err = 0;
	struct statfs mountinfo;
	const char *root_path = NULL;
	char *cur_path = NULL;
	queue_item *root_item = NULL;
	queue_item *queue = NULL;
	queue_item *item = NULL;
#if IS_BSD
	size_t n = 0;
#endif
	char *xattr_list = NULL;

	memset(&mountinfo, 0, sizeof(mountinfo));

	if(argc != 2) {
		print_error("usage: fsmanifest <root>");
		goto out;
	}

	root_path = argv[1];

	if(statfs(root_path, &mountinfo)) {
		print_perror(errno, "Error while getting mount info");
		goto out;
	}

	err = queue_item_create(NULL, root_path, &root_item);
	if(err) {
		print_perror(err, "Error while creating root queue item");
		goto out;
	}

	for(queue = root_item; queue; queue_item_release(&item)) {
		struct stat stbuf;
#ifdef HAVE_STATX
		struct statx stxbuf;
#endif
#if SHOW_ALL_FIELDS
		uint32_t blksize = 0;
#endif /* SHOW_ALL_FIELDS */
		uint32_t nlink = 0;
		uint32_t uid = 0;
		uint32_t gid = 0;
		uint16_t mode = 0;
#if SHOW_ALL_FIELDS
		uint64_t ino = 0;
#endif /* SHOW_ALL_FIELDS */
		uint64_t size = 0;
#if SHOW_ALL_FIELDS
		uint64_t blocks = 0;
#endif /* SHOW_ALL_FIELDS */
		uint64_t atimesec = 0;
		uint32_t atimensec = 0;
#if IS_MACOS || defined(HAVE_STATX)
		uint64_t btimesec = 0;
		uint32_t btimensec = 0;
#endif /* IS_MACOS || defined(HAVE_STATX) */
		uint64_t ctimesec = 0;
		uint32_t ctimensec = 0;
		uint64_t mtimesec = 0;
		uint32_t mtimensec = 0;
		uint32_t rdev_major = 0;
		uint32_t rdev_minor = 0;
#if SHOW_ALL_FIELDS
		uint32_t dev_major = 0;
		uint32_t dev_minor = 0;
#endif /* SHOW_ALL_FIELDS */

		memset(&stbuf, 0, sizeof(stbuf));
#ifdef HAVE_STATX
		memset(&stxbuf, 0, sizeof(stxbuf));
#endif

		item = queue->next_item;

		if(cur_path) {
			free(cur_path);
		}

		err = build_path(queue, &cur_path);
		if(err) {
			print_perror(err, "Error while building path for queue "
				"item %p (\"%s\")", queue, queue->name);
			goto out;
		}

		/* Detach the head of 'queue' and put it in 'item'. */
		item = queue;
		queue = queue->next_item;

		err = queue_item_open(item, cur_path,
			(item == root_item) ? O_RDONLY : open_flags);
		if(err && lstat(cur_path, &stbuf)) {
			print_perror(err, "Error while opening \"%s\"",
				cur_path);
			continue;
		}
#ifdef HAVE_STATX
		else if(item->fd != -1 && statx(
			item->fd,
			"",
			AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
			STATX_ALL,
			&stxbuf))
		{
			print_perror(errno, "Error while statx:ing \"%s\"",
				cur_path);
			continue;
		}
#endif
		else if(item->fd != -1 && fstat(item->fd, &stbuf)) {
			print_perror(errno, "Error while stat:ing \"%s\"",
				cur_path);
			continue;
		}

		/* Print relevant fields in struct stat/statx. */
		{
#if SHOW_ALL_FIELDS
			blksize =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_blksize :
#endif
				stbuf.st_blksize;
#endif /* SHOW_ALL_FIELDS */
			nlink =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_nlink :
#endif
				stbuf.st_nlink;
			uid =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_uid :
#endif
				stbuf.st_uid;
			gid =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_gid :
#endif
				stbuf.st_gid;
			mode =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_mode :
#endif
				stbuf.st_mode;
#if SHOW_ALL_FIELDS
			ino =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_ino :
#endif
				stbuf.st_ino;
#endif /* SHOW_ALL_FIELDS */
			size =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_size :
#endif
				stbuf.st_size;
#if SHOW_ALL_FIELDS
			blocks =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_blocks :
#endif
				stbuf.st_blocks;
#endif /* SHOW_ALL_FIELDS */
			atimesec =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_atime.tv_sec :
#endif
				stbuf.st_atimespec.tv_sec;
			atimensec =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_atime.tv_nsec :
#endif
				stbuf.st_atimespec.tv_nsec;
#if IS_MACOS || defined(HAVE_STATX)
			btimesec =
#ifdef HAVE_STATX
				stxbuf.stx_btime.tv_sec;
#else
				stbuf.st_birthtimespec.tv_sec;
#endif /* defined(HAVE_STATX) ... */
			btimensec =
#ifdef HAVE_STATX
				stxbuf.stx_btime.tv_nsec;
#else
				stbuf.st_birthtimespec.tv_nsec;
#endif /* defined(HAVE_STATX) ... */
#endif /* IS_MACOS || defined(HAVE_STATX) */
			ctimesec =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_ctime.tv_sec :
#endif
				stbuf.st_ctimespec.tv_sec;
			ctimensec =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_ctime.tv_nsec :
#endif
				stbuf.st_ctimespec.tv_nsec;
			mtimesec =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_mtime.tv_sec :
#endif
				stbuf.st_mtimespec.tv_sec;
			mtimensec =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_mtime.tv_nsec :
#endif
				stbuf.st_mtimespec.tv_nsec;
			rdev_major =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_rdev_major :
#endif
				major(stbuf.st_rdev);
			rdev_minor =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_rdev_minor :
#endif
				minor(stbuf.st_rdev);
#if SHOW_ALL_FIELDS
			dev_major =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_dev_major :
#endif
				major(stbuf.st_dev);
			dev_minor =
#ifdef HAVE_STATX
				stxbuf.stx_mask ? stxbuf.stx_dev_minor :
#endif
				minor(stbuf.st_dev);
#endif /* SHOW_ALL_FIELDS */
			const char *ctime_str = NULL;

			println("%s:", cur_path);
#if SHOW_ALL_FIELDS
			printlni("Root filesystem device number: (%lu, %lu)",
				(unsigned long) dev_major,
				(unsigned long) dev_minor);
#endif
			printlni("Access mode: 0%llo (%s)",
				(unsigned long long) mode,
				get_modestring(mode));
#if !SHOW_ALL_FIELDS
			/* The st_nlink field of directories is populated
			 * differently by different filesystems and cannot be
			 * relied on for cross-filesystem manifests. */
			if((mode & S_IFMT) != S_IFDIR)
#endif
			{
				printlni("Number of links: %llu",
					(unsigned long long) nlink);
			}
#if SHOW_ALL_FIELDS
			/* The inode number is assigned automatically by the
			 * filesystem and cannot be expected to be the same for
			 * two file trees. */
			printlni("Inode number: %llu",
				(unsigned long long) ino);
#endif
			{
				struct passwd *pw = NULL;

				err = 0;
				errno = 0;
				pw = getpwuid(uid);
				if(!pw && errno) {
					err = errno;
					print_perror(err, "Error while looking "
						"up user name for uid %llu",
						(unsigned long long)
						uid);
				}

				printlni("Owner User ID: %llu%s%s%s",
					(unsigned long long) uid,
					pw ? " (" : "",
					pw ? pw->pw_name :
					(err ? " <error getting user name>" :
					""),
					pw ? ")" : "");
			}

			{
				struct group *gr = NULL;

				err = 0;
				errno = 0;
				gr = getgrgid(gid);
				if(!gr && errno) {
					err = errno;
					print_perror(err, "Error while looking "
						"up group name for gid %llu",
						(unsigned long long)
						gid);
				}

				printlni("Owner Group ID: %llu%s%s%s",
					(unsigned long long) gid,
					gr ? " (" : "",
					gr ? gr->gr_name :
					(err ? " <error getting group name>" :
					""),
					gr ? ")" : "");
			}
#if !SHOW_ALL_FIELDS
			if((mode & S_IFMT) == S_IFBLK ||
				(mode & S_IFMT) == S_IFCHR)
#endif
			{
				printlni("Device number: (%llu, %llu)",
					(unsigned long long) rdev_major,
					(unsigned long long) rdev_minor);
			}
			ctime_str = get_ctime(atimesec);
			printlni("Last access time: { %lld, %lld } "
				"(%.*s.%09lld%.*s)",
				(long long) atimesec,
				(long long) atimensec,
				19, ctime_str,
				(long long) atimensec,
				5, &ctime_str[19]);
			ctime_str = get_ctime(mtimesec);
			printlni("Last modification time: { %lld, %lld } "
				"(%.*s.%09lld%.*s)",
				(long long) mtimesec,
				(long long) mtimensec,
				19, ctime_str,
				(long long) mtimensec,
				5, &ctime_str[19]);
			ctime_str = get_ctime(ctimesec);
			printlni("Last metadata change time: { %lld, %lld } "
				"(%.*s.%09lld%.*s)",
				(long long) ctimesec,
				(long long) ctimensec,
				19, ctime_str,
				(long long) ctimensec,
				5, &ctime_str[19]);
#if IS_MACOS || defined(HAVE_STATX)
#ifdef HAVE_STATX
			if(stxbuf.stx_mask & STATX_BTIME)
#endif
			{
				ctime_str = get_ctime(btimesec);
				printlni("Creation time: { %lld, %lld } "
					"(%.*s.%09lld%.*s)",
					(long long) btimesec,
					(long long) btimensec,
					19, ctime_str,
					(long long) btimensec,
					5, &ctime_str[19]);
			}
#endif /* IS_MACOS || defined(HAVE_STATX) */
#if !SHOW_ALL_FIELDS
			/* The st_size field of directories is populated
			 * differently by different filesystems and cannot be
			 * relied on for cross-filesystem manifests. */
			if((mode & S_IFMT) != S_IFDIR)
#endif
			{
				printlni("Size: %llu bytes",
					(unsigned long long) size);
			}
#if SHOW_ALL_FIELDS
			/* The st_blocks field depends on the underlying
			 * filesystem block size and characteristics and cannot
			 * be relied on for cross-filesystem manifests. */
			printlni("Number of blocks: %llu",
				(unsigned long long) blocks);
#endif
#if SHOW_ALL_FIELDS
			/* The st_blksize field depends on the underlying
			 * filesystem characteristics and cannot be relied on
			 * for cross-filesystem manifests. */
			printlni("Block size: %llu",
				(unsigned long long) blksize);
#endif
#if IS_MACOS || defined(BSD)
			{
				uint32_t flags = stbuf.st_flags;

				printi("BSD flags: 0x%llX%s",
					(unsigned long long) stbuf.st_flags,
					stbuf.st_flags ? " (macOS:" : "");
				if(flags & UF_NODUMP) {
					print(" nodump");
					flags &= ~UF_NODUMP;
				}
				if(flags & UF_IMMUTABLE) {
					print(" uchg");
					flags &= ~UF_IMMUTABLE;
				}
				if(flags & UF_APPEND) {
					print(" uappnd");
					flags &= ~UF_APPEND;
				}
				if(flags & UF_OPAQUE) {
					print(" opaque");
					flags &= ~UF_OPAQUE;
				}
#ifdef UF_COMPRESSED
				if(flags & UF_COMPRESSED) {
					print(" compressed");
					flags &= ~UF_COMPRESSED;
				}
#endif
#ifdef UF_TRACKED
				if(flags & UF_TRACKED) {
					print(" tracked");
					flags &= ~UF_TRACKED;
				}
#endif
#ifdef UF_DATAVAULT
				if(flags & UF_DATAVAULT) {
					print(" datavault");
					flags &= ~UF_DATAVAULT;
				}
#endif
				if(flags & UF_HIDDEN) {
					print(" hidden");
					flags &= ~UF_HIDDEN;
				}
				if(flags & SF_ARCHIVED) {
					print(" arch");
					flags &= ~SF_ARCHIVED;
				}
				if(flags & SF_IMMUTABLE) {
					print(" schg");
					flags &= ~SF_IMMUTABLE;
				}
				if(flags & SF_APPEND) {
					print(" sappnd");
					flags &= ~SF_APPEND;
				}
#ifdef SF_RESTRICTED
				if(flags & SF_RESTRICTED) {
					print(" restricted");
					flags &= ~SF_RESTRICTED;
				}
#endif
#ifdef SF_NOUNLINK
				if(flags & SF_NOUNLINK) {
					print(" nounlink");
					flags &= ~SF_NOUNLINK;
				}
#endif
#ifdef SF_FIRMLINK
				if(flags & SF_FIRMLINK) {
					print(" firmlink");
					flags &= ~SF_FIRMLINK;
				}
#endif
#ifdef SF_DATALESS
				if(flags & SF_DATALESS) {
					print(" dataless");
					flags &= ~SF_DATALESS;
				}
#endif
				if(flags) {
					print(" 0x%X", flags);
				}
				if(stbuf.st_flags) {
					print(")");
				}
				println("");
			}
#endif
#if SHOW_ALL_FIELDS
			/* The st_gen field is closely related to st_ino and is
			 * automatically tracked and updated by the filesystem.
			 * It cannot be expected to be the same for any two
			 * otherwise identical filesystem trees. */
			printlni("Generation: %llu",
				(unsigned long long) stbuf.st_gen);
#endif
#if SHOW_ALL_FIELDS
			/* These are fields without any defined meaning, meant
			 * for future expansion. They can be ignored. */
			printlni("st_lspare: 0x%llX",
				(unsigned long long) stbuf.st_lspare);
			printlni("st_qspare[2]: { 0x%llX, 0x%llX }",
				(unsigned long long) stbuf.st_qspare[0],
				(unsigned long long) stbuf.st_qspare[1]);
#endif

			/* Hash the file data / print the symlink target. */
			if(item->fd != -1 &&
				(mode & S_IFMT) == S_IFREG)
			{
				static const size_t buf_size = 1024UL * 1024UL;
				char *buf = NULL;
				sha512_context sha512_ctx;
				uint8_t h[64];

				memset(&sha512_ctx, 0, sizeof(sha512_ctx));

				buf = malloc(buf_size);
				if(!buf) {
					print_perror(errno, "Error while "
						"allocating buffer for hashing "
						"file data");
					goto out;
				}

				err = sha512_init(&sha512_ctx);
				if(err) {
					print_perror(err, "Error while "
						"initializing SHA-512 "
						"context");
					goto out;
				}

				while(1) {
					ssize_t nbytes;

					nbytes = read(item->fd, buf, buf_size);
					if(nbytes < 0) {
						print_perror(errno, "Error "
							"while reading data "
							"from \"%s\"",
							cur_path);
						err = (err = errno) ? err : EIO;
						break;
					}
					else if(nbytes == 0) {
						break;
					}

					sha512_update(&sha512_ctx, buf,
						(size_t) nbytes);
				}

				sha512_finalize(&sha512_ctx, h);
				if(!err) {
					printlni("Hash (SHA512): "
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x",
						h[0] , h[1] , h[2] , h[3] ,
						h[4] , h[5] , h[6] , h[7] ,
						h[8] , h[9] , h[10], h[11],
						h[12], h[13], h[14], h[15],
						h[16], h[17], h[18], h[19],
						h[20], h[21], h[22], h[23],
						h[24], h[25], h[26], h[27],
						h[28], h[29], h[30], h[31],
						h[32], h[33], h[34], h[35],
						h[36], h[37], h[38], h[39],
						h[40], h[41], h[42], h[43],
						h[44], h[45], h[46], h[47],
						h[48], h[49], h[50], h[51],
						h[52], h[53], h[54], h[55],
						h[56], h[57], h[58], h[59],
						h[60], h[61], h[62], h[63]);
				}

				free(buf);
			}
			else if((mode & S_IFMT) == S_IFLNK) {
				size_t buf_size = 0;
				char *buf = NULL;
				ssize_t buf_valid_size = 0;

				buf_size = 4096;
				while(1) {

					buf = realloc(buf, buf_size);
					if(!buf) {
						print_perror(errno, "Error "
							"while allocating %zu "
							"byte symlink buffer",
							buf_size);
						err = (err = errno) ? err :
							ENOMEM;
						goto out;
					}

					buf_valid_size =
						readlink(cur_path, buf,
						buf_size);
					if(buf_valid_size < 0) {
						print_perror(errno, "Error "
							"while reading symlink "
							"data");
						err = (err = errno) ? err : EIO;
						break;
					}
					else if((size_t) buf_valid_size <=
						buf_size - 1)
					{
						break;
					}

					buf_size *= 2;
				}

				if(!err) {
					printlni("Symlink target: %.*s",
						(int) buf_valid_size, buf);
				}

				if(buf) {
					free(buf);
				}
			}
		}

		/* List any extended attributes and hash their data. */
#if IS_BSD
		for(n = 0; n < sizeof(namespaces) / sizeof(namespaces[0]); ++n)
#endif
		{
#if IS_BSD
			const int namespace = namespaces[n];
#endif

			ssize_t xattr_list_size = 0;

			xattr_list_size = queue_item_listxattr(
				item,
				cur_path,
#if IS_BSD
				namespace,
#endif
				NULL,
				0);
#if IS_LINUX
			if(xattr_list_size < 0 && errno == EBADF &&
				(mode & S_IFMT) == S_IFLNK)
			{
				/* This is expected for symlinks in Linux, which
				 * cannot have extended attributes. */
				xattr_list_size = 0;
				errno = 0;
			}
#endif /* IS_LINUX */

#if IS_SOLARIS
			if(xattr_list_size < 0 && errno == ENOENT &&
				(mode & S_IFMT) == S_IFLNK)
			{
				/* This is expected for symlinks in Solaris,
				 * which has no way of opening a file descriptor
				 * for a symlink and not its target. Thus we
				 * cannot ever use the APIs needed to access
				 * xattrs, effectively preventing their use on
				 * symlinks. */
				xattr_list_size = 0;
				errno = 0;
			}
#endif /* IS_SOLARIS */

			if(xattr_list_size < 0) {
				print_perror(errno, "Error while getting size "
					"of list of xattrs for \"%s\"",
					cur_path);
			}
			else if(xattr_list_size != 0) {
				size_t i = 0;
				char **xattr_list_list = NULL;
				size_t xattr_list_list_length = 0;

				if(xattr_list) {
					free(xattr_list);
				}

				xattr_list = malloc((size_t) xattr_list_size);
				if(!xattr_list) {
					print_perror(errno, "Error while "
						"allocating %zd bytes for "
						"xattr list for \"%s\"",
						xattr_list_size, cur_path);
					goto out;
				}

				xattr_list_size = queue_item_listxattr(
					item,
					cur_path,
#if IS_BSD
					namespace,
#endif
					xattr_list,
					xattr_list_size);
				if(xattr_list_size < 0) {
					/* TODO: Retry here if ERANGE. xattrs
					 * may have changed behind our backs. */
					print_perror(errno, "Error while "
						"getting list of xattrs for "
						"\"%s\"", cur_path);
					goto out;
				}

				/* Add pointers to the start of each xattr to
				 * 'xattr_list_list' and sort the list before
				 * proceeding. */
				while(i < (size_t) xattr_list_size) {
					char *cur_entry = &xattr_list[i];
					const size_t cur_entry_length =
						strlen(cur_entry);

					char **new_xattr_list_list = NULL;

					new_xattr_list_list =
						realloc(xattr_list_list,
						(xattr_list_list_length + 1) *
						sizeof(xattr_list_list[0]));
					if(!new_xattr_list_list) {
						print_perror(errno, "Error "
							"while expanding list "
							"of xattrs pointers");
						err = (err = errno) ? err :
							ENOMEM;
						free(xattr_list_list);
						goto out;
					}

					xattr_list_list = new_xattr_list_list;
					xattr_list_list[xattr_list_list_length]
						= cur_entry;
					++xattr_list_list_length;

					i += cur_entry_length + 1;
				}

				qsort(xattr_list_list, xattr_list_list_length,
					sizeof(xattr_list_list[0]),
					compare_strings);

				printlni("Extended attributes:");
				for(i = 0; i < xattr_list_list_length; ++i) {
					char *const cur_entry =
						xattr_list_list[i];
					const size_t cur_entry_length =
						strlen(cur_entry);

					ssize_t cur_xattr_size = 0;
					char *cur_xattr_buf = NULL;
					sha512_context sha512_ctx;
					uint8_t h[64];

					memset(&sha512_ctx, 0,
						sizeof(sha512_ctx));

					if(!cur_entry_length) {
						break;
					}

					printlnii("%s", cur_entry);

					cur_xattr_size = queue_item_getxattr(
						item,
						cur_path,
#if IS_BSD
						namespace,
#endif
						cur_entry,
						NULL,
						0);
					if(cur_xattr_size < 0) {
						print_perror(errno, "Error "
							"while getting size "
							"for xattr \"%s\" of "
							"entry \"%s\"",
							cur_entry, cur_path);
						continue;
					}

					printlniii("Size: %zd bytes",
						cur_xattr_size);

					cur_xattr_buf = malloc(cur_xattr_size);
					if(!cur_xattr_buf) {
						print_perror(errno, "Error "
							"while allocating "
							"xattr buffer");
						err = (err = errno) ? err :
							ENOMEM;
						break;
					}

					cur_xattr_size = queue_item_getxattr(
						item,
						cur_path,
#if IS_BSD
						namespace,
#endif
						cur_entry,
						cur_xattr_buf,
						(size_t) cur_xattr_size);
					if(cur_xattr_size < 0) {
						print_perror(errno, "Error "
							"while reading data "
							"for xattr \"%s\" of "
							"entry \"%s\"",
							cur_entry, cur_path);
						free(cur_xattr_buf);
						continue;
					}

					err = sha512_init(&sha512_ctx);
					if(err) {
						print_perror(err, "Error while "
							"initializing SHA-512 "
							"context");
						free(cur_xattr_buf);
						goto out;
					}

					if(cur_xattr_size) {
						sha512_update(&sha512_ctx,
							cur_xattr_buf,
							(size_t)
							cur_xattr_size);
					}

					sha512_finalize(&sha512_ctx, h);

					free(cur_xattr_buf);

					printlniii("Hash (SHA512): "
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x"
						"%02x%02x%02x%02x",
						h[0] , h[1] , h[2] , h[3] ,
						h[4] , h[5] , h[6] , h[7] ,
						h[8] , h[9] , h[10], h[11],
						h[12], h[13], h[14], h[15],
						h[16], h[17], h[18], h[19],
						h[20], h[21], h[22], h[23],
						h[24], h[25], h[26], h[27],
						h[28], h[29], h[30], h[31],
						h[32], h[33], h[34], h[35],
						h[36], h[37], h[38], h[39],
						h[40], h[41], h[42], h[43],
						h[44], h[45], h[46], h[47],
						h[48], h[49], h[50], h[51],
						h[52], h[53], h[54], h[55],
						h[56], h[57], h[58], h[59],
						h[60], h[61], h[62], h[63]);
				}

				if(xattr_list_list) {
					free(xattr_list_list);
				}

				if(err) {
					goto out;
				}
			}
		}

		/* We are done printing metadata and checksums for this entry,
		 * so flush stdout. */
		fflush(stdout);

		/* If this is a directory, the list it and add the directory
		 * entries to the queues after sorting them. */
		{
			int is_mountpoint = 0;

			if((mode & S_IFMT) == S_IFDIR &&
				!(err = matches_mountpoint(
					/* const struct statfs *mountinfo */
					&mountinfo,
					/* const char *cur_path */
					cur_path,
					/* int *out_is_mountpoint */
					&is_mountpoint)) &&
				!is_mountpoint)
			{
				/* List the directory and add contents to head
				 * of queue. */
#ifdef HAVE_FDOPENDIR
				int dirfd = -1;
#endif
				DIR *dirp = NULL;
				struct dirent *de = NULL;
				queue_item *first_item = NULL;
				queue_item *prev_item = NULL;
				size_t queue_item_count = 0;
				queue_item **queue_items = NULL;
				size_t i = 0;

#ifdef HAVE_FDOPENDIR
				if(item->fd != -1) {
					/* We have to duplicate the file
					 * descriptor because after passing it
					 * to fdopendir it won't be usable
					 * anymore. */
					dirfd = dup(item->fd);
					if(dirfd == -1) {
						print_perror(errno, "Error "
							"while duplicating "
							"directory file "
							"descriptor");
						goto out;
					}

					dirp = fdopendir(dirfd);
				}
				else
#endif
				{
					dirp = opendir(cur_path);
				}
				if(!dirp) {
					print_perror(errno, "Error while "
						"opening directory");
					err = (err = errno) ? err : EIO;
#ifdef HAVE_FDOPENDIR
					close(dirfd);
#endif
				}
				else while((de = readdir(dirp))) {
					queue_item **new_queue_items = NULL;
					queue_item *de_item = NULL;

					if(de->d_name[0] == '.' &&
						(de->d_name[1] == '\0'||
						(de->d_name[1] == '.' &&
						de->d_name[2] == '\0')))
					{
						/* Ignore '.' / '..' */
						continue;
					}

					new_queue_items =
						realloc(queue_items,
						(queue_item_count + 1) *
						sizeof(queue_items[0]));
					if(!new_queue_items) {
						print_perror(errno, "Error "
							"while expanding queue "
							"items to %zu elements",
							queue_item_count + 1);
						err = (err = errno) ? err :
							ENOMEM;
						break;
					}

					queue_items = new_queue_items;
					queue_items[queue_item_count] =
						NULL;

					err = queue_item_create(item,
						de->d_name, &de_item);
					if(err) {
						print_perror(err, "Error while "
							"creating queue item "
							"for dirent \"%s\"",
							de->d_name);
						break;
					}

					queue_items[queue_item_count] =
						de_item;

					++queue_item_count;
				}

				if(dirp) {
					closedir(dirp);
				}

				if(err) {
					if(queue_items) {
						free(queue_items);
					}

					while(first_item) {
						queue_item *release_item =
							first_item;
						first_item =
							first_item->next_item;
						queue_item_release(
							&release_item);
					}

					goto out;
				}

				qsort(queue_items, queue_item_count,
					sizeof(queue_items[0]),
					compare_queue_items);

				for(i = 0; i < queue_item_count; ++i) {
					if(prev_item) {
						prev_item->next_item =
							queue_items[i];
					}
					else {
						first_item = queue_items[i];
					}

					prev_item = queue_items[i];
				}

				free(queue_items);

				if(first_item) {
					/* Add the list of dirents to the head
					 * of 'queue'. */
					prev_item->next_item = queue;
					queue = first_item;
				}
			}
		}
	}

	ret = (EXIT_SUCCESS);
out:
	if(xattr_list) {
		free(xattr_list);
	}

	while(queue) {
		queue_item *release_item = queue;
		queue = queue->next_item;
		queue_item_release(&release_item);
	}

	if(cur_path) {
		free(cur_path);
	}

	return ret;
}
