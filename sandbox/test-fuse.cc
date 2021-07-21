// c++ -std=c++20 -ggdb3 -Wfatal-errors test-fuse.cc `pkg-config fuse3 --cflags --libs` -D_FORTIFY_SOURCE=2 -o test-fuse && ./test-fuse

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>

#include "../src/sjdlib.h"

static timespec ts;

static void *elfs_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg) {
  syslog(LOG_INFO, "elfs_init");
  (void) conn;
  cfg->kernel_cache = 1;
  timespec_get(&ts, TIME_UTC); // used in private_data field in fuse_context
  return &ts;
}
static int elfs_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi)
{
  syslog(LOG_INFO, "elfs_getattr: %s", path);
  (void) fi;
  int res = 0;
  memset(stbuf, 0, sizeof(struct stat));
  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    stbuf->st_atim.tv_sec = reinterpret_cast<timespec *>(fuse_get_context()->private_data)->tv_sec;
    stbuf->st_mtim.tv_sec = reinterpret_cast<timespec *>(fuse_get_context()->private_data)->tv_sec;
    stbuf->st_ctim.tv_sec = reinterpret_cast<timespec *>(fuse_get_context()->private_data)->tv_sec;
  // } else if (strcmp(path + 1, options.filename) == 0) {
  //   stbuf->st_mode = S_IFREG | 0444;
  //   stbuf->st_nlink = 1;
  //   stbuf->st_size = strlen(options.contents);
  } else
    res = -ENOENT;
  return res;
}

static int elfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
  syslog(LOG_INFO, "elfs_readdir: %s", path);
  (void) offset;
  (void) fi;
  (void) flags;
  // if (strcmp(path, "/") != 0)
  //   return -ENOENT;
  // filler(buf, ".", NULL, 0, 0);
  // filler(buf, "..", NULL, 0, 0);
  // filler(buf, options.filename, NULL, 0, 0);
  return 0;
}

static int elfs_open(const char *path, struct fuse_file_info *fi)
{
  syslog(LOG_INFO, "elfs_open: %s", path);
  // if (strcmp(path+1, options.filename) != 0)
  //   return -ENOENT;
  // if ((fi->flags & O_ACCMODE) != O_RDONLY)
  //   return -EACCES;
  return 0;
}
static int elfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
  syslog(LOG_INFO, "elfs_read: %s", path);
  size_t len;
  (void) fi;
  // if(strcmp(path+1, options.filename) != 0)
  //   return -ENOENT;
  // len = strlen(options.contents);
  // if (offset < len) {
  //   if (offset + size > len)
  //     size = len - offset;
  //   memcpy(buf, options.contents + offset, size);
  // } else
    size = 0;
  return size;
}

static const struct fuse_operations elfs_operations = {
  .getattr        = elfs_getattr,
  .open           = elfs_open,
  .read           = elfs_read,
  .readdir        = elfs_readdir,
  .init           = elfs_init,
};

int main(int argc, char **argv) {
  MARK();
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  // fuse_main expect at least a folder where to mount the file system.
  // fuse_main will fork this process and kill the current process. The child
  // will then become a daemon attached to init.
  int ret = fuse_main(args.argc, args.argv, &elfs_operations, NULL);
  fuse_opt_free_args(&args);
  return ret;
}
