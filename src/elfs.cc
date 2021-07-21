// ls sjdlib.h elfs.cc | entr bash -c "clear && make && date"
// ls elfs | entr bash -c '(umount /tmp/mnt || true) && sleep 1 && ./elfs elfs /tmp/mnt && date'
#define FUSE_USE_VERSION 31

#include <libelf.h>
#include <fuse.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include <filesystem>
#include <vector>
#include <algorithm>
#include <map>

#include "sjdlib.h"

using path = std::filesystem::path;

#define GET_FILESYSTEM() reinterpret_cast<filesystem_t *>(fuse_get_context()->private_data)

class Node;

typedef struct {
  timespec creation_ts;
  Elf *elf;
  Elf64_Ehdr *header;
  Elf64_Phdr *program_headers;
  Elf64_Shdr **section_headers;
  Elf64_Sym *symbols;
  u16 synum;
  Elf_Scn **sections;
  std::unique_ptr<Node> tree;
} filesystem_t;

static filesystem_t filesystem;

// / -> Dir (Node)
// /header -> Dir (Node)
// /header/e_machine -> Header (Leaf (Node))
class Node {
public:
  Node() = delete;
  Node(const Node &) = delete;
  explicit Node(const std::string& name): m_name(name) {}
  virtual ~Node() noexcept {};

  // Traverse the tree using the path iterator as guide.
  Result<Node *, int> fetch(path::iterator& it, const path::iterator& end) {
    if (it == end) {
      // We found the node we were looking for
      return Result<Node *, int>::Ok(this);
    }
    // Look among the children for that node
    auto node = this->getNode(*it);

    if (node.has_value()) {
      // We found child node corresponding to that iterator
      // but the iterator is not ended yet so we fetch in the subtree
      return node.value()->fetch(++it, end);
    }
    // We could not find the node
    return Result<Node *, int>::Err(ENOENT);
  }

  Option<Node *> getNode(const std::string& name) {
    auto result = std::find_if(this->m_children.begin(),
                               this->m_children.end(),
                               [&name] (const std::unique_ptr<Node>& n) {
                                return n->m_name == name;
                              });
    return (result != this->m_children.end()) ? Option<Node *>(&**result) : Option<Node *>::None();
  }


  virtual int getattr(const char *, struct stat *stbuf, struct fuse_file_info *) = 0;
  virtual int readdir(const char *, void *, fuse_fill_dir_t,
                      off_t, struct fuse_file_info *,
                      enum fuse_readdir_flags flags) { UNREACHABLE(); return 0; }
  virtual int read(const char *, char *, size_t, off_t, struct fuse_file_info *) = 0;
  virtual int open(const char *, struct fuse_file_info *) = 0;

  std::string m_name;
  std::vector<std::unique_ptr<Node>> m_children;
};

class Dir: public Node {
public:
  Dir(const std::string& name): Node(name) {}

  int getattr(const char *, struct stat *stbuf, struct fuse_file_info *) {
    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    stbuf->st_atim.tv_sec = filesystem.creation_ts.tv_sec;
    stbuf->st_mtim.tv_sec = filesystem.creation_ts.tv_sec;
    stbuf->st_ctim.tv_sec = filesystem.creation_ts.tv_sec;
    return 0;
  }

  int readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                   off_t offset, struct fuse_file_info *fi,
                   enum fuse_readdir_flags flags) {
    if (offset == 0) {
      if (filler(buf, ".", NULL, ++offset, (fuse_fill_dir_flags) 0) == 1) return 0;
    }
    if (offset <= 1) {
      if (filler(buf, "..", NULL, ++offset, (fuse_fill_dir_flags) 0) == 1) return 0;
    }
    off_t children_offset = offset - 2;
    if (children_offset < 0 || static_cast<size_t>(children_offset) > (this->m_children.size() - 1))
      return 0;
    auto it = this->m_children.begin() + children_offset;
    for (; it != this->m_children.end(); ++it) {
      if (filler(buf, (*it)->m_name.c_str(), NULL, ++offset, (fuse_fill_dir_flags) 0) == 1) {
        return 0;
      }
    }
    return 0;
  }

  // int readdir(const char *path, void *buf, fuse_fill_dir_t filler,
  //                  off_t offset, struct fuse_file_info *fi,
  //                  enum fuse_readdir_flags flags) {
  //   filler(buf, ".", NULL, 0, (fuse_fill_dir_flags) 0);
  //   filler(buf, "..", NULL, 0, (fuse_fill_dir_flags) 0);
  //   for (auto& entry: this->m_children) {
  //     filler(buf, entry->m_name.c_str(), NULL, 0, (fuse_fill_dir_flags) 0);
  //   }
  //   return 0;
  // }
  int read(const char *p, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) { return EISDIR; }
  int open(const char *, struct fuse_file_info *) { return EISDIR; }
};

class Leaf : public Node {
public:
  Leaf(const std::string& name): Node(name) {}

  virtual int getattr(const char *, struct stat *stbuf, struct fuse_file_info *fi) {
    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_atim.tv_sec = filesystem.creation_ts.tv_sec;
    stbuf->st_mtim.tv_sec = filesystem.creation_ts.tv_sec;
    stbuf->st_ctim.tv_sec = filesystem.creation_ts.tv_sec;
    stbuf->st_size = this->content().size;
    return 0;
  }

  virtual int open(const char *, struct fuse_file_info *fi) {
    if ((fi->flags & O_ACCMODE) != O_RDONLY) {
      // Readonly filesystem
      return -EACCES;
    }
    return 0;
  }

  virtual int read(const char *p, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    slice_t content = this->content();
    if (offset < static_cast<long int>(content.size)) {
      if (offset + size > content.size)
        size = content.size - offset;
      memcpy(buf, content.buffer + offset, size);
    } else {
      size = 0;
    }

    return size;
  }

  virtual slice_t content() = 0;

  slice_t create_slice_from_string(std::string data) {
    return {
      // TODO: never released
      .buffer = strndup(data.c_str(), data.size()),
      .size = data.size(),
    };
  }

protected:
  std::map<std::string, slice_t> data;
  Option<slice_t>                m_slice;
};

class ProgramHeader : public Leaf {
public:
  ProgramHeader(const std::string& name, size_t index): Leaf(name), m_index(index) {}

  slice_t content() {
    if (!this->m_slice.has_value()) {
      if (this->m_name == "p_type") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_type) + '\n');
      } else if (this->m_name == "p_flags") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_flags) + '\n');
      } else if (this->m_name == "p_offset") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_offset) + '\n');
      } else if (this->m_name == "p_vaddr") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_vaddr) + '\n');
      } else if (this->m_name == "p_paddr") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_paddr) + '\n');
      } else if (this->m_name == "p_filesz") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_filesz) + '\n');
      } else if (this->m_name == "p_memsz") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_memsz) + '\n');
      } else if (this->m_name == "p_align") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.program_headers[this->m_index].p_align) + '\n');
      } else if (this->m_name == "content") {
        char *data = elf_rawfile(filesystem.elf, 0);
        this->m_slice = {
          .buffer = data + filesystem.program_headers[this->m_index].p_offset,
          .size = filesystem.program_headers[this->m_index].p_filesz,
        };
      } else { UNREACHABLE(); }
    }

    return this->m_slice.value();
  }

  size_t m_index;
};

class SectionHeader : public Leaf {
public:
  SectionHeader(const std::string& name, size_t index): Leaf(name), m_index(index) {}

  slice_t content() {
    if (!this->m_slice.has_value()) {
      if (this->m_name == "sh_name") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_name) + '\n');
      } else if (this->m_name == "sh_type") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_type) + '\n');
      } else if (this->m_name == "sh_flags") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_flags) + '\n');
      } else if (this->m_name == "sh_addr") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_addr) + '\n');
      } else if (this->m_name == "sh_offset") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_offset) + '\n');
      } else if (this->m_name == "sh_size") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_size) + '\n');
      } else if (this->m_name == "sh_link") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_link) + '\n');
      } else if (this->m_name == "sh_info") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_info) + '\n');
      } else if (this->m_name == "sh_addralign") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_addralign) + '\n');
      } else if (this->m_name == "sh_entsize") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.section_headers[this->m_index]->sh_entsize) + '\n');
      } else if (this->m_name == "content") {
        char *data = elf_rawfile(filesystem.elf, 0);
        this->m_slice = {
          .buffer = data + filesystem.section_headers[this->m_index]->sh_offset,
          .size = filesystem.section_headers[this->m_index]->sh_size,
        };
      } else { UNREACHABLE(); }
    }

    return this->m_slice.value();
  }

  size_t m_index;
};

class Header : public Leaf {
public:
  Header(const std::string& name): Leaf(name) {}

  slice_t content() {
    if (!this->m_slice.has_value()) {
      if (this->m_name == "e_type") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_type) + '\n');
      } else if (this->m_name == "e_machine") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_machine) + '\n');
      } else if (this->m_name == "e_version") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_version) + '\n');
      } else if (this->m_name == "e_entry") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_entry) + '\n');
      } else if (this->m_name == "e_phoff") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_phoff) + '\n');
      } else if (this->m_name == "e_shoff") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_shoff) + '\n');
      } else if (this->m_name == "e_flags") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_flags) + '\n');
      } else if (this->m_name == "e_ehsize") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_ehsize) + '\n');
      } else if (this->m_name == "e_phentsize") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_phentsize) + '\n');
      } else if (this->m_name == "e_phnum") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_phnum) + '\n');
      } else if (this->m_name == "e_shentsize") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_shentsize) + '\n');
      } else if (this->m_name == "e_shnum") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_shnum) + '\n');
      } else if (this->m_name == "e_shstrndx") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.header->e_shstrndx) + '\n');
      } else { UNREACHABLE(); }
    }

    return this->m_slice.value();
  }
};

class SymbolHeader : public Leaf {
public:
  SymbolHeader(const std::string &name, size_t index,
    size_t symtable_header_index, size_t symstrtable_header_index)
    : Leaf(name), m_index(index), m_symtable_header_index(symtable_header_index),
      m_symstrtable_header_index(symstrtable_header_index) {}

  // std::string content() {
  //   if (this->m_content == "") {
  //     char *strtable = data + symstrtable_header->sh_offset;
  //     for (size_t j = 0; j < filesystem.synum; ++j) {
  //       m_content += std::string(strtable + filesystem.symbols[j].st_name) + "\n";
  //     }
  //   }
  //   return m_content;
  // }


  slice_t content() {
    if (!this->m_slice.has_value()) {
      if (this->m_name == "st_name") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.symbols[this->m_index].st_name) + '\n');
      } else if (this->m_name == "st_info") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.symbols[this->m_index].st_info) + '\n');
      } else if (this->m_name == "st_other") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.symbols[this->m_index].st_other) + '\n');
      } else if (this->m_name == "st_shndx") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.symbols[this->m_index].st_shndx) + '\n');
      } else if (this->m_name == "st_value") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.symbols[this->m_index].st_value) + '\n');
      } else if (this->m_name == "st_size") {
        this->m_slice = create_slice_from_string(std::to_string(filesystem.symbols[this->m_index].st_size) + '\n');
      } else if (this->m_name == "name") {
        char *data = elf_rawfile(filesystem.elf, 0);
        char *strtable = data + filesystem.section_headers[this->m_symstrtable_header_index]->sh_offset;

        this->m_slice = {
          .buffer = strtable + filesystem.symbols[this->m_index].st_name,
          .size = strlen(strtable + filesystem.symbols[this->m_index].st_name),
        };
      } else UNREACHABLE();
    }

    return this->m_slice.value();
  }

private:
  size_t m_index;
  size_t m_symtable_header_index;
  size_t m_symstrtable_header_index;
};

// Read the ELF with libelf and create the file hierarchy.
void init_filesystem(int fd, filesystem_t& filesystem) {
  filesystem.tree = std::make_unique<Dir>("/");
  filesystem.tree->m_children.push_back(std::make_unique<Dir>("header"));
  filesystem.tree->m_children.push_back(std::make_unique<Dir>("programs"));
  filesystem.tree->m_children.push_back(std::make_unique<Dir>("sections"));

  // You HAVE to call this function, otherwise elf_begin just does not work.
  if (elf_version(EV_CURRENT) == EV_NONE) {
    syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
    exit(1);
  }

  // Call it once to allocate the structure...
  if ((filesystem.elf = elf_begin(fd, ELF_C_READ, (Elf *) 0)) == NULL) {
    syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
    exit(1);
  }
  // ... then call it again to fill it. Great design!
  if (elf_begin(fd, ELF_C_READ, filesystem.elf) == NULL) {
    syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
    exit(1);
  }

  if ((filesystem.header = elf64_getehdr(filesystem.elf)) == NULL) {
    syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
    exit(1);
  }

  auto header = filesystem.tree->getNode("header").value();
  header->m_children.push_back(std::make_unique<Header>("e_type"));
  header->m_children.push_back(std::make_unique<Header>("e_machine"));
  header->m_children.push_back(std::make_unique<Header>("e_version"));
  header->m_children.push_back(std::make_unique<Header>("e_entry"));
  header->m_children.push_back(std::make_unique<Header>("e_phoff"));
  header->m_children.push_back(std::make_unique<Header>("e_shoff"));
  header->m_children.push_back(std::make_unique<Header>("e_flags"));
  header->m_children.push_back(std::make_unique<Header>("e_ehsize"));
  header->m_children.push_back(std::make_unique<Header>("e_phentsize"));
  header->m_children.push_back(std::make_unique<Header>("e_phnum"));
  header->m_children.push_back(std::make_unique<Header>("e_shentsize"));
  header->m_children.push_back(std::make_unique<Header>("e_shnum"));
  header->m_children.push_back(std::make_unique<Header>("e_shstrndx"));

  if ((filesystem.program_headers = elf64_getphdr(filesystem.elf)) == NULL) {
    syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
    exit(1);
  }

  // Program headers
  auto programs = filesystem.tree->getNode("programs").value();
  for (size_t i = 0; i < filesystem.header->e_phnum; ++i) {
    std::string i_str = std::to_string(i);
    programs->m_children.push_back(std::make_unique<Dir>(i_str));
    auto program = programs->getNode(i_str).value();
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_type", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_flags", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_offset", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_vaddr", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_paddr", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_filesz", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_memsz", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("p_align", i));
    program->m_children.push_back(std::make_unique<ProgramHeader>("content", 1));
  }

  // Section headers
  auto sections = filesystem.tree->getNode("sections").value();
  filesystem.sections = (Elf_Scn **) malloc(sizeof (Elf_Scn *) * filesystem.header->e_shnum);
  filesystem.section_headers =
    (Elf64_Shdr **) malloc(sizeof (Elf64_Shdr *) * filesystem.header->e_shnum);
  Option<size_t> symtable_header_index;
  Option<size_t> symstrtable_header_index;
  for (size_t i = 0; i < filesystem.header->e_shnum; ++i) {
    if ((filesystem.sections[i] = elf_getscn(filesystem.elf, i)) == NULL) {
      syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
      exit(1);
    }

    if ((filesystem.section_headers[i] = elf64_getshdr(filesystem.sections[i])) == NULL) {
      syslog(LOG_PERROR, "init_filesystem: %s", elf_errmsg(elf_errno()));
      exit(1);
    }

    const char *section_name = elf_strptr(filesystem.elf, filesystem.header->e_shstrndx,
      filesystem.section_headers[i]->sh_name);
    if (strnlen(section_name, 2) == 0) {
      std::string i_str = std::to_string(i);
      section_name = (std::string("<empty>-") + i_str).c_str();
    }
    sections->m_children.push_back(std::make_unique<Dir>(section_name));
    auto section_node = sections->getNode(section_name).value();
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_name", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_type", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_flags", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_addr", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_offset", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_size", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_link", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_info", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_addralign", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("sh_entsize", i));
    section_node->m_children.push_back(std::make_unique<SectionHeader>("content", i));

    if (filesystem.section_headers[i]->sh_type == SHT_SYMTAB) {
      symtable_header_index = i;
    }
    if (strncmp(section_name, ".strtab", 7) == 0) {
      symstrtable_header_index = i;
    }
  }

  // Symbols
  if (symtable_header_index.has_value() && symstrtable_header_index.has_value()) {
    // https://stackoverflow.com/q/48833887/2603925
    char *data = elf_rawfile(filesystem.elf, 0);
    Elf64_Shdr *symtable_header = filesystem.section_headers[symtable_header_index.value()];

    filesystem.symbols = (Elf64_Sym *) (data + symtable_header->sh_offset);
    filesystem.synum = symtable_header->sh_size / symtable_header->sh_entsize;

    // Append a Symbol file in the section's directory
    sections->m_children[symtable_header_index.value()]->m_children.push_back(
      std::make_unique<Dir>("symbols"));
    auto symbols = sections->m_children[symtable_header_index.value()]->getNode("symbols").value();
    for (int i = 0; i < filesystem.synum; ++i) {
      size_t s = symtable_header_index.value();
      size_t ss = symstrtable_header_index.value();
      std::string i_str = std::to_string(i);
      symbols->m_children.push_back(std::make_unique<Dir>(i_str));
      auto symbol = symbols->getNode(i_str).value();
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("st_name", i, s, ss));
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("st_info", i, s, ss));
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("st_other", i, s, ss));
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("st_shndx", i, s, ss));
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("st_value", i, s, ss));
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("st_size", i, s, ss));
      symbol->m_children.push_back(std::make_unique<SymbolHeader>("name", i, s, ss));
    }
      // std::make_unique<Symbol>("symbols",
      //                          symtable_header_index.value(),
      //                          symstrtable_header_index.value()));
  } else {
    syslog(LOG_INFO, "No symbols or symbol string table");
  }
}

static void *elfs_init(struct fuse_conn_info *conn,
                       struct fuse_config *cfg) {
  (void) conn;
  cfg->kernel_cache = 1;

  timespec_get(&filesystem.creation_ts, TIME_UTC); // used in private_data field in fuse_context
  return &filesystem;
}
static int elfs_getattr(const char *p, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
  (void) fi;
  path filepath(p);
  auto it(filepath.begin());
  auto entry = filesystem.tree->fetch(++it, filepath.end());
  if (entry.is_ok()) {
    return entry.unwrap()->getattr(p, stbuf, fi);
  }
  return ENOENT;
}

static int elfs_readdir(const char *p, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
  (void) offset;
  (void) fi;
  (void) flags;
  path filepath(p);
  auto it(filepath.begin());
  auto entry = filesystem.tree->fetch(++it, filepath.end());
  if (entry.is_ok()) {
    return entry.unwrap()->readdir(p, buf, filler, offset, fi, flags);
  }
  return entry.err();
}

static int elfs_open(const char *p, struct fuse_file_info *fi)
{
  path filepath(p);
  auto it(filepath.begin());
  auto entry = filesystem.tree->fetch(++it, filepath.end());
  if (entry.is_ok()) {
    return entry.unwrap()->open(p, fi);
  }
  return entry.err();
}

static int elfs_read(const char *p, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
  (void) fi;
  path filepath(p);
  auto it(filepath.begin());
  auto entry = filesystem.tree->fetch(++it, filepath.end());
  if (entry.is_ok()) {
    return entry.unwrap()->read(p, buf, size, offset, fi);
  }
  return entry.err();
}

static const struct fuse_operations elfs_operations = {
  .getattr        = elfs_getattr,
  .open           = elfs_open,
  .read           = elfs_read,
  .readdir        = elfs_readdir,
  .init           = elfs_init,
};

void usage() {
  std::cout << "usage: elfs elf_file /mount/point" << std::endl;
}

int main(int argc, char **argv) {
  syslog(LOG_INFO, "elfs version " VERSION);
  if (argc < 3) {
    std::cerr << "error: expecting at least two arguments" << std::endl;
    usage();
    exit(1);
  }
  int fd = !make_int_result(open(argv[1], O_RDONLY));
  init_filesystem(fd, filesystem);

  // Reproduce the argc/argv for fuse without the binary already read.
  int fargc = argc - 1;
  char **fargv = (char **) malloc(sizeof (char *) * fargc);
  fargv[0] = strdup(argv[0]);
  for (int i = 2; i < argc; ++i) fargv[i - 1] = strdup(argv[i]);
  // Initialize fuse
  struct fuse_args args = FUSE_ARGS_INIT(fargc, fargv);
  int ret = fuse_main(args.argc, args.argv, &elfs_operations, NULL);
  fuse_opt_free_args(&args);
  close(fd);
  return ret;
}
