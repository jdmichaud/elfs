// c++ -std=c++20 -ggdb3 test-elf.cc -lelf -o test-elf && ./test-elf

// format: https://raw.githubusercontent.com/corkami/pics/master/binary/elf101/elf101-64.pdf
// freebsd man page (way more helpful than linux's one):
//   elf: https://www.freebsd.org/cgi/man.cgi?query=elf&apropos=0&sektion=3&manpath=FreeBSD+13.0-RELEASE+and+Ports&arch=default&format=html
//   elf_begin: https://www.freebsd.org/cgi/man.cgi?query=elf_begin&apropos=0&sektion=3&manpath=FreeBSD+13.0-RELEASE+and+Ports&arch=default&format=html
//   elf64_getshdr :https://www.freebsd.org/cgi/man.cgi?query=elf64_getshdr&apropos=0&sektion=3&manpath=FreeBSD+13.0-RELEASE+and+Ports&arch=default&format=html
// A description of ELF with enum values and constants:
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.intro.html
// libelf by example:
// https://kumisystems.dl.sourceforge.net/project/elftoolchain/Documentation/libelf-by-example/20120308/libelf-by-example.pdf

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <cstdint>

#include <iostream>
#include <string>

#include <libelf.h>

#include "../src/sjdlib.h"

int main(int argc, char **argv) {
  int fd = !make_int_result(open(argv[0], O_RDONLY));

  // You HAVE to call this function, otherwise elf_begin just does not work.
  if (elf_version(EV_CURRENT) == EV_NONE) {
    ERROR(elf_errmsg(elf_errno()));
    exit(1);
  }

  Elf *elf = NULL;

  // Call it once o allocate the structure...
  if ((elf = elf_begin(fd, ELF_C_READ, (Elf *) 0)) == NULL) {
    ERROR(elf_errmsg(elf_errno()));
    exit(1);
  }
  // ... then call it again to fill it. Great design!
  if (elf_begin(fd, ELF_C_READ, elf) == NULL) {
    ERROR(elf_errmsg(elf_errno()));
    exit(1);
  }

  Elf64_Ehdr *header = NULL;
  if ((header = elf64_getehdr(elf)) == NULL) {
    ERROR(elf_errmsg(elf_errno()));
    exit(1);
  }

  std::cout << "CPU: " << header->e_machine << std::endl;
  std::cout << "nb of section: " << header->e_shnum << std::endl;
  std::cout << "shstrtbl index: " << header->e_shstrndx << std::endl;

  Elf_Scn *section = NULL;
  if ((section = elf_getscn(elf, 0)) == NULL) {
    ERROR(elf_errmsg(elf_errno()));
    exit(1);
  }

  // Load sections and their headers
  Elf_Scn **sections = (Elf_Scn **) malloc(header->e_shnum * sizeof (Elf_Scn *));
  Elf64_Shdr **section_headers = (Elf64_Shdr **) malloc(header->e_shnum * sizeof (Elf64_Shdr *));
  size_t index = 0;
  while (section != NULL) {
    Elf64_Shdr *section_header = NULL;
    if ((section_header = elf64_getshdr(section)) == NULL) {
      ERROR(elf_errmsg(elf_errno()));
      exit(1);
    }
    sections[index] = section;
    section_headers[index] = section_header;
    section = elf_nextscn(elf, section);
    index++;
  }

  for (size_t i = 0; i < header->e_shnum; ++i) {
    std::cout << " " << section_headers[i]->sh_name
              << " " << elf_strptr(elf, header->e_shstrndx, section_headers[i]->sh_name)
              << std::endl;
  }

  elf_end(elf);
  close(fd);
  return 0;
}
