The layout of the ELF filesystem follows closely the ELF structures as defined by the libelf.

```
.
├── header
│   ├── e_ident[EI_NIDENT]
│   ├── e_type
│   ├── e_machine
│   ├── e_version
│   ├── e_entry
│   ├── e_phoff
│   ├── e_shoff
│   ├── e_flags
│   ├── e_ehsize
│   ├── e_phentsize
│   ├── e_phnum
│   ├── e_shentsize
│   ├── e_shnum
│   └── e_shstrndx
├── programs
│   ├── 0
│   │   ├── p_type
│   │   ├── p_flags
│   │   ├── p_offset
│   │   ├── p_vaddr
│   │   ├── p_paddr
│   │   ├── p_filesz
│   │   ├── p_memsz
│   │   └── p_align
│   └── 1
│       ├── p_type
│       ├── p_flags
│       ├── p_offset
│       ├── p_vaddr
│       ├── p_paddr
│       ├── p_filesz
│       ├── p_memsz
│       └── p_align
└── sections
    ├── .init
    │   ├── p_type
    │   ├── p_flags
    │   ├── p_offset
    │   ├── p_vaddr
    │   ├── p_paddr
    │   ├── p_filesz
    │   ├── p_memsz
    │   └── p_align
    ├── .rodata
    │   ├── p_type
    │   ├── p_flags
    │   ├── p_offset
    │   ├── p_vaddr
    │   ├── p_paddr
    │   ├── p_filesz
    │   ├── p_memsz
    │   └── p_align
    └── .symtab
        ├── p_type
        ├── p_flags
        ├── p_offset
        ├── p_vaddr
        ├── p_paddr
        ├── p_filesz
        ├── p_memsz
        └── p_align
```
