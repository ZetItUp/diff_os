#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

static void read_strtab(FILE *f, Elf32_Shdr *sh, char **buf)
{
    *buf = malloc(sh->sh_size);
    fseek(f, sh->sh_offset, SEEK_SET);
    fread(*buf, 1, sh->sh_size, f);
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <input.elf> <output.txt>\n", argv[0]);

        return 1;
    }

    FILE *fin = fopen(argv[1], "rb");

    if (!fin)
    {
        perror("fopen input");

        return 1;
    }

    FILE *fout = fopen(argv[2], "w");

    if (!fout)
    {
        perror("fopen output");
        fclose(fin);

        return 1;
    }

    Elf32_Ehdr eh;
    fread(&eh, 1, sizeof(eh), fin);

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "Not an ELF file\n");
        fclose(fin);
        fclose(fout);

        return 1;
    }

    fprintf(fout, "ELF HEADER type=%u machine=%u entry=0x%X shoff=0x%X shnum=%u shentsize=%u shstrndx=%u\n",
        eh.e_type, eh.e_machine, eh.e_entry, eh.e_shoff, eh.e_shnum, eh.e_shentsize, eh.e_shstrndx);

    // Read section headers
    Elf32_Shdr *shdrs = malloc(eh.e_shnum * sizeof(Elf32_Shdr));
    fseek(fin, eh.e_shoff, SEEK_SET);
    fread(shdrs, sizeof(Elf32_Shdr), eh.e_shnum, fin);

    // Read section name string table
    char *shstrtab = NULL;

    if (eh.e_shstrndx != SHN_UNDEF)
    {
        read_strtab(fin, &shdrs[eh.e_shstrndx], &shstrtab);
    }

    // For looking up symbol names
    char **all_strtabs = calloc(eh.e_shnum, sizeof(char*));

    // First pass: dump sections and load strtab
    for (int i = 0; i < eh.e_shnum; i++)
    {
        const char *secname = shstrtab ? shstrtab + shdrs[i].sh_name : "";

        fprintf(fout, "SECTION idx=%d name=%s type=%u flags=0x%X addr=0x%X off=0x%X size=0x%X link=%u info=%u addralign=0x%X entsize=0x%X\n",
            i, secname, shdrs[i].sh_type, shdrs[i].sh_flags,
            shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_size,
            shdrs[i].sh_link, shdrs[i].sh_info,
            shdrs[i].sh_addralign, shdrs[i].sh_entsize);

        if (shdrs[i].sh_type == SHT_STRTAB)
        {
            read_strtab(fin, &shdrs[i], &all_strtabs[i]);
        }
    }

    // Second pass: dump symbol tables
    for (int i = 0; i < eh.e_shnum; i++)
    {
        if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM)
        {
            int strtab_index = shdrs[i].sh_link;
            char *symstr = all_strtabs[strtab_index];
            int count = shdrs[i].sh_size / sizeof(Elf32_Sym);
            Elf32_Sym sym;

            fseek(fin, shdrs[i].sh_offset, SEEK_SET);

            for (int s = 0; s < count; s++)
            {
                fread(&sym, 1, sizeof(sym), fin);
                const char *name = symstr ? symstr + sym.st_name : "";

                fprintf(fout, "SYMBOL secidx=%d name=%s value=0x%X size=0x%X bind=%u type=%u other=%u shndx=%u\n",
                    i, name, sym.st_value, sym.st_size,
                    ELF32_ST_BIND(sym.st_info), ELF32_ST_TYPE(sym.st_info),
                    sym.st_other, sym.st_shndx);
            }
        }
    }

    // Third pass: dump relocations
    for (int i = 0; i < eh.e_shnum; i++)
    {
        if (shdrs[i].sh_type == SHT_REL)
        {
            int symtab_index = shdrs[i].sh_link;
            char *symstr = NULL;
            Elf32_Sym *symtab = NULL;
            int symcount = 0;

            if (shdrs[symtab_index].sh_type == SHT_SYMTAB || shdrs[symtab_index].sh_type == SHT_DYNSYM)
            {
                int stridx = shdrs[symtab_index].sh_link;
                symstr = all_strtabs[stridx];
                symcount = shdrs[symtab_index].sh_size / sizeof(Elf32_Sym);
                symtab = malloc(shdrs[symtab_index].sh_size);
                fseek(fin, shdrs[symtab_index].sh_offset, SEEK_SET);
                fread(symtab, sizeof(Elf32_Sym), symcount, fin);
            }

            int relcount = shdrs[i].sh_size / sizeof(Elf32_Rel);
            Elf32_Rel rel;

            fseek(fin, shdrs[i].sh_offset, SEEK_SET);

            for (int r = 0; r < relcount; r++)
            {
                fread(&rel, 1, sizeof(rel), fin);
                uint32_t sym_idx = ELF32_R_SYM(rel.r_info);
                const char *symname = (sym_idx < (uint32_t)symcount && symstr) ? symstr + symtab[sym_idx].st_name : "";

                fprintf(fout, "RELOC secidx=%d offset=0x%X type=%u symidx=%u symname=%s addend=N/A\n",
                    i, rel.r_offset, ELF32_R_TYPE(rel.r_info), sym_idx, symname);
            }

            if (symtab)
            {
                free(symtab);
            }
        }
        else if (shdrs[i].sh_type == SHT_RELA)
        {
            // ELF with explicit addend, rare for i386 but we include it
            int symtab_index = shdrs[i].sh_link;
            char *symstr = NULL;
            Elf32_Sym *symtab = NULL;
            int symcount = 0;

            if (shdrs[symtab_index].sh_type == SHT_SYMTAB || shdrs[symtab_index].sh_type == SHT_DYNSYM)
            {
                int stridx = shdrs[symtab_index].sh_link;
                symstr = all_strtabs[stridx];
                symcount = shdrs[symtab_index].sh_size / sizeof(Elf32_Sym);
                symtab = malloc(shdrs[symtab_index].sh_size);
                fseek(fin, shdrs[symtab_index].sh_offset, SEEK_SET);
                fread(symtab, sizeof(Elf32_Sym), symcount, fin);
            }

            int relcount = shdrs[i].sh_size / sizeof(Elf32_Rela);
            Elf32_Rela rela;

            fseek(fin, shdrs[i].sh_offset, SEEK_SET);

            for (int r = 0; r < relcount; r++)
            {
                fread(&rela, 1, sizeof(rela), fin);
                uint32_t sym_idx = ELF32_R_SYM(rela.r_info);
                const char *symname = (sym_idx < (uint32_t)symcount && symstr) ? symstr + symtab[sym_idx].st_name : "";

                fprintf(fout, "RELOC secidx=%d offset=0x%X type=%u symidx=%u symname=%s addend=0x%X\n",
                    i, rela.r_offset, ELF32_R_TYPE(rela.r_info), sym_idx, symname, (uint32_t)rela.r_addend);
            }

            if (symtab)
            {
                free(symtab);
            }
        }
    }

    // Clean up memory
    for (int i = 0; i < eh.e_shnum; i++)
    {
        if (all_strtabs[i])
        {
            free(all_strtabs[i]);
        }
    }

    free(all_strtabs);

    if (shstrtab)
    {
        free(shstrtab);
    }

    free(shdrs);
    fclose(fin);
    fclose(fout);

    return 0;
}
