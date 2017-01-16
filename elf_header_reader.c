#include <stdio.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

struct file_info
{
    int8_t file_class;
    int8_t data_encoding;
};

typedef struct file_info* FILE_INFO;

enum Elf_type { elf32, elf64 };

struct elf_header
{
    enum Elf_type ELF_type;
    union
    {
        Elf32_Ehdr *elf32;
        Elf64_Ehdr *elf64;
    };
};

FILE_INFO check_system(FILE *fp)
{
    if (!fp)
        return NULL;
    else
    {
        char check[8];
        int check_size = fread(check, sizeof(check), 1, fp);
        check_size *= sizeof(check);
        if (check_size < 8)
            return NULL;
        if (strncmp(check, ELFMAG, 4))
        {
            return NULL;
        }
        if (!check[EI_VERSION] == EV_CURRENT || !check[EI_CLASS])
        {
            return NULL;
        }
        FILE_INFO res = NULL;
        res = (FILE_INFO)malloc(sizeof(struct file_info));
        if (!res)
        {
            return NULL;
        }
        else
        {
            res -> file_class = check[EI_CLASS];
            res -> data_encoding = check[EI_DATA];
        }
        return res;
    }
}

const char* check_ABI(uint8_t abi)
{
    switch(abi)
    {
        case 0:
            return "UNIX - System V";
        case 2:
            return "GNU ELF extensions";
        case 97:
            return "ARM";
    }
}

void readelf(FILE *fp, FILE_INFO file)
{
    struct elf_header *elf_h = NULL;
    elf_h = (struct elf_header*)malloc(sizeof(struct elf_header));
    if (!elf_h)
        return;
    printf("ELF Header:\n");
    printf("\tMagic:   ");
    if (file -> file_class == 1)
    {
        elf_h -> ELF_type = elf32;
        elf_h -> elf32 = (Elf32_Ehdr*)malloc(sizeof(Elf32_Ehdr));
        if (!elf_h -> elf32)
            return;
        fread(elf_h -> elf32, sizeof(Elf32_Ehdr), 1, fp);
        for (int i = 0; i < EI_NIDENT; ++i)
        {
            printf("%02x ", elf_h -> elf32 -> e_ident[i]);
        }
        printf("\n\tClass: ELF32\n\tData: 2's complement, ");
        if (elf_h -> elf32 -> e_type == ELFDATA2LSB)
        {
            printf("little endian");
        }
        else
        {
            printf("big endian");
        }
        printf("\n\tVersion: 1(Current)\n\tOS/ABI: %s\n\tABI Version: 0\n", check_ABI(elf_h -> elf32 -> e_ident[EI_OSABI]));
    }
    else
    {
        elf_h -> ELF_type = elf64;
        elf_h -> elf64 = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
        if (!elf_h -> elf64)
            return;
        fread(elf_h -> elf64, sizeof(Elf64_Ehdr), 1, fp);
        for (int i = 0; i < EI_NIDENT; ++i)
        {
            printf("%02x ", elf_h -> elf64 -> e_ident[i]);
        }
        printf("\n\tClass: ELF64\n\tData: 2's complement, ");
        if (elf_h -> elf64 -> e_type == ELFDATA2LSB)
        {
            printf("little endian");
        }
        else
        {
            printf("big endian");
        }
        printf("\n\tVersion: 1(Current)\n\tOS/ABI: %s\n\tABI Version: 0\n", check_ABI(elf_h -> elf64 -> e_ident[EI_OSABI]));
    }
}

int main(int argc, char **argv)
{
    FILE *fp = NULL;
    FILE_INFO file = NULL;
    if (argc < 2)
    {
        return 0;
    }
    fp = fopen(argv[1], "rb");
    file = check_system(fp);
    if (!file)
    {
        return 0;
    }
    rewind(fp);
    readelf(fp, file);
}
