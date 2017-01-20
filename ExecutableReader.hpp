#ifndef _EXCUTABLE_READER_
#define _EXCUTABLE_READER_

#include <string>
#include <cstring>
#include <fstream>
#include <cstdint>
#include <iostream>
#include <vector>

using std::cout;
using std::endl;

class ExecutableReader
{
public:
    ExecutableReader(const std::string &file_name) : file_name(file_name) { }
	enum FILE_TYPE {Error, ELF32, ELF64, PE32, PE64};
	static FILE_TYPE type_check(const std::string&);
protected:
	enum FILE_TYPE file_type;
	std::string file_name;
};

#ifdef linux
#include <elf.h>

class ELFReader : public ExecutableReader
{
public:
    ELFReader(const std::string &file_name) : ExecutableReader(file_name) { }
    static FILE_TYPE type_check(const std::string&);
    virtual void read_file() = 0;
};

ExecutableReader::FILE_TYPE ELFReader::type_check(const std::string &file_name)
{
    std::FILE *fp = nullptr;
    fp = std::fopen(file_name.c_str(), "rb");
    if (!fp)
        exit(1);
    char ident[EI_NIDENT + 1];
    int8_t check_size = std::fread(ident, EI_NIDENT, 1, fp);
    if (check_size * EI_NIDENT < EI_NIDENT || ident[EI_VERSION] != EV_CURRENT)
        return FILE_TYPE::Error;
    switch (ident[EI_CLASS])
    {
        case ELFCLASS32:
            return FILE_TYPE::ELF32;
        case ELFCLASS64:
            return FILE_TYPE::ELF64;
        default:
            return FILE_TYPE::Error;
    }
}

class ELF32Reader : public ELFReader
{
    Elf32_Ehdr header;
    Elf32_Shdr string_table_header;
    std::vector<Elf32_Shdr> section_headers;
    std::vector<std::vector<char>> section_content;
    std::vector<std::string> section_names;
public:
    void read_file();
    ELF32Reader(const std::string &file_name) : ELFReader(file_name) { }
};

class ELF64Reader : public ELFReader
{
    Elf64_Ehdr header;
    Elf64_Shdr string_table_header;
    std::vector<Elf64_Shdr> section_headers;
    std::vector<std::vector<char>> section_content;
    std::vector<std::string> section_names;
public:
    void read_file();
    ELF64Reader(const std::string &file_name) : ELFReader(file_name) { }
};

std::ostream& operator<<(std::ostream &out, Elf32_Shdr section_header)
{
    out << std::hex << "sh_name: " << section_header.sh_name << endl;
    out << "sh_type: " << section_header.sh_type << endl;
    out << "sh_flags: " << section_header.sh_flags << endl;
    out << "sh_addr: " << section_header.sh_addr << endl;
    out << "sh_offset: " << section_header.sh_offset << endl;
    out << "sh_size: " << section_header.sh_size << endl;
    out << "sh_link: " << section_header.sh_link << endl;
    out << "sh_info: " << section_header.sh_info << endl;
    out << "sh_addralign: " << section_header.sh_addralign << endl;
    out << "sh_entsize: " << section_header.sh_entsize << std::dec << endl;
    return out;
}

std::ostream& operator<<(std::ostream &out, Elf64_Shdr section_header)
{
    out << std::hex << "sh_name: " << section_header.sh_name << endl;
    out << "sh_type: " << section_header.sh_type << endl;
    out << "sh_flags: " << section_header.sh_flags << endl;
    out << "sh_addr: " << section_header.sh_addr << endl;
    out << "sh_offset: " << section_header.sh_offset << endl;
    out << "sh_size: " << section_header.sh_size << endl;
    out << "sh_link: " << section_header.sh_link << endl;
    out << "sh_info: " << section_header.sh_info << endl;
    out << "sh_addralign: " << section_header.sh_addralign << endl;
    out << "sh_entsize: " << section_header.sh_entsize << std::dec << endl;
    return out;
}

std::ostream& operator<<(std::ostream &out, Elf32_Ehdr header)
{
    cout << std::hex << "e_ident: " << header.e_ident << endl;
    cout << "e_type: " << header.e_type << endl;
    cout << "e_machine: " << header.e_machine << endl;
    cout << "e_version: " << header.e_version << endl;
    cout << "e_entry: " << header.e_entry << endl;
    cout << "e_phoff: " << header.e_phoff << endl;
    cout << "e_shoff: " << header.e_shoff << endl;
    cout << "e_flags: " << header.e_flags << endl;
    cout << "e_ehsize: " << header.e_ehsize << endl;
    cout << "e_phentsize: " << header.e_phentsize << endl;
    cout << "e_phnum: " << header.e_phnum << endl;
    cout << "e_shentsize: " << header.e_shentsize << endl;
    cout << "e_shnum: " << header.e_shnum << endl;
    cout << "e_shstrndx: " << header.e_shstrndx << std::dec << endl;
}

std::ostream& operator<<(std::ostream &out, Elf64_Ehdr header)
{
    cout << std::hex << "e_ident: " << header.e_ident << endl;
    cout << "e_type: " << header.e_type << endl;
    cout << "e_machine: " << header.e_machine << endl;
    cout << "e_version: " << header.e_version << endl;
    cout << "e_entry: " << header.e_entry << endl;
    cout << "e_phoff: " << header.e_phoff << endl;
    cout << "e_shoff: " << header.e_shoff << endl;
    cout << "e_flags: " << header.e_flags << endl;
    cout << "e_ehsize: " << header.e_ehsize << endl;
    cout << "e_phentsize: " << header.e_phentsize << endl;
    cout << "e_phnum: " << header.e_phnum << endl;
    cout << "e_shentsize: " << header.e_shentsize << endl;
    cout << "e_shnum: " << header.e_shnum << endl;
    cout << "e_shstrndx: " << header.e_shstrndx << std::dec << endl;
}

void ELF32Reader::read_file()
{
    std::FILE *fp = nullptr;
    fp = std::fopen(file_name.c_str(), "rb");
    if (!fp)
        exit(1);
    fread(&header, sizeof(Elf32_Ehdr), 1, fp);
    fseek(fp, header.e_shoff + header.e_shentsize * header.e_shstrndx, SEEK_SET);
    fread(&string_table_header, sizeof(Elf32_Shdr), 1, fp);

    cout << endl << string_table_header << endl;

    char string_table[string_table_header.sh_size + 1];
    fseek(fp, string_table_header.sh_offset, SEEK_SET);
    fread(&string_table, string_table_header.sh_size, 1, fp);
    fseek(fp, header.e_shoff, SEEK_SET);
    section_headers = std::vector<Elf32_Shdr>(header.e_shnum);
    section_names = std::vector<std::string>(header.e_shnum);
    section_content.reserve(header.e_shnum);
    fread(&section_headers[0], header.e_shentsize, header.e_shnum, fp);
    for (int32_t i = 0; i < header.e_shnum; ++i)
    {
        char *name = string_table + section_headers[i].sh_name;
        int32_t len = strlen(name);
        char tmp[len + 1];
        tmp[len] = '\0';
        strncpy(tmp, name, len);
        section_names[i] = tmp;
        cout << section_names[i] << endl;
        cout << section_headers[i] << endl;
        fseek(fp, section_headers[i].sh_offset, SEEK_SET);
        std::vector<char> content_tmp(section_headers[i].sh_size);
        fread(&content_tmp[0], section_headers[i].sh_size, 1, fp);
        section_content.push_back(content_tmp);
    }
    std::fclose(fp);
}

void ELF64Reader::read_file()
{
    std::FILE *fp = nullptr;
    fp = std::fopen(file_name.c_str(), "rb");
    if (!fp)
        exit(1);
    fread(&header, sizeof(Elf64_Ehdr), 1, fp);
    fseek(fp, header.e_shoff + header.e_shentsize * header.e_shstrndx, SEEK_SET);
    fread(&string_table_header, sizeof(Elf64_Shdr), 1, fp);

    cout << endl << string_table_header << endl;

    char string_table[string_table_header.sh_size + 1];
    fseek(fp, string_table_header.sh_offset, SEEK_SET);
    fread(&string_table, string_table_header.sh_size, 1, fp);
    fseek(fp, header.e_shoff, SEEK_SET);
    section_headers = std::vector<Elf64_Shdr>(header.e_shnum);
    section_names = std::vector<std::string>(header.e_shnum);
    section_content.reserve(header.e_shnum);
    fread(&section_headers[0], header.e_shentsize, header.e_shnum, fp);
    for (int32_t i = 0; i < header.e_shnum; ++i)
    {
        char *name = string_table + section_headers[i].sh_name;
        int32_t len = strlen(name);
        char tmp[len + 1];
        tmp[len] = '\0';
        strncpy(tmp, name, len);
        section_names[i] = tmp;
        cout << section_names[i] << endl;
        cout << section_headers[i] << endl;
        fseek(fp, section_headers[i].sh_offset, SEEK_SET);
        std::vector<char> content_tmp(section_headers[i].sh_size);
        fread(&content_tmp[0], section_headers[i].sh_size, 1, fp);
        section_content.push_back(content_tmp);
    }
    std::fclose(fp);
}

#endif

#if (defined _WIN64) || (defined _WIN32)
#include <Windows.h>

class PEReader : public ExecutableReader
{
	friend std::ostream& operator<<(std::ostream&, const PEReader&);
public:
	PEReader(const std::string &file_name) : ExcutableReader(file_name) {}
	PEReader(const PEReader&) = delete;
	PEReader(PEReader&&);
	PEReader& operator=(const PEReader&) = delete;
	PEReader& operator=(PEReader&&);
	static FILE_TYPE type_check(const std::string &);
	virtual void read_file() = 0;
	~PEReader();
protected:
	IMAGE_DOS_HEADER idh;
	std::vector<IMAGE_SECTION_HEADER> ish;
	std::vector<std::vector<char>> sections;
	char *dos_stub;
	DWORD machine_type;
};

class PE32Reader : public PEReader
{
	IMAGE_NT_HEADERS32 inh;
public:
	void read_file() override;
	PE32Reader(const std::string &file_name) : PEReader(file_name) { }
};

class PE64Reader : public PEReader
{
	IMAGE_NT_HEADERS64 inh;
public:
	void read_file() override;
	PE64Reader(const std::string &file_name) : PEReader(file_name) { }
};

std::ostream& operator<<(std::ostream &out, const IMAGE_DOS_HEADER &idh)
{
	out << std::hex << "e_magic: " << idh.e_magic << "\tMagic number" << endl;
	out << "e_cblp: " << idh.e_cblp << "\tBytes on last page of file" << endl;
	out << "e_cp: " << idh.e_cp << "\tPages in file" << endl;
	out << "e_crlc: " << idh.e_crlc << "\tRelocations" << endl;
	out << "e_cparhdr: " << idh.e_cparhdr << "\tSize of header in paragraphs" << endl;
	out << "e_minalloc: " << idh.e_minalloc << "\tMinimum extra paragraphs needed" << endl;
	out << "e_maxalloc: " << idh.e_maxalloc << "\tMaximum extra paragraphs needed" << endl;
	out << "e_ss: " << idh.e_ss << "\tInitial(relative) SS value" << endl;
	out << "e_sp: " << idh.e_sp << "\tInitial SP value" << endl;
	out << "e_csum: " << idh.e_csum << "\tChecksum" << endl;
	out << "e_ip: " << idh.e_ip << "\tInitial IP value" << endl;
	out << "e_cs: " << idh.e_cs << "\tInitial(relative) CS value" << endl;
	out << "e_lfarlc: " << idh.e_lfarlc << "\tFile address of relocation table" << endl;
	out << "e_ovno: " << idh.e_ovno << "\tOverlay number" << endl;
	out << "e_res: " << idh.e_res << "\tReserved words" << endl;
	out << "e_oemid: " << idh.e_oemid << "\tOEM identifier(for e_oeminfo)" << endl;
	out << "e_oeminfo: " << idh.e_oeminfo << "\tOEM information; e_oemid specific" << endl;
	out << "e_res2: " << idh.e_res2 << "\tReserved words" << endl;
	out << "e_lfanew: " << idh.e_lfanew << "\tFile address of the new exe header" << endl << std::dec;
    return out;
}

std::ostream& operator<<(std::ostream &out, const PEReader &pv)
{
	out << pv.idh;
    return out;
}

PEReader::PEReader(PEReader &&pv) : ExecutableReader(std::move(file_name))
{
	if (dos_stub)
		delete []dos_stub;
	dos_stub = pv.dos_stub;
	pv.dos_stub = nullptr;
	idh = std::move(pv.idh);
	machine_type = std::move(pv.machine_type);	
}

PEReader& PEReader::operator=(PEReader &&pv)
{
	if (&pv != this)
	{
		if (dos_stub)
			delete []dos_stub;
		dos_stub = std::move(pv.dos_stub);
		idh = std::move(pv.idh);
		machine_type = std::move(pv.machine_type);
	}
	return *this;
}

ExecutableReader::FILE_TYPE PEReader::type_check(const std::string &file_name)
{
	IMAGE_DOS_HEADER idh;
	std::FILE *fp = nullptr;
	fp = fopen(file_name.c_str(), "rb");
	if (!fp)
	{
		exit(1);
	}
	fread(&idh, sizeof(IMAGE_DOS_HEADER), 1, fp);
	if (idh.e_magic != IMAGE_DOS_SIGNATURE)
		return FILE_TYPE::Error;
	uint16_t machine_type;
	uint32_t signature;
	fseek(fp, idh.e_lfanew, SEEK_SET);
	fread(&signature, sizeof(uint32_t), 1, fp);
	fread(&machine_type, sizeof(uint16_t), 1, fp);
	if (signature != IMAGE_NT_SIGNATURE)
		return FILE_TYPE::Error;
	switch (machine_type)
	{
		case IMAGE_FILE_MACHINE_I386:
			return FILE_TYPE::PE32;
		case IMAGE_FILE_MACHINE_IA64:
		case IMAGE_FILE_MACHINE_AMD64:
			return FILE_TYPE::PE64;
		default:
			return FILE_TYPE::Error;
	}
}

PEReader::~PEReader()
{
	if (dos_stub)
		delete []dos_stub;
}

void PE32Reader::read_file()
{
	std::FILE *fp = nullptr;
	fp = std::fopen(file_name.c_str(), "rb");
	if (!fp)
	{
		exit(1);
	}
	std::fread(&idh, sizeof(IMAGE_DOS_HEADER), 1, fp);
	int16_t dos_stub_len = idh.e_lfanew - sizeof(IMAGE_DOS_HEADER) + 1;
	dos_stub = new char[dos_stub_len];
	dos_stub[dos_stub_len - 1] = '\0';
	std::fread(dos_stub, dos_stub_len - 1, sizeof(char), fp);

//	std::fseek(fp, idh.e_lfanew, SEEK_SET);
	std::fread(&inh, sizeof(IMAGE_NT_HEADERS32), 1, fp);
	ish = std::vector<IMAGE_SECTION_HEADER>(inh.FileHeader.NumberOfSections);
	sections.reserve(inh.FileHeader.NumberOfSections);
	std::fread(&ish[0], sizeof(IMAGE_SECTION_HEADER), inh.FileHeader.NumberOfSections, fp);
	for (int32_t i = 0; i < inh.FileHeader.NumberOfSections; ++i)
	{
		cout << ish[i].Name << endl;
		sections.push_back(std::vector<char>(ish[i].SizeOfRawData));
		std::fseek(fp, ish[i].PointerToRawData, SEEK_SET);
		std::fread(&sections[i][0], sizeof(char), ish[i].SizeOfRawData, fp);
	}
	std::fclose(fp);
}

void PE64Reader::read_file()
{
	std::FILE *fp = nullptr;
	fp = std::fopen(file_name.c_str(), "rb");
	if (!fp)
	{
		exit(1);
	}
	std::fread(&idh, sizeof(IMAGE_DOS_HEADER), 1, fp);
	int16_t dos_stub_len = idh.e_lfanew - sizeof(IMAGE_DOS_HEADER) + 1;
	dos_stub = new char[dos_stub_len];
	dos_stub[dos_stub_len - 1] = '\0';
	std::fread(dos_stub, dos_stub_len - 1, sizeof(char), fp);

//	std::fseek(fp, idh.e_lfanew, SEEK_SET);
	std::fread(&inh, sizeof(IMAGE_NT_HEADERS64), 1, fp);
	ish = std::vector<IMAGE_SECTION_HEADER>(inh.FileHeader.NumberOfSections);
	sections.reserve(inh.FileHeader.NumberOfSections);
	std::fread(&ish[0], sizeof(IMAGE_SECTION_HEADER), inh.FileHeader.NumberOfSections, fp);
	for (int32_t i = 0; i < inh.FileHeader.NumberOfSections; ++i)
	{
		cout << ish[i].Name << endl;
		sections.push_back(std::vector<char>(ish[i].SizeOfRawData));
		std::fseek(fp, ish[i].PointerToRawData, SEEK_SET);
		std::fread(&sections[i][0], sizeof(char), ish[i].SizeOfRawData, fp);
	}
	std::fclose(fp);
}

#endif

enum ExecutableReader::FILE_TYPE ExecutableReader::type_check(const std::string &file_name)
{
    std::FILE *fp = nullptr;
    fp = fopen(file_name.c_str(), "rb");
    if (!fp)
    {
        exit(1);
    }
    char first_four_characters[5];
    fread(first_four_characters, sizeof(char), 4, fp);
    first_four_characters[4] = '\0';
#ifdef linux
    if (!strncmp("\177ELF", first_four_characters, 4))
    {
        return ELFReader::type_check(file_name);
    }
#endif
#if (defined _WIN64) || (defined _WIN32)
    if(!strncmp("MZ", first_four_characters, 2))
    {
        return PEReader::type_check(file_name);
    }
#endif
    return FILE_TYPE::Error;
}

#endif
