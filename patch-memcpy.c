
	/* (c) 2012 Andrei Nigmatulin */

	/* This small utility programm can strip a binary or a shared library
       in particular way to remove dependency from memcpy@GLIBC_2.14 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>


int process_elf(void *elf, size_t elf_sz)
{
	Elf64_Ehdr *elf_hdr = elf;

	Elf64_Shdr *sh = (Elf64_Shdr *) ((char *) elf + elf_hdr->e_shoff);
	Elf64_Shdr *sh_str = sh + elf_hdr->e_shstrndx;
	char *strtab = (char *) elf + sh_str->sh_offset;

	Elf64_Shdr *sh_dynsym = 0;
	Elf64_Sym *dynsym = 0;

	Elf64_Shdr *sh_dynstr = 0;
	char *dynstr = 0;

	Elf64_Shdr *sh_version = 0;
	unsigned short *versions = 0;

	Elf64_Shdr *sh_version_r = 0;
	Elf64_Verneed *verneed = 0;

	unsigned i;

	for (i = 1; i < elf_hdr->e_shnum; i++) {
		Elf64_Shdr *this = sh + i;

		char *name = strtab + this->sh_name;

		if (this->sh_type == SHT_DYNSYM && !strcmp(name, ".dynsym")) {
			sh_dynsym = this;
			dynsym = (typeof(dynsym)) ((char *) elf + this->sh_offset);
			printf("[ok] found .dynsym section\n");
		}
		else if (this->sh_type == SHT_STRTAB && !strcmp(name, ".dynstr")) {
			sh_dynstr = this;
			dynstr = (typeof(dynstr)) ((char *) elf + this->sh_offset);
			printf("[ok] found .dynstr section\n");
		}
		else if (this->sh_type == SHT_GNU_versym && !strcmp(name, ".gnu.version")) {
			sh_version = this;
			versions = (typeof(versions)) ((char *) elf + this->sh_offset);
			printf("[ok] found .gnu.version section\n");
		}
		else if (this->sh_type == SHT_GNU_verneed && !strcmp(name, ".gnu.version_r")) {
			sh_version_r = this;
			verneed = (typeof(verneed)) ((char *) elf + this->sh_offset);
			printf("[ok] found .gnu.version_r section\n");
		}

//		printf("%s\n", name);
	}

	if (!sh_dynsym || !sh_dynstr || !sh_version || !sh_version_r) {
		fprintf(stderr, "can't find one or more required sections\n");
		return -1;
	}

	/* find GLIBC_2.14 & GLIBC_2.2.5 version numbers */

	unsigned glibc_2_14_version_idx = -1U;
	unsigned glibc_2_2_5_version_idx = -1U;

	Elf64_Verneed *next_verneed;
	int last = 0;

	for ( ; !last; verneed = next_verneed) {
		char *filename = dynstr + verneed->vn_file;
		next_verneed = (typeof(next_verneed)) ((char *) verneed + verneed->vn_next);

		last = verneed->vn_next == 0;

		if (strcmp(filename, "libc.so.6")) {
			continue;
		}

		char *end_of_naux;

		if (last) {
			end_of_naux = (char *) elf + sh_version_r->sh_offset + sh_version_r->sh_size;
		}
		else {
			end_of_naux = (char *) next_verneed;
		}

		unsigned cnt = verneed->vn_cnt;
		Elf64_Vernaux *naux = (typeof(naux)) ((char *) verneed + verneed->vn_aux);
		Elf64_Vernaux *next_naux;

		for ( ; cnt --; naux = next_naux) {
			char *name = dynstr + naux->vna_name;
			next_naux = (typeof(next_naux)) ((char *) naux + naux->vna_next);

//			printf("checking name %p %s %u\n", naux, name, naux->vna_next);

			if (!strcmp(name, "GLIBC_2.14")) {
				glibc_2_14_version_idx = naux->vna_other;

				if (cnt > 0) {
					memmove(naux, next_naux, end_of_naux - (char *) next_naux);
				}

				verneed->vn_cnt --;

				next_naux = naux;
			}
			else if (!strcmp(name, "GLIBC_2.2.5")) {
				glibc_2_2_5_version_idx = naux->vna_other;
			}
		}

		break;
	}

	if (glibc_2_14_version_idx == -1U) {
		fprintf(stderr, "can't find GLIBC_2.14 version index - already patched ?\n");
		return -1;
	}

	if (glibc_2_2_5_version_idx == -1U) {
		fprintf(stderr, "can't find GLIBC_2.2.5 version index\n");
		return -1;
	}

	printf("[ok] found GLIBC_2.14 version index %u\n", glibc_2_14_version_idx);
	printf("[ok] found GLIBC_2.2.5 version index %u\n", glibc_2_2_5_version_idx);

	/* find and patch all symbols dependant on GLIBC_2.14 version number */

	for (i = 1; i < sh_version->sh_size / sizeof(unsigned short); i++) {
		unsigned short v = versions[i];

		if (v != glibc_2_14_version_idx) {
			continue;
		}

		printf("  patching '%s': %u -> %u\n", dynstr + dynsym[i].st_name, glibc_2_14_version_idx, glibc_2_2_5_version_idx);

		versions[i] = glibc_2_2_5_version_idx;
	}

	return 0;
}


int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <filename>\n", argv[0]);
		return 1;
	}

	int fd = open(argv[1], O_RDWR);

	if (0 > fd) {
		perror("open() failed");
		return 1;
	}

	struct stat st;

	if (0 > fstat(fd, &st)) {
		perror("fstat() failed");
		close(fd);
		return 1;
	}

	void *mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (mem == MAP_FAILED) {
		perror("mmap() failed");
		close(fd);
		return 1;
	}

	close(fd);

	process_elf(mem, st.st_size);

	if (0 > msync(mem, st.st_size, MS_SYNC)) {
		perror("msync() failed");
		return 1;
	}

	munmap(mem, st.st_size);

	return 0;
}

