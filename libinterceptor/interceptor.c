/**
 *  Advanced Operating Systems class
 *	MIM UW
 *
 *	Task #1: ELF
 *
 *	Author: Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>
 */

#define _GNU_SOURCE

#include "interceptor.h"

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(x) ((void)(x))

#define ITER_GO		(0)
#define ITER_BREAK	(1)

#define REL_SYMBOL_NOT_FOUND	(0)
#define REL_SYMBOL_FOUND		(1)

#define REL_TABLE_SIZE_TAG(t) ((t) == DT_REL ? DT_RELSZ  : DT_RELASZ)
#define REL_ENTRY_SIZE_TAG(t) ((t) == DT_REL ? DT_RELENT : DT_RELAENT)

enum rel_action {
	INTERCEPT,
	UNINTERCEPT
};

struct rel_slot_result {
	// Input parameter: function name
	const char *name;
	enum rel_action action;
	void *new_func;

	// Output: original function address if it was resolved
	void *original_func;
};

struct rel_symbol_result {
	// Input parameter: function name
	const char *name;

	// Output: resolved function address
	void *fn;
};

static bool
raw_strequal(const char *lhs, const char *rhs)
{
	while (*lhs != '\0' && *rhs != '\0' && *lhs == *rhs) {
		++lhs;
		++rhs;
	}

	if (*lhs == '\0' && *rhs == '\0') 
		return true;
	else
		return false;
}

static ElfW(Dyn) *
find_dyn_entry_with_tag(ElfW(Dyn) *entry, uint64_t tag)
{
	while (entry->d_tag != DT_NULL) {
		if (entry->d_tag == tag) {
			return entry;
		}

		++entry;
	}

	if (entry->d_tag == DT_NULL && tag == DT_NULL) {
		return entry;
	} else {
		return NULL;
	}
}

static const ElfW(Phdr) *
find_dynamic_section(struct dl_phdr_info *info)
{
	for (int i = 0; i < info->dlpi_phnum; ++i) {
		const ElfW(Phdr) *phdr = &(info->dlpi_phdr[i]);
		if (phdr->p_type == PT_DYNAMIC) {
			return phdr;
		}
	}
	
	return NULL;
}

static ElfW(Dyn) *
dynamic_section_start(struct dl_phdr_info *info, const ElfW(Phdr) *phdr)
{
	return (ElfW(Dyn) *)(info->dlpi_addr + phdr->p_vaddr);
}

static ElfW(Rela) *
find_rela_entry_with_name(const char *name, ElfW(Rela) *rel_table, size_t rel_count,
	const char *str_table, ElfW(Sym) *sym_table)
{
	for (unsigned int i = 0; i < rel_count; ++i) {
		ElfW(Rela) *reloc = &(rel_table[i]);
	
		if (ELF64_R_TYPE(reloc->r_info) != R_X86_64_JUMP_SLOT)
			continue;

		uint64_t sym_index = ELF64_R_SYM(reloc->r_info);
		if (sym_index == 0)
			continue;

		ElfW(Sym) *sym = &(sym_table[sym_index]);
		ElfW(Word) str_index = sym->st_name;
		if (str_index == 0)
			continue;

		const char *str = &(str_table[str_index]);
		if (raw_strequal(str, name)) {
			return reloc;
		}
	}

	return NULL;
}

static bool
is_symbol_wanted(const ElfW(Sym) *symbol,
		const char *wanted,
		const char *strtab)
{
	ElfW(Word) str_index = 0;
	const char *symbol_name = NULL;
	uint64_t type = 0;
	uint64_t bind = 0;

	// Omit non-function symbols
	type = ELF64_ST_TYPE(symbol->st_info);
	if (type != STT_FUNC && type != STT_GNU_IFUNC)
		return false;

	// Omit local symbols
	bind = ELF64_ST_BIND(symbol->st_info);
	if (bind == STB_LOCAL)
		return false;

	// Omit undefined symbols (without resolved st_value)
	if (symbol->st_shndx == SHN_UNDEF)
		return false;

	str_index = symbol->st_name;
	if (str_index == 0)
		return false;

	symbol_name = strtab + str_index;
	if (raw_strequal(symbol_name, wanted))
		return true;
	else
		return false;
}

// Implementation taken from Sun's Linker and Libraries guide (page 206)
static unsigned long
calc_sysv_hash(const unsigned char *name)
{
	unsigned long h = 0;
	unsigned long g;

	while (*name)
	{
		h = (h << 4) + *name++;
		if ( (g = h & 0xf0000000) )
			h ^= g >> 24;
		h &= ~g;
	}

	return h;
}

// dl_new_hash function from https://sourceware.org/ml/binutils/2006-10/msg00377.html
static uint_fast32_t
calc_gnu_hash (const char *s)
{
	uint_fast32_t h = 5381;
	for (unsigned char c = *s; c != '\0'; c = *++s)
		h = h * 33 + c;
	return h & 0xffffffff;
}

static ElfW(Sym) *
handle_sysv_symbol_lookup(const char *wanted, ElfW(Dyn) *dynamic_section,
		ElfW(Sym) *symtab, const char *strtab, ElfW(Dyn) *hashtab)
{
	ElfW(Word) *hash_table = (ElfW(Word) *)(hashtab->d_un.d_ptr);

	// According to Sun's Linker guide, nchains should be equal to amount of
	// symbol table entries
	ElfW(Word) nbucket	= *(hash_table);
	ElfW(Word) nchain	= *(hash_table + 1);
	ElfW(Word) *bucket	=  (hash_table + 2);
	ElfW(Word) *chain	=  (bucket + nbucket);

	const unsigned char *name = (const unsigned char *)(wanted);
	unsigned long request_hash = calc_sysv_hash(name);
	ElfW(Word) index = bucket[request_hash % nbucket];

	while (index != STN_UNDEF) {
		ElfW(Sym) *symbol = &symtab[index];
		if (is_symbol_wanted(symbol, wanted, strtab))
			return symbol;

		if (index >= nchain)
			break;
		index = chain[index];
	}

	return NULL;
}

// Based on description from:
// https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
static ElfW(Sym) *
handle_gnu_symbol_lookup(const char *wanted, ElfW(Dyn) *dynamic_section,
		ElfW(Sym) *symtab, const char *strtab, ElfW(Dyn) *hashtab_entry)
{
	// GNU_HASH starts with 4 32-bit words
	Elf32_Word *hashtab = (Elf32_Word *)hashtab_entry->d_un.d_ptr;

	Elf32_Word nbuckets = *(hashtab++);
	Elf32_Word symndx = *(hashtab++);
	Elf32_Word maskwords = *(hashtab++);
	Elf32_Word shift2 = *(hashtab++);

	UNUSED(nbuckets);
	UNUSED(symndx);
	UNUSED(maskwords);
	UNUSED(shift2);

#if __ELF_NATIVE_CLASS == 64
	Elf64_Xword *bloom = (Elf64_Xword *)hashtab;
#else
	Elf32_Word  *bloom = (Elf32_Word *)hashtab;
#endif

	// Skip the Bloom filter. It consists of `maskwords` words.
	bloom += maskwords;

	Elf32_Word *buckets = (Elf32_Word *)bloom;
	Elf32_Word *hashvals = buckets + nbuckets;

	Elf32_Word wanted_h = calc_gnu_hash(wanted);
	Elf32_Word index = (wanted_h % nbuckets);
	Elf32_Word symidx = buckets[index];
	if (symidx == 0)
		return NULL;
	
	ElfW(Sym) *symbol = &symtab[symidx];
	Elf32_Word *hashval = &hashvals[symidx - symndx];
	for (; true; symbol++) {
		Elf32_Word h = *hashval++;

		// Compare top 31 bits
		if (((wanted_h & ~1) == (h & ~1)) && is_symbol_wanted(symbol, wanted, strtab))
			return symbol;

		// Least significant bit of hash chain is used as stopper bit
		if (h & 1)
			break;
	}

	return NULL;
}

static ElfW(Sym) *
handle_symbol_lookup(const char *wanted, ElfW(Dyn) *dynamic_section,
		ElfW(Sym) *symtab, const char *strtab)
{
	ElfW(Dyn) *hashtab = NULL;

	// Try with System V-style hash table
	hashtab = find_dyn_entry_with_tag(dynamic_section, DT_HASH);
	if (hashtab != NULL)
		return handle_sysv_symbol_lookup(wanted, dynamic_section, symtab, strtab, hashtab);
	
	// Try with GNU-style hash table
	hashtab = find_dyn_entry_with_tag(dynamic_section, DT_GNU_HASH);
	if (hashtab != NULL)
		return handle_gnu_symbol_lookup(wanted, dynamic_section, symtab, strtab, hashtab);
	
	// Nothing else to try, thus symbol not found
	return NULL;
}

static int
rel_symbol_finder(struct dl_phdr_info *info, size_t size, void *data)
{
	struct rel_symbol_result *rel_symbol = (struct rel_symbol_result *)data;

	if (raw_strequal(info->dlpi_name, "linux-vdso.so.1"))
		return REL_SYMBOL_NOT_FOUND;

	// Find .dynamic
	const ElfW(Phdr) *dynamic_section = find_dynamic_section(info);
	if (dynamic_section == NULL)
		return REL_SYMBOL_NOT_FOUND;
	
	// First .dynamic section entry
	ElfW(Dyn) *dynamic_start_entry = dynamic_section_start(info, dynamic_section);

	// Find symbol table
	ElfW(Dyn) *symtab = find_dyn_entry_with_tag(dynamic_start_entry, DT_SYMTAB);
	if (symtab == NULL)
		return REL_SYMBOL_NOT_FOUND;
	
	ElfW(Sym) *sym_table = (ElfW(Sym) *)(symtab->d_un.d_ptr);
	if (sym_table == NULL)
		return REL_SYMBOL_NOT_FOUND;
	
	// Find string table
	ElfW(Dyn) *strtab = find_dyn_entry_with_tag(dynamic_start_entry, DT_STRTAB);
	if (strtab == NULL)
		return REL_SYMBOL_NOT_FOUND;
	
	const char *str_table = (const char *)(strtab->d_un.d_ptr);
	if (str_table == NULL)
		return REL_SYMBOL_NOT_FOUND;
	
	// Find symbol entry for original function using hash tables
	ElfW(Sym) *sym = handle_symbol_lookup(rel_symbol->name, dynamic_start_entry,
		sym_table, str_table);
	if (sym != NULL) {
		uint64_t symbol_type = ELF64_ST_TYPE(sym->st_info);

		// Depending on function's symbol type - we might need to call ifunc resolver to
		// get the proper address
		void *(*ifunc_resolver)() = NULL;
		void *symbol_value = (void *)(info->dlpi_addr + sym->st_value);
		if (symbol_type == STT_FUNC) {
			rel_symbol->fn = symbol_value;
		} else {
			ifunc_resolver = (void *(*)())(symbol_value);
			rel_symbol->fn = ifunc_resolver();
		}

		return REL_SYMBOL_FOUND;
	}

	return REL_SYMBOL_NOT_FOUND;
}

static int
handle_relocation_entries(struct dl_phdr_info *info, size_t size, void *data)
{
	struct rel_slot_result *rel_slot = data;

	// Find .dynamic
	const ElfW(Phdr) *dynamic_section = find_dynamic_section(info);
	if (dynamic_section == NULL)
		return ITER_GO;
	
	// First .dynamic section entry
	ElfW(Dyn) *dynamic_start_entry = dynamic_section_start(info, dynamic_section);

	// Find symbol table
	ElfW(Dyn) *symtab = find_dyn_entry_with_tag(dynamic_start_entry, DT_SYMTAB);
	if (symtab == NULL)
		return ITER_GO;
	
	ElfW(Sym) *sym_table = (ElfW(Sym) *)(symtab->d_un.d_ptr);
	if (sym_table == NULL)
		return ITER_GO;
	
	// Find string table
	ElfW(Dyn) *strtab = find_dyn_entry_with_tag(dynamic_start_entry, DT_STRTAB);
	if (strtab == NULL)
		return ITER_GO;
	
	const char *str_table = (const char *)(strtab->d_un.d_ptr);
	if (str_table == NULL)
		return ITER_GO;

	// Find relocation entries type (DT_REL or DT_RELA)
	ElfW(Dyn) *pltrel = find_dyn_entry_with_tag(dynamic_start_entry, DT_PLTREL);
	if (pltrel == NULL)
		return ITER_GO;
	
	uint64_t reloc_table_tag = pltrel->d_un.d_val;
	uint64_t reloc_entry_size_tag = REL_ENTRY_SIZE_TAG(reloc_table_tag);

	ElfW(Dyn)* relent = find_dyn_entry_with_tag(dynamic_start_entry, reloc_entry_size_tag);
	ElfW(Dyn)* jmprel = find_dyn_entry_with_tag(dynamic_start_entry, DT_JMPREL);
	ElfW(Dyn)* pltrelsz = find_dyn_entry_with_tag(dynamic_start_entry, DT_PLTRELSZ);

	size_t rel_entry_size = relent->d_un.d_val;
	size_t rel_total_size = pltrelsz->d_un.d_val;
	size_t rel_entries = rel_total_size / rel_entry_size;

	// According to: https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-54839.html#chapter7-2
	// on x64 only Elf64_Rela entries are used
	// Also: in calculating JUMP_SLOT relocation, r_addend is not used
	ElfW(Rela) *rel_table = (ElfW(Rela) *)(jmprel->d_un.d_ptr);
	ElfW(Rela) *entry = find_rela_entry_with_name(rel_slot->name,
		rel_table, rel_entries, str_table, sym_table);
	if (entry == NULL)
		return ITER_GO;

	if (rel_slot->original_func == NULL) {
		struct rel_symbol_result rel_symbol = { 0 };

		rel_symbol.name = rel_slot->name;
		if (dl_iterate_phdr(rel_symbol_finder, &rel_symbol) == REL_SYMBOL_NOT_FOUND)
			return ITER_BREAK;

		rel_slot->original_func = rel_symbol.fn;
		if (rel_slot->original_func == NULL)
			return ITER_BREAK;
	}

	void **got_entry = (void **)(info->dlpi_addr + entry->r_offset);
	if (rel_slot->action == INTERCEPT) {
		*got_entry = rel_slot->new_func;
	} else {
		*got_entry = rel_slot->original_func;
	}

	return ITER_GO;
}

/**
 *	Intercept PLT function call
 */
void *
intercept_function(const char *name, void *new_func)
{
	struct rel_slot_result rel_slot = { 0 };

	rel_slot.name = name;
	rel_slot.action = INTERCEPT;
	rel_slot.new_func = new_func;
	dl_iterate_phdr(handle_relocation_entries, &rel_slot);

	return rel_slot.original_func;
}

/**
 * Disable interception of PLT function call
 */
void
unintercept_function(const char *name)
{
	struct rel_slot_result rel_slot = { 0 };

	rel_slot.name = name;
	rel_slot.action = UNINTERCEPT;

	// We do not need to check return value
	dl_iterate_phdr(handle_relocation_entries, &rel_slot);
}
