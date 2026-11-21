#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct lookup {
    const void *address;
    unsigned long base;
    const char *name;
};

static int find_object(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct lookup *lookup = opaque;
    uintptr_t address = (uintptr_t)lookup->address;
    size_t index;

    (void)size;
    for (index = 0; index < info->dlpi_phnum; index++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];
        uintptr_t start;
        uintptr_t end;

        if (header->p_type != PT_LOAD) continue;
        start = (uintptr_t)info->dlpi_addr + header->p_vaddr;
        end = start + header->p_memsz;
        if (address >= start && address < end) {
            lookup->base = (unsigned long)info->dlpi_addr;
            lookup->name = info->dlpi_name;
            return 1;
        }
    }
    return 0;
}

int dladdr(const void *address, Dl_info *info)
{
    static int (*next_dladdr)(const void *, Dl_info *);
    struct lookup lookup = { address, 0, NULL };
    const char *fallback;

    if (!next_dladdr) next_dladdr = dlsym(RTLD_NEXT, "dladdr");
    if (next_dladdr && next_dladdr(address, info) &&
        info->dli_fname && *info->dli_fname)
        return 1;

    /*
     * Jasper's bounded ELF loader does not populate glibc's complete DSO
     * directory. Recover the path from the actual loaded program headers.
     * Wine's own binary remains unmodified; this is a Linux compatibility
     * adapter for the incomplete host loader interface.
     */
    dl_iterate_phdr(find_object, &lookup);
    fallback = lookup.name;
    if (!fallback || !*fallback) fallback = getenv("JASPER_WINE_NTDLL_PATH");
    if (!fallback || !*fallback) return 0;
    info->dli_fname = fallback;
    info->dli_fbase = (void *)lookup.base;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    return 1;
}
