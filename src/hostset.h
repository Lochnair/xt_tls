/* 
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#define MAX_HOST_SET_NAME_LEN 31
#ifndef CONFIG_PROC_FS
#error "XT_TLS requires proc filesystem support enabled in the kernel"
#endif

// Host set element holding a single host name
struct host_set_elem {
    struct host_set_elem *left_child, *right_child;
    char name[]; //the host name (stringz)
};//host_set_elem


// Host set itself
struct host_set {
    __u32 refcount; // reference count: increased by 1 with each rule using this set
    char name[MAX_HOST_SET_NAME_LEN + 1];  //the set name (stringz)
    struct host_set_elem *hosts;
    struct proc_dir_entry *proc_file;
};//host_set


// Initialize a host set
int hs_init(struct host_set *hs, const char *name);
// Increment the usage count for the host set
static inline void hs_hold(struct host_set *hs) { hs->refcount++; }
// Free a host set entry (taking into account its refcount)
void hs_free(struct host_set *hs);
// Free a host set entry (unconditionally)
void hs_destroy(struct host_set *hs);
// Check if this host set entry is free (unused)
static inline bool hs_is_free(struct host_set *hs) { return hs->refcount == 0; }
// Zeroize a host set entry (mark it unused)
static inline void hs_zeroize(struct host_set *hs) { hs->refcount = 0; }

// Free a host element tree
void hse_free(struct host_set_elem *hse);
