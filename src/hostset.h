/* 
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#include <linux/rbtree.h>

#ifndef CONFIG_PROC_FS
#error "XT_TLS requires proc filesystem support enabled in the kernel"
#endif

// Host set element holding a single host name
struct host_set_elem {
    struct rb_node rbnode;
    __u64 hit_count;
    char name[]; //the host name (reversed)
};//host_set_elem


// Host set itself
struct host_set {
    __u32 refcount; // reference count: increased by 1 with each rule using this set
    char name[MAX_HOSTSET_NAME_LEN + 1];  //the set name (stringz)
    struct rb_root hosts;
    struct proc_dir_entry *proc_file;
    loff_t filesize;
};//host_set


// Descriptor holding a pointer to the host set table for the specific net namespace
struct host_set_table_descriptor {
    struct net *net;
    struct proc_dir_entry *proc_fs_dir, *proc_fs_hostset_dir;
    struct host_set *host_sets;
    struct host_set_table_descriptor *next;
};//host_set_table_descriptor

// The list of the host sets tables we use
extern struct host_set_table_descriptor *host_set_tables;


// Initialize a host set
int hs_init(struct host_set *hs, const char *name, struct proc_dir_entry *parent_dir);
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
// Lookup the host set for the specifed host name
bool hs_lookup(struct host_set *hs, const char *hostname, bool suffix_matching);

// Find the host set table for a given net namespace
static inline struct host_set_table_descriptor 
    *find_host_set_table(struct net *net, struct host_set_table_descriptor ***ppprev)
{
    struct host_set_table_descriptor **pp;
    for (pp = &host_set_tables; *pp; pp = &((*pp)->next)) {
	if ((*pp)->net == net) {
	    if (ppprev)
		*ppprev = pp;
	    return *pp;
	}//if
    }//for
    return NULL;
}//find_host_set_table
