/* 
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <asm/errno.h>
#include "hostset.h"

// Initialize a host set
int hs_init(struct host_set *hs, const char *name)
{
#ifdef CONFIG_PROC_FS
    struct proc_dir_entry *pde;
    kuid_t uid = make_kuid(&init_user_ns, 0);
    kgid_t gid = make_kgid(&init_user_ns, 0);
#endif
    
    if (strlen(name) > MAX_HOST_SET_NAME_LEN)
	return -EINVAL;

    strcpy(hs->name, name);
    hs->refcount = 1;
    hs->hosts = NULL;
    
    return 0;
}//hs_init


// Free a host set entry (taking into account its refcount)
void hs_free(struct host_set *hs)
{
    if (hs->refcount && --hs->refcount == 0 && hs->hosts)
	hse_free(hs->hosts);
}//hs_free


// Free a host set entry (unconditionally)
void hs_destroy(struct host_set *hs)
{
    if (hs->refcount && hs->hosts) {
	hs->refcount = 0;
	hse_free(hs->hosts);
    }//if
}//hs_destroy


// Free a host element tree
void hse_free(struct host_set_elem *hse)
{
    if (hse->left_child)
	hse_free(hse->left_child);
    if (hse->right_child)
	hse_free(hse->right_child);
    kfree(hse);
}//hse_free
