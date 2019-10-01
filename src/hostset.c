/* 
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#define pr_fmt(fmt) "[" KBUILD_MODNAME "]: " fmt
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <asm/errno.h>
#include "xt_tls.h"
#include "hostset.h"

static struct file_operations proc_fops = {
    
};

// Initialize a host set
int hs_init(struct host_set *hs, const char *name)
{
    kuid_t uid = make_kuid(&init_user_ns, 0);
    kgid_t gid = make_kgid(&init_user_ns, 0);
    
    if (strlen(name) > MAX_HOST_SET_NAME_LEN)
	return -EINVAL;

    strcpy(hs->name, name);
    hs->refcount = 1;
    hs->hosts = NULL;
    
    hs->proc_file = proc_create_data(name, 0644, proc_fs_hostset_dir, 
	    &proc_fops, &hs);
    if (! hs->proc_file) {
	pr_err("Cannot create a procfs file for the host set %s", name);
	return -EFAULT;
    }//if
    proc_set_user(hs->proc_file, uid, gid);
    
    return 0;
}//hs_init


// Free a host set entry (taking into account its refcount)
void hs_free(struct host_set *hs)
{
    if (hs->refcount && --hs->refcount == 0 && hs->hosts)
	hs_destroy(hs);
}//hs_free


// Free a host set entry (unconditionally)
void hs_destroy(struct host_set *hs)
{
    if (hs->refcount && hs->hosts) {
	hs->refcount = 0;
	proc_remove(hs->proc_file);
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
