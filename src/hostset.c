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

static DEFINE_SPINLOCK(hs_lock);

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
	pr_err("Cannot create a procfs file for the host set %s\n", name);
	return -EFAULT;
    }//if
    proc_set_user(hs->proc_file, uid, gid);
    
    return 0;
}//hs_init


// Empty the content of the host set
static void hs_flush(struct host_set *hs)
{
    if (hs->hosts) {
	hse_free(hs->hosts);
	hs->hosts = NULL;
    }//if
}//hs_flush


// Free a host set entry (unconditionally)
static void _hs_destroy(struct host_set *hs)
{
    hs->refcount = 0;
    proc_remove(hs->proc_file);
    hs_flush(hs);
}//_hs_destroy

void hs_destroy(struct host_set *hs)
{
    if (hs->refcount) {
	_hs_destroy(hs);
    }//if
}//hs_destroy


// Free a host set entry (taking into account its refcount)
void hs_free(struct host_set *hs)
{
    if (hs->refcount && --hs->refcount == 0)
	_hs_destroy(hs);
}//hs_free


// Free a host element tree
void hse_free(struct host_set_elem *hse)
{
    struct host_set_elem *left_child, *right_child;
    spin_lock_bh(&hs_lock);
    left_child = hse->left_child;
    hse->left_child = 0;
    right_child = hse->right_child;
    hse->right_child = 0;
    spin_unlock_bh(&hs_lock);
    
    if (left_child)
	hse_free(left_child);
    if (right_child)
	hse_free(right_child);
    kfree(hse);
}//hse_free
