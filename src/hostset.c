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

static DEFINE_RWLOCK(hs_lock);

static void hse_free(struct host_set_elem *hse);
static void strrev(char *dst, const char *src);
static ssize_t proc_file_read(struct file * file, char __user * buf, 
	                      size_t size, loff_t * ppos);

static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = proc_file_read,
};

// Initialize a host set
int hs_init(struct host_set *hs, const char *name)
{
    kuid_t uid = make_kuid(&init_user_ns, 0);
    kgid_t gid = make_kgid(&init_user_ns, 0);
    
    if (strlen(name) > MAX_HOSTSET_NAME_LEN)
	return -EINVAL;

    strcpy(hs->name, name);
    hs->refcount = 1;
    hs->hosts = RB_ROOT;
    
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
    struct rb_root hosts;
    write_lock_bh(&hs_lock);
    hosts = hs->hosts;
    //RB_EMPTY_ROOT(hs->hosts);
    hs->hosts = RB_ROOT;
    write_unlock_bh(&hs_lock);
    
    if (hosts.rb_node)
	hse_free((struct host_set_elem *)hosts.rb_node);
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
static void hse_free(struct host_set_elem *hse)
{
    if (hse->rbnode.rb_left)
	hse_free((struct host_set_elem *)hse->rbnode.rb_left);
    if (hse->rbnode.rb_right)
	hse_free((struct host_set_elem *)hse->rbnode.rb_right);
    kfree(hse);
}//hse_free


// Lookup the host set for the specifed host name
bool hs_lookup(struct host_set *hs, const char *hostname)
{
    bool result = false;
    char pattern[MAX_HOSTNAME_LEN + 1];
    struct rb_node *node;
    
    if (! hs->hosts.rb_node)
	return false;
    
    strrev(pattern, hostname);
    
    if (! read_trylock(&hs_lock))
	return false;
    read_unlock(&hs_lock);
    
    read_lock_bh(&hs_lock);
    for (node = hs->hosts.rb_node; ! result && node;) {
	struct host_set_elem *hse = rb_entry(node, struct host_set_elem, rbnode);
	int cmp = strcmp(pattern, hse->name);
	if (cmp < 0)
	    node = node->rb_left;
	else if (cmp > 0)
	    node = node->rb_right;
	else
	    result = true;
    }//for
    read_unlock_bh(&hs_lock);
    return result;
}//hs_lookup


// Reverse a string
static void strrev(char *dst, const char *src)
{
    const char *ps = src + strlen(src);
    char *pd = dst;
    while (ps-- > src)
	*pd++ = *ps;
    *pd = '\0';
}//strrev


// Implementation of the read operation for the hostset proc-file
static ssize_t walk_hs_tree(struct host_set_elem *hse, char **bufptr, 
	                    size_t *pcount, loff_t *offs)
{
    return 0;
}//walk_hs_tree

static ssize_t proc_file_read(struct file *filp, char __user *buf, 
	                      size_t count, loff_t *offs)
{
    char *linbuf, *bufptr;
    struct host_set *hs = PDE_DATA(file_inode(filp));
    ssize_t chars_read;
    if (! hs->hosts.rb_node)
	return 0;

    bufptr = linbuf = kmalloc(count, GFP_KERNEL);
    read_lock_bh(&hs_lock);
    read_unlock_bh(&hs_lock);
    kfree(linbuf);
    
    return chars_read;
}//proc_file_read
