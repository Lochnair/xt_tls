/* 
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#define pr_fmt(fmt) "[" KBUILD_MODNAME "]: " fmt
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <asm/errno.h>

#include "compat.h"
#include "xt_tls.h"
#include "hostset.h"

static DEFINE_RWLOCK(hs_lock);

static void hse_free(struct host_set_elem *hse);
static void strrev(char *dst, const char *src, size_t max_len);
static int seq_file_open(struct inode *inode, struct file *file);
static ssize_t proc_write(struct file *file, const char __user *input, 
    size_t size, loff_t *loff);

// Params for displaying a hostset content and calculationg its file size
#define HIT_COUNT_DISPL_WIDTH 12
#define HSE_SIZE_OVERHEAD (HIT_COUNT_DISPL_WIDTH + 2)

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = seq_file_open,
    .read = seq_read,
    .write = proc_write,
    .release = seq_release,	
};
#else
static struct proc_ops proc_fops = {
    .proc_open = seq_file_open,
    .proc_read = seq_read,
    .proc_write = proc_write,
    .proc_release = seq_release,
};
#endif

// Initialize a host set
int hs_init(struct net *net, struct host_set *hs, const char *name)
{
    struct xt_net *xt = tls_net(net);

    kuid_t uid = make_kuid(&init_user_ns, 0);
    kgid_t gid = make_kgid(&init_user_ns, 0);
    
    if (strlen(name) > MAX_HOSTSET_NAME_LEN)
	return -EINVAL;

    strcpy(hs->name, name);
    hs->refcount = 1;
    hs->hosts = RB_ROOT;
    hs->filesize = 0;
    
    hs->proc_file = proc_create_data(name, 0644, xt->proc_fs_hostset_dir, 
	    &proc_fops, hs);
    if (! hs->proc_file) {
	pr_err("Cannot create a procfs file for the host set %s\n", name);
	return -EFAULT;
    }//if
    proc_set_user(hs->proc_file, uid, gid);
    
    return 0;
}//hs_init


// Create a new hostset element in the heap
static struct host_set_elem *hse_create(const char *hostname)
{
    size_t len = strlen(hostname);
    struct host_set_elem *hse;
    
    if (len > MAX_HOSTNAME_LEN)
	len = MAX_HOSTNAME_LEN;
    
    hse = kmalloc(sizeof(struct host_set_elem) + len + 1, GFP_KERNEL);
    if (! hse)
	return NULL;
    
    RB_CLEAR_NODE(&hse->rbnode);
    hse->rbnode.rb_left = hse->rbnode.rb_right = NULL;
    hse->hit_count = 0;
    strrev(hse->name, hostname, len);
    return hse;
}//hse_create


// Add a hostname to this set
static int hs_add_hostname(struct host_set *hs, const char *hostname)
{
    struct rb_node **link = &hs->hosts.rb_node, *parent = NULL;
    bool already_have = false;
    struct host_set_elem *new_elem;
    
    if (strlen(hostname) == 0) {
	pr_err("Empty host names are not allowed\n");
	return -EINVAL;
    }//if
    
    new_elem = hse_create(hostname);
    if (! new_elem) {
	pr_err("Cannot allocate memory for a new hostname\n");
	return -ENOMEM;
    }//if
    
#ifdef XT_TLS_DEBUG
    pr_info("New hostset elem created at %px:\n", new_elem);
    pr_info("  rbnode: l=%px, r=%px, color=%lu\n", new_elem->rbnode.rb_left, 
	    new_elem->rbnode.rb_left, new_elem->rbnode.__rb_parent_color);
    pr_info("  name='%s'\n", new_elem->name);
#endif
    
    write_lock_bh(&hs_lock);
    
    while (*link) {
	struct host_set_elem *hse = rb_entry(*link, struct host_set_elem, rbnode);
	int cmp = strcmp(new_elem->name, hse->name);
	parent = *link;
	if (cmp < 0)
	    link = &(*link)->rb_left;
	else if (cmp > 0)
	    link = &(*link)->rb_right;
	else {
	    already_have = true;
	    break;
	}//if
    }//while

    if (! already_have) {
	rb_link_node(&new_elem->rbnode, parent, link);
	rb_insert_color(&new_elem->rbnode, &hs->hosts);	
	hs->filesize += strlen(hostname) + HSE_SIZE_OVERHEAD;
    }//if
    
    write_unlock_bh(&hs_lock);
    
    if (already_have)
	kfree(new_elem);
    
    return 0;
}//hs_add_hostname


// Remove a hostname from this set
static int hs_remove_hostname(struct host_set *hs, const char *hostname)
{
    struct rb_node *node = hs->hosts.rb_node;
    struct host_set_elem *hse;
    bool found = false;
    char hostnamerev[MAX_HOSTNAME_LEN + 1];
    
    if (strlen(hostname) == 0) {
	pr_err("Empty host names are not allowed\n");
	return -EINVAL;
    }//if
    
    strrev(hostnamerev, hostname, MAX_HOSTNAME_LEN);
    
    write_lock_bh(&hs_lock);
    
    while (node) {
	int cmp;
	hse = rb_entry(node, struct host_set_elem, rbnode);
	cmp = strcmp(hostnamerev, hse->name);
	if (cmp < 0)
	    node = node->rb_left;
	else if (cmp > 0)
	    node = node->rb_right;
	else {
	    found = true;
	    break;
	}//if
    }//while

    if (found) {
	rb_erase(node, &hs->hosts);
	hs->filesize -= strlen(hostname) + HSE_SIZE_OVERHEAD;
    }//if
    
    write_unlock_bh(&hs_lock);
    
    if (found) {
	kfree(hse);
    } else {
	pr_err("No such host: %s\n", hostname);
	return -ENOENT;
    }//if
    
    return 0;
}//hs_remove_hostname


// Empty the content of the host set
static void hs_flush(struct host_set *hs)
{
    struct rb_root hosts;
    write_lock_bh(&hs_lock);
    hosts = hs->hosts;
    hs->hosts = RB_ROOT;
    hs->filesize = 0;
    write_unlock_bh(&hs_lock);
    
    if (hosts.rb_node)
	hse_free(rb_entry(hosts.rb_node, struct host_set_elem, rbnode));
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
	hse_free(rb_entry(hse->rbnode.rb_left, struct host_set_elem, rbnode));
    if (hse->rbnode.rb_right)
	hse_free(rb_entry(hse->rbnode.rb_right, struct host_set_elem, rbnode));
    kfree(hse);
}//hse_free


// Lookup the host set for the specifed host name
bool hs_lookup(struct host_set *hs, const char *hostname, bool suffix_matching)
{
    bool result = false;
    char pattern[MAX_HOSTNAME_LEN + 1];
    struct rb_node *node;
    if (! hs->hosts.rb_node)
	return false;
    
    strrev(pattern, hostname, MAX_HOSTNAME_LEN);
    
    if (! read_trylock(&hs_lock))
	return false;
    read_unlock(&hs_lock);
    
    read_lock_bh(&hs_lock);
    for (node = hs->hosts.rb_node; ! result && node;) {
	struct host_set_elem *hse = rb_entry(node, struct host_set_elem, rbnode);
	int cmp;
	if (suffix_matching) {
	    size_t len = strlen(hse->name);
	    cmp = strncmp(pattern, hse->name, len);
	} else {
	    cmp = strcmp(pattern, hse->name);
	}//if
	
	if (cmp < 0)
	    node = node->rb_left;
	else if (cmp > 0)
	    node = node->rb_right;
	else {
	    hse->hit_count++;
	    result = true;
	}//if
    }//for
    read_unlock_bh(&hs_lock);
    return result;
}//hs_lookup


// Reverse a string
static void strrev(char *dst, const char *src, size_t max_len)
{
    const char *ps = src + strlen(src);
    char *pd = dst;
    while (ps-- > src && (pd - dst) < max_len)
	*pd++ = *ps;
    *pd = '\0';
}//strrev


// Implementation of the read/write operations for the hostset proc-file

// Sequential proc file reading operations (callbacks)
static void *seq_read_start(struct seq_file *seq, loff_t *pos)
    __acquires(hs_lock)
{
    const struct host_set *hs = pde_data(file_inode(seq->file));
    struct rb_node *node;
    loff_t p = *pos;

#ifdef XT_TLS_DEBUG
    pr_info("Seq read start: %s\n", hs->name);
#endif

    read_lock_bh(&hs_lock);

    for (node = rb_first(&hs->hosts); node; node = rb_next(node)) {
	if (p-- == 0)
	    return node;
    }//for

    return NULL;
}//*seq_read_start


static void *seq_read_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct rb_node *node = rb_next(v);
    (*pos)++;
    return node;
}//seq_read_next


static void seq_read_stop(struct seq_file *seq, void *v)
    __releases(hs_lock)
{
    read_unlock_bh(&hs_lock);
}//seq_read_stop


static int seq_read_show(struct seq_file *seq, void *v)
{
    const struct host_set_elem *hse = rb_entry(v, struct host_set_elem, rbnode);
    const char *p = hse->name + strlen(hse->name);
#ifdef XT_TLS_DEBUG
    pr_info("Seq read show: %s\n", hse->name);
#endif
    
    seq_printf(seq, "%*llu ", HIT_COUNT_DISPL_WIDTH, hse->hit_count);
    while (--p >= hse->name)
        seq_putc(seq, *p);
    
    seq_putc(seq, '\n');
    return 0;
}//seq_read_show


static const struct seq_operations seq_ops = {
    .start          = seq_read_start,
    .next           = seq_read_next,
    .stop           = seq_read_stop,
    .show           = seq_read_show,
};


static int seq_file_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &seq_ops);
}//seq_file_open


// Callback for writing to the proc file
static ssize_t
proc_write(struct file *file, const char __user *input, size_t size, loff_t *loff)
{
    struct inode *inode = file_inode(file);
    struct host_set *hs = pde_data(inode);
    char buf[MAX_HOSTNAME_LEN + 2];
    int rc;

    if (size == 0)
	return 0;
    if (size > sizeof(buf) - 1)
	size = sizeof(buf) - 1;
    if (copy_from_user(buf, input, size) != 0)
	return -EFAULT;
    buf[size] = '\0';

    /* Strict protocol! */
    if (*loff != 0)
	return -ESPIPE;
    
    switch (buf[0]) {
    case '/': /* flush table */
	hs_flush(hs);
	break;
    case '-': /* remove hostname */
	rc = hs_remove_hostname(hs, strim(buf + 1));
	if (rc < 0)
	    return rc;
	break;
    case '+': /* add hostname */
	rc = hs_add_hostname(hs, strim(buf + 1));
	if (rc < 0)
	    return rc;
	break;
    default:
	pr_err("The first char must be an opcode: '+' to add a hostname, '-' to remove and '/' to flush the entire set\n");
	return -EINVAL;
    }//switch
    
    proc_set_size(hs->proc_file, hs->filesize);
    return size;
}//proc_write
