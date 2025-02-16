#include <linux/slab.h>
#include <linux/device-mapper.h>
#include "pbn_manager.h"

static struct pbn_rb_node *create_pbn_rb_node(uint64_t pbn)
{
    struct pbn_rb_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return NULL;
    node->pbn = pbn;
    node->refcount = 1; // if pbn is in rb_tree than there must be a reference on it
    return node;
}

static void free_pbn_rb_node(struct pbn_rb_node *node)
{
    kfree(node);
}

static int compare_pbns(uint64_t lhs, uint64_t rhs)
{
    return lhs < rhs ? -1 : (lhs == rhs ? 0 : 1);
}

static struct pbn_rb_node *pbn_rb_search(struct rb_root *root, uint64_t pbn)
{
    struct rb_node *node = root->rb_node;
    while (node)
    {
        struct pbn_rb_node *data = rb_entry(node, struct pbn_rb_node, node);
        int res = compare_pbns(pbn, data->pbn);
        if (res < 0)
        {
            node = node->rb_left;
        }
        else if (res > 0)
        {
            node = node->rb_right;
        }
        else
        {
            return data;
        }
    }
    return NULL;
}

static int pbn_rb_insert(struct rb_root *root, uint64_t pbn)
{
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct pbn_rb_node *this;
    int res;
    while (*new)
    {
        this = rb_entry(*new, struct pbn_rb_node, node);
        res = compare_pbns(pbn, this->pbn);
        parent = *new;
        if (res < 0)
            new = &((*new)->rb_left);
        else if (res > 0)
            new = &((*new)->rb_right);
        else
        {
            pr_err("!!!!!!!!!CALL OF INSERT WHILE PBN ALREADY EXISTS, INVESTIGATE!!!!!\n");
            return -EINVAL;
        }
    }
    struct pbn_rb_node *data = create_pbn_rb_node(pbn);
    if (!data)
        goto no_mem;
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 0;
no_mem:
    return -ENOMEM;
}

static void pbn_rb_remove(struct rb_root *root, uint64_t pbn)
{
    struct pbn_rb_node *data = pbn_rb_search(root, pbn);
    if (data)
    {
        rb_erase(&data->node, root);
        free_pbn_rb_node(data);
    }
}

struct pbn_manager *create_pbn_manager(uint64_t start_pbn, uint64_t len)
{
    struct pbn_manager *manager = kzalloc(sizeof(*manager), GFP_KERNEL);
    if (!manager)
        return NULL;
    manager->ref_root = RB_ROOT;
    manager->start_pbn = start_pbn;
    manager->len = len;
    return manager;
}

void free_pbn_manager(struct pbn_manager *manager)
{
    struct pbn_rb_node *pos, *node;
    rbtree_postorder_for_each_entry_safe(pos, node, &manager->ref_root, node)
    {
        free_pbn_rb_node(node);
    }
    kfree(manager);
}

static uint64_t next_pbn(uint64_t cur, uint64_t len)
{
    cur += 1;
    return dm_sector_div64(cur, len);
}

int alloc_pbn(struct pbn_manager *manager, uint64_t *pbn)
{
    int ret;
    uint64_t head = manager->alloc_ptr;
    uint64_t tail = manager->alloc_ptr;
    do
    {
        if (!pbn_rb_search(&manager->ref_root, head))
        {

            ret = pbn_rb_insert(&manager->ref_root, head);
            if (ret)
            {
                pr_err("alloc_pbn: can't insert block");
                return ret;
            }
            *pbn = head;
            manager->alloc_ptr = next_pbn(head, manager->len);
            return 0;
        }

        head = next_pbn(head, manager->len);
    } while (head != tail);

    pr_err("alloc_pbn: no free pbn found");
    return -ENOSPC;
}

int inc_refcount(struct pbn_manager *manager, uint64_t pbn)
{
    struct pbn_rb_node *node = pbn_rb_search(&manager->ref_root, pbn);
    if (!node)
        goto not_present;
    node->refcount++;
    return 0;

not_present:
    pr_err("inc refcount: !!!!INCREMENTING REFCOUNT ON PBN THAT IS NOT PRESENT IN RBT!!!!!!!\n");
    return -EINVAL;
}

int dec_refcount(struct pbn_manager *manager, uint64_t pbn)
{

    struct pbn_rb_node *node = pbn_rb_search(&manager->ref_root, pbn);
    if (!node)
        goto not_present;
    node->refcount--;
    if (node->refcount == 0)
    {
        // TODO: optimize -- double search occures;
        pbn_rb_remove(&manager->ref_root, pbn);
    }
    return 0;

not_present:
    pr_err("dec refcount: !!!!DECREMENTING REFCOUNT ON PBN THAT IS NOT PRESENT IN RBT!!!!!!!\n");
    return -EINVAL;
}
