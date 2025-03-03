#ifndef DEDUP_PBN_MANAGER
#define DEDUP_PBN_MANAGER
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/list.h>

/*
    pbn_list contains unused pbns
    whenever new pbn is allocated via alloc_pbn an entry
    in ref_root is created with refcount = 1 and pbn is deleted from pbn list
    if dec_refcount causes refcount == 0 entry is deleted from rb_tree and pbn returns
    into the list of the free pbns

*/
struct pbn_rb_node
{
    struct rb_node node;
    uint64_t pbn;
    uint32_t refcount;
};

struct pbn_manager
{
    struct rb_root ref_root;
    uint64_t start_pbn;
    uint64_t len;
    uint64_t alloc_ptr;
    uint64_t occupied_num;
};

struct pbn_manager *create_pbn_manager(uint64_t start_pbn, uint64_t last_pbn);

void free_pbn_manager(struct pbn_manager *manager);

int inc_refcount(struct pbn_manager *manager, uint64_t pbn);

int dec_refcount(struct pbn_manager *manager, uint64_t pbn);

int alloc_pbn(struct pbn_manager *manager, uint64_t *pbn);
#endif
