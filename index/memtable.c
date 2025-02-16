#include "memtable.h"
#include <linux/slab.h>

struct hash_pbn_node {
    struct rb_node node;
    hash_t hash;
    sector_t *pbns;
    int pbns_len;
};

static struct hash_pbn_node *create_hash_pbn_node(hash_t hash, sector_t pbn)
{
    struct hash_pbn_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return NULL;

    node->pbns = kzalloc(sizeof(*node->pbns), GFP_KERNEL);
    if (!node->pbns)
        goto dealloc;
    node->pbns_len = 1;
    node->hash = hash;
    node->pbns[0] = pbn;

    pr_info("create_hash_pbn_node: Created node for hash %llu with pbn %llu\n",
            (unsigned long long)hash, (unsigned long long)pbn);

    return node;
dealloc:
    kfree(node);
    return NULL;
}

static void free_hash_pbn_node(struct hash_pbn_node *node)
{
    kfree(node->pbns);
    kfree(node);
}

static int compare_hash(hash_t lhs, hash_t rhs)
{
    return lhs < rhs ? -1 : (lhs == rhs ? 0 : 1);
}

static struct hash_pbn_node *__hash_pbn_underlying_search(struct rb_root *root, hash_t hash)
{
    struct rb_node *node = root->rb_node;
    while (node) {
        struct hash_pbn_node *data = rb_entry(node, struct hash_pbn_node, node);
        int res = compare_hash(hash, data->hash);
        if (res < 0)
            node = node->rb_left;
        else if (res > 0)
            node = node->rb_right;
        else {
            pr_info("__hash_pbn_underlying_search: Found node for hash %llu\n",
                    (unsigned long long)hash);
            return data;
        }
    }
    pr_info("__hash_pbn_underlying_search: No node found for hash %llu\n",
            (unsigned long long)hash);
    return NULL;
}

static int __hash_pbn_underlying_insert(struct rb_root *root, hash_t hash, sector_t pbn)
{
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct hash_pbn_node *this;
    int res;

    while (*new) {
        this = rb_entry(*new, struct hash_pbn_node, node);
        res = compare_hash(hash, this->hash);
        parent = *new;
        if (res < 0)
            new = &((*new)->rb_left);
        else if (res > 0)
            new = &((*new)->rb_right);
        else {
            this->pbns_len++;
            sector_t *dummy = krealloc(this->pbns, sizeof(*this->pbns) * this->pbns_len, GFP_KERNEL);
            if (!dummy) {
                this->pbns_len--;
                pr_err("__hash_pbn_underlying_insert: krealloc failed for hash %llu\n",
                       (unsigned long long)hash);
                goto no_mem;
            }
            this->pbns = dummy;
            this->pbns[this->pbns_len - 1] = pbn;
            pr_info("__hash_pbn_underlying_insert: Updated node for hash %llu, new pbns_len=%d\n",
                    (unsigned long long)hash, this->pbns_len);
            return sizeof(pbn);
        }
    }
    struct hash_pbn_node *data = create_hash_pbn_node(hash, pbn);
    if (!data)
        goto no_mem;
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    pr_info("__hash_pbn_underlying_insert: Inserted new node for hash %llu\n", (unsigned long long)hash);
    return sizeof(struct hash_pbn_node);
no_mem:
    return -ENOMEM;
}

struct hash_pbn_memtable *create_hash_pbn()
{
    struct hash_pbn_memtable *new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
    if (!new_table)
        return NULL;
    new_table->root = RB_ROOT;
    pr_info("create_hash_pbn: Created hash_pbn_memtable\n");
    return new_table;
}

void free_hash_pbn(struct hash_pbn_memtable *table)
{
    if (!table)
        return;
    struct hash_pbn_node *pos, *node;
    rbtree_postorder_for_each_entry_safe(pos, node, &table->root, node) {
        pr_info("free_hash_pbn: Freeing node for hash %llu\n", (unsigned long long)pos->hash);
        free_hash_pbn_node(pos);
    }
    kfree(table);
}

int hash_pbn_add(struct hash_pbn_memtable *table, hash_t hash, sector_t pbn)
{
    return __hash_pbn_underlying_insert(&table->root, hash, pbn);
}

bool hash_pbn_get(struct hash_pbn_memtable *table, hash_t hash, sector_t **res, int *len)
{
    struct hash_pbn_node *target = __hash_pbn_underlying_search(&table->root, hash);
    if (target) {
        *len = target->pbns_len;
        *res = kzalloc((*len) * sizeof(sector_t), GFP_KERNEL);
        if (!*res)
            goto no_mem;
        memcpy(*res, target->pbns, sizeof(sector_t) * (*len));
        pr_info("hash_pbn_get: Found node for hash %llu with %d pbns\n",
                (unsigned long long)hash, *len);
        return true;
    }
    return false;
no_mem:
    *res = NULL;
    *len = -1;
    pr_err("hash_pbn_get: Memory allocation failed for hash %llu\n", (unsigned long long)hash);
    return false;
}

struct lbn_pbn_node {
    struct rb_node node;
    sector_t lbn;
    sector_t pbn;
};

static struct lbn_pbn_node *create_lbn_pbn_node(sector_t lbn, sector_t pbn)
{
    struct lbn_pbn_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return NULL;
    node->lbn = lbn;
    node->pbn = pbn;
    pr_info("create_lbn_pbn_node: Created node for lbn %llu with pbn %llu\n",
            (unsigned long long)lbn, (unsigned long long)pbn);
    return node;
}

static void free_lbn_pbn_node(struct lbn_pbn_node *node)
{
    kfree(node);
}

static int compare_lbns(sector_t lhs, sector_t rhs)
{
    return lhs < rhs ? -1 : (lhs == rhs ? 0 : 1);
}

static struct lbn_pbn_node *__lbn_pbn_underlying_search(struct rb_root *root, sector_t lbn)
{
    struct rb_node *node = root->rb_node;
    while (node) {
        struct lbn_pbn_node *data = rb_entry(node, struct lbn_pbn_node, node);
        int res = compare_lbns(lbn, data->lbn);
        if (res < 0)
            node = node->rb_left;
        else if (res > 0)
            node = node->rb_right;
        else {
            pr_info("__lbn_pbn_underlying_search: Found node for lbn %llu\n", (unsigned long long)lbn);
            return data;
        }
    }
    pr_info("__lbn_pbn_underlying_search: No node found for lbn %llu\n", (unsigned long long)lbn);
    return NULL;
}

static int __lbn_pbn_underlying_insert(struct rb_root *root, sector_t lbn, sector_t pbn)
{
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct lbn_pbn_node *this;
    int res;

    while (*new) {
        this = rb_entry(*new, struct lbn_pbn_node, node);
        res = compare_lbns(lbn, this->lbn);
        parent = *new;
        if (res < 0)
            new = &((*new)->rb_left);
        else if (res > 0)
            new = &((*new)->rb_right);
        else {
            pr_info("__lbn_pbn_underlying_insert: Updating node for lbn %llu with new pbn %llu\n",
                    (unsigned long long)lbn, (unsigned long long)pbn);
            this->pbn = pbn;
            return 0;
        }
    }
    struct lbn_pbn_node *data = create_lbn_pbn_node(lbn, pbn);
    if (!data)
        goto no_mem;
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    pr_info("__lbn_pbn_underlying_insert: Inserted new node for lbn %llu with pbn %llu\n",
            (unsigned long long)lbn, (unsigned long long)pbn);
    return 0;
no_mem:
    return -ENOMEM;
}

struct lbn_pbn_memtable *create_lbn_pbn()
{
    struct lbn_pbn_memtable *new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
    if (!new_table)
        return NULL;
    new_table->root = RB_ROOT;
    pr_info("create_lbn_pbn: Created lbn_pbn_memtable\n");
    return new_table;
}

void free_lbn_pbn(struct lbn_pbn_memtable *table)
{
    if (!table)
        return;
    struct lbn_pbn_node *pos, *node;
    rbtree_postorder_for_each_entry_safe(pos, node, &table->root, node) {
        pr_info("free_lbn_pbn: Freeing node for lbn %llu\n", (unsigned long long)pos->lbn);
        free_lbn_pbn_node(pos);
    }
    kfree(table);
}

int lbn_pbn_insert(struct lbn_pbn_memtable *table, sector_t lbn, sector_t pbn)
{
    return __lbn_pbn_underlying_insert(&table->root, lbn, pbn);
}

bool lbn_pbn_get(struct lbn_pbn_memtable *table, sector_t lbn, sector_t *res_pbn)
{
    struct lbn_pbn_node *target = __lbn_pbn_underlying_search(&table->root, lbn);
    if (target) {
        *res_pbn = target->pbn;
        pr_info("lbn_pbn_get: Found mapping: lbn %llu -> pbn %llu\n",
                (unsigned long long)lbn, (unsigned long long)target->pbn);
        return true;
    }
    pr_info("lbn_pbn_get: No mapping found for lbn %llu\n", (unsigned long long)lbn);
    return false;
}
