#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/list.h>

#ifndef DEDUP_MEMTBL_H
#define DEDUP_MEMTBL_H

typedef uint64_t hash_t;

/* rb tree that stores hash -> array of pbns entries */
struct hash_pbn_memtable
{
    struct rb_root root;
};

struct hash_pbn_memtable *create_hash_pbn(void);

void free_hash_pbn(struct hash_pbn_memtable *table);

/* 
    if entry with such hash already exists add pbn to the end of the array 
    returns amount of allocated bytes 
    returns <0 on error
*/
int hash_pbn_add(struct hash_pbn_memtable *table, hash_t hash, sector_t pbn);

/*  
    returns true if found entry with such hash
    array of pbns is copied into res
    sets len = -1 if couldn't allocate space for pbns
    */
bool hash_pbn_get(struct hash_pbn_memtable *table, hash_t hash, sector_t **res, int *res_len);

/*rb_tree that stores lbn->pbn entries*/
//TODO: change to using xarray
struct lbn_pbn_memtable
{
    struct rb_root root;
};

struct lbn_pbn_memtable *create_lbn_pbn(void);

void free_lbn_pbn(struct lbn_pbn_memtable *table);

/*overwrites pbn if entry with such lbn already exists*/
int lbn_pbn_insert(struct lbn_pbn_memtable *table, sector_t lbn, sector_t pbn);

/*return true if found entry with such lbn
    pbn is stored in res*/
bool lbn_pbn_get(struct lbn_pbn_memtable *table, sector_t lbn, sector_t *res_pbn);

#endif