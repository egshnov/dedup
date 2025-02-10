#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include "index/memtable.h"

#define DEVICE_NAME "dedup"
#define GD_NAME "dedup_gd"
#define CHUNK_SIZE 4096
#define SECTOR_SHIFT 9

static struct dedup_target
{
    struct block_device *bdev;
    struct gendisk *gd;
    struct bio_set bs;
    sector_t head;
    struct hash_pbn_memtable *hash_pbn;
    struct lbn_pbn_memtable *lbn_pbn;
    int major;
} dedup;
static void dedup_submit_bio(struct bio *bio)
{
}

static const struct block_device_operations dedup_bio_ops = {
    .owner = THIS_MODULE,
    .submit_bio = dedup_submit_bio,
};

static int set_gendisk()
{
    int err;

    dedup.gd = blk_alloc_disk(NULL, NUMA_NO_NODE);
    if (!dedup.gd)
        goto no_mem;

    dedup.gd->major = dedup.major;
    dedup.gd->first_minor = 1;
    dedup.gd->minors = 1;
    dedup.gd->fops = &dedup_bio_ops;
    dedup.gd->private_data = &dedup;
    dedup.gd->flags |= GENHD_FL_NO_PART;
    strcpy(dedup.gd->disk_name, GD_NAME);
    set_capacity(dedup.gd, get_capacity(dedup.bdev->bd_disk));

    err = add_disk(dedup.gd);
    if (err)
        goto disk_err;
no_mem:
    pr_err("set_gendisk: couldn't allocate gendisk\n");
    return -ENOMEM;
disk_err:
    pr_err("set_gendisk: couldn't add gendisk %d\n", err);
    put_disk(dedup.gd);
    dedup.gd = NULL;
    return err;
};

static int init_dedup(void)
{
    
}

static int __init dedup_init(void)
{
    int err;
}