#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/xxhash.h>
#include <linux/kstrtox.h>
#include <linux/slab.h>
#include <linux/dm-bufio.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include "index/memtable.h"
#include <linux/dm-io.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/slab.h>

#define TARGET_NAME "dedup"
#define CHUNK_SIZE 4096
#define MIN_DEDUP_WORK_IO 16
#define SECTOR_SHIFT 9 /* 512-byte sectors => shift by 9 */

// TODO: cahnge bio_alloc_bioset to GFP_NOIO

/* Main structure for device mapper target */
struct dedup_target
{
    /* deduplication logic fields */
    struct dm_dev *dev;
    sector_t head;
    struct hash_pbn_memtable *hash_pbn;
    struct lbn_pbn_memtable *lbn_pbn;

    /*bio resubmitting logic fields*/
    struct workqueue_struct *wq;
    mempool_t *work_pool;
    struct bio_set bs;
};

struct dedup_work
{
    struct work_struct worker;
    struct dedup_target *target;
    struct bio *bio;
};

static int process_read(struct dedup_target *target, struct bio *bio)
{
    int ret;
    pr_info("process_read: read called\n");
    bio_set_dev(bio, target->dev->bdev);
    pr_info("process_read: submitting sub_bio\n");

    submit_bio_noacct(bio);
    pr_info("process_read: bio passed \n");

    return ret;
}

static int compute_bio_hash(struct bio *bio, u64 *hash)
{
    struct xxh64_state state;
    struct bio_vec bvec;
    struct bvec_iter iter;
    unsigned long flags;

    xxh64_reset(&state, 0);

    bio_for_each_segment(bvec, bio, iter)
    {
        char *data = kmap_local_page(bvec.bv_page);

        if (!data)
        {
            pr_err("Failed to map bio segment\n");
            return -EINVAL; // TODO: change error flag
        }

        xxh64_update(&state, data + bvec.bv_offset, bvec.bv_len);
        kunmap_local(data);
    }

    *hash = xxh64_digest(&state);
    return 0;
}

static int process_write(struct dedup_target *target, struct bio *bio)
{
    u64 hash;
    int ret;
    pr_info("process_write: read called\n");
    int r = compute_bio_hash(bio, &hash);
    if (r)
    {
        pr_err("process_write: couldn't calculatere hash for the bio\n");
    }
    else
    {
        pr_info("process_write: hash for bio is %llu\n", hash);
    }
    bio_set_dev(bio, target->dev->bdev);
    pr_info("process_write: submitting sub_bio\n");

    submit_bio_noacct(bio);
    return ret;
}
static int process_bio(struct dedup_target *target, struct bio *bio)
{
    pr_info("dedup_target_map: mapping bio, bio_op=%d\n", bio_op(bio));
    int res;

    if (bio_op(bio) != REQ_OP_READ && bio_op(bio) != REQ_OP_WRITE)
    {
        bio_set_dev(bio, target->dev->bdev);
        pr_info("dedup_target_map: Passing through non-read/write bio\n");
        return DM_MAPIO_REMAPPED;
    }

    if (bio_op(bio) == REQ_OP_WRITE)
    {
        res = process_write(target, bio);
        if (res != DM_MAPIO_SUBMITTED)
        {
            pr_err("dedup_target_map: Write bio processing failed, returning DM_MAPIO_KILL\n");
            return DM_MAPIO_KILL;
        }
        return DM_MAPIO_SUBMITTED;
    }
    else
    {
        res = process_read(target, bio);
        if (res != DM_MAPIO_SUBMITTED)
        {
            pr_err("dedup_target_map: Read bio processing failed, returning DM_MAPIO_KILL\n");
            return DM_MAPIO_KILL;
        }
        return DM_MAPIO_SUBMITTED;
    }
}
static void do_work(struct work_struct *ws)
{
    struct dedup_work *data = container_of(ws, struct dedup_work, worker);
    struct dedup_target *target = (struct dedup_target *)data->target;
    struct bio *bio = (struct bio *)data->bio;

    mempool_free(data, target->work_pool);

    process_bio(target, bio);
}

static void defer_bio(struct dedup_target *target, struct bio *bio)
{
    struct dedup_work *data;
    data = mempool_alloc(target->work_pool, GFP_NOIO);
    if (!data)
    {
        bio->bi_status = BLK_STS_RESOURCE;
        bio_endio(bio);
        return;
    }
    data->bio = bio;
    data->target = target;
    INIT_WORK(&(data->worker), do_work);
    queue_work(target->wq, &(data->worker));
}

static int dedup_map(struct dm_target *ti, struct bio *bio)
{
    struct dedup_target *target = (struct dedup_target *)ti->private;
    defer_bio(target, bio);
    return DM_MAPIO_SUBMITTED;
}

/* Constructor function for dm target */
static int dedup_target_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct dedup_target *target;
    sector_t head;
    int ret;
    pr_info("dedup_target_ctr: in\n");

    if (argc != 2)
    {
        pr_err("dedup_target_ctr: Invalid number of arguments\n");
        ti->error = "Invalid number of arguments";
        return -EINVAL;
    }

    target = kzalloc(sizeof(*target), GFP_KERNEL);
    if (!target)
        goto no_mem_for_target;

    ret = bioset_init(&target->bs, 128, 0, BIOSET_NEED_BVECS);
    if (ret)
    {
        pr_err("dedup_target_ctr: bioset_init failed with %d\n", ret);
        goto cant_init_bioset;
    }
    pr_info("dedup_target_ctr: Initialized bioset at %p\n", &target->bs);

    if (sscanf(argv[1], "%llu", &head) != 1)
    {
        ti->error = "dedup_target_ctr: Invalid device sector";
        goto error;
    }
    target->head = head;
    pr_info("dedup_target_ctr: Using head=%llu\n", (unsigned long long)head);

    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &target->dev))
    {
        ti->error = "dedup_target_ctr: Device lookup failed";
        goto error;
    }
    pr_info("dedup_target_ctr: Device lookup succeeded; target->dev = %p, bdev = %p\n",
            target->dev, target->dev ? target->dev->bdev : NULL);

    target->hash_pbn = create_hash_pbn();
    target->lbn_pbn = create_lbn_pbn();
    if (!target->hash_pbn || !target->lbn_pbn)
        goto cant_alloc_index;

    pr_info("dedup_target_ctr: memtables created successfully\n");
    target->wq = create_singlethread_workqueue("dedup");
    if (!target->wq)
    {
        ti->error = "failed to create workqueue";
        ret = -ENOMEM;
        goto cant_create_wq;
    }
    pr_info("dedup_target_ctr: qorkqueue created\n");

    target->work_pool = mempool_create_kmalloc_pool(MIN_DEDUP_WORK_IO,
                                                    sizeof(struct dedup_work));
    if (!target->work_pool)
    {
        ti->error = "failed to create dedup mempool";
        ret = -ENOMEM;
        goto cant_create_workpool;
    }
    pr_info("dedup_target_ctr: workpool create\n");
    ti->private = target;
    pr_info("dedup_target_ctr: out\n");
    return 0;

// TODO: simplify errors
no_mem_for_target:
    pr_err("dedup_target_ctr: Could not allocate dedup target structure\n");
    ti->error = "Cannot allocate dedup target";
    return -ENOMEM;
cant_init_bioset:
    pr_err("dedup_target_ctr: bioset_init failed with %d\n", ret);
    kfree(target);
    return ret;
error:
    bioset_exit(&(target->bs));
    kfree(target);
    pr_err("dedup_target_ctr: %s\n", ti->error);
    return -EINVAL;
cant_alloc_index:
    free_hash_pbn(target->hash_pbn);
    free_lbn_pbn(target->lbn_pbn);
    bioset_exit(&(target->bs));
    kfree(target);
    pr_err("dedup_target_ctr: Couldn't allocate index structures\n");
    return -ENOMEM;

cant_create_wq:
    free_hash_pbn(target->hash_pbn);
    free_lbn_pbn(target->lbn_pbn);
    bioset_exit(&(target->bs));
    kfree(target);
    pr_err("dedup_target_ctr: Couldn't allocate index structures\n");
    return -ENOMEM;

cant_create_workpool:
    free_hash_pbn(target->hash_pbn);
    free_lbn_pbn(target->lbn_pbn);
    bioset_exit(&(target->bs));
    destroy_workqueue(target->wq);
    kfree(target);
    pr_err("dedup_target_ctr: Couldn't allocate index structures\n");
    return -ENOMEM;
}

static void dedup_target_dtr(struct dm_target *ti)
{
    struct dedup_target *target = ti->private;
    pr_info("dedup_target_dtr: in\n");
    dm_put_device(ti, target->dev);
    bioset_exit(&target->bs);
    free_hash_pbn(target->hash_pbn);
    free_lbn_pbn(target->lbn_pbn);
    destroy_workqueue(target->wq);
    mempool_destroy(target->work_pool);
    kfree(target);
    pr_info("dedup_target_dtr: out\n");
}

static struct target_type dedup_ops = {
    .name = TARGET_NAME,
    .version = {0, 0, 1},
    .module = THIS_MODULE,
    .ctr = dedup_target_ctr,
    .dtr = dedup_target_dtr,
    .map = dedup_map,
};

static int __init dedup_init(void)
{
    int res = dm_register_target(&dedup_ops);
    if (res < 0)
    {
        pr_err("dedup_init: Couldn't register target (res=%d)\n", res);
        return -res;
    }
    pr_info("dedup_init: Target registered successfully\n");
    return 0;
}

static void dedup_exit(void)
{
    dm_unregister_target(&dedup_ops);
    pr_info("dedup_exit: Target unregistered\n");
}

module_init(dedup_init);
module_exit(dedup_exit);

MODULE_AUTHOR("Egor Shalashnov <shalasheg@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Deduplication driver");
MODULE_SOFTDEP("pre: dm-bufio");
