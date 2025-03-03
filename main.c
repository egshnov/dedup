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
#include <linux/dm-io.h>

#include "index/memtable.h"
#include "index/pbn_manager.h"

#define TARGET_NAME "dedup"
#define CHUNK_SIZE 4096
#define MIN_DEDUP_WORK_IO 16
#define SECTOR_SHIFT 9 /* 512-byte sectors => shift by 9 */

static struct dedup_stats
{
    uint64_t total_lbn;
    uint64_t unique_pbn;
} stats;

/* Main structure for device mapper target */
struct dedup_target
{
    struct dm_dev *dev;
    sector_t head;
    sector_t sectors_per_block; // TODO: pass chunk size as arg

    /* deduplication logic fields */
    struct hash_pbn_memtable *hash_pbn;
    struct lbn_pbn_memtable *lbn_pbn;
    struct pbn_manager *manager;
    // TODO: add refcounter for lbns (for deletion)

    /*bio resubmitting logic fields*/
    struct workqueue_struct *wq;
    mempool_t *work_pool;
    struct bio_set bs;
};

static void get_stats(struct dedup_target *target)
{
    stats.total_lbn = target->lbn_pbn->occupied_num;
    stats.unique_pbn = target->manager->occupied_num;
}

struct dedup_work
{
    struct work_struct worker;
    struct dedup_target *target;
    struct bio *bio;
};

static void remap_device(struct dedup_target *target, struct bio *bio)
{
    bio_set_dev(bio, target->dev->bdev);
    submit_bio_noacct(bio);
}

static void do_io(struct dedup_target *target, struct bio *bio, uint64_t pbn)
{
    int offset;
    offset = sector_div(bio->bi_iter.bi_sector, target->sectors_per_block);
    bio->bi_iter.bi_sector = (sector_t)pbn * target->sectors_per_block + offset;
    remap_device(target, bio);
}

static uint64_t bio_lbn(struct dedup_target *target, struct bio *bio)
{
    sector_t lbn = bio->bi_iter.bi_sector;

    sector_div(lbn, target->sectors_per_block);
    return lbn;
}

static void bio_zero_endio(struct bio *bio)
{
    zero_fill_bio(bio);
    bio->bi_status = BLK_STS_OK;
    bio_endio(bio);
}

static int process_read(struct dedup_target *target, struct bio *bio)
{
    uint64_t lbn, pbn;
    lbn = bio_lbn(target, bio);

    pr_info("process_read: lbn is = %llu\n", lbn);

    if (lbn_pbn_get(target->lbn_pbn, lbn, &pbn))
    {
        pr_info("process_read: doing io at pbn = %llu\n", pbn);
        do_io(target, bio, pbn);
    }
    else
    {
        pr_info("process_read: lbn-> pbn not found, zero out bio\n");
        bio_zero_endio(bio);
    }
    return 0;
}

static int compute_bio_hash(struct bio *bio, u64 *hash)
{
    struct xxh64_state state;
    struct bio_vec bvec;
    struct bvec_iter iter;

    xxh64_reset(&state, 0);

    bio_for_each_segment(bvec, bio, iter)
    {
        char *data = kmap_local_page(bvec.bv_page);

        if (!data)
        {
            pr_err("compute_bio_hash: Failed to map bio segment\n");
            return -EINVAL; // TODO: change error flag
        }

        xxh64_update(&state, data + bvec.bv_offset, bvec.bv_len);
        kunmap_local(data);
    }

    *hash = xxh64_digest(&state);
    return 0;
}

// TODO: process possible hash collisions
static int write_hash_present(struct dedup_target *target, struct bio *bio, uint64_t hash, uint64_t lbn, uint64_t *pbns, uint32_t pbns_len)
{
    int err;
    uint64_t old_pbn;
    bool lbn_present = lbn_pbn_get(target->lbn_pbn, lbn, &old_pbn);
    if (lbn_present && old_pbn == pbns[0])
        goto out;

    err = lbn_pbn_insert(target->lbn_pbn, lbn, pbns[0]);
    if (err)
        goto cant_insert;

    err = inc_refcount(target->manager, pbns[0]);
    if (err)
        goto cant_inc_refcount;

    if (lbn_present)
    {
        err = dec_refcount(target->manager, old_pbn);
        if (err)
        {
            pr_err("REFCOUNT WONT DECREASE INVESTIGATE!!!!!!!!!!!");
        }
    }

out:
    bio->bi_status = BLK_STS_OK;
    bio_endio(bio);
    return DM_MAPIO_SUBMITTED;
cant_insert:
    return DM_MAPIO_KILL;

cant_inc_refcount:
    lbn_pbn_remove(target->lbn_pbn, lbn);
    return DM_MAPIO_KILL;
}

static int write_hash_not_present(struct dedup_target *target, struct bio *bio, uint64_t hash, uint64_t lbn)
{
    sector_t old_pbn, new_pbn; // pbn mapped to the passed lbn value in lbn_pbn_memtable (might not exist)
    int ret;

    pr_info("write_hash_not_present: writing new chunk with lbn = %llu, hash=%llu\n", lbn, hash);

    bool lbn_present = lbn_pbn_get(target->lbn_pbn, lbn, &old_pbn);
    ret = alloc_pbn(target->manager, &new_pbn); // creates with refcount 1s
    if (ret)
        return ret;

    pr_info("write_hash_not_present: allocated pbn = %llu\n", new_pbn);

    ret = lbn_pbn_insert(target->lbn_pbn, lbn, new_pbn);
    if (ret)
        goto lbn_insert_fail;

    ret = hash_pbn_add(target->hash_pbn, hash, new_pbn);
    if (ret)
        goto hash_insert_fail;

    if (lbn_present)
    {
        ret = dec_refcount(target->manager, old_pbn);
        if (ret)
            pr_info("REFCOUNT FAILS SOMEHOW INVESTIGATE\n"); // TODO: add propper exception
    }

    do_io(target, bio, new_pbn);
    return DM_MAPIO_SUBMITTED;

hash_insert_fail:
    lbn_pbn_remove(target->lbn_pbn, lbn);
lbn_insert_fail:
    dec_refcount(target->manager, new_pbn);
    return ret;
}

static int process_write(struct dedup_target *target, struct bio *bio)
{
    uint64_t hash, lbn;
    sector_t *pbns; // TODO: currently doesn't support hash collision processing
    int pbns_len;

    pr_info("process_write: called\n");
    int err = compute_bio_hash(bio, &hash);
    if (err)
    {
        pr_err("process_write: couldn't calculatere hash for the bio\n");
        return err;
    }
    pr_info("process_write: hash for bio is %llu\n", hash);

    lbn = bio_lbn(target, bio);

    pr_info("process_write: lbn is = %llu\n", lbn);

    if (hash_pbn_get(target->hash_pbn, hash, &pbns, &pbns_len))
    {
        pr_info("process_write: found pbn = %llu\n", pbns[0]);
        pr_info("process_write: hash present going to write_hash_present\n");
        // TODO: process hash collision here i guess?
        err = write_hash_present(target, bio, hash, lbn, pbns, pbns_len);
    }
    else
    {
        pr_info("process_write: hash not present going to write_hash_not_present\n");
        err = write_hash_not_present(target, bio, hash, lbn);
    }
    if (err)
        return err;

    get_stats(target);
    pr_info("current stats: total_lbn = %llu unique_pbn = %llu\n", stats.total_lbn, stats.unique_pbn);
    pr_info("saved space = %llu\n", (stats.total_lbn - stats.unique_pbn) * CHUNK_SIZE);
    return 0;
}
static int process_bio(struct dedup_target *target, struct bio *bio)
{
    pr_info("process_bio: processing bio, bio_op=%d\n", bio_op(bio));
    int res;

    // TODO: add discard processing
    if (bio_op(bio) != REQ_OP_READ && bio_op(bio) != REQ_OP_WRITE)
    {
        bio_set_dev(bio, target->dev->bdev);
        pr_info("process_bio: Passing through non-read/write bio\n");
        return DM_MAPIO_REMAPPED;
    }

    if (bio_op(bio) == REQ_OP_WRITE)
    {
        pr_info("procec_bio: write request\n");
        res = process_write(target, bio);
        if (res != DM_MAPIO_SUBMITTED)
        {
            pr_err("process_bio: Write bio processing failed, returning DM_MAPIO_KILL\n");
            return DM_MAPIO_KILL;
        }
        return DM_MAPIO_SUBMITTED;
    }
    else
    {
        pr_info("procec_bio: read request\n");
        res = process_read(target, bio);
        if (res != DM_MAPIO_SUBMITTED)
        {
            pr_err("process_bio: Read bio processing failed, returning DM_MAPIO_KILL\n");
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
    target->sectors_per_block = to_sector(CHUNK_SIZE);

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
    target->manager = create_pbn_manager(ti->begin, ti->len); // TODO: is begine really needed?
    if (!target->manager)
        goto all_uninit;
    ret = dm_set_target_max_io_len(ti, target->sectors_per_block);
    if (ret)
        goto all_uninit;
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
    pr_err("dedup_target_ctr: Couldn't create workpool\n");
    return -ENOMEM;
all_uninit:
    free_hash_pbn(target->hash_pbn);
    free_lbn_pbn(target->lbn_pbn);
    bioset_exit(&(target->bs));
    destroy_workqueue(target->wq);
    mempool_destroy(target->work_pool);
    kfree(target);
    pr_err("dedup_target_ctr: Couldn't create pbn_manage`r\n");
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

static int dedup_param_get_stats(char *buf, const struct kernel_param *kp)
{
	char stats_buff[100];
    int len = snprintf(stats_buff, sizeof(stats_buff), "%llu %llu\n", stats.total_lbn, stats.unique_pbn);
    strcpy(buf, stats_buff);
    return len;
}

static const struct kernel_param_ops get_stats_ops = {
	.set = NULL,
	.get = dedup_param_get_stats,
};

MODULE_PARM_DESC(get_stats, "Deduplication statisics in format 'total_lbn unique_pbn'");
module_param_cb(get_stats, &get_stats_ops, NULL, S_IRUGO);


module_init(dedup_init);
module_exit(dedup_exit);

MODULE_AUTHOR("Egor Shalashnov <shalasheg@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Deduplication driver");
// MODULE_SOFTDEP("pre: dm-bufio");
