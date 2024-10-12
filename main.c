// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#define BLKDEV_NAME "dedup"
#define GD_NAME "dedup_disk_1"
#define mode (FMODE_READ | FMODE_WRITE)
#define CONST_REQ_SIZE 4096

/*
virtual layer <--> dedup_dm_target
structure stores information about the underlying device

*/

static struct dedup_dm_target {
	struct dm_dev *dev;
	sector_t head;
};

static int dedup_target_map(struct dm_target *ti, struct bio *bio)
{
	struct dedup_dm_target *target;

	target = (struct dedup_dm_target *)ti->private;
	pr_info(" \n >>in function dedup_target_map \n");
	pr_info("\n dedup_target_map: target->dev->bdev == NULL = %d\n",
		target->dev->bdev == NULL);
	bio_set_dev(bio, target->dev->bdev);

	if (bio_op(bio) == REQ_OP_READ) {
		pr_info("function dedup_target_map: bio is read request\n");
	} else if (bio_op(bio) == REQ_OP_WRITE) {
		pr_info("function dedup_target_map: bio is write request\n");
	}

	submit_bio(bio);
	pr_info("\n << out function dedup_target_map \n");
	return DM_MAPIO_SUBMITTED;
}

/*
constructor of dedup target
argc - num of arguments (assuming first is the name) TODO: check
argv - arguments 0 - path to the underlying block device, 1 num of the first sector on the underlying device TODO: change to the default i guess
*/

static int dedup_target_ctr(struct dm_target *ti, unsigned int argc,
			    char **argv)
{
	struct dedup_dm_target *target;
	unsigned long long head;

	pr_info("\n in function ctr \n");
	if (argc != 2) {
		pr_info("Invalid number of arguments");
		ti->error = "Invalid arguments count";
		return -EINVAL;
	}

	target = kzalloc(sizeof(struct dedup_dm_target), GFP_KERNEL);

	if (target == NULL)
		goto cant_alloc_target;

	if (sscanf(argv[1], "%llu", &head) != 1) {
		ti->error = "dedup_target_ctr: Invalid device sector";
		goto error;
	}

	target->head = (sector_t)head;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
			  &target->dev)) {
		ti->error = "dedup_target_ctr: Device lookup failed";
		goto error;
	}
	ti->private = target;
	pr_info("\n out of dedup_target_ctr \n");
	return 0;

cant_alloc_target:
	pr_info("Couldnt allocate target structure \n");
	ti->error = "dedup_target_ctr: cannot allocate dedup target";
	return -ENOMEM;

error:
	kfree(target);
	pr_info("%s\n", ti->error);
	pr_err("\n>>out function dedup_target_ctr with error \n");
	return -EINVAL;
}

static void dedup_target_dtr(struct dm_target *ti)
{
	struct dedup_dm_target *target;
	target = ti->private;
	pr_info("\n in dedup_target_dtr \n");
	dm_put_device(ti, target->dev);
	kfree(target);
	pr_info(" \n out of dedup_target_dtr \n");
}

static struct target_type dedup_target = {
	.name = "dedup",
	.version = { 0, 0, 1 },
	.module = THIS_MODULE,
	.ctr = dedup_target_ctr,
	.dtr = dedup_target_dtr,
	.map = dedup_target_map,
};

static int __init dedup_init(void)
{
	int res;

	res = dm_register_target(&dedup_target);
	if (res < 0) {
		pr_err("Couldn't register \n");
		return -res;
	}
	return 0;
}

static void dedup_exit(void)
{
	dm_unregister_target(&dedup_target);
}

module_init(dedup_init);
module_exit(dedup_exit);

MODULE_AUTHOR("Egor Shalashnov <shalasheg@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Deduplication driver");
