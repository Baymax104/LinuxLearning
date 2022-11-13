/*
 *  linux/mm/page_io.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, 
 *  Asynchronous swapping added 30.12.95. Stephen Tweedie
 *  Removed race in async swapping. 14.4.1996. Bruno Haible
 *  Add swap of shared pages through the page cache. 20.2.1998. Stephen Tweedie
 *  Always use brw_page, life becomes simpler. 12 May 1998 Eric Biederman
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/locks.h>
#include <linux/swapctl.h>

#include <asm/pgtable.h>

/*
 * Reads or writes a swap page.
 * wait=1: start I/O and wait for completion. wait=0: start asynchronous I/O.
 *
 * Important prevention of race condition: the caller *must* atomically 
 * create a unique swap cache entry for this swap page before calling
 * rw_swap_page, and must lock that page.  By ensuring that there is a
 * single page of memory reserved for the swap entry, the normal VM page
 * lock on that page also doubles as a lock on swap entries.  Having only
 * one lock to deal with per swap entry (rather than locking swap and memory
 * independently) also makes it easier to make certain swapping operations
 * atomic, which is particularly important when we are trying to ensure 
 * that shared pages stay shared while being swapped.
 */
// 读写交换页
/**
 * rw:读写标志
 * entry:主要表示页在swap分区中的偏移量
 * page:读写的页面
 * return:1:成功,0:失败
 */
static int rw_swap_page_base(int rw, swp_entry_t entry, struct page *page)
{
	unsigned long offset;
	int zones[PAGE_SIZE/512];
	int zones_used;
	kdev_t dev = 0; // kdev_t = unsigned short
	int block_size;
	struct inode *swapf = 0;

	if (rw == READ) {
        // 清除page的Uptodate状态，page状态见/include/linux/page-flags.h
		ClearPageUptodate(page);
        // pswpin,pswpout:从swap分区中读入读出的页数
        // https://www.cnblogs.com/york-hust/p/4810906.html
		kstat.pswpin++;
	} else
		kstat.pswpout++;

    // 获取entry对应的偏移量和swap设备/文件，见/linux/mm/swapfile.c
	get_swaphandle_info(entry, &offset, &dev, &swapf);
    // 若当前读写的swap分区为swap设备
	if (dev) {
		zones[0] = offset;
		zones_used = 1;
        // blocksize为一个页面
		block_size = PAGE_SIZE;
	} else if (swapf) { // 若当前读写的swap分区为swap文件
		int i, j;
		unsigned int block = offset
			<< (PAGE_SHIFT - swapf->i_sb->s_blocksize_bits);

        // blocksize为该文件占有的页面数
		block_size = swapf->i_sb->s_blocksize;
        // zone记录filesystem中包含页面数据的所有块
		for (i=0, j=0; j< PAGE_SIZE ; i++, j += block_size)
			if (!(zones[i] = bmap(swapf,block++))) {
				printk("rw_swap_page: bad swap file\n");
				return 0;
			}
		zones_used = i;
		dev = swapf->i_dev;
	} else {
        // swap设备或文件都不存在，返回失败
		return 0;
	}

 	/* block_size == PAGE_SIZE/zones_used */
     // 执行读写IO
     brw_page(rw, page, dev, zones, block_size);

 	/* Note! For consistency we do all of the logic,
 	 * decrementing the page count, and unlocking the page in the
 	 * swap lock map - in the IO completion handler.
 	 */
	return 1;
}

/*
 * A simple wrapper so the base function doesn't need to enforce
 * that all swap pages go through the swap cache! We verify that:
 *  - the page is locked
 *  - it's marked as being swap-cache
 *  - it's associated with the swap inode
 */
// rw_swap_page_base检查版本
/**
 * rw:读写标志
 * page:读写的页面
 * return:void
 */
void rw_swap_page(int rw, struct page *page)
{
	swp_entry_t entry;

	entry.val = page->index;

    // 检查是否上锁
	if (!PageLocked(page))
		PAGE_BUG(page);
    // 检查是否存在swap cache中
	if (!PageSwapCache(page))
		PAGE_BUG(page);
    // 检查是否地址空间已经转换
	if (page->mapping != &swapper_space)
		PAGE_BUG(page);
    // 执行rw_swap_page_base
	if (!rw_swap_page_base(rw, entry, page))
		UnlockPage(page);
}

/*
 * The swap lock map insists that pages be in the page cache!
 * Therefore we can't use it.  Later when we can remove the need for the
 * lock map and we can reduce the number of functions exported.
 */
// 读写交换页非加锁版本
/**
 * rw:读写标志
 * entry:swap页入口
 * buf:页面逻辑地址
 */
void rw_swap_page_nolock(int rw, swp_entry_t entry, char *buf)
{
    // 将逻辑地址转换为对应的page指针
	struct page *page = virt_to_page(buf);

    // 检查是否上锁
	if (!PageLocked(page))
		PAGE_BUG(page);
    // 检查是否存在swap cache中
	if (PageSwapCache(page))
		PAGE_BUG(page);
    // 检查是否映射不为空
	if (page->mapping)
		PAGE_BUG(page);
	/* needs sync_page to wait I/O completation */
    // 将映射设置为交换地址空间
	page->mapping = &swapper_space;
    // 执行rw_swap_page_base
	if (!rw_swap_page_base(rw, entry, page))
		UnlockPage(page);
    // 加入等待队列，等待页面IO操作完成
	wait_on_page(page);
    // 释放页面映射
	page->mapping = NULL;
}
