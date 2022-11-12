/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the opereation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * linux/Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/pagemap.h>
#include <linux/init.h>

#include <asm/dma.h>
#include <asm/uaccess.h> /* for copy_to/from_user */
#include <asm/pgtable.h>

/* How many pages do we try to swap or page in/out together? */
// 一次交换的页框总数
int page_cluster;

pager_daemon_t pager_daemon = {
	512,	/* base number for calculating the number of tries */
	SWAP_CLUSTER_MAX,	/* minimum number of tries */
	8,	/* do swap I/O in clusters of this size */
};

/*
 * Move an inactive page to the active list.
 */
// 激活一个页框
/**
 * page:待激活的页框
 * return:void
 */
static inline void activate_page_nolock(struct page * page)
{
    // 检查page标志，是否由LRU调入，是否为inactive
	if (PageLRU(page) && !PageActive(page)) {
        // 从inactive list中删除，添加到active list中
		del_page_from_inactive_list(page);
		add_page_to_active_list(page);
	}
}

// active_page_nolock的上锁版本
/**
 * page:待激活的页框
 * return:void
 */
void activate_page(struct page * page)
{
	spin_lock(&pagemap_lru_lock);
	activate_page_nolock(page);
	spin_unlock(&pagemap_lru_lock);
}

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
// 将一个页框添加到lru_cache
/**
 * page:待添加的页框
 * return:void
 */
void lru_cache_add(struct page * page)
{
    // 检查并设置page.flags为PG_lru
	if (!TestSetPageLRU(page)) {
		spin_lock(&pagemap_lru_lock);
        // 将页框添加到inactive list中
		add_page_to_inactive_list(page);
		spin_unlock(&pagemap_lru_lock);
	}
}

/**
 * __lru_cache_del: remove a page from the page lists
 * @page: the page to add
 *
 * This function is for when the caller already holds
 * the pagemap_lru_lock.
 */
// 将一个页框从lru_cache中删除
/**
 * page:待删除的页框
 * return:void
 */
void __lru_cache_del(struct page * page)
{
    // 检查page.flags == PG_lru并清除page.flags
	if (TestClearPageLRU(page)) {
        // 若page为active，则从active list中删除
        // 否则从inactive list中删除
		if (PageActive(page)) {
			del_page_from_active_list(page);
		} else {
			del_page_from_inactive_list(page);
		}
	}
}

/**
 * lru_cache_del: remove a page from the page lists
 * @page: the page to remove
 */
// __lru_cache_del的上锁版本
/**
 * page:待删除的页框
 * return:void
 */
void lru_cache_del(struct page * page)
{
	spin_lock(&pagemap_lru_lock);
	__lru_cache_del(page);
	spin_unlock(&pagemap_lru_lock);
}

/*
 * Perform any setup for the swap system
 */
// 启动初始化swap系统
/**
 * void
 * return:void
 */
void __init swap_setup(void)
{
	unsigned long megs = num_physpages >> (20 - PAGE_SHIFT);

	/* Use a smaller cluster for small-memory machines */
    // 根据megs大小设置一次交换的页框数
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}
