/*
 *	linux/mm/mmap.c
 *
 * Written by obz.
 */
#include <linux/slab.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>

#include <asm/uaccess.h>
#include <asm/pgalloc.h>

/*
 * WARNING: the debugging will use recursive algorithms so never enable this
 * unless you know what you are doing.
 */
#undef DEBUG_MM_RB

/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type	prot
 *		PROT_NONE	PROT_READ	PROT_WRITE	PROT_EXEC
 * MAP_SHARED	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (yes) yes	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *		
 * MAP_PRIVATE	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (copy) copy	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 */
 
 /*
	页面保护映射数组，存储rwx权限
 */
pgprot_t protection_map[16] = {
	__P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
	__S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111
};

int sysctl_overcommit_memory;



// 检查进程是否有足够的空间去申请一个vma
/**
 * pages:需要申请的页框数
 * return:1，true；0，false
 */
int vm_enough_memory(long pages)
{
	// free记录当前空闲的空间
	unsigned long free;
	
        /* Sometimes we want to use more memory than we have. */
	if (sysctl_overcommit_memory)
	    return 1;

	// 原子读page_cache_size变量，page_cache_size变量在/mm/filemap.c中声明
	// 由swap.h引入
	// 只在filemap.c中调用atomic_inc和atomic_dec操作，用于将page添加到hash队列
	free = atomic_read(&page_cache_size);
	
	// nr_free_pages：返回RAM中的空闲页框数，定义在/mm/page_alloc.c中
	free += nr_free_pages();
	// page_alloc.c中的全局变量
	free += nr_swap_pages;

	/*
	 * This double-counts: the nrpages are both in the page-cache
	 * and in the swapper space. At the same time, this compensates
	 * for the swap-space over-allocation (ie "nr_swap_pages" being
	 * too small.
	 */
	// 交换空间中的空闲页框
	free += swapper_space.nrpages;

	/*
	 * The code below doesn't account for free space in the inode
	 * and dentry slab cache, slab cache fragmentation, inodes and
	 * dentries which will become freeable under VM load, etc.
	 * Lets just hope all these (complex) factors balance out...
	 */
	// 空闲单元 * 单元大小 / 页框大小 = 空闲页框数
	free += (dentry_stat.nr_unused * sizeof(struct dentry)) >> PAGE_SHIFT;
	free += (inodes_stat.nr_unused * sizeof(struct inode)) >> PAGE_SHIFT;

	// 空闲空间是否大于请求的空间
	return free > pages;
}

/* Remove one vm structure from the inode's i_mapping address space. */
// 从inode映射的vma地址空间中的共享内存部分删除一个vma
/**
 * vma:需要删除的vma
 * return:void
 */
static inline void __remove_shared_vm_struct(struct vm_area_struct *vma)
{
	struct file * file = vma->vm_file;

	if (file) {
		// 文件繁忙不允许写，inode原子递增writecount
		struct inode *inode = file->f_dentry->d_inode;
		if (vma->vm_flags & VM_DENYWRITE)
			atomic_inc(&inode->i_writecount);
			
		// 双向链表删除操作，后连前，前连后
		if(vma->vm_next_share)
			vma->vm_next_share->vm_pprev_share = vma->vm_pprev_share;
		*vma->vm_pprev_share = vma->vm_next_share;
	}
}

// remove_shared_vma的加锁版本
/**
 * vma:删除的vma
 * return:void
 */
static inline void remove_shared_vm_struct(struct vm_area_struct *vma)
{
	lock_vma_mappings(vma);
	__remove_shared_vm_struct(vma);
	unlock_vma_mappings(vma);
}

// 上锁
/**
 * vma:上锁的vma
 * return:void
 */
void lock_vma_mappings(struct vm_area_struct *vma)
{
	struct address_space *mapping;

	mapping = NULL;
	// 获取vma对应的inode的mapping
	// vm_file:vma指向的文件
	// f_dentry:文件的目录项
	// d_inode:目录项中记录的inode
	// i_mapping:inode映射的vma地址空间
	if (vma->vm_file)
		mapping = vma->vm_file->f_dentry->d_inode->i_mapping;
		
	// 将inode映射的vma共享地址空间上锁
	if (mapping)
		spin_lock(&mapping->i_shared_lock);
}

// 解锁，过程类似上锁
/**
 * vma:解锁的vma
 * return:void
 */
void unlock_vma_mappings(struct vm_area_struct *vma)
{
	struct address_space *mapping;

	mapping = NULL;
	if (vma->vm_file)
		mapping = vma->vm_file->f_dentry->d_inode->i_mapping;
	if (mapping)
		spin_unlock(&mapping->i_shared_lock);
}

/*
 *  sys_brk() for the most part doesn't need the global kernel
 *  lock, except when an application is doing something nasty
 *  like trying to un-brk an area that has already been mapped
 *  to a regular file.  in this case, the unmapping will need
 *  to invoke file system routines that need the global lock.
 */
 // 分配动态内存
 /**
  * brk:新分配的动态内存结束地址(起始地址固定)
  * return:分配的动态内存结束地址，分配不成功时返回当前mm.brk
  */
asmlinkage unsigned long sys_brk(unsigned long brk)
{
	unsigned long rlim, retval;
	unsigned long newbrk, oldbrk;
	
	// current是定义在current.h中的宏
	// define current get_current()
	// get_current()是current.h中的函数，内嵌汇编获取当前的task_struct
	// 获取esp寄存器指向的函数
	struct mm_struct *mm = current->mm;

	// 写者获取mm的读写信号量
	down_write(&mm->mmap_sem);

	// brk地址不合法，大小关系见进程内存分布
	if (brk < mm->end_code)
		goto out;
		
	// PAGE_ALIGN宏位于page.h，将brk地址对齐到下一个页框的起始地址
	// define PAGE_ALIGN(addr) (((addr)+PAGE_SIZE-1)&PAGE_MASK)
	// PAGE_SIZE = 1 << 12 = 4KB
	newbrk = PAGE_ALIGN(brk);
	oldbrk = PAGE_ALIGN(mm->brk);
	
	// 若对齐后相等，则brk和mm.brk原先在同一个页框中
	if (oldbrk == newbrk)
		goto set_brk;

	/* Always allow shrinking brk. */
	// 若brk<=mm.brk，则减小堆内存段
	if (brk <= mm->brk) {
		// 销毁映射，若成功，则跳转到out，若不成功，则跳转到set_brk
		if (!do_munmap(mm, newbrk, oldbrk-newbrk))
			goto set_brk;
		goto out;
	}

	/* Check against rlimit.. */
	// rlim:进程资源限制，rlimit类型数组
	// rlimit:结构体，包含rlim_cur和rlim_max
	// RLIMIT_DATA = 2，resource.h
	rlim = current->rlim[RLIMIT_DATA].rlim_cur;
	// 若分配后的堆内存和数据段大小大于资源限制，则out
	if (rlim < RLIM_INFINITY && brk - mm->start_data > rlim)
		goto out;

	/* Check against existing mmap mappings. */
	// 查找oldbrk和newbrk+PAGE_SIZE之间是否存在vma映射
	if (find_vma_intersection(mm, oldbrk, newbrk+PAGE_SIZE))
		goto out;

	/* Check if we have enough memory.. */
	// 检查是否还有空间申请vma
	if (!vm_enough_memory((newbrk-oldbrk) >> PAGE_SHIFT))
		goto out;

	/* Ok, looks good - let it rip. */
	// 到达此处表示mm.brk和brk不在一个页框中
	// 且需要增加堆内存段
	// 且分配后不超过资源限制
	// 且分配后的段中没有vma映射
	// 且进程还有空间申请vma
	// 执行do_brk，若分配成功，返回oldbrk
	if (do_brk(oldbrk, newbrk-oldbrk) != oldbrk)
		goto out;
set_brk:
	mm->brk = brk;
out: // 直接跳到out表示分配不成功
	retval = mm->brk;
	// 写者释放信号量
	up_write(&mm->mmap_sem);
	return retval;
}

/* Combine the mmap "prot" and "flags" argument into one "vm_flags" used
 * internally. Essentially, translate the "PROT_xxx" and "MAP_xxx" bits
 * into "VM_xxx".
 */
 // 合并prot和flags的信息到vm_flags
 // TODO
static inline unsigned long calc_vm_flags(unsigned long prot, unsigned long flags)
{
#define _trans(x,bit1,bit2) \
((bit1==bit2)?(x&bit1):(x&bit1)?bit2:0)

	unsigned long prot_bits, flag_bits;
	prot_bits =
		_trans(prot, PROT_READ, VM_READ) |
		_trans(prot, PROT_WRITE, VM_WRITE) |
		_trans(prot, PROT_EXEC, VM_EXEC);
	flag_bits =
		_trans(flags, MAP_GROWSDOWN, VM_GROWSDOWN) |
		_trans(flags, MAP_DENYWRITE, VM_DENYWRITE) |
		_trans(flags, MAP_EXECUTABLE, VM_EXECUTABLE);
	return prot_bits | flag_bits;
#undef _trans
}

// 判断DEBUG_MM_RB宏是否被定义
#ifdef DEBUG_MM_RB
// 递归遍历红黑树
/**
 * rb_node:红黑树节点
 * return:节点个数
 */
static int browse_rb(rb_node_t * rb_node) {
	int i = 0;
	if (rb_node) {
		i++;
		i += browse_rb(rb_node->rb_left);
		i += browse_rb(rb_node->rb_right);
	}
	return i;
}

// 检查mm_struct是否合法
/**
 * mm:受检查的mm_struct
 * return:void，出现bug时调用BUG()
 */
static void validate_mm(struct mm_struct * mm) {
	// 是否有bug
	int bug = 0;
	
	// 遍历vma链表，记录链表vma个数
	int i = 0;
	struct vm_area_struct * tmp = mm->mmap;
	while (tmp) {
		tmp = tmp->vm_next;
		i++;
	}
	// 若链表vma个数 != mm记录的vma个数，出现异常
	if (i != mm->map_count)
		printk("map_count %d vm_next %d\n", mm->map_count, i), bug = 1;
		
	// 遍历红黑树，记录个数
	i = browse_rb(mm->mm_rb.rb_node);
	// 若树节点个数 != mm记录的vma个数，出现异常
	if (i != mm->map_count)
		printk("map_count %d rb %d\n", mm->map_count, i), bug = 1;
	
	// 若出现异常，调用BUG()
	// BUG宏定义在tapedefs.h，打印错误信息
	if (bug)
		BUG();
}
#else
// 若DEBUG_MM_RB未定义，则定义validata_mm(mm)为do {} while (0);
// do {} while (0)的作用：将{}的代码分块，对于#ifdef分支来说，其中有一个代码块为do {} while (0);
// 保证使用宏时无编译错误
#define validate_mm(mm) do { } while (0)
#endif

// 查找插入位置的前一个vma
/**
 * mm:被搜索的mm
 * addr:开始查找的addr
 * pprev:待赋值的vma.pprev
 * rb_link:待赋值的目标vma的rb_node
 * rb_parent:待赋值的目标vma的rb_node.rb_parent
 * return:查找到的vma
 */
static struct vm_area_struct * find_vma_prepare(struct mm_struct * mm, unsigned long addr,
						struct vm_area_struct ** pprev,
						rb_node_t *** rb_link, rb_node_t ** rb_parent)
{
	struct vm_area_struct * vma;
	rb_node_t ** __rb_link, * __rb_parent, * rb_prev;

    // __rb_link变量存储当前mm的红黑树根节点
    // mm_rb: rb_root_s 根节点结构体
    // rb_node: rb_node_s 实际的节点结构体
	__rb_link = &mm->mm_rb.rb_node;

	rb_prev = __rb_parent = NULL;
	vma = NULL;

    // 若根节点不为空
	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;

        // rb_entry (type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member))
        // (struct vma*)((char*)__rb_parent - (ul)(&((vma*)0)->vm_rb))
        // 获得包含__rb_parent的vma，即__rb_parent对应的vma
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

        // 搜索树查找
		if (vma_tmp->vm_end > addr) { // 查找左子树
			vma = vma_tmp;
            // 若vma_tmp包含addr，直接返回
			if (vma_tmp->vm_start <= addr)
                // 若vma包含addr，则不设置pprev
				return vma;
			__rb_link = &__rb_parent->rb_left;
		} else { // 查找右子树，rb_prev记录当前节点
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

    // 到达此处说明红黑树中没有，__rb_link为__rb_parent的后继前驱节点(右子树中最小的节点)
    // 链表序中__rb_parent.next = __rb_link
    // vma为对应的vma，vma.vm_start > addr

    // 与find_vma_prev的不同
    // find_vma_prev需要考虑查找节点与它的子节点形成的前驱后继关系以及查找节点与祖先节点构成的后继前驱关系
    // find_vma_prepare用于查找插入位置的前驱节点，不需要考虑查找节点与它的子节点形成的前驱后继关系
    // 查找插入位置说明目标vma不存在，只需要记录rb_prev的状态
    // rb_prev的状态出现在两种情况下
    // 1.__rb_link总是向左查找时，rb_prev为空
    // 2.__rb_link存在向右查找时，rb_prev不为空，值为查找右子树时的根节点
	*pprev = NULL;
    // 若rb_prev为空，则查找到的vma为红黑树中左子树的节点，不是任何一个节点的后继前驱节点
    // 若rb_prev不为空，则vma属于某个节点的右子树，rb_prev记录该节点
    // TODO rb_prev = __rb_parent，不知道为什么设置两个变量
	if (rb_prev)
        // 赋值rb_prev对应的vma
        // 地址满足以下关系
        // pprev.vm_end < addr < vma.vm_start < vma.vm_end
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
    // 若vma不包含addr，则设置pprev表示包含区间
	return vma;
}

// 将vma插入到list和rbtree中
/**
 * mm:被处理的mm_struct
 * vma:插入的vma
 * prev:插入位置的前驱vma
 * rb_parent:插入位置对应的前驱rb_node
 * return:void
 */
static inline void __vma_link_list(struct mm_struct * mm, struct vm_area_struct * vma, struct vm_area_struct * prev,
				   rb_node_t * rb_parent)
{
    // 若有前驱vma
    // 若链表中有前驱vma，则红黑树中vma为prev的后继前驱节点
	if (prev) {
        // 单链表插入
		vma->vm_next = prev->vm_next;
		prev->vm_next = vma;
        // 此处只是插入链表，后续会调用__vma_link_rb在红黑树中插入
	} else { // 若没有前驱vma，则当前vma为list的第一个，头插
		mm->mmap = vma;
        // 若存在rb_parent，则将rb_parent对应的vma接在后面
        // 链表序中，vma为第一个，则红黑树中的所有节点都比vma大，vma为红黑树中最左的节点
        // rb_parent为插入位置的父节点，通过rb_parent获取vma
		if (rb_parent)
			vma->vm_next = rb_entry(rb_parent, struct vm_area_struct, vm_rb);
		else
			vma->vm_next = NULL;
	}
}

// 红黑树插入操作
/**
 * mm:被处理的mm
 * vma:需要调整的vma
 * rb_link:需要调整的rb_node
 * rb_parent:rb_link.rb_parent
 * return:void
 */
static inline void __vma_link_rb(struct mm_struct * mm, struct vm_area_struct * vma,
				 rb_node_t ** rb_link, rb_node_t * rb_parent)
{
    // 插入红黑树
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);
    // 红黑树性质调整
	rb_insert_color(&vma->vm_rb, &mm->mm_rb);
}

// vma连接文件处理
/**
 * vma:被连接的vma
 * return:void
 */
static inline void __vma_link_file(struct vm_area_struct * vma)
{
	struct file * file;

    // vma映射的文件
	file = vma->vm_file;
	if (file) {
        // 文件所属的inode
		struct inode * inode = file->f_dentry->d_inode;
        // inode的映射空间
		struct address_space *mapping = inode->i_mapping;
		struct vm_area_struct **head;

        // 文件繁忙不允许写，i_writecount递减
		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&inode->i_writecount);

        // inode映射的vma私有地址空间(表头)
		head = &mapping->i_mmap;
        // 若当前vma的标志位为共享，则设置head为vma共享地址空间(表头)
		if (vma->vm_flags & VM_SHARED)
			head = &mapping->i_mmap_shared;
      
		/* insert vma into inode's share list */
        // 将表头设置为vma的下一个共享节点
        // TODO 为什么将next_share设为表头
		if((vma->vm_next_share = *head) != NULL)
            // 将vma的下一个共享节点的pprev设为自身
			(*head)->vm_pprev_share = &vma->vm_next_share;

        // 将vma的pprev设为自身，表头设为vma
		*head = vma;
		vma->vm_pprev_share = head;
	}
}

// 向mm中的vma空间添加vma的聚合操作
/**
 * mm:被处理的mm
 * vma:添加的vma
 * prev:添加位置的前驱vma
 * rb_link:目标vma的rb_node
 * rb_parent:目标vma的rb_node.rb_parent
 * return:void
 */
static void __vma_link(struct mm_struct * mm, struct vm_area_struct * vma,  struct vm_area_struct * prev,
		       rb_node_t ** rb_link, rb_node_t * rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	__vma_link_file(vma);
}

// 在__vma_link的基础上进行加锁和验证
/**
 * mm:被处理的mm
 * vma:添加的vma
 * prev:添加位置的前驱vma
 * rb_link:目标vma的rb_node
 * rb_parent:目标vma的rb_node.rb_parent
 * return:void
 */
static inline void vma_link(struct mm_struct * mm, struct vm_area_struct * vma, struct vm_area_struct * prev,
			    rb_node_t ** rb_link, rb_node_t * rb_parent)
{
    // 锁进程vma
	lock_vma_mappings(vma);
    // 锁页表
	spin_lock(&mm->page_table_lock);
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	spin_unlock(&mm->page_table_lock);
	unlock_vma_mappings(vma);

    // 增加计数并验证
	mm->map_count++;
	validate_mm(mm);
}

// 合并vma
/**
 * mm:被处理的mm_struct
 * prev:合并区间的前一个vma
 * rb_parent:红黑树中合并区间的前一个rb_node
 * addr:合并区间起始地址
 * end:合并区间结束地址
 * vm_flags:vma权限
 * return:1，成功;0，失败
 */
static int vma_merge(struct mm_struct * mm, struct vm_area_struct * prev,
		     rb_node_t * rb_parent, unsigned long addr, unsigned long end, unsigned long vm_flags)
{
    // prev 为前一个vma
    // addr、end表示合并的地址区间

	spinlock_t * lock = &mm->page_table_lock;

    // 若prev为空，则获取rb_parent对应的vma
	if (!prev) {
		prev = rb_entry(rb_parent, struct vm_area_struct, vm_rb);
		goto merge_next;
	}

    // 若两个vma边界重合，并且前一个vma允许merge
	if (prev->vm_end == addr && can_vma_merge(prev, vm_flags)) {
		struct vm_area_struct * next;

        // 上锁
		spin_lock(lock);
        // 扩展prev边界
		prev->vm_end = end;
		next = prev->vm_next;
        // 获取后一个vma，若边界重合且允许merge
		if (next && prev->vm_end == next->vm_start && can_vma_merge(next, vm_flags)) {
            // 扩展边界
			prev->vm_end = next->vm_end;
            // 删除next vma
			__vma_unlink(mm, next, prev);

            // 解锁，计数-1，清除cache
			spin_unlock(lock);

			mm->map_count--;
			kmem_cache_free(vm_area_cachep, next);
			return 1;
		}
		spin_unlock(lock);
		return 1;
	}

    // 若边界不重合
	prev = prev->vm_next;
	if (prev) {
 merge_next:
        // 若不允许merge，直接return
		if (!can_vma_merge(prev, vm_flags))
			return 0;

        // 若下一个vma的start为合并区间的end，即合并区间不在prev->next里
		if (end == prev->vm_start) {
			spin_lock(lock);
            // 扩展下一个vma的起始地址
			prev->vm_start = addr;
			spin_unlock(lock);
			return 1;
		}
	}

	return 0;
}

// do_mmap核心函数
/**
 * file:被映射的file
 * addr:开始映射的线性区地址
 * len:映射长度
 * prot:访问权限
 * flags:映射标志
 * pgoff:文件偏移量
 * return:映射线性区起始地址(成功返回addr)
 */
unsigned long do_mmap_pgoff(struct file * file, unsigned long addr, unsigned long len,
	unsigned long prot, unsigned long flags, unsigned long pgoff)
{
    // 获取当前mm_struct
	struct mm_struct * mm = current->mm;

	struct vm_area_struct * vma, * prev;
	unsigned int vm_flags;
    // 初始共享该vma的进程数为0
	int correct_wcount = 0;
	int error;
	rb_node_t ** rb_link, * rb_parent;

    // 检查file是否含有mmap函数
	if (file && (!file->f_op || !file->f_op->mmap))
		return -ENODEV;

    // 将len对齐，len的值为映射的所有页框的长度
    // 若映射长度不超过一个页框，则返回addr作为起始地址
	if ((len = PAGE_ALIGN(len)) == 0)
		return addr;

    // 若映射长度超过进程用户空间，错误
	if (len > TASK_SIZE)
		return -EINVAL;

	/* offset overflow? */
    // len << PAGE_SHIFT为映射的页框个数
    // 判断文件偏移量是否溢出，即页框个数是否是负数
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EINVAL;

	/* Too many mappings? */
    // 若当前映射数大于最大映射数，错误
	if (mm->map_count > MAX_MAP_COUNT)
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
    // 从addr开始查找未映射的区域的起始地址
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
    // TODO addr在页框中
	if (addr & ~PAGE_MASK)
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
    // 合并标志信息
	vm_flags = calc_vm_flags(prot,flags) | mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	/* mlock MCL_FUTURE? */
    // 若vma标志为上锁状态
	if (vm_flags & VM_LOCKED) {
        // 获取当前上锁的vma拥有的页框数
		unsigned long locked = mm->locked_vm << PAGE_SHIFT;
        // 加上当前需要映射的页框数
		locked += len;
        // 检查资源分配
		if (locked > current->rlim[RLIMIT_MEMLOCK].rlim_cur)
			return -EAGAIN;
	}

	if (file) {
        // 若映射的是文件，检查映射类型及权限
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if ((prot & PROT_WRITE) && !(file->f_mode & FMODE_WRITE))
				return -EACCES;

			/* Make sure we don't allow writing to an append-only file.. */
			if (IS_APPEND(file->f_dentry->d_inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			/* make sure there are no mandatory locks on the file. */
			if (locks_verify_locked(file->f_dentry->d_inode))
				return -EAGAIN;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);

			/* fall through */
		case MAP_PRIVATE:
			if (!(file->f_mode & FMODE_READ))
				return -EACCES;
			break;

		default:
			return -EINVAL;
		}
	} else {
        // 若映射的是进程其他段
		vm_flags |= VM_SHARED | VM_MAYSHARE;
		switch (flags & MAP_TYPE) {
		default:
			return -EINVAL;
		case MAP_PRIVATE:
			vm_flags &= ~(VM_SHARED | VM_MAYSHARE);
			/* fall through */
		case MAP_SHARED:
			break;
		}
	}

	/* Clear old maps */
	error = -ENOMEM;
munmap_back:
    // 查找插入位置
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
    // 若vma包含addr+len，则销毁[addr,addr+len]的映射
    // 跳转到munmap_back直到找到合法的插入位置
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limit. */
    // 检查资源分配
	if ((mm->total_vm << PAGE_SHIFT) + len
	    > current->rlim[RLIMIT_AS].rlim_cur)
		return -ENOMEM;

	/* Private writable mapping? Check memory availability.. */
    // 检查是否有足够空间建立映射
	if ((vm_flags & (VM_SHARED | VM_WRITE)) == VM_WRITE &&
	    !(flags & MAP_NORESERVE)				 &&
	    !vm_enough_memory(len >> PAGE_SHIFT))
		return -ENOMEM;

	/* Can we just expand an old anonymous mapping? */
    // 尝试合并已有的匿名映射
    // 匿名映射不映射实际的文件，用于映射用户进程请求分配的内存(malloc)
	if (!file && !(vm_flags & VM_SHARED) && rb_parent)
		if (vma_merge(mm, prev, rb_parent, addr, addr + len, vm_flags))
            // 合并成功，跳转到out
			goto out;

	/* Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
    // 分配cache内存
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma)
		return -ENOMEM;

    // 设置vma属性
	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = protection_map[vm_flags & 0x0f];
	vma->vm_ops = NULL;
	vma->vm_pgoff = pgoff;
	vma->vm_file = NULL;
	vma->vm_private_data = NULL;
	vma->vm_raend = 0;

    // 若当前映射到file
	if (file) {
		error = -EINVAL;
        // 若vma为向上增长或向下增长
		if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
			goto free_vma;
        // 若vma拒绝写
		if (vm_flags & VM_DENYWRITE) {
            // 检查是否文件拒绝写
			error = deny_write_access(file);
			if (error)
				goto free_vma;
            // 文件允许写，则共享vma进程数为1
			correct_wcount = 1;
		}
		vma->vm_file = file;
		get_file(file);
        // 执行file的映射操作
		error = file->f_op->mmap(file, vma);
		if (error)
            // 错误在则销毁映射并释放vma
			goto unmap_and_free_vma;
        
	} else if (flags & MAP_SHARED) {
        // 若映射为共享映射，则建立一个共享映射
		error = shmem_zero_setup(vma);
		if (error)
            // 错误则释放vma
			goto free_vma;
	}

	/* Can addr have changed??
	 *
	 * Answer: Yes, several device drivers can do it in their
	 *         f_op->mmap method. -DaveM
	 */
    // 更新addr为vma.vm_start
	addr = vma->vm_start;

    // 将vma连接到mm的相关结构上
	vma_link(mm, vma, prev, rb_link, rb_parent);
    // 若共享进程大于0，则原子递增共享进程数
	if (correct_wcount)
		atomic_inc(&file->f_dentry->d_inode->i_writecount);

out:
    // 增加vm页框计数
	mm->total_vm += len >> PAGE_SHIFT;
    // 若vma为上锁状态
	if (vm_flags & VM_LOCKED) {
        // 增加上锁页框计数
		mm->locked_vm += len >> PAGE_SHIFT;
		make_pages_present(addr, addr + len);
	}
	return addr;

unmap_and_free_vma:
    // 检查共享进程数
	if (correct_wcount)
		atomic_inc(&file->f_dentry->d_inode->i_writecount);
	vma->vm_file = NULL;
	fput(file);

	/* Undo any partial mapping done by a device driver. */
    // 移除进程用户空间页面
	zap_page_range(mm, vma->vm_start, vma->vm_end - vma->vm_start);
free_vma:
    // 释放vma，返回错误
	kmem_cache_free(vm_area_cachep, vma);
	return error;
}

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
#ifndef HAVE_ARCH_UNMAPPED_AREA

// 获取未映射区域的起始地址-架构实现
/**
 * filp:被映射的file
 * addr:开始查找的addr
 * len:映射长度
 * pgoff:文件的偏移量
 * flags:映射标志
 * return:未映射的区域的起始地址(vmas未覆盖的区域)
 */
static inline unsigned long arch_get_unmapped_area(struct file *filp, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct vm_area_struct *vma;

    // 若映射长度大于进程用户空间
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (addr) {
        // 将addr对齐后find_vma查找第一个满足addr < vm_end的vma
		addr = PAGE_ALIGN(addr);
		vma = find_vma(current->mm, addr);

        // 若找不到vma或者vma不包含addr+len(不包含addr+len必定不包含addr)
        // 直接返回addr
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
    // 将addr对齐后再次查找
	addr = PAGE_ALIGN(TASK_UNMAPPED_BASE);

    // 从第一个addr < vm_end的vma开始，直到查找到合法的vma
	for (vma = find_vma(current->mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr)
			return -ENOMEM;
		if (!vma || addr + len <= vma->vm_start)
			return addr;
		addr = vma->vm_end;
	}
}
#else
extern unsigned long arch_get_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
#endif	

// 获取未映射区域的起始地址
/**
 * file:被映射的file
 * addr:开始查找的addr
 * len:映射长度
 * pgoff:文件内的偏移量
 * flags:映射标志
 * return:未映射的区域的起始地址
 */
unsigned long get_unmapped_area(struct file *file, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)
{
    // flags检查
	if (flags & MAP_FIXED) {
		if (addr > TASK_SIZE - len)
			return -ENOMEM;
		if (addr & ~PAGE_MASK)
			return -EINVAL;
		return addr;
	}

    // 若文件存在且操作集中包含get_unmapped_area函数，执行文件的get_unmapped_are
	if (file && file->f_op && file->f_op->get_unmapped_area)
		return file->f_op->get_unmapped_area(file, addr, len, pgoff, flags);

    // 否则执行架构实现的get_unmapped_area
	return arch_get_unmapped_area(file, addr, len, pgoff, flags);
}

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
// 查找第一个满足addr < vm_end的vma
/**
 * mm:被查找的mm_struct
 * addr:目标地址(addr不一定落在vma内)
 * return:目标vma
 */
struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct *vma = NULL;

	if (mm) {
		/* Check the cache first. */
		/* (Cache hit rate is typically around 35%.) */
        // 首先查看cache，cache为上一次find_vma的结果
		vma = mm->mmap_cache;
        // 若cache不满足则红黑树搜索，满足直接返回
		if (!(vma && vma->vm_end > addr && vma->vm_start <= addr)) {
			rb_node_t * rb_node;

			rb_node = mm->mm_rb.rb_node;
			vma = NULL;

			while (rb_node) {
				struct vm_area_struct * vma_tmp;

				vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

                // addr < end，往左查找
				if (vma_tmp->vm_end > addr) {
					vma = vma_tmp;
                    // 满足条件直接break
					if (vma_tmp->vm_start <= addr)
						break;
					rb_node = rb_node->rb_left;
				} else // addr >= end，往右查找
					rb_node = rb_node->rb_right;
			}
            // 将查找结果存入cache
			if (vma)
				mm->mmap_cache = vma;
		}
	}
    // 当vma = NULL时，mm中红黑树根不存在或者搜索树时总是向右查找，树中所有节点的vm_end都比addr小
    // 当vma != NULL时，addr一定比vma.vm_end小，但addr和vma.vm_start的大小关系无法得知
	return vma;
}

/* Same as find_vma, but also return a pointer to the previous VMA in *pprev. */
// 搜索包含addr
/**
 * mm:被搜索的mm_struct
 * addr:开始查找的addr
 * pprev:查找到的vma的pprev(待赋值)
 * return:查找到的vma
 */
struct vm_area_struct * find_vma_prev(struct mm_struct * mm, unsigned long addr,
				      struct vm_area_struct **pprev)
{
	if (mm) {
		/* Go through the RB tree quickly. */
        // 直接查找红黑树
		struct vm_area_struct * vma;
		rb_node_t * rb_node, * rb_last_right, * rb_prev;

        // rb_node为当前遍历到的节点
		rb_node = mm->mm_rb.rb_node;
		rb_last_right = rb_prev = NULL;
		vma = NULL;

		while (rb_node) {
			struct vm_area_struct * vma_tmp;

			vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

            // 查找左子树
			if (vma_tmp->vm_end > addr) {
				vma = vma_tmp;
				rb_prev = rb_last_right;
				if (vma_tmp->vm_start <= addr)
					break;
				rb_node = rb_node->rb_left;
			} else { // 查找右子树
                // rb_last_right记录右子树的父节点
				rb_last_right = rb_node;
				rb_node = rb_node->rb_right;
			}
		}
        // 若vma为空，则vma为树中最右的节点，没有满足条件的vma，跳到return NULL;
        // 若vma不为空的情况
        // 1.经过break跳出，vma.vm_start <= addr < vma.vm_end，vma可能不是叶子节点
        // 2.循环结束跳出，vma是第一个满足vm_start > addr的节点，vma一定是叶子节点
        // rb_prev是否为空的rb_node状态
        // rb_node总是向左查找或存在向右查找但不构成后继前驱关系时，rb_prev为空
        // rb_node存在向右查找且构成后继前驱关系时，rb_prev不为空
		if (vma) {
            // 结合上面的情况，会产生四种状态
            // 1.rb_prev为空，vma没有左子树
            //   此时rb_node为红黑树中最左的节点，vm_end最小的节点，对应链表中的第一个节点
            // 2.rb_prev为空，vma有左子树
            //   此时rb_node总是向左查找但vma不是最左的节点，是第一个vm_end > addr的节点
            // 3.rb_prev不为空，vma没有左子树
            //   此时rb_node一定为叶节点，vma为rb_prev的后继前驱节点
            // 4.rb_prev不为空，vma有左子树
            //   此时vma一定包含addr，含有左子树说明存在vm_end大于rb_prev小于vma的节点，依然更新rb_prev

            // 若rb_node有左子树，查找前驱后继节点
			if (vma->vm_rb.rb_left) {
                // rb_prev移动到rb_node左子树中的最右节点
				rb_prev = vma->vm_rb.rb_left;
				while (rb_prev->rb_right)
					rb_prev = rb_prev->rb_right;
			}
			*pprev = NULL;
			if (rb_prev)
                // rb_prev不为空则*pprev设为rb_prev对应的vma
                // rb_prev为vm_end小于vma.vm_end的最大节点(类似二分查找，在链表上顺序排在vma之前)
                // 二叉搜索树的中序与链表升序一致
				*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
            // 检查链表上的顺序，即pprev.next=vma
            // 若rb_prev为空，则vma为链表的表头
			if ((rb_prev ? (*pprev)->vm_next : mm->mmap) != vma)
				BUG();
			return vma;
		}
	}
	*pprev = NULL;
	return NULL;
}

// 查找第一个扩展的vma，可扩展的vma为addr < vma.vm_start,addr < vma.vm_end
/**
 * mm:被查找的mm_struct
 * addr:开始查找的地址
 * return:被扩展的vma
 */
struct vm_area_struct * find_extend_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct * vma;
	unsigned long start;

    // 将addr对齐页框
	addr &= PAGE_MASK;
    // 查找第一个vm_end > addr的vma
	vma = find_vma(mm,addr);
	if (!vma)
		return NULL;
    // 若vma包含addr，直接返回vma
	if (vma->vm_start <= addr)
		return vma;
    // 若vma的标志不是可向下扩展的，直接返回
    // 栈向下扩展，堆向上扩展，上方向为高地址
	if (!(vma->vm_flags & VM_GROWSDOWN))
		return NULL;
    // 扩展vma
	start = vma->vm_start;
	if (expand_stack(vma, addr))
		return NULL;
	if (vma->vm_flags & VM_LOCKED) {
		make_pages_present(addr, start);
	}
	return vma;
}

/* Normal function to fix up a mapping
 * This function is the default for when an area has no specific
 * function.  This may be used as part of a more specific routine.
 * This function works out what part of an area is affected and
 * adjusts the mapping information.  Since the actual page
 * manipulation is done in do_mmap(), none need be done here,
 * though it would probably be more appropriate.
 *
 * By the time this function is called, the area struct has been
 * removed from the process mapping list, so it needs to be
 * reinserted if necessary.
 *
 * The 4 main cases are:
 *    Unmapping the whole area
 *    Unmapping from the start of the segment to a point in it
 *    Unmapping from an intermediate point to the end
 *    Unmapping between to intermediate points, making a hole.
 *
 * Case 4 involves the creation of 2 new areas, for each side of
 * the hole.  If possible, we reuse the existing area rather than
 * allocate a new one, and the return indicates whether the old
 * area was reused.
 */
// 修正未映射区域
/**
 * mm:mm_struct
 * area:待处理的vma
 * addr:起始地址
 * len:映射长度
 * extra:用于映射未映射区域的vma
 * return:修正后新映射区域的vma
 */
static struct vm_area_struct * unmap_fixup(struct mm_struct *mm, 
	struct vm_area_struct *area, unsigned long addr, size_t len, 
	struct vm_area_struct *extra)
{
	struct vm_area_struct *mpnt;
	unsigned long end = addr + len;

	area->vm_mm->total_vm -= len >> PAGE_SHIFT;
	if (area->vm_flags & VM_LOCKED)
		area->vm_mm->locked_vm -= len >> PAGE_SHIFT;

	/* Unmapping the whole area. */
    // 若vma的映射的整个区域都将销毁，则清除vma的相关结构后返回
	if (addr == area->vm_start && end == area->vm_end) {
		if (area->vm_ops && area->vm_ops->close)
			area->vm_ops->close(area);
		if (area->vm_file)
			fput(area->vm_file);
		kmem_cache_free(vm_area_cachep, area);
		return extra;
	}

	/* Work out to one of the ends. */
    // 若销毁区域与vma的范围只有一个边界重合，则调整vma范围即可
	if (end == area->vm_end) {
		/*
		 * here area isn't visible to the semaphore-less readers
		 * so we don't need to update it under the spinlock.
		 */
		area->vm_end = addr;
        // 上锁
		lock_vma_mappings(area);
		spin_lock(&mm->page_table_lock);
	} else if (addr == area->vm_start) {
        // 移动文件偏移量
		area->vm_pgoff += (end - area->vm_start) >> PAGE_SHIFT;
		/* same locking considerations of the above case */
		area->vm_start = end;
        // 上锁
		lock_vma_mappings(area);
		spin_lock(&mm->page_table_lock);
	} else {
	/* Unmapping a hole: area->vm_start < addr <= end < area->vm_end */
    // 删除部分位于vma范围内部
		/* Add end mapping -- leave beginning for below */
        // 增加[end,vma.vm_end]部分的映射
		mpnt = extra;
		extra = NULL;

        // 设置extra属性
		mpnt->vm_mm = area->vm_mm;
		mpnt->vm_start = end;
		mpnt->vm_end = area->vm_end;
		mpnt->vm_page_prot = area->vm_page_prot;
		mpnt->vm_flags = area->vm_flags;
		mpnt->vm_raend = 0;
		mpnt->vm_ops = area->vm_ops;
		mpnt->vm_pgoff = area->vm_pgoff + ((end - area->vm_start) >> PAGE_SHIFT);
		mpnt->vm_file = area->vm_file;
		mpnt->vm_private_data = area->vm_private_data;
		if (mpnt->vm_file)
			get_file(mpnt->vm_file);
		if (mpnt->vm_ops && mpnt->vm_ops->open)
			mpnt->vm_ops->open(mpnt);

        // 调整vma的end边界
		area->vm_end = addr;	/* Truncate area */

		/* Because mpnt->vm_file == area->vm_file this locks
		 * things correctly.
		 */
        // 上锁
		lock_vma_mappings(area);
		spin_lock(&mm->page_table_lock);
        // 插入新映射的vma
		__insert_vm_struct(mm, mpnt);
	}

    // 插入处理后的原vma
    // 流程的思路为将free list中的vma都先进行删除，然后传入fixup进行处理，处理完成后再插入回去
	__insert_vm_struct(mm, area);
    // 解锁
	spin_unlock(&mm->page_table_lock);
	unlock_vma_mappings(area);
    // 若extra已使用，则extra为NULL，否则保留原值
	return extra;
}

/*
 * Try to free as many page directory entries as we can,
 * without having to work very hard at actually scanning
 * the page tables themselves.
 *
 * Right now we try to free page tables if we have a nice
 * PGDIR-aligned area that got free'd up. We could be more
 * granular if we want to, but this is fast and simple,
 * and covers the bad cases.
 *
 * "prev", if it exists, points to a vma before the one
 * we just free'd - but there's no telling how much before.
 */
// 释放页表项
static void free_pgtables(struct mm_struct * mm, struct vm_area_struct *prev,
	unsigned long start, unsigned long end)
{
	unsigned long first = start & PGDIR_MASK;
	unsigned long last = end + PGDIR_SIZE - 1;
	unsigned long start_index, end_index;

	if (!prev) {
		prev = mm->mmap;
		if (!prev)
			goto no_mmaps;
		if (prev->vm_end > start) {
			if (last > prev->vm_start)
				last = prev->vm_start;
			goto no_mmaps;
		}
	}
	for (;;) {
		struct vm_area_struct *next = prev->vm_next;

		if (next) {
			if (next->vm_start < start) {
				prev = next;
				continue;
			}
			if (last > next->vm_start)
				last = next->vm_start;
		}
		if (prev->vm_end > first)
			first = prev->vm_end + PGDIR_SIZE - 1;
		break;
	}
no_mmaps:
	/*
	 * If the PGD bits are not consecutive in the virtual address, the
	 * old method of shifting the VA >> by PGDIR_SHIFT doesn't work.
	 */
	start_index = pgd_index(first);
	end_index = pgd_index(last);
	if (end_index > start_index) {
		clear_page_tables(mm, start_index, end_index - start_index);
		flush_tlb_pgtables(mm, first & PGDIR_MASK, last & PGDIR_MASK);
	}
}

/* Munmap is split into 2 main parts -- this part which finds
 * what needs doing, and the areas themselves, which do the
 * work.  This now handles partial unmappings.
 * Jeremy Fitzhardine <jeremy@sw.oz.au>
 */
// 销毁虚拟内存映射
/**
 * mm:mm_struct
 * addr:销毁映射的起始地址
 * len:销毁的映射长度
 * return:1:成功,0:失败
 */
int do_munmap(struct mm_struct *mm, unsigned long addr, size_t len)
{
	struct vm_area_struct *mpnt, *prev, **npp, *free, *extra;

    // 检查参数范围
	if ((addr & ~PAGE_MASK) || addr > TASK_SIZE || len > TASK_SIZE-addr)
		return -EINVAL;

    // 若映射长度不超过一个页框，错误
	if ((len = PAGE_ALIGN(len)) == 0)
		return -EINVAL;

	/* Check if this memory area is ok - put it on the temporary
	 * list if so..  The checks here are pretty simple --
	 * every area affected in some way (by any overlap) is put
	 * on the list.  If nothing is put on, nothing is affected.
	 */
    // 查待找删除vma并将前一个vma赋值prev
	mpnt = find_vma_prev(mm, addr, &prev);
	if (!mpnt)
		return 0;
	/* we have  addr < mpnt->vm_end  */

    // 若销毁部分不在查找到的vma的范围内，失败
	if (mpnt->vm_start >= addr+len)
		return 0;

	/* If we'll make "hole", check the vm areas limit */
    // 若删除部分在vma内，则会使vma的范围产生一个洞，删除后一个vma会变为两个
    // 此时检查vma总数是否超过最大值
	if ((mpnt->vm_start < addr && mpnt->vm_end > addr+len)
	    && mm->map_count >= MAX_MAP_COUNT)
		return -ENOMEM;

    // 到此处销毁部分与查找到的vma范围有四种关系
    // 1.addr <= vm_start < addr + len < vm_end
    // 2.addr <= vm_start < vm_end <= vm_end
    // 3.vm_start < addr < addr + len < vm_end
    // 4.vm_start < addr < vm_end < addr + len

	/*
	 * We may need one additional vma to fix up the mappings ... 
	 * and this is the last chance for an easy error exit.
	 */
    // 额外分配一个vma来映射删除后产生的新的未映射区域
	extra = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!extra)
		return -ENOMEM;

    // 若prev不存在，则赋值为表头
	npp = (prev ? &prev->vm_next : &mm->mmap);
	free = NULL;
    // 页表上锁，进行删除
	spin_lock(&mm->page_table_lock);
    // 将删除部分的vma指针反向，形成free list，free为表头
    // vma1 -> vma2 <- free1 <- free2 <-...<- free | mpnt -> vma3 ->...
	for ( ; mpnt && mpnt->vm_start < addr+len; mpnt = *npp) {
		*npp = mpnt->vm_next;
		mpnt->vm_next = free;
		free = mpnt;
        // 红黑树删除节点
		rb_erase(&mpnt->vm_rb, &mm->mm_rb);
	}
	mm->mmap_cache = NULL;	/* Kill the cache. */
	spin_unlock(&mm->page_table_lock);

	/* Ok - we have the memory areas we should free on the 'free' list,
	 * so release them, and unmap the page range..
	 * If the one of the segments is only being partially unmapped,
	 * it will put new vm_area_struct(s) into the address space.
	 * In that case we have to be careful with VM_DENYWRITE.
	 */
    // 遍历free list进行删除
	while ((mpnt = free) != NULL) {
		unsigned long st, end, size;
		struct file *file = NULL;

		free = free->vm_next;

        // 确定删除范围
        // 若[addr,addr+len]超出[vm_start,vm_end]，则st=vm_start,end=vm_end
		st = addr < mpnt->vm_start ? mpnt->vm_start : addr;
		end = addr+len;
		end = end > mpnt->vm_end ? mpnt->vm_end : end;
		size = end - st;

        // 检查共享进程数
		if (mpnt->vm_flags & VM_DENYWRITE &&
		    (st != mpnt->vm_start || end != mpnt->vm_end) &&
		    (file = mpnt->vm_file) != NULL) {
			atomic_dec(&file->f_dentry->d_inode->i_writecount);
		}
        // 删除vma
		remove_shared_vm_struct(mpnt);
		mm->map_count--;

        // 删除指定范围的页框
		zap_page_range(mm, st, size);

		/*
		 * Fix the mapping, and free the old area if it wasn't reused.
		 */
        // 修正删除后产生的未映射区域
		extra = unmap_fixup(mm, mpnt, st, size, extra);
        // 若当前vma映射了文件，则增加共享进程数
		if (file)
			atomic_inc(&file->f_dentry->d_inode->i_writecount);
	}
    // 检查mm
	validate_mm(mm);

	/* Release the extra vma struct if it wasn't used */
    // 若extra不为空，则extra未使用，释放extra
	if (extra)
		kmem_cache_free(vm_area_cachep, extra);

    // 释放页表项
	free_pgtables(mm, prev, addr, addr+len);

	return 0;
}

// 系统调用，销毁虚拟内存映射
/**
 * addr:销毁的线性区起始地址
 * len:映射长度
 * return:TODO
 */
asmlinkage long sys_munmap(unsigned long addr, size_t len)
{
	int ret;
	struct mm_struct *mm = current->mm;

	down_write(&mm->mmap_sem);
	ret = do_munmap(mm, addr, len);
	up_write(&mm->mmap_sem);
	return ret;
}

/*
 *  this is really a simplified "do_mmap".  it only handles
 *  anonymous maps.  eventually we may be able to do some
 *  brk-specific accounting here.
 */
// 分配动态内存
unsigned long do_brk(unsigned long addr, unsigned long len)
{
	struct mm_struct * mm = current->mm;
	struct vm_area_struct * vma, * prev;
	unsigned long flags;
	rb_node_t ** rb_link, * rb_parent;

	len = PAGE_ALIGN(len);
	if (!len) 
		return addr;

	/*
	 * mlock MCL_FUTURE?
	 */
	if (mm->def_flags & VM_LOCKED) {
		unsigned long locked = mm->locked_vm << PAGE_SHIFT;
		locked += len;
		if (locked > current->rlim[RLIMIT_MEMLOCK].rlim_cur)
			return -EAGAIN;
	}

	/*
	 * Clear old maps.  this also does some error checking for us
	 */
 munmap_back:
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limits *after* clearing old maps... */
	if ((mm->total_vm << PAGE_SHIFT) + len
	    > current->rlim[RLIMIT_AS].rlim_cur)
		return -ENOMEM;

	if (mm->map_count > MAX_MAP_COUNT)
		return -ENOMEM;

	if (!vm_enough_memory(len >> PAGE_SHIFT))
		return -ENOMEM;

	flags = calc_vm_flags(PROT_READ|PROT_WRITE|PROT_EXEC,
				MAP_FIXED|MAP_PRIVATE) | mm->def_flags;

	flags |= VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	/* Can we just expand an old anonymous mapping? */
	if (rb_parent && vma_merge(mm, prev, rb_parent, addr, addr + len, flags))
		goto out;

	/*
	 * create a vma struct for an anonymous mapping
	 */
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma)
		return -ENOMEM;

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = flags;
	vma->vm_page_prot = protection_map[flags & 0x0f];
	vma->vm_ops = NULL;
	vma->vm_pgoff = 0;
	vma->vm_file = NULL;
	vma->vm_private_data = NULL;

	vma_link(mm, vma, prev, rb_link, rb_parent);

out:
	mm->total_vm += len >> PAGE_SHIFT;
	if (flags & VM_LOCKED) {
		mm->locked_vm += len >> PAGE_SHIFT;
		make_pages_present(addr, addr + len);
	}
	return addr;
}

/* Build the RB tree corresponding to the VMA list. */
// 根据vma list建红黑树
/**
 * mm:建树的mm_struct
 * return:void
 */
void build_mmap_rb(struct mm_struct * mm)
{
	struct vm_area_struct * vma;
	rb_node_t ** rb_link, * rb_parent;

    // RB_ROOT:rb_node_t结构
	mm->mm_rb = RB_ROOT;
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
    // 遍历vma链表，每个节点调用__vma_link_rb插入到红黑树中
    // 链表升序，红黑树总是从右节点插入
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		__vma_link_rb(mm, vma, rb_link, rb_parent);
		rb_parent = &vma->vm_rb;
		rb_link = &rb_parent->rb_right;
	}
}

/* Release all mmaps. */
// 销毁所有映射
/**
 * mm:待销毁映射的mm_struct
 * return:void
 */
void exit_mmap(struct mm_struct * mm)
{
	struct vm_area_struct * mpnt;

    // 释放mm的context和LDT
	release_segments(mm);

    // 页表上锁
	spin_lock(&mm->page_table_lock);
    // 获取vma链表表头
	mpnt = mm->mmap;
    // 清空mm结构
	mm->mmap = mm->mmap_cache = NULL;
	mm->mm_rb = RB_ROOT;
	mm->rss = 0;
	spin_unlock(&mm->page_table_lock);
	mm->total_vm = 0;
	mm->locked_vm = 0;

    // 刷新cache
	flush_cache_mm(mm);

    // 清空vma链表
	while (mpnt) {
		struct vm_area_struct * next = mpnt->vm_next;
		unsigned long start = mpnt->vm_start;
		unsigned long end = mpnt->vm_end;
		unsigned long size = end - start;

        // 关闭vma
		if (mpnt->vm_ops) {
			if (mpnt->vm_ops->close)
				mpnt->vm_ops->close(mpnt);
		}

        // 删除vma并释放页框
		mm->map_count--;
		remove_shared_vm_struct(mpnt);
		zap_page_range(mm, start, size);
        // 将vma指向的file结构清零
		if (mpnt->vm_file)
			fput(mpnt->vm_file);
        // 清空缓存
		kmem_cache_free(vm_area_cachep, mpnt);
		mpnt = next;
	}
    // 刷新tlb
	flush_tlb_mm(mm);

	/* This is just debugging */
	if (mm->map_count)
		BUG();

    // 清空页表
	clear_page_tables(mm, FIRST_USER_PGD_NR, USER_PTRS_PER_PGD);
}

/* Insert vm structure into process list sorted by address
 * and into the inode's i_mmap ring.  If vm_file is non-NULL
 * then the i_shared_lock must be held here.
 */
// 插入vma
/**
 * mm:被插入的mm_struct
 * vma:插入的vma
 * return:void
 */
void __insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	rb_node_t ** rb_link, * rb_parent;

    // 查找插入位置的前一个vma，以vma.vm_start为查找的起始地址
	__vma = find_vma_prepare(mm, vma->vm_start, &prev, &rb_link, &rb_parent);
    // 若vma已存在，则返回__vma不为空且__vma在vma之前或__vma == vma
	if (__vma && __vma->vm_start < vma->vm_end)
		BUG();
    // vma不存在，此时，prev不为空，vma.vm_end <= __vma.vm_start
	__vma_link(mm, vma, prev, rb_link, rb_parent);
    // 增加计数并验证
	mm->map_count++;
	validate_mm(mm);
}

// 插入vma，实现同__insert_vm_struct
/**
 * mm:被插入的mm_struct
 * vma:插入的vma
 * return:void
 */
void insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	rb_node_t ** rb_link, * rb_parent;

	__vma = find_vma_prepare(mm, vma->vm_start, &prev, &rb_link, &rb_parent);
	if (__vma && __vma->vm_start < vma->vm_end)
		BUG();
	vma_link(mm, vma, prev, rb_link, rb_parent);
	validate_mm(mm);
}
