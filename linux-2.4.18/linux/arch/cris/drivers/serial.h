/*
 * serial.h: Arch-dep definitions for the Etrax100 serial driver.
 *
 * Copyright (C) 1998, 1999, 2000 Axis Communications AB
 */

#ifndef _ETRAX_SERIAL_H
#define _ETRAX_SERIAL_H

#include <linux/config.h>
#include <linux/circ_buf.h>
#include <asm/termios.h>

/* Software state per channel */

#ifdef __KERNEL__
/*
 * This is our internal structure for each serial port's state.
 * 
 * Many fields are paralleled by the structure used by the serial_struct
 * structure.
 *
 * For definitions of the flags field, see tty.h
 */

#define SERIAL_RECV_DESCRIPTORS 8

struct etrax_recv_buffer {
	struct etrax_recv_buffer *next;
	unsigned short length;
	unsigned char error;
	unsigned char pad;

	unsigned char buffer[0];
};

struct e100_serial {
	int			baud;
	volatile u8		*port; /* R_SERIALx_CTRL */
	u32			irq;  /* bitnr in R_IRQ_MASK2 for dmaX_descr */

	/* Output registers */
	volatile u8		*oclrintradr; /* adr to R_DMA_CHx_CLR_INTR */
	volatile u32		*ofirstadr;   /* adr to R_DMA_CHx_FIRST */
	volatile u8		*ocmdadr;     /* adr to R_DMA_CHx_CMD */
	const volatile u8	*ostatusadr;  /* adr to R_DMA_CHx_STATUS */
	volatile u32		*ohwswadr;    /* adr to R_DMA_CHx_HWSW */
	volatile u32		*odescradr;   /* adr to R_DMA_CHx_DESCR */

	/* Input registers */
	volatile u8		*iclrintradr; /* adr to R_DMA_CHx_CLR_INTR */
	volatile u32		*ifirstadr;   /* adr to R_DMA_CHx_FIRST */
	volatile u8		*icmdadr;     /* adr to R_DMA_CHx_CMD */
	const volatile u8	*istatusadr;  /* adr to R_DMA_CHx_STATUS */
	volatile u32		*ihwswadr;    /* adr to R_DMA_CHx_HWSW */
	volatile u32		*idescradr;   /* adr to R_DMA_CHx_DESCR */

	int			flags;	/* defined in tty.h */

	u8			rx_ctrl; /* shadow for R_SERIALx_REC_CTRL */
	u8			tx_ctrl; /* shadow for R_SERIALx_TR_CTRL */
	u8			iseteop; /* bit number for R_SET_EOP for the input dma */

	int			enabled; /* Set to 1 if the port is enabled in HW config */
  
	/* end of fields defined in rs_table[] in .c-file */

	int			uses_dma; /* Set to 1 if DMA should be used */
	unsigned char           forced_eop; /* a fifo eop has been forced */

	struct etrax_dma_descr	tr_descr;
	struct etrax_dma_descr	rec_descr[SERIAL_RECV_DESCRIPTORS];
	int			cur_rec_descr;

	volatile int		tr_running; /* 1 if output is running */

	struct tty_struct	*tty;
	int			read_status_mask;
	int			ignore_status_mask;
	int			x_char;	/* xon/xoff character */
	int			close_delay;
	unsigned short		closing_wait;
	unsigned short		closing_wait2;
	unsigned long		event;
	unsigned long		last_active;
	int			line;
	int			type;  /* PORT_ETRAX */
	int			count;	    /* # of fd on device */
	int			blocked_open; /* # of blocked opens */
	long			session; /* Session of opening process */
	long			pgrp; /* pgrp of opening process */
	struct circ_buf		xmit;
	struct etrax_recv_buffer *first_recv_buffer;
	struct etrax_recv_buffer *last_recv_buffer;
	unsigned int		recv_cnt;
	unsigned int		max_recv_cnt;

	struct tq_struct	tqueue;
	struct async_icount	icount;   /* error-statistics etc.*/
	struct termios		normal_termios;
	struct termios		callout_termios;
#ifdef DECLARE_WAITQUEUE
	wait_queue_head_t	open_wait;
	wait_queue_head_t	close_wait;
#else
	struct wait_queue	*open_wait;
	struct wait_queue	*close_wait;
#endif  

	unsigned long		char_time_usec;       /* The time for 1 char, in usecs */
	unsigned long		last_tx_active_usec;  /* Last tx usec in the jiffies */
	unsigned long		last_tx_active;       /* Last tx time in jiffies */
	unsigned long		last_rx_active_usec;  /* Last rx usec in the jiffies */
	unsigned long		last_rx_active;       /* Last rx time in jiffies */

	int			break_detected_cnt;
	int			errorcode;

#ifdef CONFIG_RS485
	struct rs485_control	rs485;  /* RS-485 support */
#endif
};

/* this PORT is not in the standard serial.h. it's not actually used for
 * anything since we only have one type of async serial-port anyway in this
 * system.
 */

#define PORT_ETRAX 1

/*
 * Events are used to schedule things to happen at timer-interrupt
 * time, instead of at rs interrupt time.
 */
#define RS_EVENT_WRITE_WAKEUP	0

#endif /* __KERNEL__ */

#endif /* !_ETRAX_SERIAL_H */
