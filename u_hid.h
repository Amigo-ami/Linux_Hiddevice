/*
 * u_hid.h
 *
 * Utility definitions for the hid function
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Author: Andrzej Pietrasiewicz <andrzej.p@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __U_HID_H__
#define __U_HID_H__

#include <linux/usb/composite.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define HID_PACKGAE 0x03

struct f_hid_opts {
	struct usb_function_instance func_inst ;
	int minor ;
	unsigned char subclass ;
	unsigned char protocol ;
	unsigned short report_length ;  
	unsigned short report_desc_length ;
  unsigned char *report_desc;
  bool report_desc_alloc;
  /* 
    Protect the data form coneurrent access by read/write 
    and creat systermlink/remove systermlink .
    
  */
  struct mutex lock ;
  int refcnt ;
};

struct f_hidg_req_list {
	struct usb_request	*req;
	unsigned int		pos;
	struct list_head 	list;
};



struct f_hidg {
	
	/* configuration */
	unsigned char			bInterfaceSubClass;  
	unsigned char			bInterfaceProtocol; // 
	unsigned short		report_desc_length; // 报告描述符长度
	char				      *report_desc;       // 报告描述符
	unsigned short	  report_length;      // 报告长度 / 即每次请求数据包的大小

	/* recv report */
	struct list_head		 completed_out_req; // 链表头
	spinlock_t			     spinlock;          // 自旋锁
	wait_queue_head_t		 read_queue;        // 读队列
	unsigned int			   qlen;              // 队列数量        

	/* send report */
	struct mutex			    lock;             // 互斥锁
	bool				          write_pending;    // bool 
	wait_queue_head_t		  write_queue;      // 写队列
	struct usb_request		*req; // I/O 请求，在gadget驱动中描述一次传输请求，类似于主机端的URB
	struct usb_reques     *out_req;

	int				            minor;            // 设备号
	struct cdev			      cdev;             // 字符设备
	struct usb_function		func;             // usb_function // 向usb_core 注册功能函数   

	struct usb_ep			   *in_ep;            // in endpiont 
	struct usb_ep			   *out_ep;           // out endpoint 
};

static inline struct f_hidg *func_to_hidg(struct usb_function *f)
{
	 return container_of(f, struct f_hidg, func );  //
}

static inline struct usb_request *hidg_alloc_ep_req(struct usb_ep *ep,
						    unsigned length)
{
	return alloc_ep_req(ep, length, length);
}

static inline struct f_hid_opts *to_f_hid_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_hid_opts, func_inst.group);
}

int ghid_setup(struct usb_gadget *g, int count);
void ghid_cleanup(void);
int ghid_device_create(struct f_hidg *ghid);
void ghid_device_remove(struct f_hidg *ghid);
ssize_t insert_report_descriptor(struct f_hid_opts *opts);

#endif /* U_HID_H */
