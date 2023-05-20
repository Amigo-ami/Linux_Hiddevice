/*
 * f_hid.c -- USB HID function driver
 *
 * Copyright (C) 2010 Fabien Chouteau <fabien.chouteau@barco.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hid.h>
#include <linux/idr.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/usb/g_hid.h>

#include "u_f.h"
#include "u_hid.h"

#define HIDG_MINORS	4

static DEFINE_IDA(hidg_ida);
static DEFINE_MUTEX(hidg_ida_lock); /* protects access to hidg_ida */


/*-------------------------------------------------------------------------*/
/*                           Static descriptors                            */

/*--------------------        接口描述符                     -------------*/
static struct usb_interface_descriptor hidg_interface_desc = {
	.bLength		= sizeof(hidg_interface_desc),
	.bDescriptorType	= USB_DT_INTERFACE,
	.bInterfaceNumber	= 0x03,
	.bAlternateSetting	= 0,
	.bNumEndpoints		= 2,
	.bInterfaceClass	= USB_CLASS_HID,
	.bInterfaceSubClass	= 0x00,
	.bInterfaceProtocol	= 0x00,
	.iInterface		=       0x00,
};

/*             hid 描述符                */
static struct hid_descriptor hidg_desc = {
	.bLength			= sizeof(hidg_desc),
	.bDescriptorType = HID_DT_HID,
	.bcdHID				= 0x0111,
	.bCountryCode			= 0x00,
	.bNumDescriptors		= 0x01,
	.desc[0].bDescriptorType	= 0x22, 
	.desc[0].wDescriptorLength	= 0x0035,
};

/* Super-Speed Support */

static struct usb_endpoint_descriptor hidg_ss_in_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize	= 0x0040,
	.bInterval		= 0x04, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
  };

static struct usb_ss_ep_comp_descriptor hidg_ss_in_comp_desc = {
	.bLength                = sizeof(hidg_ss_in_comp_desc),
	.bDescriptorType        = USB_DT_SS_ENDPOINT_COMP,
  .wBytesPerInterval      = 0x0004 
	/* .bMaxBurst           = 0, */
	/* .bmAttributes        = 0, */
	/* .wBytesPerInterval   = DYNAMIC */
};

static struct usb_endpoint_descriptor hidg_ss_out_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize	= 0x0040,
	.bInterval		= 0x04, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_ss_ep_comp_descriptor hidg_ss_out_comp_desc = {
	.bLength                = sizeof(hidg_ss_out_comp_desc),
	.bDescriptorType        = USB_DT_SS_ENDPOINT_COMP,
  .wBytesPerInterval      = 0x0004
	/* .bMaxBurst           = 0, */
	/* .bmAttributes        = 0, */
	/* .wBytesPerInterval   = DYNAMIC */
};

static struct usb_descriptor_header *hidg_ss_descriptors[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_ss_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_ss_in_comp_desc,
	(struct usb_descriptor_header *)&hidg_ss_out_ep_desc,
	(struct usb_descriptor_header *)&hidg_ss_out_comp_desc,
	NULL,
};

/* High-Speed Support */

static struct usb_endpoint_descriptor hidg_hs_in_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize	= 0x0040,
	.bInterval		= 4, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_endpoint_descriptor hidg_hs_out_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize	= 0x0040,
	.bInterval		= 4, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_descriptor_header *hidg_hs_descriptors[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_hs_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_hs_out_ep_desc,
	NULL,
};


/* Full-Speed Support */
static struct usb_endpoint_descriptor hidg_fs_in_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize	= 0x0040,
	.bInterval		= 10, /* FIXME: Add this field in the
				       * HID gadget configuration?
				       * (struct hidg_func_descriptor)
				       */
};

static struct usb_endpoint_descriptor hidg_fs_out_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize	= 0x0040,
	.bInterval		= 10, /* FIXME: Add this field in the
				       * HID gadget configuration?
				       * (struct hidg_func_descriptor)
				       */
};

static struct usb_descriptor_header *hidg_fs_descriptors[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_fs_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_fs_out_ep_desc,
	NULL,
};

/*-------------------------------------------------------------------------*/
/*                            Report                                       */
/*
const unsigned char ReportDescriptor[49] = 
{
	0x05 , 0x0C , // 1
	0x09 , 0x01 , // 2
	0xA1 , 0x01 , // 3
	0x85 , 0x01 , // 4 
	0x15 , 0x00 , // 5
	0x25 , 0x01 , // 6
	0x75 , 0x01 , // 7
	0x95 , 0x01 , // 8
	0x09 , 0xE9 , // 9
	0x81 , 0x02 , // 10
	0x09 , 0xEA , // 11
	0x81 , 0x02 , // 12
	0x95 , 0x08 , // 13
	0x81 , 0x01 , // 14 
	0x95 , 0x01 ,
	0x05 , 0x0B , // 15
	0x09 , 0x24 , // 16
	0x81 , 0x02 , // 17
	0x09 , 0x20 , // 18
	0x81 , 0x02 , // 19
	0x09 , 0x2F , // 20
	0x81 , 0x06 , // 21
	0x95 , 0x05 , // 22
	0x81 , 0x01 , // 23
	0xC0		
}; **/

/*-------------------------------------------------------------------------*/
/*                                 Strings                                 */

#define CT_FUNC_HID_IDX	0

static struct usb_string ct_func_string_defs[] = {
	[CT_FUNC_HID_IDX].s	= "HID Interface",
	{},			/* end of list */
};

static struct usb_gadget_strings ct_func_string_table = {
	.language	= 0x0409,	/* en-US */
	.strings	= ct_func_string_defs,
};

static struct usb_gadget_strings *ct_func_strings[] = {
	&ct_func_string_table,
	NULL,
};


static inline int hidg_get_minor(void)
{
	int ret;

	ret = ida_simple_get(&hidg_ida, 0, 0, GFP_KERNEL);
	if (ret >= HIDG_MINORS) {
		ida_simple_remove(&hidg_ida, ret);
		ret = -ENODEV;
	}

	return ret;
}

static inline void hidg_put_minor(int minor)
{
	ida_simple_remove(&hidg_ida, minor);
}


/*-------------------------------------------------------------------------*/
/*                              Char Device                                */


/*-------------------------------------------------------------------------*/
/*                                usb_function                             */

static void hidg_set_report_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_hidg *hidg = (struct f_hidg *) req->context;
	struct f_hidg_req_list *req_list;
	unsigned long flags;

	req_list = kzalloc(sizeof(*req_list), GFP_ATOMIC);
	if (!req_list)
		return;

	req_list->req = req;

	spin_lock_irqsave(&hidg->spinlock, flags);
	list_add_tail(&req_list->list, &hidg->completed_out_req);
	spin_unlock_irqrestore(&hidg->spinlock, flags);
	
	wake_up(&hidg->read_queue);
}

/* 将描述符发送给主机，主机根据描述符建立相应设备 */
static int hidg_setup(struct usb_function *fn,
		const struct usb_ctrlrequest *ctrl)
{
	struct f_hidg			*hidg = func_to_hidg(fn);
	struct usb_configuration *cfg = fn->config;
	//struct usb_composite_dev	*cdev = fn->config->cdev;
	struct usb_composite_dev *cdev = cfg->cdev ;
	struct usb_gadget *gadget = cdev->gadget;
	struct usb_request		*req  = cdev->req;
	int status = 0;
	__u16 value, length;

	value	= __le16_to_cpu(ctrl->wValue);
	length	= __le16_to_cpu(ctrl->wLength);

	VDBG(cdev,
	     "%s crtl_request : bRequestType:0x%x bRequest:0x%x Value:0x%x\n",
	     __func__, ctrl->bRequestType, ctrl->bRequest, value);

	switch ((ctrl->bRequestType << 8) | ctrl->bRequest) 
	  {
	    case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		         | HID_REQ_GET_REPORT):
		    {    	
		      VDBG(cdev, "get_report\n");

		       /* send an empty report */
		       length = min_t(unsigned, length, hidg->report_length);
		       memset(req->buf, 0x0, length);

		        goto respond;
	      } break;

	    case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		         | HID_REQ_GET_PROTOCOL):
		    {     	
		         VDBG(cdev, "get_protocol\n");
	           goto stall;
	           
	      } break;

	    case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		         | HID_REQ_SET_REPORT):
		    {
		        VDBG(cdev, "set_report | wLength=%d\n", ctrl->wLength);
		        goto stall;
		        
	      } break;

	    case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		         | HID_REQ_SET_PROTOCOL):
		    {
		    	
		      VDBG(cdev, "set_protocol\n");
		      goto stall;
		      
	      } break;

	    case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8
		         | USB_REQ_GET_DESCRIPTOR):
		    { 
		    	 switch (value >> 8) 
		    	   {
		            case HID_DT_HID:  //上报HID描述符 
		              {
			               struct hid_descriptor hidg_desc_copy = hidg_desc;

			               VDBG(cdev, "USB_REQ_GET_DESCRIPTOR: HID\n");
			               hidg_desc_copy.desc[0].bDescriptorType = HID_DT_REPORT;
			               hidg_desc_copy.desc[0].wDescriptorLength =
				             cpu_to_le16(hidg->report_desc_length);
				             
			               length = min_t(unsigned short, length,
						                        hidg_desc_copy.bLength);
			               memcpy(req->buf, &hidg_desc_copy, length);
			               goto respond;
			            } break;
			            
		            case HID_DT_REPORT:
		            	{
			               VDBG(cdev, "USB_REQ_GET_DESCRIPTOR: REPORT\n");
			               length = min_t(unsigned short, length, hidg->report_desc_length);
			               memcpy(req->buf, hidg->report_desc, length);

				       /*

					  if (usb_ep_queue(hidg->in_ep, hidg->req, GFP_ATOMIC) < 0) {
                        		  printk("****** usb_ep_queue error on ep out ************** \n");
                       			  return -1;
                     			}

                                        */
  			               
			               goto respond;
			            } break;

		            default:
		            	{
		           	     VDBG(cdev, "Unknown descriptor request 0x%x\n",
				             value >> 8);
			               goto stall;
			            } break;
	         	 }
		    } break;

	    default:
	    	{
		       VDBG(cdev, "Unknown request 0x%x\n",
			     ctrl->bRequest);
		       goto stall;
		    } break;
	  }

stall:
	return -EOPNOTSUPP;

respond:
	req->zero = 0;
	req->length = length;
	status = usb_ep_queue(gadget->ep0, req, GFP_ATOMIC);
	if (status < 0)
		ERROR(cdev, "usb_ep_queue error on ep0 %d\n", value);
	return status;
		
}


static void hidg_disable(struct usb_function *f)
{
	struct f_hidg *hidg = func_to_hidg(f);
	struct f_hidg_req_list *list, *next;
	unsigned long flags;
   
  kfree(hidg->req->buf) ;
  usb_ep_dequeue(hidg->in_ep, hidg->req);
  usb_ep_free_request(hidg->in_ep, hidg->req);
	if( usb_ep_disable(hidg->in_ep) != 0 )
		{
			 ERROR(hidg->func.config->cdev, "%s:%d Error!\n",  __func__, __LINE__ );
		}
	
	kfree(hidg->out_req->buf);			
  usb_ep_dequeue(hidg->out_ep, hidg->out_req);
  usb_ep_free_request(hidg->out_ep, hidg->out_req);
	if( usb_ep_disable(hidg->out_ep) != 0 )
		{
			 ERROR(hidg->func.config->cdev, "%s:%d Error!\n",  __func__, __LINE__ );
		}	
		
	spin_lock_irqsave(&hidg->spinlock, flags);
	list_for_each_entry_safe(list, next, &hidg->completed_out_req, list) {
		free_ep_req(hidg->out_ep, list->req);
		list_del(&list->list);
		kfree(list);
	}
	spin_unlock_irqrestore(&hidg->spinlock, flags);
}

/* 该函数在设备层的setup函数中被调用,控制通信设置接口*/
static int hidg_set_alt(struct usb_function *fn, unsigned intf, unsigned alt)
{
	struct f_hidg *hidg = func_to_hidg(fn);
	struct usb_configuration *cfg = fn->config;
	//struct usb_composite_dev		*cdev = fn->config->cdev;	
	struct usb_composite_dev *cdev = cfg->cdev;
	struct usb_gadget *gadget = cdev->gadget ;	
	int i, status = 0;
	
	VDBG(cdev, "hidg_set_alt intf:%d alt:%d\n", intf, alt);
	
	if (hidg->in_ep != NULL) {
		
		/* restart endpoint */
	  usb_ep_disable(hidg->in_ep);	  
		status = config_ep_by_speed(gadget, fn, hidg->in_ep);
		if (status) {
			ERROR(cdev, "config_ep_by_speed FAILED!\n");
			goto fail;
		}
			
		status = usb_ep_enable(hidg->in_ep);
		if (status < 0) {
			ERROR(cdev, "Enable IN endpoint FAILED!\n");
			goto fail;

		}		
															
		hidg->in_ep->driver_data = hidg;
		
		hidg->req = usb_ep_alloc_request(hidg->in_ep, GFP_KERNEL); // 注册/分配端口请求
		if (!hidg->req)
					goto fail;
						
		hidg->req->buf = kmalloc(hidg->report_length, GFP_KERNEL); // 为报告请求分配缓冲池
		if (!hidg->req->buf)
				goto fail;		
						
    printk("*************** hidg->in_ep enable success ******************* \n");
    
	}
			
	if (hidg->out_ep != NULL) {
		
		/* restart endpoint */
		usb_ep_disable(hidg->out_ep);

		status = config_ep_by_speed(gadget, fn,
					    hidg->out_ep);
		if (status) {
			ERROR(cdev, "config_ep_by_speed FAILED!\n");
			goto fail;
		}
		status = usb_ep_enable(hidg->out_ep);
		if (status < 0) {
			ERROR(cdev, "Enable OUT endpoint FAILED!\n");
			goto fail;
		}
		hidg->out_ep->driver_data = hidg;

		/*
		 * allocate a bunch of read buffers and queue them all at once.
		 */
		 
		for (i = 0; i < hidg->qlen && status == 0; i++)
		 {
			 struct usb_request *req = hidg_alloc_ep_req(hidg->out_ep, hidg->report_length);
			 if (req) {
			 	
			 	hidg->out_req = req;
			 	
			 	req->zero = 0;
				req->complete = hidg_set_report_complete;
				req->context  = hidg;
				
				status = usb_ep_queue(hidg->out_ep, req, GFP_ATOMIC);
				if (status)
					ERROR(cdev, "%s queue req --> %d\n", hidg->out_ep->name, status);
			 } 
		   else {
			    usb_ep_disable(hidg->out_ep);
			    status = -ENOMEM;
			    goto fail;
			 }
		 } 
		 	 
	}

fail:
	return status;
}


static int hidg_bind(struct usb_configuration *cfg, struct usb_function *fn)
{
	struct usb_ep		*ep;
	struct f_hidg		*hidg = func_to_hidg(fn);
	struct usb_composite_dev *cdev = cfg->cdev ;
	struct usb_gadget *gadget = cdev->gadget;
	struct usb_string	*us;
	int status;
	
	/* maybe allocate device-global string IDs, and patch descriptors */
	us = usb_gstrings_attach(cdev, ct_func_strings,
				 ARRAY_SIZE(ct_func_string_defs));
	if (IS_ERR(us))
		return PTR_ERR(us);
		
	hidg_interface_desc.iInterface = us[CT_FUNC_HID_IDX].id; // 获取接口号描述索引值

	/* allocate instance-specific interface IDs, and patch descriptors */
	status = usb_interface_id(cfg, fn); // 获取接口号
	if (status < 0)
		goto fail;
		
	hidg_interface_desc.bInterfaceNumber = status; //分配接口号

	/* allocate instance-specific endpoints */
	status = -ENODEV;
	ep = usb_ep_autoconfig(gadget, &hidg_fs_in_ep_desc);  // 向gadget配置输出端口和端口描述符描述符
	if (!ep)
		goto fail;
	hidg->in_ep = ep;

	ep = usb_ep_autoconfig(gadget, &hidg_fs_out_ep_desc); // 向gadget配置输出端口和端口描述符描述符
	if (!ep)
		goto fail;
	hidg->out_ep = ep;                                    // 

	/* preallocate request and buffer */
	status = -ENOMEM;
	
	/*
	
	hidg->req = usb_ep_alloc_request(hidg->in_ep, GFP_KERNEL); // 注册/分配端口请求
	if (!hidg->req)
		goto fail;
		
	hidg->req->buf = kmalloc(hidg->report_length, GFP_KERNEL); // 为报告请求分配缓冲池
	if (!hidg->req->buf)
		goto fail;
			
	*/
  printk("*************** hid_bind test ******************* \n");
		
	/* set descriptor dynamic values */
	//hidg_interface_desc.bInterfaceSubClass = hidg->bInterfaceSubClass;
	//hidg_interface_desc.bInterfaceProtocol = hidg->bInterfaceProtocol;
	//hidg_ss_in_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	//hidg_ss_in_comp_desc.wBytesPerInterval = cpu_to_le16(hidg->report_length);
	//hidg_hs_in_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	//hidg_fs_in_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	
	//hidg_ss_out_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	//hidg_ss_out_comp_desc.wBytesPerInterval = cpu_to_le16(hidg->report_length);
	//hidg_hs_out_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	//hidg_fs_out_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	/*
	 * We can use hidg_desc struct here but we should not relay
	 * that its content won't change after returning from this function.
	 */
	 
	hidg_desc.desc[0].bDescriptorType = HID_DT_REPORT;
	hidg_desc.desc[0].wDescriptorLength = cpu_to_le16(hidg->report_desc_length);

	hidg_hs_in_ep_desc.bEndpointAddress =
		hidg_fs_in_ep_desc.bEndpointAddress;
	hidg_hs_out_ep_desc.bEndpointAddress =
		hidg_fs_out_ep_desc.bEndpointAddress;

	hidg_ss_in_ep_desc.bEndpointAddress =
		hidg_fs_in_ep_desc.bEndpointAddress;
	hidg_ss_out_ep_desc.bEndpointAddress =
		hidg_fs_out_ep_desc.bEndpointAddress;

	status = usb_assign_descriptors(fn, hidg_fs_descriptors,
			hidg_hs_descriptors, hidg_ss_descriptors);  // 注册描述符
	if (status)
		goto fail;
		
	mutex_init(&hidg->lock);
	spin_lock_init(&hidg->spinlock);
	init_waitqueue_head(&hidg->write_queue);
	init_waitqueue_head(&hidg->read_queue);
	INIT_LIST_HEAD(&hidg->completed_out_req);
	
	/* create char device */
  /*
	cdev_init(&hidg->cdev, &f_hidg_fops);
	dev = MKDEV(major, hidg->minor);
	status = cdev_add(&hidg->cdev, dev, 1);
	if (status)
		goto fail_free_descs;

	device = device_create(hidg_class, NULL, dev, NULL,
			       "%s%d", "hidg", hidg->minor);
	if (IS_ERR(device)) {
		status = PTR_ERR(device);
		goto del;
	} */
		
	status = ghid_device_create(hidg); //创建设备
	if(status > 0)
		goto fail_free_descs ;
	else if( status < 0 )
		goto del;
		
	return 0;
	
del:
	cdev_del(&hidg->cdev);
fail_free_descs:
	usb_free_all_descriptors(fn);
fail:
	ERROR(fn->config->cdev, "hidg_bind FAILED\n");
	if (hidg->req != NULL) {
		kfree(hidg->req->buf);
		if (hidg->in_ep != NULL)
			usb_ep_free_request(hidg->in_ep, hidg->req);
	}
	return status;
	
}

static void hid_attr_release(struct config_item *item)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);

	usb_put_function_instance(&opts->func_inst);
}

static struct configfs_item_operations hidg_item_ops = {
	.release	= hid_attr_release,
};

#define F_HID_OPT(name, prec, limit)					\
static ssize_t f_hid_opts_##name##_show(struct config_item *item, char *page)\
{									\
	struct f_hid_opts *opts = to_f_hid_opts(item);			\
	int result;							\
									\
	mutex_lock(&opts->lock);					\
	result = sprintf(page, "%d\n", opts->name);			\
	mutex_unlock(&opts->lock);					\
									\
	return result;							\
}									\
									\
static ssize_t f_hid_opts_##name##_store(struct config_item *item,	\
					 const char *page, size_t len)	\
{									\
	struct f_hid_opts *opts = to_f_hid_opts(item);			\
	int ret;							\
	u##prec num;							\
									\
	mutex_lock(&opts->lock);					\
	if (opts->refcnt) {						\
		ret = -EBUSY;						\
		goto end;						\
	}								\
									\
	ret = kstrtou##prec(page, 0, &num);				\
	if (ret)							\
		goto end;						\
									\
	if (num > limit) {						\
		ret = -EINVAL;						\
		goto end;						\
	}								\
	opts->name = num;						\
	ret = len;							\
									\
end:									\
	mutex_unlock(&opts->lock);					\
	return ret;							\
}									\
									\
CONFIGFS_ATTR(f_hid_opts_, name)

F_HID_OPT(subclass, 8, 255);
F_HID_OPT(protocol, 8, 255);
F_HID_OPT(report_length, 16, 65535);

static ssize_t f_hid_opts_report_desc_show(struct config_item *item, char *page)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);
	int result;

	mutex_lock(&opts->lock);
	result = opts->report_desc_length;
	memcpy(page, opts->report_desc, opts->report_desc_length);
	mutex_unlock(&opts->lock);

	return result;
}

static ssize_t f_hid_opts_report_desc_store(struct config_item *item,
					    const char *page, size_t len)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);
	int ret = -EBUSY;
	char *d;

	mutex_lock(&opts->lock);

	if (opts->refcnt)
		goto end;
		
	if (len > PAGE_SIZE) {
		ret = -ENOSPC;
		goto end;
	}
	
	d = kmemdup(page, len, GFP_KERNEL);
	if (!d) {
		ret = -ENOMEM;
		goto end;
	}
	kfree(opts->report_desc);
	opts->report_desc = d;
	opts->report_desc_length = len;
	opts->report_desc_alloc = true;
	ret = len;
end:
	mutex_unlock(&opts->lock);
	return ret;
}

CONFIGFS_ATTR(f_hid_opts_, report_desc);

static struct configfs_attribute *hid_attrs[] = {
	&f_hid_opts_attr_subclass,
	&f_hid_opts_attr_protocol,
	&f_hid_opts_attr_report_length,
	&f_hid_opts_attr_report_desc,
	NULL,
};

static const struct config_item_type hid_func_type = {
	.ct_item_ops	= &hidg_item_ops,
	.ct_attrs	= hid_attrs,
	.ct_owner	= THIS_MODULE,
};


static void hidg_free_inst(struct usb_function_instance *f)
{
	struct f_hid_opts *opts;

	opts = container_of(f, struct f_hid_opts, func_inst);

	mutex_lock(&hidg_ida_lock);

	hidg_put_minor(opts->minor);
	if (idr_is_empty(&hidg_ida.idr))
		ghid_cleanup();

	mutex_unlock(&hidg_ida_lock);

	if (opts->report_desc_alloc)
		kfree(opts->report_desc);

	kfree(opts);
}

static struct usb_function_instance *hidg_alloc_inst(void)
{
	struct f_hid_opts *opts;
	struct usb_function_instance *ret;
	int status = 0;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);
	mutex_init(&opts->lock);
	opts->func_inst.free_func_inst = hidg_free_inst;
	ret = &opts->func_inst;

	mutex_lock(&hidg_ida_lock);

	if (idr_is_empty(&hidg_ida.idr)) {
		status = ghid_setup(NULL, HIDG_MINORS);
		if (status)  {
			ret = ERR_PTR(status);
			kfree(opts);
			goto unlock;
		}
	}

	opts->minor = hidg_get_minor();
	if (opts->minor < 0) {
		ret = ERR_PTR(opts->minor);
		kfree(opts);
		if (idr_is_empty(&hidg_ida.idr))
			ghid_cleanup();
		goto unlock;
	}	
		
	status = insert_report_descriptor(opts);
		
  config_group_init_type_name(&opts->func_inst.group, "", &hid_func_type);
  	
unlock:
	mutex_unlock(&hidg_ida_lock);
	return ret;
}

static void hidg_free(struct usb_function *f)
{
	struct f_hidg *hidg;
	struct f_hid_opts *opts;

	hidg = func_to_hidg(f);
	opts = container_of(f->fi, struct f_hid_opts, func_inst);
	kfree(hidg->report_desc);
	kfree(hidg);
	mutex_lock(&opts->lock);
	--opts->refcnt;
	mutex_unlock(&opts->lock);
}

static void hidg_unbind(struct usb_configuration *cfg, struct usb_function *fn)
{
	struct f_hidg *hidg = func_to_hidg(fn);
  
  /*
	device_destroy(hidg_class, MKDEV(major, hidg->minor));
	cdev_del(&hidg->cdev); 
	*/
	
  ghid_device_remove(hidg);
  
	/* disable/free request and end point */
	
	usb_ep_disable(hidg->in_ep);
	kfree(hidg->req->buf);
	usb_ep_dequeue(hidg->in_ep, hidg->req);
	usb_ep_free_request(hidg->in_ep, hidg->req);
	
	usb_ep_disable(hidg->out_ep);
	kfree(hidg->out_req->buf);
	usb_ep_dequeue(hidg->out_ep, hidg->out_req);
	usb_ep_free_request(hidg->in_ep, hidg->req);
	
	usb_free_all_descriptors(fn);
	
  printk("*************** hid_bind test ******************* \n");
	 
}

static struct usb_function *hidg_alloc(struct usb_function_instance *fi)
{
	struct f_hidg *hidg;
	struct f_hid_opts *opts;

	/* allocate and initialize one new instance */
	hidg = kzalloc(sizeof(*hidg), GFP_KERNEL);
	if (!hidg)
		return ERR_PTR(-ENOMEM);

	opts = container_of(fi, struct f_hid_opts, func_inst);

	mutex_lock(&opts->lock);
	++opts->refcnt;

	hidg->minor = opts->minor;
	hidg->bInterfaceSubClass = opts->subclass;
	hidg->bInterfaceProtocol = opts->protocol;
	hidg->report_length = opts->report_length;
	hidg->report_desc_length = opts->report_desc_length;
	if (opts->report_desc) {
		hidg->report_desc = kmemdup(opts->report_desc,
					    opts->report_desc_length,
					    GFP_KERNEL);
		if (!hidg->report_desc) {
			kfree(hidg);
			mutex_unlock(&opts->lock);
			return ERR_PTR(-ENOMEM);
		}
	}

	mutex_unlock(&opts->lock);

	hidg->func.name    = "hid";
	hidg->func.bind    = hidg_bind;
	hidg->func.unbind  = hidg_unbind;
	hidg->func.set_alt = hidg_set_alt;
	hidg->func.disable = hidg_disable;
	hidg->func.setup   = hidg_setup;
	hidg->func.free_func = hidg_free;

	/* this could me made configurable at some point */
	hidg->qlen	   = 4;

	return &hidg->func;
	
}

DECLARE_USB_FUNCTION_INIT(hid, hidg_alloc_inst, hidg_alloc); // 静态注册USB设备
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabien Chouteau");


