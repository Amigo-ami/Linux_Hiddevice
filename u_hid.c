#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hid.h>
#include <linux/device.h>
//#include <linux/idr.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/usb/g_hid.h>

#include "u_f.h"
#include "u_hid.h"

int major, minors;
struct class *hidg_class;

/*
unsigned char ReportDescriptor[63] = {
		0x05, 0x0C,        //   Usage Page (Consumer)
		0x09, 0x01,        //   Usage (Consumer Control)
		0xA1, 0x01,        //   Collection (Application)
		0x85, 0x01,        //   Report ID (1)
		0x15, 0x00,        //   Logical Minimum (0)
		0x25, 0x01,        //   Logical Maximum (1)
		0x75, 0x08,        //   Report Size (8)   // 字段位宽，一次report多少个位表示一个操作/数据
		0x95, 0x01,        //   Report Count (1)  // 字段数，表示一次report 有多少个这样的域
		0x09, 0xE9,        //   Usage (Volume Increment)
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0x09, 0xEA,        //   Usage (Volume Decrement)
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0x09, 0xCD,        //   Usage (Volume Play/Pause)
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0x09, 0xB5,        //   Usage (Scan Next Track)
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position) 
		0x09, 0xB6,        //   LOCAL_USAGE(Scan Previous Track) 
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position) 
		0x09, 0xB7,        //   LOCAL_USAGE(Stop)    
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)  
		0x09, 0xE2,        //   LOCAL_USAGE(Mute) 
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0x05, 0x0B,        //   Usage Page (Telephony)
		0x09, 0x24,        //   Usage (Redial)
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0x09, 0x20,        //   Usage (Hook Switch)
		0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0x09, 0x2F,        //   Usage (Phone Mute)
		0x81, 0x02,        //   Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
		0x95, 0x05,        //   Report Count (1)
		0x81, 0x01,        //   Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
		0xC0               // End Collection
}; 
*/

unsigned char ReportDescriptor[53] = {
    0x05, 0x0C,    //0       GLOBAL_USAGE_PAGE(Consumer)    
    0x09, 0x01,    //2       LOCAL_USAGE(Consumer Control)    
    0xA1, 0x01,    //4       MAIN_COLLECTION(Applicatior)
    0x85, 0x01,    //6       GLOBAL_REPORT_ID(1)     
    0x15, 0x00,    //6       GLOBAL_LOGICAL_MINIMUM(0)    
    0x25, 0x01,    //8       GLOBAL_LOCAL_MAXIMUM(1)    
    0x09, 0xE9,    //10      LOCAL_USAGE(Volume Increment)    
    0x09, 0xEA,    //12      LOCAL_USAGE(Volume Decrement)      
    0x09, 0xCD,    //16      LOCAL_USAGE(Play/Pause)    
    0x09, 0xB5,    //18      LOCAL_USAGE(Scan Next Track)    
    0x09, 0xB6,    //20      LOCAL_USAGE(Scan Previous Track) 
    0x09, 0xB7,    //24      LOCAL_USAGE(Stop)     
    0x09, 0xE2,    //14      LOCAL_USAGE(Mute)       
    0x09, 0xB3,    //22      LOCAL_USAGE(Fast Forward)      
    0x09, 0xCA,    //26      LOCAL_USAGE(Tracking Increment)    
    0x09, 0xCB,    //28      LOCAL_USAGE(Tracking Decrement)    
    0x09, 0xCC,    //30      LOCAL_USAGE(Stop/Eject)    
    0x09, 0xE0,    //32      LOCAL_USAGE(Volume)    
    0x0A, 0x50, 0x01, //34   LOCAL_USAGE(Balance Right)    
    0x0A, 0x51, 0x01, //37   LOCAL_USAGE(Balance Left)    
    0x09, 0xB0,    //40      LOCAL_USAGE(Play)    
    0x09, 0xB1,    //42      LOCAL_USAGE(Pause)    
    0x75, 0x01,    //44      GLOBAL_REPORT_SIZE(1)    
    0x95, 0x10,    //46      GLOBAL_REPORT_COUNT(16)    
    0x81, 0x42,    //48      MAIN_INPUT(data var absolute NoWrap linear PreferredState NullState NonVolatile )    Input 2.0
    0xC0  
}; 

/*
unsigned char ReportDescriptor[67] = {
	
0x05,0x0C,   //0  GLOBAL_USAGE_PAGE(Consumer)    
0x09,0x01,   //2  LOCAL_USAGE(    Consumer Control     )    
0xA1,0x01,   //4  MAIN_COLLECTION(Applicatior)    
0x85,0x01,   //6  GLOBAL_REPORT_ID(1)   
0x15,0x00,   //8  GLOBAL_LOGICAL_MINIMUM(0) 
0x25,0x01,   //10 GLOBAL_LOCAL_MAXIMUM(1)    
0x75,0x01,   //12 GLOBAL_REPORT_SIZE(1)    
0x95,0x01,   //14 GLOBAL_REPORT_COUNT(1)    
0x09,0xE9,   //16 LOCAL_USAGE(    Volume Increment     )    
0x81,0x02,   //18 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.1
0x09,0xEA,   //20 LOCAL_USAGE(    Volume Decrement     )    
0x81,0x02,   //22 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.2
0x09,0xCD,   //24 LOCAL_USAGE(    Play/Pause     )    
0x81,0x02,   //26 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.3
0x09,0xB5,   //28 LOCAL_USAGE(    Scan Next Track     )    
0x81,0x02,   //30 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.4
0x09,0xB6,   //32 LOCAL_USAGE(    Scan Previous Track     )    
0x81,0x02,   //34 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.5
0x09,0xB7,   //36 LOCAL_USAGE(    Stop     )    
0x81,0x02,   //38 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.6
0x09,0xB3,   //40 LOCAL_USAGE(    Fast Forward     )    
0x81,0x02,   //42 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 0.7
0x09,0xB4,   //44 LOCAL_USAGE(    Rewind     )    
0x81,0x02,   //46 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 1.0
0x05,0x0B,   //48 GLOBAL_USAGE_PAGE(Telephony)    
0x09,0x24,   //50 LOCAL_USAGE(    Redial     )    
0x81,0x02,   //52 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 1.1
0x09,0x20,   //54 LOCAL_USAGE(    Hook Switch     )    
0x81,0x02,   //56 MAIN_INPUT(data var absolute NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 1.2
0x09,0x2F,   //58 LOCAL_USAGE(    Phone Mute     )    
0x81,0x06,   //60 MAIN_INPUT(data var relative NoWrap linear PreferredState NoNullPosition NonVolatile )    Input 1.3
0x95,0x05,   //62 GLOBAL_REPORT_COUNT(5)    
0x81,0x01,   //64 MAIN_INPUT(const array absolute NoWrap linear PreferredState NoNullPosition NonVolatile ) Input 2.0
0xC0         //6

}; 

*/

static void ghid_req_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_hidg *ghid = (struct f_hidg *)ep->driver_data ;
	if(req->status != 0)
		{
			ERROR(ghid->func.config->cdev, "End Point Request ERROR: %d\n", req->status);
		}		
	ghid->write_pending = false ;
	
	wake_up(&ghid->write_queue);
		
}

static int ghid_open(struct inode *inode, struct file *fd)
{
	
	struct f_hidg *ghid = container_of(inode->i_cdev, struct f_hidg, cdev);
	fd->private_data = ghid ; // 将操作的数据指向设备驱动私有数据	
	return 0;
}

static int ghid_release(struct inode *inode, struct file *fd)
{
	
	fd->private_data = NULL ; // 释放私有数据
	
	return 0 ;
}

static ssize_t ghid_write(struct file *file, const char __user *buffer, size_t count, loff_t *offp )
{
	struct f_hidg *ghid = file->private_data ;
	ssize_t status = -ENOMEM ;
	
	if(!access_ok(VERIFY_READ, buffer, count))
		 return -EFAULT;
		 	 
	mutex_lock(&ghid->lock);
	
#define WRITE_COND (!ghid->write_pending)
  
  while(!WRITE_COND){
  	mutex_unlock(&ghid->lock);
  	if(file->f_flags & O_NONBLOCK)
  		 return -EAGAIN ;
  		 
  	if(wait_event_interruptible_exclusive(ghid->write_queue, WRITE_COND ))
  		return -ERESTARTSYS;
  			
    mutex_lock(&ghid->lock);  	
    
  }	
  
  count = min_t(unsigned int, count, ghid->report_length);
  status = copy_from_user(ghid->req->buf, buffer, count);
  
  if(status != 0 ){
  	
  	ERROR(ghid->func.config->cdev, "copy_from_user error\n");
  	mutex_unlock(&ghid->lock);
  	return -EINVAL ;
  	
  }
   	
	ghid->req->status = 0 ;
	ghid->req->zero = 0 ;
	ghid->req->length = count ;
	ghid->req->complete = ghid_req_complete ;
	ghid->req->context = ghid ;
	ghid->write_pending = true ;
		
	status = usb_ep_queue(ghid->in_ep, ghid->req, GFP_ATOMIC);
	if(status < 0){
		
		ERROR(ghid->func.config->cdev, "maybe usb_ep_queue error on int endpoint %zd\n",status);
		ghid->write_pending = false;
		wake_up(&ghid->write_queue);	
			
	}
  else 
	{
		status = count ;
	}
	
	mutex_unlock(&ghid->lock);
	
	return status ;
	
}

static ssize_t ghid_read(struct file *file, char __user *buffer, size_t count, loff_t *ptr)
{
	 struct f_hidg *ghid = file->private_data;
	 struct f_hidg_req_list *list ;
	 struct usb_request *req ;
	 unsigned long flags ;
 	 int ret ;
	
	 if(!count)
		  return 0 ;
		  
	 if(!access_ok(VERTFY_WRITE, buffer, count ))
	 	  return -EFAULT ;
	 	  
	 spin_lock_irqsave(&ghid->spinlock, flags);

#define READ_COND (!list_empty(&ghid->completed_out_req))

   while(!READ_COND)
   {
   	 spin_unlock_irqrestore(&ghid->spinlock, flags);
   	 if(file->f_flags && O_NONBLOCK)
   	 	return -EAGAIN;
   	 	
   	 if(wait_event_interruptible(ghid->read_queue, READ_COND))
   	 	 return -ERESTARTSYS ;
   	 	 
   	 spin_lock_irqsave(&ghid->spinlock, flags);
   }	 
   list = list_first_entry(&ghid->completed_out_req, struct f_hidg_req_list, list);
   
   list_del(&list->list);
   req = list->req;
   count = min_t(unsigned int, count, req->actual - list->pos);
   spin_unlock_irqrestore(&ghid->spinlock, flags);
   
   count -= copy_to_user(buffer, req->buf + list->pos, count);
   list->pos += count ;
   
   if(list->pos == req->actual){
   	
   	kfree(list);
   	
   	req->length = ghid->report_length ;
   	ret = usb_ep_queue(ghid->out_ep, req, GFP_KERNEL);
   	if(ret< 0) {
   		 free_ep_req(ghid->out_ep, req);
   		 
   		 return ret ;
   	}
   	
   }
   else
   {
   	spin_lock_irqsave(&ghid->spinlock, flags);
   	list_add(&list->list, &ghid->completed_out_req);
   	spin_unlock_irqrestore(&ghid->spinlock, flags);  		
   	wake_up(&ghid->read_queue); 		
   }
   
   return count;
       	
}

static unsigned int ghid_poll(struct file *file, poll_table *wait)
{
	struct f_hidg *ghid = file->private_data ;
	unsigned int ret = 0 ;
		
	poll_wait(file, &ghid->read_queue, wait);
	poll_wait(file, &ghid->write_queue, wait);
		
	if(WRITE_COND)
		ret |= POLLOUT | POLLWRNORM;
 
  if(READ_COND)
  	ret |= POLLIN | POLLRDNORM ;
  		
  return ret ;
}

#undef WRITE_COND 
#undef READ_COND


static const struct file_operations ghid_fops = {
		
	.owner = THIS_MODULE,
	.open = ghid_open,       // open 
	.release = ghid_release, // 释放函数
	.write = ghid_write,     // 写函数
	.read = ghid_read,       // 读函数
	.poll = ghid_poll,       // 阻塞函数
	.llseek = noop_llseek,	 // 指针偏移函数		
};

int ghid_setup(struct usb_gadget *g, int count)
{
	int status;
	dev_t dev;
	hidg_class = class_create(THIS_MODULE, "hidg");
	if (IS_ERR(hidg_class)) {
		status = PTR_ERR(hidg_class);
		hidg_class = NULL;
		return status;
	}

	status = alloc_chrdev_region(&dev, 0, count, "hidg");
	if (status) {
		class_destroy(hidg_class);
		hidg_class = NULL;
		return status;
	}
				
	major = MAJOR(dev);
	minors = count;
	return 0;	
}

EXPORT_SYMBOL_GPL(ghid_setup);

void ghid_cleanup(void)
{
	if(major) {
		unregister_chrdev_region(MKDEV(major, 0), minors);
		major = minors = 0;
	}
	class_destroy(hidg_class);
	hidg_class = NULL;
}

EXPORT_SYMBOL_GPL(ghid_cleanup);

int ghid_device_create(struct f_hidg *ghid)
{
	struct device *device ;
	dev_t dev ;
	int status = 0;
	
	cdev_init(&ghid->cdev, &ghid_fops);
	dev = MKDEV(major, ghid->minor);
	status = cdev_add(&ghid->cdev, dev, 1);
	if(status)
		 return 1 ;
	 
	 device = device_create(hidg_class, NULL, dev, NULL, "%s%d", "hidg", ghid->minor);
	 if(IS_ERR(device)){
	 	  status = PTR_ERR(device);
	 	  return -1 ;
	 }
	 
	return 0 ;
}

EXPORT_SYMBOL_GPL(ghid_device_create);

void ghid_device_remove(struct f_hidg *ghid)
{
	
	device_destroy(hidg_class, MKDEV(major, ghid->minor));
	cdev_del(&ghid->cdev);	
	
}

EXPORT_SYMBOL_GPL(ghid_device_remove);

ssize_t insert_report_descriptor(struct f_hid_opts *opts)
{
  int len;
  len = sizeof(ReportDescriptor);
  opts->subclass = 0x00; 
  opts->protocol = 0x00;
	opts->report_desc = ReportDescriptor;
	opts->report_desc_length = 0x0035;
	opts->report_length = 0x03;
	opts->report_desc_alloc = true;
	return len ;
	
}

EXPORT_SYMBOL_GPL(insert_report_descriptor);
