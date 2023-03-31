/*
 * Strict Priority Queueing (SP)
 *
 * Variables:
 * queue_num_: number of CoS queues
 * thresh_: ECN marking threshold
 * mean_pktsize_: configured mean packet size in bytes
 * marking_scheme_: Disable ECN (0), Per-queue ECN (1) and Per-port ECN (2)
 */

#include "priority.h"
#include "flags.h"
#include "math.h"
#include "tcp.h"
#include "packet.h"

#define max(arg1,arg2) (arg1>arg2 ? arg1 : arg2)
#define min(arg1,arg2) (arg1<arg2 ? arg1 : arg2)

static class PriorityClass : public TclClass {
 public:
	PriorityClass() : TclClass("Queue/Priority") {}
	TclObject* create(int, const char*const*) {
		return (new Priority);
	}
} class_priority;

void Priority::enque(Packet* p)
{ 
    queue_num_=max(min(queue_num_,MAX_QUEUE_NUM),1);
	hdr_ip *iph = hdr_ip::access(p);
	//int prio = iph->prio();
	//prio=min(prio,queue_num_-1);
	hdr_tcp *tcpheader=hdr_tcp::access(p);
	int pktlen=hdr_cmn::access(p)->size();
	int prio=3;
	if(pktlen==1500) prio=1;
	else if(pktlen==1000) prio=2;
	const unsigned int TH_ACK=0x10;
	int ack=(tcpheader->flags()&&TH_ACK);
	if(ack) prio=0;
	hdr_flags* hf = hdr_flags::access(p);
	//int qlimBytes = qlim_ * mean_pktsize_;
	int TotalBufferBytes=qlim_ * mean_pktsize_;
	printf("queue packet prio is %d,packet size =%d",prio,pktlen);
    // 1<=queue_num_<=MAX_QUEUE_NUM
   
    
	//queue length exceeds the queue limit
	/*if(TotalByteLength()+hdr_cmn::access(p)->size()>qlimBytes)
	{
		drop(p);
		return;
	}*/
	if(TotalByteLength()+hdr_cmn::access(p)->size()>TotalBufferBytes)
	{
		int nowlen=hdr_cmn::access(p)->size();
		
		int sum_afterqueue=0;
		int sum=0;
		for(int i=prio+1;i<queue_num_;i++)
		{
			sum_afterqueue+=q_[i]->byteLength();
		}
		if(nowlen>sum_afterqueue)
		{
			drop(p);
			return;
		}
		int flag=0;
		for(int i=queue_num_-1;i>=prio+1;i--)
		{
			while(q_[i]->length()>0)
			{
				//Packet* headPacket = q_[i]->deque();
				//Packet* fro=q_[i]->head()
				Packet *tail_packet = q_[i]->tail();
				sum=sum+hdr_cmn::access(tail_packet)->size();
				q_[i]->remove(tail_packet);
				drop(tail_packet);
				//q_[i]->deque(tail_packet);
				if(sum>=nowlen)
				{
					q_[prio]->enque(p);
					flag=1;
					break;
				}
			}
			if(flag) break;
		}
	}
	else
	{
		q_[prio]->enque(p);
	}

    /*
	if(prio>=queue_num_)
        prio=queue_num_-1;
	
	if(ack) prio=0;

	//Enqueue packet
	q_[prio]->enque(p);
    */
    //Enqueue ECN marking: Per-queue or Per-port
    if((marking_scheme_==PER_QUEUE_ECN && q_[prio]->byteLength()>thresh_*mean_pktsize_)||
    (marking_scheme_==PER_PORT_ECN && TotalByteLength()>thresh_*mean_pktsize_))
    {
        if (hf->ect()) //If this packet is ECN-capable
            hf->ce()=1;
    }
}

Packet* Priority::deque()
{
    if(TotalByteLength()>0)
	{
        //high->low: 0->7
	    for(int i=0;i<queue_num_;i++)
	    {
		    if(q_[i]->length()>0)
            {
			    Packet* p=q_[i]->deque();
		        return (p);
		    }
        }
    }

	return NULL;
}
