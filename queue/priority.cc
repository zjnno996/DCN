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
	int ack=(tcpheader->flags()&TH_ACK);
	if(ack) prio=0;
	hdr_flags* hf = hdr_flags::access(p);
	/*if((marking_scheme_==PER_QUEUE_ECN && q_[prio]->byteLength()>thresh_*mean_pktsize_)||
    (marking_scheme_==PER_PORT_ECN && TotalByteLength()>thresh_*mean_pktsize_))
    {
        if (hf->ect()) //If this packet is ECN-capable
		{
			
            hf->ce()=1;
			prio=0;
		}
    }*/

	int TotalBufferBytes=qlim_ * mean_pktsize_;

	if(TotalByteLength()+hdr_cmn::access(p)->size()>TotalBufferBytes)
	{
		int nowlen=hdr_cmn::access(p)->size();
		
		/*int sum_afterqueue=0;
		int sum=0;
		for(int i=prio+1;i<queue_num_;i++)
		{
			sum_afterqueue+=q_[i]->byteLength();
		}
		if(nowlen>sum_afterqueue)
		{
			drop(p);
			//Packet *new_pkt = p->copy();  
            //new_pkt->setdata(NULL, 0); 
			//q_[0]->enque(new_pkt);
			return;
		}*/
		int flag=0;
		if(nowlen==40)
		{
			int k=0;
			for(int i=3;i>=1;i--){
				if(q_[i]->length()>0) k=i;
			}
			if(k==0) drop(p);
			else
			{
				    Packet *tail_packet = q_[i]->tail();
				    q_[k]->remove(tail_packet);
					int header_size = hdr_cmn::access(tail_packet)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
					drop(tail_packet);
					q_[0]->enque(p);
				    q_[0]->enque(new_pkt);
					
			}
		}
		else if(nowlen==1500)
		{
			int k3=q_[3]->length();
			int k2=q_[2]->length();
			int k1=q_[1]->length();
			int sum=TotalByteLength()+nowlen-k2*960-k3*460;//2-3优先级剔除，是否够
			if(sum<=TotalBufferBytes)
			{
				int k=3;
				int now_sum=TotalByteLength()+nowlen;
				while(now_sum>TotalBufferBytes)
				{
					if(q_[k]->length()==0) k--;
					Packet *tail_packet = q_[k]->tail();
				    q_[k]->remove(tail_packet);
					int header_size = hdr_cmn::access(tail_packet)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
					drop(tail_packet);
				    q_[0]->enque(new_pkt);
					if(k==3)
					now_sum=now_sum-460;
				    else
					now_sum=now_sum-960;
				}
				q_[1]->enque(p);
			}
			else
			{
				if(TotalByteLength()+40<=TotalBufferBytes){
					int header_size = hdr_cmn::access(p)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(p);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
					drop(p);
				    q_[0]->enque(new_pkt);
				}
				else
				{
					
					if(k1+k2+k3>0){
						for(int i=3;i>=1;i--){
							if(q_[i]->length()>0)
							{
								Packet *tail_packet = q_[i]->tail();
				                q_[i]->remove(tail_packet);
					            int header_size = hdr_cmn::access(tail_packet)->size();
                                // 创建一个新的数据包，只包含头部
                                Packet* new_pkt = Packet::alloc();
                                hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                                hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                                memcpy(new_hdr, hdr, header_size);
					            drop(tail_packet);
				
                                Packet* new_pkt1 = Packet::alloc();
                                hdr_cmn* hdr1 = hdr_cmn::access(p);
                                hdr_cmn* new_hdr1 = hdr_cmn::access(new_pkt1);
                                memcpy(new_hdr1, hdr1, header_size);
					            drop(p);
				                q_[0]->enque(new_pkt1);
				                q_[0]->enque(new_pkt);
								break;
							}
						}
							
					}
					else
					{
						drop(p);
					}
				}
			}
		}
		else if(nowlen==1000){
			int k3=q_[3]->length();
			int k2=q_[2]->length();
			int k1=q_[1]->length();
			int sum=TotalByteLength()+nowlen-k3*460;//3优先级剔除，是否够
			if(sum<=TotalBufferBytes)
			{
				int k=3;
				int now_sum=TotalByteLength()+nowlen;
				while(now_sum>TotalBufferBytes)
				{
					if(q_[k]->length()==0) k--;
					Packet *tail_packet = q_[k]->tail();
				    q_[k]->remove(tail_packet);
					int header_size = hdr_cmn::access(tail_packet)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
					drop(tail_packet);
				    q_[0]->enque(new_pkt);
					if(k==3)
					now_sum=now_sum-460;
				}
				q_[2]->enque(p);
			}
			else
			{
				
				    if(k1+k2+k3>0){
						for(int i=3;i>=1;i--){
							if(q_[i]->length()>0)
							{
								Packet *tail_packet = q_[i]->tail();
				                q_[i]->remove(tail_packet);
					            int header_size = hdr_cmn::access(tail_packet)->size();
                                // 创建一个新的数据包，只包含头部
                                Packet* new_pkt = Packet::alloc();
                                hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                                hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                                memcpy(new_hdr, hdr, header_size);
					            drop(tail_packet);
				
                                Packet* new_pkt1 = Packet::alloc();
                                hdr_cmn* hdr1 = hdr_cmn::access(p);
                                hdr_cmn* new_hdr1 = hdr_cmn::access(new_pkt1);
                                memcpy(new_hdr1, hdr1, header_size);
					            drop(p);
				                q_[0]->enque(new_pkt1);
				                q_[0]->enque(new_pkt);
								break;
							}
						}
							
					}
					else
					{
						drop(p);
					}
				
				
			}
			
			
			
			
		}
		else
		{
		    int k3=q_[3]->length();
			int k2=q_[2]->length();
			int k1=q_[1]->length();
		
			 if(k1+k2+k3>0){
						for(int i=3;i>=1;i--){
							if(q_[i]->length()>0)
							{
								Packet *tail_packet = q_[i]->tail();
				                q_[i]->remove(tail_packet);
					            int header_size = hdr_cmn::access(tail_packet)->size();
                                // 创建一个新的数据包，只包含头部
                                Packet* new_pkt = Packet::alloc();
                                hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                                hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                                memcpy(new_hdr, hdr, header_size);
					            drop(tail_packet);
				
                                Packet* new_pkt1 = Packet::alloc();
                                hdr_cmn* hdr1 = hdr_cmn::access(p);
                                hdr_cmn* new_hdr1 = hdr_cmn::access(new_pkt1);
                                memcpy(new_hdr1, hdr1, header_size);
					            drop(p);
				                q_[0]->enque(new_pkt1);
				                q_[0]->enque(new_pkt);
								break;
							}
						}
							
					}
					else
					{
						drop(p);
					}
		}
		/*for(int i=queue_num_-1;i>=prio;i--)
		{
			while(q_[i]->length()>0)
			{
				//Packet* headPacket = q_[i]->deque();
				//Packet* fro=q_[i]->head()
				if(nowlen+TotalByteLength()>TotalBufferBytes)
				{
					if(i==prio)
					{
					int header_size = hdr_cmn::access(p)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(p);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
				    q_[0]->enque(new_pkt);
					drop(p);
					  flag=1;
					break;
					}
					else
					{
					Packet *tail_packet = q_[i]->tail();
				    q_[i]->remove(tail_packet);
					int header_size = hdr_cmn::access(tail_packet)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
					drop(tail_packet);
				    q_[0]->enque(new_pkt);
					}
				    //Packet *new_pkt = tail_packet->copy();  
					int header_size = hdr_cmn::access(tail_packet)->size();
                    // 创建一个新的数据包，只包含头部
                    Packet* new_pkt = Packet::alloc();
                    hdr_cmn* hdr = hdr_cmn::access(tail_packet);
                    hdr_cmn* new_hdr = hdr_cmn::access(new_pkt);
                    memcpy(new_hdr, hdr, header_size);
					
                    //new_pkt->setdata(NULL, 0); 
					//new_pkt->remove_data(new_pkt->length() - new_pkt->hdrlen());
			        
				}
				else
				{
					q_[prio]->enque(p);
					flag=1;
					break;
				}
				
			}
			
		}*/
		
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
    /*if((marking_scheme_==PER_QUEUE_ECN && q_[prio]->byteLength()>thresh_*mean_pktsize_)||
    (marking_scheme_==PER_PORT_ECN && TotalByteLength()>thresh_*mean_pktsize_))
    {
        if (hf->ect()) //If this packet is ECN-capable
            hf->ce()=1;
    }*/
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
