#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <fstream> 
#include <string>
#include <zlib.h>
#include <iconv.h>
#include <list>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h> // System setup need.
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
using namespace std;
#define OK  0 
#define QUEUE_LEN  1024

uint32_t defaultime =  0;
typedef struct
{
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		unsigned int ihl:4;
		unsigned int version:4;
	#elif __BYTE_ORDER == __BIG_ENDIAN
		unsigned int version:4;
		unsigned int ihl:4;
	#else
	#error	"Please fix <bits/endian.h>"
	#endif
} ip_version;


typedef  struct IPLIST{
	uint32_t uiaddr;
	uint32_t uimask; 
	float    ftime;
	struct IPLIST  *next;
}IPLIST,*p_IPLIST;


enum hook_mark
{
	HOOK_MARK_BEGIN,
	INPUT_MARK = 1,
	CONN_BYTES_MARK = 2,
	MATCH_REP_PLAIN_MARK = 3,
	MATCH_REP_GZIP_MARK = 4,
	HOOK_MARK_END
};

p_IPLIST gHead_Iplist =  NULL  ;
p_IPLIST gTail_Iplist =  NULL  ;

pthread_mutex_t mut;

typedef struct
{
	uint32_t ipaddr;
	uint32_t i_pack_id;
	nfq_q_handle * qh;	
	
}packet_info_t;

/*********************************************************************************
  *Function:  do_delay
  *Description：根据IP地址所在的网段，执行相应的延时，默认15ms
  *Calls:  NULL
  *Called By:  thread_start
  *Input:  待延时的IP地址
  *Output:  NULL
  *Return:  延时结果
  *date:  2013-05-23
**********************************************************************************/
int  do_delay( uint32_t uiIPaddr )
{
	p_IPLIST plist = NULL;
	plist = &(*gHead_Iplist);

	while( plist != NULL )
	{
		/*check if at the same ip area*/
		if( ( uiIPaddr>>(32-(plist->uimask)) ) == (( plist->uiaddr )>>( 32-(plist->uimask) )))
		{
			if( 0 == plist->ftime )
			{
				usleep(defaultime*1000);
			}
			else
			{
				usleep( plist->ftime*1000 );
			}
			return OK;
		}
		
		plist = plist->next;
	}
	usleep(defaultime*1000);
	return -1;
}
/*********************************************************************************
  *Function:  thread_start
  *Description：根据报文的属性，决定并执行相应延时
  *Calls:  NULL
  *Called By:  creat_thread
  *Input:  待延时的报文属性结构体指针，包括qh，包ID，Ip地址
  *Output:  NULL
  *Return:  线程结束
  *date:  2013-05-23
**********************************************************************************/
static void * thread_start(void * p_Node)
{
	packet_info_t  node = {0};
	node = *(packet_info_t *) p_Node ;
	
	
	if( node.ipaddr == 0 )
	{
		free(p_Node);
		pthread_exit(NULL);
	}
	
	do_delay( node.ipaddr );
	nfq_set_verdict( node.qh,node.i_pack_id,NF_ACCEPT,0,NULL );
	free(p_Node);
	pthread_exit(NULL);
}
/*********************************************************************************
  *Function:  get_packet_id
  *Description：获取包Id并返回
  *Calls:  NULL
  *Called By:  input_handler
  *Input:  待延时的报文属性tb
  *Output:  NULL
  *Return:  pkt_id
  *date:  2013-05-23
**********************************************************************************/
u_int32_t get_packet_id ( struct nfq_data *tb )
{
	u_int32_t pkt_id = 0;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
	if(ph)
	{
		pkt_id = ntohl(ph->packet_id);
	}
	return pkt_id;
}
/*********************************************************************************
  *Function:  creat_thread
  *Description：创建延时线程
  *Calls:  NULL
  *Called By:  input_handler
  *Input:  id_packet，IP地址，和队列句柄qh
  *Output:  NULL
  *Return:  pkt_id
  *date:  2013-05-23
**********************************************************************************/
uint32_t creat_thread(uint32_t id_packet, uint32_t addr, struct nfq_q_handle *qh)
{
	uint32_t  uiBit8   = 0;
	uint32_t  uiBit16  = 0;
	uint32_t  uiBit24  = 0;
	uint32_t  uiBit32  = 0;
	uint32_t  uiIPaddr = 0;
	pthread_t pthread_id;
	
	
	uiBit8  = (( addr&0xFF000000)>>24);
	uiBit16 = (( addr&0xFF0000)>>16);
	uiBit24 = (( addr&0xFF00)>>8);
	uiBit32 = (addr&0xFF);
	
	uiIPaddr = ((uiBit32<<24)+(uiBit24<<16) +(uiBit16<<8)+uiBit8);
	
	
	packet_info_t * p_Node = NULL;
	p_Node = ( packet_info_t * )malloc(sizeof(packet_info_t));
	
	
	p_Node->ipaddr = uiIPaddr;
	p_Node->i_pack_id = id_packet;
	p_Node->qh = qh;
			

			
	pthread_create(&pthread_id,NULL,&thread_start,(void*)p_Node);
	
	if ( 0 != pthread_detach(pthread_id))
	{
		printf("pthread_join error!\n");
		exit(1);
	}	
	
	return OK;
}



uint32_t input_handler( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
	//first judge ipv4 or ipv6
	uint32_t id_packet = get_packet_id(nfa);
	uint32_t i_mark    = nfq_get_nfmark(nfa);
	uint32_t uiRet  = 0;
	
	if( i_mark != INPUT_MARK )
	{
		nfq_set_verdict(qh,id_packet,NF_ACCEPT,0,NULL);
		return id_packet;
	}
	unsigned char * ip_payload_data = NULL;
	int i_payload_len = nfq_get_payload(nfa,&ip_payload_data);
	if( -1 == i_payload_len )
	{
		nfq_set_verdict(qh,id_packet,NF_ACCEPT,0,NULL);
		return id_packet;
	}
	ip_version * p_version = (ip_version*)(ip_payload_data);
	if( 4 != p_version->version )
	{
		nfq_set_verdict(qh,id_packet,NF_ACCEPT,0,NULL);
		return id_packet;
	}
	struct iphdr * ip_header = (iphdr*)(ip_payload_data);

		
	if( ip_header->protocol == IPPROTO_ICMP )
	{	
		uiRet = creat_thread( id_packet,ip_header->daddr,qh);
	}
	else if(  ip_header->protocol == IPPROTO_TCP )
	{
			if( i_payload_len == 60 || i_payload_len == 52 )
			{
				uiRet = creat_thread( id_packet,ip_header->daddr,qh);
			}
			else
			{
			    nfq_set_verdict(qh,id_packet,NF_ACCEPT,0,NULL);
			}
	}
		
	
	return id_packet;
}


static int main_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
	u_int32_t id_packet = get_packet_id(nfa);
	uint32_t i_mark = nfq_get_nfmark(nfa);
	if( i_mark  == INPUT_MARK )
	input_handler(qh,nfmsg,nfa,data);
	else
	{
		nfq_set_verdict( qh,id_packet,NF_ACCEPT,0,NULL );
	}
	
	return id_packet;
}

/*********************************************************************************
  *Function:  Str_to_Num
  *Description：将从数据库中获取的字符串形式的IP地址，转化成32bit的无符号整数
  *Calls:  NULL
  *Called By:  Get_Insert_Joint_IP
  *Input:  从数据库中获取的字符串形式的IP地址
  *Output:  NULL
  *Return:  IP地址对应的32bit的无符号整数
  *date:  2013-02-22
**********************************************************************************/
uint32_t Str_to_Num ( string st ) 
{
	uint32_t uiWord  = 0;
	uint32_t uiBlock = 0;	
	uint32_t uiLoop  = 0;
	while( uiLoop < st.size() )
	{
		uiWord = 0;
		if(st[uiLoop] <'0'||st[uiLoop] >'9')
		{
		/* 如果取到的不是0~9的数字，取下一个 */  
			uiLoop++;
		}
		else
		{
			/* 计算IP地址，放到uiBlock中 */  
			while(st[uiLoop]>='0' && st[uiLoop]<='9')
			{
				uiWord = uiWord* 10 + st[uiLoop]-'0';
				uiLoop++;
			}
			
			uiBlock = (uiBlock<<8) + uiWord;
		}
	}
	return uiBlock;
}
/*********************************************************************************
  *Function:  Insert_addr
  *Description：将列表中的地址和对应延时添加到链表中，作为后续做延时的依据
  *Calls:  NULL
  *Called By:  Get_Insert_Joint_IP
  *Input:  从iplist.txt中获取的IP地址和延时
  *Output:  NULL
  *Return:  延时关系链表
  *date:  2013-02-22
**********************************************************************************/
uint32_t Insert_addr( p_IPLIST *pstHead,p_IPLIST *psTail,uint32_t uiIpaddr,uint32_t uiMask,float tm)
{
	//修改算法，如果比当前节点的值大，则往后遍历找位置，比当前小的从头遍历找位置，插入后返回插入位置，为下一次插入做比较基准
	uint32_t uiLtemp 	   = 0;
	uint32_t uiLtempmask   = 0;
	uint32_t uiLtemptime  = 0;
	p_IPLIST pstmp   = NULL;
	p_IPLIST pstHsek = NULL;
	p_IPLIST pstHtil = NULL;
	
	pstHtil = *psTail ;
	/*新申请节点 */  
	pstmp = new IPLIST ;
	if( pstmp == NULL )
	{
		#ifdef DEBUG
		printf("sorry,failed to malloc mem pstmp == NULL!!\n");
		#endif
		return OK;
	}
		
		
	if( *pstHead == NULL )
	{
		/* 如果还没有节点，则新增节点，入参放到新增节点中去 */  
		pstmp->next = NULL;
		*psTail  = pstmp;
		*pstHead = pstmp;
		pstmp->uiaddr = uiIpaddr ;
		pstmp->uimask = uiMask ;
		pstmp->ftime  = tm  ;
		return OK;
	}
		
	/* 如果入参比末尾节点大，则新增节点，入参放到新增节点中去 */  
	pstmp->next = NULL;
	pstHtil->next = pstmp;
	
	*psTail = pstmp;
		
	pstmp->uiaddr = uiIpaddr;
	pstmp->uimask = uiMask;
	pstmp->ftime  = tm  ;
	return OK;
	
}


int main( int argc, char *argv[] )
{
	uint32_t    uiRet  = 0;
	uint32_t    mask   = 0;
	uint32_t    uiIP   = 0;
	float  ftime = 0;
	int i_queue_num = 1;
	string ipaddr;
	p_IPLIST pDel  = NULL;
	p_IPLIST ploop = NULL;
	
	if(argc != 2)
	{
		printf("please input ./delay *default delay time(ms)*,example: ./delay 10\n");
		return 0;
	}
	int itime = 0;
	sscanf(argv[1],"%d",&itime);
	defaultime = itime;
	
	struct nfq_handle *  handler = nfq_open();
	if (!handler)
	{
		exit(1);
	}

	if ( nfq_unbind_pf(handler, AF_INET) < 0 )
	{
		exit(1);
	}

	if ( nfq_bind_pf( handler, AF_INET) < 0 )
	{
		exit(1);
	}
	
	
	fstream Fplist;
	Fplist.open("iplist.txt",ios::in);
	if(!Fplist)
	{ 
		cout<<"can not open iplist.txt\n"; 
		return -1;
	} 
	
	while( Fplist >> ipaddr )
	{
		Fplist >> mask;
		Fplist >> ftime;
		uiIP =  Str_to_Num ( ipaddr );
		uiRet = Insert_addr( &gHead_Iplist,&gTail_Iplist,uiIP,mask,ftime);
	}
	
		
		
	struct nfq_q_handle *qh = NULL;
	qh = nfq_create_queue(handler, i_queue_num, &main_handler, NULL);
	if (!qh)
	{
		exit(1);
	}
	
	if ( nfq_set_mode( qh, NFQNL_COPY_PACKET, 0xffff ) < 0)
	{
		exit(1);
	}

	if( nfq_set_queue_maxlen( qh,0xffffffff ) < 0 )
	{
		exit(1);
	}

	int fd = nfq_fd(handler);
		
	char buf[4096] __attribute__ ((aligned));
	int rv = -1;
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
	{
		
		nfq_handle_packet(handler, buf, rv);
		
	}

	
	ploop = &(*gHead_Iplist);

	while( ploop != NULL )
	{
		pDel = ploop;
		ploop = ploop->next;
		free( pDel );
		pDel = NULL;
	}
	
	nfq_destroy_queue(qh);
	nfq_close(handler);
	
	return 0;
	
}
