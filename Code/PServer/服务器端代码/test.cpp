#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <pthread.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <cstdio>
#include <algorithm>
#include <string>
#include <cmath>
#include <ctime>
#include <set>
#define RX_RING_SIZE 1024
//#define TX_RING_SIZE 512
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191*2
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 4
using namespace std;
int literal_count = 0;
int clause_count = 0;
uint8_t packet_index = 0;
long long packet_num = 0;
int time_in_forward_packet = 0;
int time_in_print = 0;
long long tx = 0;
vector<vector<int> > clauses;
vector<int> literal_polarity;
vector<vector<int> > table;
vector<vector<int> > variables;
int xl = 1;
int x2 = 1;
//这里用skleten 默认配置
enum Cat{satisfied,unsatisfied,normal,completed};
class Formula {
public:
	vector<int> literal_frequency;
	vector<int> literals;
	vector<struct value> v_value;
	vector<struct assigned> v_assigned;
	
	Formula(){}
	Formula(const Formula &f) {
		literal_frequency = f.literal_frequency;
		literals = f.literals;
		v_value = f.v_value;
		v_assigned = f.v_assigned;
	}
};
//struct rte_mempool *mbuf_pool;
struct rte_mempool *mbuf_pool;
static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
//static const struct rte_eth_conf port_conf_default;
struct assigned{
	uint8_t assigned_bytes[32];
};
struct value{
	uint8_t value_bytes[32];
};
struct unit_variable_id{
	uint8_t unit_bytes[4];
};
struct  my_hdr{
	uint8_t tmp;
	uint8_t packet_index;
	struct assigned my_assigned;
	struct value my_value;
	struct unit_variable_id my_unit_variable_id;

};

void initialize(Formula& formula) {
	char c;
	string s;
	while (true) {
		cin >> c;
		if (c == 'c')getline(cin, s);
		else {
			cin >> s;
			break;
		}
	}
	cin >> literal_count;
	cin >> clause_count;
	formula.literals.clear();
	formula.literals.resize(literal_count+1,-1);
	formula.literals[literal_count] = 0;
	formula.literal_frequency.clear();
	formula.literal_frequency.resize(literal_count,0);
	literal_polarity.clear();
	literal_polarity.resize(literal_count,0);
	clauses.clear();
	clauses.resize(clause_count);
	int literal;
	for (int i = 0; i < clause_count; i++) {
		while (true) {
			cin >> literal;
			if (literal > 0){
				clauses[i].push_back(literal);
				formula.literal_frequency[literal-1] = formula.literal_frequency[literal-1]+1;
				literal_polarity[literal-1] = literal_polarity[literal-1]+1;
			}
			else if (literal < 0){
				clauses[i].push_back(literal);
				formula.literal_frequency[-literal-1]=formula.literal_frequency[-literal-1]+1;
				literal_polarity[-literal-1]=literal_polarity[-literal-1]-1;
			}
			else {
				break;
			}
		}
	}

	int tablesize;
	cin>>tablesize;
	table.resize(tablesize);
	variables.resize(literal_count+1);
	formula.v_value.clear();
	formula.v_value.resize(tablesize);
	formula.v_assigned.clear();
	formula.v_assigned.resize(tablesize);
	//printf("value sie and assigned size: %ld %ld\n",formula.v_value.size(),formula.v_assigned.size());
	for(int i=0;i<tablesize;i++){
		while(true){
			cin>>literal;
			if(literal!=0)table[i].push_back(literal);
			else{
				break;
			}
		}
	}
	for(int i=1;i<=literal_count;i++){
		while(true){
			cin>>literal;
			if(literal!=-1)variables[i].push_back(literal);
			else{
				break;
			}
		}
	}
	for(int i=0;i<tablesize;i++)
	{
		for(int j=0;j<32;j++)
		{
			formula.v_value[i].value_bytes[j] = 0x00;
			formula.v_assigned[i].assigned_bytes[j] = 0x00;
		}
	}
	

}
/*
 *这个是简单的端口初始化 
 *我在这里简单的端口0 初始化了一个 接收队列和一个发送队列
 *并且打印了一条被初始化的端口的MAC地址信息
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 2, tx_rings = 2;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;
	/*获取当前网口信息，并存入dev_info中*/
	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}
	/*查看网口设备是否支持mbufs快速释放的功能，支持的话就默认加上*/
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	/*配置网口参数，rx_rings和tx_rings是设置的接受/发送的队列数目*/
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
	/*这个函数是去判断port网口是否支持nb_rxd/nb_txd个接受/发送描述符，*/
	/*如果不支持那么多会自动调整到边界个数*/
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	/*为网口设置接受队列，因为rx_rings为1，所以为网口设置一个接受队列*/
	/*rth_eth_dev_socket_id返回一个NUMA结构套接字，所谓的NUMA结构套接字是将多台服务器连接起来当做一台使用的技术*/
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	/*为port网口设置发送队列，比上一个函数少一个内存池参数，所以发送队列是没有缓冲区的*/
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	/*启动port网口*/
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	/*设置网口的混杂模式，不管是不是发给它的都会接受*/
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}
void show_packet(struct my_hdr *myhdr,int index)
{
	//x2++;
	//cout<<"xl: ";
	//cout<<xl<<endl;
	
	printf("-------------------------------------\n");
	
	if(index==0)
	{
		printf("成功发送一个包\n");
	}
	else
 	{
		printf("成功接受一个包\n");
	}
	printf("table_index:\n");
	printf("%d\n",(int)((myhdr->tmp)>>4));
	printf("if_conflict:\n");
	printf("%d\n",(int)(((myhdr->tmp)>>3)&1));
	printf("if_found_unit_clause:\n");
	printf("%d\n",(int)(((myhdr->tmp)>>2)&1));
	printf("polarity:\n");
	printf("%d\n",(int)(((myhdr->tmp)>>1)&1));
	printf("clause_or_conflict:\n");
	printf("%d\n",(int)(((myhdr->tmp))&1));
	printf("packet_index:\n");
	printf("%d\n",(int)(myhdr->packet_index));
	printf("assigned:\n");
	for(int i=0;i<32;i++){
		printf("%02x ",myhdr->my_assigned.assigned_bytes[i]);
	}
	printf("\n");
	printf("value:\n");
	for(int i=0;i<32;i++){
		printf("%02x ",myhdr->my_value.value_bytes[i]);
	}
	printf("\n");
	printf("unit_variable_id:\n");
	for(int i=0;i<4;i++){
		printf("%02x ",myhdr->my_unit_variable_id.unit_bytes[i]);
	}
	printf("\n");
	printf("--------------------------------------\n");
	
}
/*输出初始化后的结果*/
void show_initialize_formula(Formula f)
{
	printf("literal_count: %d\nclause_count: %d\n",literal_count,clause_count);
	printf("clauses:\n");
	for(int i=0;i<clause_count;i++)
	{
		for(int j=0;j<clauses[i].size();j++)
		{
			printf("%d ",clauses[i][j]);
		}
		printf("\n");
	}
	printf("literals:\n");
	for(int i=0;i<literal_count;i++)
	{
		if(f.literals[i]==0)printf("-%d ",i+1);
		else if(f.literals[i]==1)printf("+%d ",i+1);
		else printf("-1 ");
	}
	printf("%d",f.literals[literal_count]);
	printf("\n");
	printf("literal_frequency:\n");
	for(int i=0;i<literal_count;i++)printf("%d ",f.literal_frequency[i]);
	printf("\n");
	printf("v_value:\n");
	printf("the v_value size is: %ld\n",f.v_value.size());
	for(int i=0;i<f.v_value.size();i++)
	{
		for(int j=0;j<32;j++)
		{
			printf("%02x ",f.v_value[i].value_bytes[j]);
		}
		printf("\n");
	}
	printf("v_assigned:\n");
	printf("the v_assigned size is: %ld\n",f.v_assigned.size());
	for(int i=0;i<f.v_assigned.size();i++)
	{
		for(int j=0;j<32;j++)
		{
			printf("%02x ",f.v_assigned[i].assigned_bytes[j]);
		}
		printf("\n");
	}
	printf("literal_polarity:\n");
	for(int i=0;i<literal_count;i++)printf("%d ",literal_polarity[i]);
	printf("\n");
	printf("variables:\n");
	for(int i=1;i<=literal_count;i++)
	{
		printf("%d: ",i);
		for(int j=0;j<variables[i].size();j++)
		{
			printf("%d ",variables[i][j]);
		}
		printf("\n");
	}
	printf("tables:\n");
	printf("the table size is: %ld\n",table.size());
	for(int i=0;i<table.size();i++)
	{
		printf("%d: %ld\n",i,table[i].size());
		for(int j=0;j<table[i].size();j++)
		{
			printf("%d ",table[i][j]);
		}
		printf("\n");
	}	
}
void show_formula(Formula f)
{
	printf("literal_count: %d\nclause_count: %d\n",literal_count,clause_count);
	printf("literals:\n");
	for(int i=0;i<literal_count;i++)
	{
		if(f.literals[i]==0)printf("-%d ",i+1);
		else if(f.literals[i]==1)printf("+%d ",i+1);
		else printf("-1 ");
	}
	printf("%d",f.literals[literal_count]);
	printf("\n");
	printf("literal_frequency:\n");
	for(int i=0;i<literal_count;i++)printf("%d ",f.literal_frequency[i]);
	printf("\n");
	printf("v_value:\n");
	printf("the v_value size is: %ld\n",f.v_value.size());
	for(int i=0;i<f.v_value.size();i++)
	{
		for(int j=0;j<32;j++)
		{
			printf("%02x ",f.v_value[i].value_bytes[j]);
		}
		printf("\n");
	}
	printf("v_assigned:\n");
	printf("the v_assigned size is: %ld\n",f.v_assigned.size());
	for(int i=0;i<f.v_assigned.size();i++)
	{
		for(int j=0;j<32;j++)
		{
			printf("%02x ",f.v_assigned[i].assigned_bytes[j]);
		}
		printf("\n");
	}
	printf("literal_polarity:\n");
	for(int i=0;i<literal_count;i++)printf("%d ",literal_polarity[i]);
	printf("\n");
}
void send_receive_packet(struct my_hdr& tmphdr)
{
    uint16_t nb_tx,nb_rx;
	struct rte_ether_hdr *eth_hdr;
	uint16_t ether_type = 0x5555;
	struct rte_mbuf *pkt[BURST_SIZE];
	struct my_hdr *myhdr;
	for(int i=0;i<BURST_SIZE;i++)
	{
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);
		eth_hdr = rte_pktmbuf_mtod(pkt[i],struct rte_ether_hdr*);
		eth_hdr->ether_type = ether_type;
		myhdr = (struct my_hdr*)(rte_pktmbuf_mtod(pkt[i],char*)+sizeof(struct rte_ether_hdr));
		myhdr->tmp = tmphdr.tmp;
		myhdr->packet_index = tmphdr.packet_index;
		myhdr->my_assigned = tmphdr.my_assigned;
		myhdr->my_value = tmphdr.my_value;
		myhdr->my_unit_variable_id = tmphdr.my_unit_variable_id;
		int pkt_size = sizeof(struct rte_ether_hdr)+sizeof(struct my_hdr);
		pkt[i]->data_len = pkt_size;
		pkt[i]->pkt_len = pkt_size;
		
	}
    //printf("434\n");
	int aflag = 1;
	while(aflag){
		nb_tx = rte_eth_tx_burst(0,0,pkt,BURST_SIZE);
		
		//cout<<"nb_tx:"<<nb_tx<<endl;
		if(nb_tx>0){
			aflag=0;
            //printf("nb_tx: %d\n",nb_tx);
			//int mystart = clock();
			//show_packet(myhdr,0);
			//int myend = clock();
			//time_in_print += myend - mystart;
			//printf("myend-mystart: %d\n",myend-mystart);
		}
	}
    //printf("450\n");
	for(int i=0;i<BURST_SIZE;i++)
		rte_pktmbuf_free(pkt[i]);
	aflag = 1;
    //printf("454\n");
    for(int i=0;i<BURST_SIZE;i++) {
			pkt[i] = rte_pktmbuf_alloc(mbuf_pool);
		}
	while(aflag)
	{
        
        //printf("457\n");
		
		//从接受队列中取出包
		nb_rx = rte_eth_rx_burst(0, 0,pkt,BURST_SIZE);
		//cout<<"nb_rx:"<<nb_rx<<endl;
		//cin>>aflag;
        //printf("nb_rx: %d\n",nb_rx);
		if(nb_rx == 0)
		{
			continue;
		}
		for(int i=0;i<BURST_SIZE;i++)
		{
			myhdr = rte_pktmbuf_mtod_offset(pkt[i],struct my_hdr*,sizeof(struct rte_ether_hdr));
			//show_packet(myhdr,1);
			//printf("nb_rx: %d\n",nb_rx);
            //printf("nb_tx: %d\n",nb_tx);
			//printf("myend-mystart: %d\n",myend-mystart);
			//printf("packet_index: %02x\n",(int)packet_index);
			//printf("myhdr->packet_index: %02x\n",(int)myhdr->packet_index);
            //printf("packet_num: %d\n",packet_num);
			if(myhdr->packet_index==packet_index)
			{
                //printf("aaa\n");
				aflag=0;
				//int mystart = clock();
				//show_packet(myhdr,0);
				//int myend = clock();
				//time_in_print += myend - mystart;
				tmphdr.tmp = myhdr->tmp;
				tmphdr.packet_index = myhdr->packet_index;
				tmphdr.my_assigned = myhdr->my_assigned;
				tmphdr.my_value = myhdr->my_value;
				tmphdr.my_unit_variable_id = myhdr->my_unit_variable_id;
				break;
			}
		}
		
	}
    for(int i=0;i<BURST_SIZE;i++)rte_pktmbuf_free(pkt[i]);



}

int dpll(Formula f)
{
	//printf("493\n");
	char cc;
	int xxx;
	int if_found_unit = 1;
	while(if_found_unit)
	{
		if_found_unit = 0;
		/*遍历每个表*/
		for(int i=0;i<table.size();i++)
		{
			struct my_hdr tmphdr;
			tmphdr.tmp = (uint8_t)(((i+1)<<4)+0);
			tmphdr.packet_index = packet_index++;
			packet_num++;
			//printf("packet_num: %d\n",packet_num);
			tmphdr.my_assigned = f.v_assigned[i];
			tmphdr.my_value = f.v_value[i];
			tmphdr.my_unit_variable_id = {{0x00,0x00,0x00,0x00}};
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<"/*---------------------------------------------------------*/"<<endl;
			//cout<<"line 486 debug, send and receive a packet, please input a literal to continue!\n";
			int my_start = clock();
			//printf("find whether ther is a unit variable!\n");
			//printf("527\n");
			send_receive_packet(tmphdr);
			//printf("529\n");
			//cin>>cc;
			int my_end = clock();
			time_in_forward_packet += my_end - my_start;
			//cout<<"/*---------------------------------------------------------*/"<<endl;
			//cin>>xxx;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			



			if(((tmphdr.tmp>>2)&1)==1)//如果发现单元子句
			{
				//printf("find a unit variable!\n");
				if_found_unit = 1;
				int v_id = 0;
				for(int q=0;q<4;q++){
					v_id = (v_id<<8)+(int)(tmphdr.my_unit_variable_id.unit_bytes[q]);
				}
				if(((tmphdr.tmp>>1)&1)==0)//如果返回的polarity==0,相对应的literals赋值为false，否则，赋值为false
				{
					f.literals[v_id-1]=0;
				}
				else
				{
					f.literals[v_id-1]=1;
				}
				f.literal_frequency[v_id-1]=-1;
				f.literals[literal_count]++;
				for(int p=0;p<variables[v_id].size();p++)
				{
					int tmp_id = variables[v_id][p];
					int j = distance(table[tmp_id].begin(),find(table[tmp_id].begin(),table[tmp_id].end(),v_id));
					f.v_assigned[tmp_id].assigned_bytes[31-j/8]=f.v_assigned[tmp_id].assigned_bytes[31-j/8]|(0x01<<(j%8));
					if(((tmphdr.tmp>>1)&1)==1)
					{
						f.v_value[tmp_id].value_bytes[31-j/8]=f.v_value[tmp_id].value_bytes[31-j/8]|(0x01<<(j%8));
					}
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<"/*---------------------------------------------------------*/"<<endl;
					//cout<<"line 534 debug to show formula,please input a literal to continue,the next step is to send and receive a packet!\n";
					//show_formula(f);
					//cout<<"/*---------------------------------------------------------*/"<<endl;
					//cin>>xxx;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					
					
					struct my_hdr tmphdr_conf;
					tmphdr_conf.tmp = (uint8_t)(((tmp_id+1)<<4)+1);
					tmphdr_conf.packet_index = packet_index++;
					packet_num++;
					//printf("packet_num: %d\n",packet_num);
					tmphdr_conf.my_assigned = f.v_assigned[tmp_id];
					tmphdr_conf.my_value = f.v_value[tmp_id];
					tmphdr_conf.my_unit_variable_id = {{0x00,0x00,0x00,0x00}};
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<"/*---------------------------------------------------------*/"<<endl;
					//cout<<"line 557 debug, send and receive a packet, please input a literal to continue!\n";
					int myy_start = clock();
					//printf("find whether ther is a conflict!\n");
                   // printf("605\n");
					send_receive_packet(tmphdr_conf);
                   // printf("607\n");
					//cin>>cc;
					int myy_end = clock();
					time_in_forward_packet += myy_end - myy_start;
					//cout<<"/*---------------------------------------------------------*/"<<endl;
					//cin>>xxx;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;
					//cout<<endl;

					
					if((((tmphdr_conf.tmp)>>3)&1)==1)
					{
						//printf("line 573 find conflict!!!!,%d th packet!\n",(int)packet_index);
						return Cat::unsatisfied;
					}
				}
				if(f.literals[literal_count]==literal_count)
				{
					printf("sat!sat!sat!\n");
					//show_formula(f);
					return Cat::completed;
				}
				break;
			}
		}
	}
	
	int i = distance(f.literal_frequency.begin(),max_element(f.literal_frequency.begin(), f.literal_frequency.end()));
	for(int j=0;j<2;j++)
	{
		int tmp_flag = 1;
		Formula new_f = f;
		if(literal_polarity[i]>0)
		{
			new_f.literals[i] = (j+1)%2;
		}
		else
		{
			new_f.literals[i] = j;
		}
		new_f.literal_frequency[i] = -1;
		new_f.literals[literal_count]++; 
		for(int p=0;p<variables[i+1].size();p++)
		{
			int tmp_id = variables[i+1][p];
			int dis = distance(table[tmp_id].begin(),find(table[tmp_id].begin(),table[tmp_id].end(),i+1));
			new_f.v_assigned[tmp_id].assigned_bytes[31-dis/8] = new_f.v_assigned[tmp_id].assigned_bytes[31-dis/8]|(0x01<<(dis%8));
			if(new_f.literals[i]==1)
			{
				new_f.v_value[tmp_id].value_bytes[31-dis/8] = new_f.v_value[tmp_id].value_bytes[31-dis/8]|(0x01<<(dis%8));
			}
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<"/*---------------------------------------------------------*/"<<endl;
			//printf("i: %d\n",i);
			//printf("dis: %d\n",dis);
			//printf("tmp_id: %d\n",tmp_id);
			//cout<<"line 621 debug to show formula,please input a literal to continue,the next step is to send and receive a packet!\n";
			//show_formula(new_f);
			//cout<<"/*---------------------------------------------------------*/"<<endl;
			//cin>>xxx;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;

			struct my_hdr tmphdr_conf;
			tmphdr_conf.tmp = (uint8_t)(((tmp_id+1)<<4)+1);
			tmphdr_conf.packet_index = packet_index++;
			packet_num++;
			//printf("packet_num: %d\n",packet_num);
			tmphdr_conf.my_assigned = new_f.v_assigned[tmp_id];
			tmphdr_conf.my_value = new_f.v_value[tmp_id];
			tmphdr_conf.my_unit_variable_id = {{0x00,0x00,0x00,0x00}};
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<"/*---------------------------------------------------------*/"<<endl;
			//cout<<"line 643 debug, send and receive a packet, please input a literal to continue!\n";
			int my_start = clock();
			//printf("whether ther is a coflict!\n");
            //printf("697\n");
			send_receive_packet(tmphdr_conf);
            //printf("699\n");
			//cin>>cc;
			int my_end = clock();
			time_in_forward_packet += my_end - my_start;
			//cout<<"/*---------------------------------------------------------*/"<<endl;
			//cin>>xxx;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
			//cout<<endl;
	
			if((((tmphdr_conf.tmp)>>3)&1)==1)
			{
				//printf("line 658 find conflict!!!!,%02x th packet!\n",packet_index);
				tmp_flag = 0;
				break;
			}
		}
		if(tmp_flag==0)
		{
			continue;
		}
		if(new_f.literals[literal_count]==literal_count)
		{
			printf("sat!sat!sat!\n");
			//show_formula(new_f);
			return Cat::completed;
		}
		int my_result = dpll(new_f);
		if(my_result==Cat::completed)
		{
			return Cat::completed;
		}
	}
	return Cat::normal;


}

void string_2_charX(string str_s,const char* const_c_x)
{
	//string str_s = "nihao";
	//const char* const_c_x;
	const_c_x = str_s.c_str();
	//char *c_x = (char *)(const_c_x);
	//c_x = (char *)(const_c_x);
	//printf("\nstring -> char*\n");
	//printf("%s\n", c_x);
}


int main(int argc, char *argv[]) {
	char c;
	FILE *fp = NULL;
	//fp = fopen("result.txt", "w+");
	//fclose(fp);
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "initlize fail!");
	argc -= ret;
	argv += ret;
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	if (port_init(0,mbuf_pool) != 0)rte_exit(EXIT_FAILURE,"Cannot init port\n");
	
	Formula f;
	initialize(f);
	//show_initialize_formula(f);
	//cin>>c;
	int my_start = clock();
	//printf("进入算法\n");
	int result = dpll(f);
	//for(int i=0;i<10000;i++)printf("---\n");
	//printf("离开算法\n");
	if(result==Cat::normal||result==Cat::unsatisfied){
		printf("unsat\n");
	}
	int my_end = clock();
	//int ccc = 0;
	//int wca = clock();
	//for (long long i=0;i<2*packet_num;i++){
	//	int a = clock();
	//	int b = clock();
	//	ccc += b-a;
	//}
	//int wcb = clock();
	//double twc = double(wcb-wca)/CLOCKS_PER_SEC;
	//cout<<"the total time used in wc is:\n";
	//cout<<twc<<endl;
    

	cout<<"the total time used is:\n";
	double t1 = (double)(my_end - my_start)/CLOCKS_PER_SEC;
	cout << t1 << endl;
	//cout<<"the total time used in print is:\n";
	//double tp = (double)time_in_print/CLOCKS_PER_SEC;
	//cout<<tp<<endl;


	//cout<<"the total time used in solve problem is:\n";
	//t1 = t1-tp-twc;
	//cout<<t1<<endl;


	cout<<"the total time used in forward packet is:\n";
	double t2 = (double)time_in_forward_packet/CLOCKS_PER_SEC;
	//t2 = t2 - tp-twc;
	cout<< t2 <<endl;
	cout<<"t2/t1: "<<t2/t1<<endl;
	cout<<"packet_index:\n"<<(int)(packet_index)<<endl;
	cout<<"packet_num:"<<packet_num<<endl;
	cout<<"t2/packet_num: "<<t2/packet_num<<endl;
	string s = to_string(int(t1*1000000))+"\n";
	string s2 = to_string(int(t2*1000000))+"\n";
	string s3 = to_string(packet_num);
	//cout<<"s: "<<s<<endl;
	
	const char* str;
	const char* str2;
	const char* str3;
	
	str = s.c_str();
	str2 = s2.c_str();
	str3 = s3.c_str();
	//string_2_charX(s,str);
	//cout<<"str: "<<str<<endl;;
   	fp = fopen("result.txt", "w+");
   	fprintf(fp, str);
	fprintf(fp, str2);
	fprintf(fp,str3);

   	//fputs("This is testing for fputs...\n", fp);
	//fputs(t1, fp);
	   
   	fclose(fp);
	
	/*
	struct my_hdr hdr;
	hdr.tmp = 0x11;
	hdr.packet_index = packet_index++;
	for(int i=0;i<32;i++)
	{
		hdr.my_assigned.assigned_bytes[i] = 0x00;
		hdr.my_value.value_bytes[i] = 0x00;
	}
	hdr.my_assigned.assigned_bytes[31] = 0x23;
	hdr.my_unit_variable_id = {{0x00,0x00,0x00,0x00}};
	send_receive_packet(hdr);
	*/
	rte_eal_cleanup();
	return 0;
}