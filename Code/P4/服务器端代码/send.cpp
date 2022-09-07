/*-
This program is to send a Ether packet to another server.
Author : Hox Zheng
Date : 2017年 12月 31日 星期日 15:21:04 CST
 */
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
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 4
using namespace std;
int literal_count = 0;
int clause_count = 0;
uint8_t packet_index = 0;
int packet_num = 0;
int time_in_forward_packet = 0;
vector<vector<int> > clauses;
vector<int> literal_polarity;
vector<vector<int> > table;
vector<vector<int> > variables;
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
struct two_bytes{
    uint8_t bytes[2];
};
struct four_bytes{
    uint8_t bytes[4];
};
struct p4_sat_hdr{
    uint8_t if_continue;
    uint8_t if_conflict;
    uint8_t if_have_check_data;
    uint8_t value_to_set;
    uint8_t find_or_unit;
    uint8_t op;
    uint8_t if_op_done;
    uint8_t table_index;
    uint8_t segment_index;
    uint8_t position_index;
    struct two_bytes id_now;
    struct two_bytes id_all;
    struct two_bytes layer;
    struct two_bytes help;
    struct two_bytes clause_id;
};
struct p4_sat_data_hdr{
    struct four_bytes value;
    struct four_bytes assigned;
    uint8_t tmp;
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
	const uint16_t rx_rings = 1, tx_rings = 1;
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
	int aflag = 1;
	while(aflag){
		uint16_t nb_tx = rte_eth_tx_burst(0,0,pkt,BURST_SIZE);
		//cout<<"nb_tx:"<<nb_tx<<endl;
		if(nb_tx>0){
			aflag=0;
			show_packet(myhdr,0);
		}
	}
	for(int i=0;i<BURST_SIZE;i++)
		rte_pktmbuf_free(pkt[i]);
	aflag = 1;
	while(aflag)
	{
		for(int i=0;i<BURST_SIZE;i++) {
			pkt[i] = rte_pktmbuf_alloc(mbuf_pool);
		}
		//从接受队列中取出包
		uint16_t nb_rx = rte_eth_rx_burst(0, 0,pkt,BURST_SIZE);
		//cout<<"nb_rx:"<<nb_rx<<endl;
		//cin>>aflag;
		if(nb_rx == 0)
		{
			continue;
		}
		for(int i=0;i<BURST_SIZE;i++)
		{
			myhdr = rte_pktmbuf_mtod_offset(pkt[i],struct my_hdr*,sizeof(struct rte_ether_hdr));
			//show_packet(myhdr,1);
			if(myhdr->packet_index==packet_index)
			{
				aflag=0;
				show_packet(myhdr,1);
				tmphdr.tmp = myhdr->tmp;
				tmphdr.packet_index = myhdr->packet_index;
				tmphdr.my_assigned = myhdr->my_assigned;
				tmphdr.my_value = myhdr->my_value;
				tmphdr.my_unit_variable_id = myhdr->my_unit_variable_id;
				break;
			}
		}
		for(int i=0;i<BURST_SIZE;i++)rte_pktmbuf_free(pkt[i]);
	}



}
void show_p4_sat(struct p4_sat_hdr *myhdr)
{
	printf("-------------------------------------\n");
	printf("p4_sat:\n");
	printf("if_continue:\n");
	printf("%d\n",(int)(myhdr->if_continue));
	printf("if_conflict:\n");
	printf("%d\n",(int)(myhdr->if_conflict));
	printf("if_have_check_data:\n");
	printf("%d\n",(int)(myhdr->if_have_check_data));
	printf("value_to_set:\n");
	printf("%d\n",(int)(myhdr->value_to_set));
	printf("find_or_unit:\n");
	printf("%d\n",(int)(myhdr->find_or_unit));
	printf("op:\n");
	printf("%d\n",(int)(myhdr->op));
	printf("if_op_done:\n");
	printf("%d\n",(int)(myhdr->if_op_done));
	printf("table_index:\n");
	printf("%d\n",(int)(myhdr->table_index));
	printf("segment_index:\n");
	printf("%d\n",(int)(myhdr->segment_index));
	printf("position_index:\n");
	printf("%d\n",(int)(myhdr->position_index));
	printf("id_now:\n");
	for(int i=0;i<2;i++){
		printf("%02x ",myhdr->id_now.bytes[i]);
	}
	printf("\n");
	printf("id_all:\n");
	for(int i=0;i<2;i++){
		printf("%02x ",myhdr->id_all.bytes[i]);
	}
	printf("\n");
	printf("layer:\n");
	for(int i=0;i<2;i++){
		printf("%02x ",myhdr->layer.bytes[i]);
	}
	printf("\n");
	printf("help:\n");
	for(int i=0;i<2;i++){
		printf("%02x ",myhdr->help.bytes[i]);
	}
	printf("\n");
	printf("clause_id:\n");
	for(int i=0;i<2;i++){
		printf("%02x ",myhdr->clause_id.bytes[i]);
	}
	printf("\n");
	printf("--------------------------------------\n");
}
/*
void show_p4_sat_data(struct p4_sat_date_hdr* myhdr)
{
	printf("-------------------------------------\n");
	printf("p4_sat_data:\n");
	printf("value:\n");
	for(int i=0;i<4;i++){
		printf("%02x ",myhdr->value.bytes[i]);
	}
	printf("\n");
	printf("assigned:\n");
	for(int i=0;i<4;i++){
		printf("%02x ",myhdr->assigned.bytes[i]);
	}
	printf("\n");
	printf("reverse:\n");
	printf("%d\n",(int)((myhdr->tmp)>>1));
	printf("if_have_check_data:\n");
	printf("%d\n",(int)((myhdr->tmp)&1));
	printf("--------------------------------------\n");
}*/
void s_r_packet(int literal_count)
{
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type = 0x5555;
    struct rte_mbuf *pkt[BURST_SIZE];
    struct p4_sat_hdr *myhdr;
    struct p4_sat_data_hdr *mysathdr[8];
    for(int i=0;i<BURST_SIZE;i++){
        pkt[i] = rte_pktmbuf_alloc(mbuf_pool);
        eth_hdr = rte_pktmbuf_mtod(pkt[i],struct rte_ether_hdr*);
        eth_hdr->ether_type = ether_type;
        myhdr = (struct p4_sat_hdr*)(rte_pktmbuf_mtod(pkt[i],char*)+sizeof(struct rte_ether_hdr));
        myhdr->op = 10;
        myhdr->if_have_check_data = 1;
        myhdr->table_index = 255;
        myhdr->layer = {{0x00,0x00}};
        myhdr->id_all = {{0x00,literal_count}};
		for(int j=0;j<8;j++)
		{
			mysathdr[j] = (struct p4_sat_data_hdr*)(rte_pktmbuf_mtod(pkt[i],char*)+sizeof(struct rte_ether_hdr)+sizeof(struct p4_sat_hdr)+j*sizeof(struct p4_sat_data_hdr));
			mysathdr[j]->value = {{0x00,0x00,0x00,0x00}};
			mysathdr[j]->assigned = {{0x00,0x00,0x00,0x00}};
			mysathdr[j]->tmp = 1;
		}
		mysathdr[7]->tmp = 0;
        int pkt_size = sizeof(struct rte_ether_hdr)+sizeof(struct p4_sat_hdr)+sizeof(struct p4_sat_data_hdr)*8;
		pkt[i]->data_len = pkt_size;
		pkt[i]->pkt_len = pkt_size;

		
    }
    int aflag = 1;
	while(aflag){
		uint16_t nb_tx = rte_eth_tx_burst(0,0,pkt,BURST_SIZE);
		//cout<<"nb_tx:"<<nb_tx<<endl;
		//cin>>aflag;
		if(nb_tx>0){
			aflag=0;
			//printf("send a packet!\n");
			//show_p4_sat(myhdr);
			/*
			for(int i=0;i<8;i++)
			{
				printf("-------------------------------------\n");
				printf("p4_sat_data%d:\n",i+1);
				printf("value:\n");
				for(int i=0;i<4;i++){
					printf("%02x ",mysathdr[i]->value.bytes[i]);
				}
				printf("\n");
				printf("assigned:\n");
				for(int i=0;i<4;i++){
					printf("%02x ",mysathdr[i]->assigned.bytes[i]);
				}
				printf("\n");
				printf("reverse:\n");
				printf("%d\n",(int)((mysathdr[i]->tmp)>>1));
				printf("if_have_check_data:\n");
				printf("%d\n",(int)((mysathdr[i]->tmp)&1));
				printf("--------------------------------------\n");
			}
			*/
			//show_p4_sat_data(mysathdr);
			//show_packet(myhdr,0);
		}
	}
    for(int i=0;i<BURST_SIZE;i++)
		rte_pktmbuf_free(pkt[i]);
	aflag = 1;
	//printf("\n");
	//printf("\n");
	//printf("\n");
	//printf("\n");
    while(aflag)
	{
		for(int i=0;i<BURST_SIZE;i++) {
			pkt[i] = rte_pktmbuf_alloc(mbuf_pool);
		}
		//从接受队列中取出包
		uint16_t nb_rx = rte_eth_rx_burst(0, 0,pkt,BURST_SIZE);
		//cout<<"nb_rx:"<<nb_rx<<endl;
		//cin>>aflag;
		if(nb_rx == 0)
		{
			continue;
		}

		for(int i=0;i<BURST_SIZE;i++)
		{
			myhdr = rte_pktmbuf_mtod_offset(pkt[i],struct p4_sat_hdr*,sizeof(struct rte_ether_hdr));
			for(int j=0;j<8;j++)
			{
				mysathdr[j] = rte_pktmbuf_mtod_offset(pkt[i],struct p4_sat_data_hdr*,sizeof(struct rte_ether_hdr)+sizeof(struct p4_sat_hdr)+j*sizeof(struct p4_sat_data_hdr));
			}//show_packet(myhdr,1);
			//printf("receive a packet!\n");
			//show_p4_sat(myhdr);
			/*
			for(int j=0;j<8;j++)
			{
				printf("-------------------------------------\n");
				printf("p4_sat_data%d:\n",j+1);
				printf("value:\n");
				for(int i=0;i<4;i++){
					printf("%02x ",mysathdr[j]->value.bytes[i]);
				}
				printf("\n");
				printf("assigned:\n");
				for(int i=0;i<4;i++){
					printf("%02x ",mysathdr[j]->assigned.bytes[i]);
				}
				printf("\n");
				printf("reverse:\n");
				printf("%d\n",(int)((mysathdr[j]->tmp)>>1));
				printf("if_have_check_data:\n");
				printf("%d\n",(int)((mysathdr[j]->tmp)&1));
				printf("--------------------------------------\n");
			}
			*/
			//show_p4_sat_data(mysathdr);
			aflag=0;
			break;
		}
		for(int i=0;i<BURST_SIZE;i++)rte_pktmbuf_free(pkt[i]);
	}

}
int main(int argc, char *argv[]) {
	FILE *fp = NULL;
	fp = fopen("result.txt", "w+");
	fclose(fp);
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "initlize fail!");
	argc -= ret;
	argv += ret;
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	if (port_init(0,mbuf_pool) != 0)rte_exit(EXIT_FAILURE,"Cannot init port\n");
	/*
	Formula f;
	initialize(f);
	//show_initialize_formula(f);
	int my_start = clock();
	int result = dpll(f);
	if(result==Cat::normal||result==Cat::unsatisfied){
		printf("unsat\n");
	}
	int my_end = clock();
	cout<<"the total time used is:\n";
	double t1 = (double)(my_end - my_start)/CLOCKS_PER_SEC;
	cout << t1 << endl;
	cout<<"the total time used in forward packet is:\n";
	double t2 = (double)time_in_forward_packet/CLOCKS_PER_SEC;
	cout<< t2 <<endl;
	cout<<"t2/t1: "<<t2/t1<<endl;
	cout<<"packet_index:\n"<<(int)(packet_index)<<endl;
	cout<<"packet_num:"<<packet_num<<endl;
	cout<<"t2/packet_num: "<<t2/packet_num<<endl;
	*/
	
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
	char c;
	string s;
	int literal_count;
	while (true) {
		cin >> c;
		if (c == 'c')getline(cin, s);
		else {
			cin >> s;
			break;
		}
	}
	cin >> literal_count;
	//printf("literal_count:%d\n",literal_count);
	//cin >> clause_count;

	double t1 = 0;
	for(int i=0;i<1;i++){
    int my_start = clock();
    s_r_packet(literal_count);
	int my_end = clock();

	t1 += (double)(my_end - my_start)/CLOCKS_PER_SEC;
	//cout<<"t: "<<t1<<endl;
	}
	t1 = t1/1;
	s = to_string(int(t1*1000000000))+"\n";
	const char* str;
	str = s.c_str();
	fp = fopen("result.txt", "w+");
   	fprintf(fp, str);
	fclose(fp);
	rte_eal_cleanup();
	return 0;
}