#include <core.p4>
#include <tna.p4>
#include "const_state.p4"

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86DD;
const bit<16> ETHERTYPE_P4SA = 0x5555;
const bit<32> ONE  = 1;
const bit<32> ZERO = 0;



const int  ipv4_mask_length = 24;
const int  ipv4_length = 32;
const int  sharing_ratio = 256;
const int  M = 4;
const int  m = 2;


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
header ethernet_t {
    bit<48>  dst_addr;
    bit<48>  src_addr;
    bit<16>  ether_type;
}

header formula_t {					/*总包头，用以记录各式数据*/
    bit<8>  if_continue;			/*是否继续*/
    bit<8>  if_conflict;			/*是否冲突*/
    bit<8>  if_have_check_data;		/*后接包是否是匹配字段*/
    bit<8>  value_to_set;			/*赋值0还是赋值1*/
    bit<8>  find_or_unit;			/*是find还是unit*/
    bit<8>  op;						/*操作码*/
	bit<4>  mode_switch;			/*模式选码*/
	bit<4>  if_op_done;				/*当前op是否操作完成？0是没完成*/
	bit<8>  table_index;			/*表索引*/
    bit<8>  segment_index;			/*段索引*/
    bit<8>  position_index;			/*位索引*/
    bit<16> id_now;					/*当前变量*/
    bit<16> id_all;					/*有多少变量*/
    bit<16> layer;					/*当前层*/
	bit<16> help;					/*运算辅助装置*/
	bit<16> clause_id;				/*运算辅助装置*/
	bit<16> id;
}

header formula_data_t {				/*匹配字段包*/
    bit<32> value;					/*value*/
    bit<32> assigned;				/*assigned*/
    bit<8>  if_have_check_data;		/*后续数据*/
}

header formula_data_cir_t {				/*匹配字段包*/
    bit<16> k_10;					
    bit<16> k_11;					
    bit<16> k_12;					
    bit<16> k_30;					
    bit<16> k_31;					
    bit<16> k_32;					
    bit<16> k_33;					
    bit<16> k_34;					
    bit<16> k_100;					
    bit<16> k_101;					
    bit<16> k_102;					
    bit<16> k_200;					
    bit<16> k_201;					
    bit<16> k_202;					
}

header formula_position_t {			/*索引包*/
	bit<8> segment;					/*指明是表的哪一段*/
	bit<8> position;				/*指明是段的哪一位*/
}


header back_track_t {		
	bit<16> id;
	bit<16> target;			
	bit<16> h1;				
	bit<16> h2;				
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
 
 
/***********************  H E A D E R S  ************************/


struct headers {
    ethernet_t     ethernet;
    formula_t      formula;
    formula_data_t[8] formula_data;
    formula_data_cir_t formula_data_cir;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
	back_track_t back_track;
}

/***********************  P A R S E R  **************************/

parser IngressParser(packet_in      pkt,
    out headers          hdr,
    out my_ingress_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_P4SA :  parse_p4sat;
            default        :  accept;
        }
    }
	
	state parse_p4sat {
        pkt.extract(hdr.formula);
        transition select(hdr.formula.if_have_check_data) {
            1 : parse_p4_run_data;
            default: accept;
        }
    }
	
    state parse_p4_run_data {
        pkt.extract(hdr.formula_data.next);
        transition select(hdr.formula_data.last.if_have_check_data) {
            1 :  parse_p4_run_data;
			2 :  parse_p4_cir_data;
            default: accept;
        }
    }
	
	state parse_p4_cir_data {
        pkt.extract(hdr.formula_data_cir);
		transition accept;
    }
	
}


/***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout headers                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
	//*************这里往下是stage0的东西*************************//
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action l3_switch(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.formula.id_now  = hdr.formula.id_now + 1;
    }

	action action_conflict(bit<16> clause_id) {
        hdr.formula.if_conflict = 1;
        hdr.formula.if_continue = 0;
		hdr.formula.clause_id = clause_id;
    }
	
	action action_continue() {
        hdr.formula.if_conflict = 0;
        hdr.formula.if_continue = 1;
    }
	
	action action_no_action(){
		hdr.formula.if_conflict = hdr.formula.if_conflict;
	}
	
	action action_alu_help_0_0(bit<32> number) {
		hdr.formula_data[0].assigned = hdr.formula_data[0].assigned | number;
	}
	
	action action_alu_help_0_1(bit<32> number) {
		hdr.formula_data[0].assigned = hdr.formula_data[0].assigned | number;
		hdr.formula_data[0].value    = hdr.formula_data[0].value    | number;
	}
	
	action action_alu_help_1_0(bit<32> number) {
		hdr.formula_data[1].assigned = hdr.formula_data[1].assigned | number;
	}
	
	action action_alu_help_1_1(bit<32> number) {
		hdr.formula_data[1].assigned = hdr.formula_data[1].assigned | number;
		hdr.formula_data[1].value    = hdr.formula_data[1].value    | number;
	}
	
	action action_alu_help_2_0(bit<32> number) {
		hdr.formula_data[2].assigned = hdr.formula_data[2].assigned | number;
	}
	
	action action_alu_help_2_1(bit<32> number) {
		hdr.formula_data[2].assigned = hdr.formula_data[2].assigned | number;
		hdr.formula_data[2].value    = hdr.formula_data[2].value    | number;
	}
	
	action action_alu_help_3_0(bit<32> number) {
		hdr.formula_data[3].assigned = hdr.formula_data[3].assigned | number;
	}
	
	action action_alu_help_3_1(bit<32> number) {
		hdr.formula_data[3].assigned = hdr.formula_data[3].assigned | number;
		hdr.formula_data[3].value    = hdr.formula_data[3].value    | number;
	}
	
	action action_alu_help_4_0(bit<32> number) {
		hdr.formula_data[4].assigned = hdr.formula_data[4].assigned | number;
	}
	
	action action_alu_help_4_1(bit<32> number) {
		hdr.formula_data[4].assigned = hdr.formula_data[4].assigned | number;
		hdr.formula_data[4].value    = hdr.formula_data[4].value    | number;
	}

	action action_alu_help_5_0(bit<32> number) {
		hdr.formula_data[5].assigned = hdr.formula_data[5].assigned | number;
	}
	
	action action_alu_help_5_1(bit<32> number) {
		hdr.formula_data[5].assigned = hdr.formula_data[5].assigned | number;
		hdr.formula_data[5].value    = hdr.formula_data[5].value    | number;
	}
	
	action action_alu_help_6_0(bit<32> number) {
		hdr.formula_data[6].assigned = hdr.formula_data[6].assigned | number;
	}
	
	action action_alu_help_6_1(bit<32> number) {
		hdr.formula_data[6].assigned = hdr.formula_data[6].assigned | number;
		hdr.formula_data[6].value    = hdr.formula_data[6].value    | number;
	}
	
	action action_alu_help_7_0(bit<32> number) {
		hdr.formula_data[7].assigned = hdr.formula_data[7].assigned | number;
	}
	
	action action_alu_help_7_1(bit<32> number) {
		hdr.formula_data[7].assigned = hdr.formula_data[7].assigned | number;
		hdr.formula_data[7].value    = hdr.formula_data[7].value    | number;
	}
	
	table table_alu_help{
		key = {
			hdr.formula.segment_index  : exact;
			hdr.formula.position_index : exact;
			hdr.formula.value_to_set   : exact;
		}
		actions = {
			action_alu_help_0_0;
			action_alu_help_0_1;
			action_alu_help_1_0;
			action_alu_help_1_1;
			action_alu_help_2_0;
			action_alu_help_2_1;
			action_alu_help_3_0;
			action_alu_help_3_1;
			action_alu_help_4_0;
			action_alu_help_4_1;
			action_alu_help_5_0;
			action_alu_help_5_1;
			action_alu_help_6_0;
			action_alu_help_6_1;
			action_alu_help_7_0;
			action_alu_help_7_1;
            @defaultonly action_no_action;
        }
		const entries=
		{
			(0, 0,0):action_alu_help_0_0(number__0);
			(0, 0,1):action_alu_help_0_1(number__0);
			(0, 1,0):action_alu_help_0_0(number__1);
			(0, 1,1):action_alu_help_0_1(number__1);
			(0, 2,0):action_alu_help_0_0(number__2);
			(0, 2,1):action_alu_help_0_1(number__2);
			(0, 3,0):action_alu_help_0_0(number__3);
			(0, 3,1):action_alu_help_0_1(number__3);
			(0, 4,0):action_alu_help_0_0(number__4);
			(0, 4,1):action_alu_help_0_1(number__4);
			(0, 5,0):action_alu_help_0_0(number__5);
			(0, 5,1):action_alu_help_0_1(number__5);
			(0, 6,0):action_alu_help_0_0(number__6);
			(0, 6,1):action_alu_help_0_1(number__6);
			(0, 7,0):action_alu_help_0_0(number__7);
			(0, 7,1):action_alu_help_0_1(number__7);
			(0, 8,0):action_alu_help_0_0(number__8);
			(0, 8,1):action_alu_help_0_1(number__8);
			(0, 9,0):action_alu_help_0_0(number__9);
			(0, 9,1):action_alu_help_0_1(number__9);
			(0,10,0):action_alu_help_0_0(number_10);
			(0,10,1):action_alu_help_0_1(number_10);
			(0,11,0):action_alu_help_0_0(number_11);
			(0,11,1):action_alu_help_0_1(number_11);
			(0,12,0):action_alu_help_0_0(number_12);
			(0,12,1):action_alu_help_0_1(number_12);
			(0,13,0):action_alu_help_0_0(number_13);
			(0,13,1):action_alu_help_0_1(number_13);
			(0,14,0):action_alu_help_0_0(number_14);
			(0,14,1):action_alu_help_0_1(number_14);
			(0,15,0):action_alu_help_0_0(number_15);
			(0,15,1):action_alu_help_0_1(number_15);
			(0,16,0):action_alu_help_0_0(number_16);
			(0,16,1):action_alu_help_0_1(number_16);
			(0,17,0):action_alu_help_0_0(number_17);
			(0,17,1):action_alu_help_0_1(number_17);
			(0,18,0):action_alu_help_0_0(number_18);
			(0,18,1):action_alu_help_0_1(number_18);
			(0,19,0):action_alu_help_0_0(number_19);
			(0,19,1):action_alu_help_0_1(number_19);
			(0,20,0):action_alu_help_0_0(number_20);
			(0,20,1):action_alu_help_0_1(number_20);
			(0,21,0):action_alu_help_0_0(number_21);
			(0,21,1):action_alu_help_0_1(number_21);
			(0,22,0):action_alu_help_0_0(number_22);
			(0,22,1):action_alu_help_0_1(number_22);
			(0,23,0):action_alu_help_0_0(number_23);
			(0,23,1):action_alu_help_0_1(number_23);
			(0,24,0):action_alu_help_0_0(number_24);
			(0,24,1):action_alu_help_0_1(number_24);
			(0,25,0):action_alu_help_0_0(number_25);
			(0,25,1):action_alu_help_0_1(number_25);
			(0,26,0):action_alu_help_0_0(number_26);
			(0,26,1):action_alu_help_0_1(number_26);
			(0,27,0):action_alu_help_0_0(number_27);
			(0,27,1):action_alu_help_0_1(number_27);
			(0,28,0):action_alu_help_0_0(number_28);
			(0,28,1):action_alu_help_0_1(number_28);
			(0,29,0):action_alu_help_0_0(number_29);
			(0,29,1):action_alu_help_0_1(number_29);
			(0,30,0):action_alu_help_0_0(number_30);
			(0,30,1):action_alu_help_0_1(number_30);
			(0,31,0):action_alu_help_0_0(number_31);
			(0,31,1):action_alu_help_0_1(number_31);
			(1, 0,0):action_alu_help_1_0(number__0);
			(1, 0,1):action_alu_help_1_1(number__0);
			(1, 1,0):action_alu_help_1_0(number__1);
			(1, 1,1):action_alu_help_1_1(number__1);
			(1, 2,0):action_alu_help_1_0(number__2);
			(1, 2,1):action_alu_help_1_1(number__2);
			(1, 3,0):action_alu_help_1_0(number__3);
			(1, 3,1):action_alu_help_1_1(number__3);
			(1, 4,0):action_alu_help_1_0(number__4);
			(1, 4,1):action_alu_help_1_1(number__4);
			(1, 5,0):action_alu_help_1_0(number__5);
			(1, 5,1):action_alu_help_1_1(number__5);
			(1, 6,0):action_alu_help_1_0(number__6);
			(1, 6,1):action_alu_help_1_1(number__6);
			(1, 7,0):action_alu_help_1_0(number__7);
			(1, 7,1):action_alu_help_1_1(number__7);
			(1, 8,0):action_alu_help_1_0(number__8);
			(1, 8,1):action_alu_help_1_1(number__8);
			(1, 9,0):action_alu_help_1_0(number__9);
			(1, 9,1):action_alu_help_1_1(number__9);
			(1,10,0):action_alu_help_1_0(number_10);
			(1,10,1):action_alu_help_1_1(number_10);
			(1,11,0):action_alu_help_1_0(number_11);
			(1,11,1):action_alu_help_1_1(number_11);
			(1,12,0):action_alu_help_1_0(number_12);
			(1,12,1):action_alu_help_1_1(number_12);
			(1,13,0):action_alu_help_1_0(number_13);
			(1,13,1):action_alu_help_1_1(number_13);
			(1,14,0):action_alu_help_1_0(number_14);
			(1,14,1):action_alu_help_1_1(number_14);
			(1,15,0):action_alu_help_1_0(number_15);
			(1,15,1):action_alu_help_1_1(number_15);
			(1,16,0):action_alu_help_1_0(number_16);
			(1,16,1):action_alu_help_1_1(number_16);
			(1,17,0):action_alu_help_1_0(number_17);
			(1,17,1):action_alu_help_1_1(number_17);
			(1,18,0):action_alu_help_1_0(number_18);
			(1,18,1):action_alu_help_1_1(number_18);
			(1,19,0):action_alu_help_1_0(number_19);
			(1,19,1):action_alu_help_1_1(number_19);
			(1,20,0):action_alu_help_1_0(number_20);
			(1,20,1):action_alu_help_1_1(number_20);
			(1,21,0):action_alu_help_1_0(number_21);
			(1,21,1):action_alu_help_1_1(number_21);
			(1,22,0):action_alu_help_1_0(number_22);
			(1,22,1):action_alu_help_1_1(number_22);
			(1,23,0):action_alu_help_1_0(number_23);
			(1,23,1):action_alu_help_1_1(number_23);
			(1,24,0):action_alu_help_1_0(number_24);
			(1,24,1):action_alu_help_1_1(number_24);
			(1,25,0):action_alu_help_1_0(number_25);
			(1,25,1):action_alu_help_1_1(number_25);
			(1,26,0):action_alu_help_1_0(number_26);
			(1,26,1):action_alu_help_1_1(number_26);
			(1,27,0):action_alu_help_1_0(number_27);
			(1,27,1):action_alu_help_1_1(number_27);
			(1,28,0):action_alu_help_1_0(number_28);
			(1,28,1):action_alu_help_1_1(number_28);
			(1,29,0):action_alu_help_1_0(number_29);
			(1,29,1):action_alu_help_1_1(number_29);
			(1,30,0):action_alu_help_1_0(number_30);
			(1,30,1):action_alu_help_1_1(number_30);
			(1,31,0):action_alu_help_1_0(number_31);
			(1,31,1):action_alu_help_1_1(number_31);
			(2, 0,0):action_alu_help_2_0(number__0);
			(2, 0,1):action_alu_help_2_1(number__0);
			(2, 1,0):action_alu_help_2_0(number__1);
			(2, 1,1):action_alu_help_2_1(number__1);
			(2, 2,0):action_alu_help_2_0(number__2);
			(2, 2,1):action_alu_help_2_1(number__2);
			(2, 3,0):action_alu_help_2_0(number__3);
			(2, 3,1):action_alu_help_2_1(number__3);
			(2, 4,0):action_alu_help_2_0(number__4);
			(2, 4,1):action_alu_help_2_1(number__4);
			(2, 5,0):action_alu_help_2_0(number__5);
			(2, 5,1):action_alu_help_2_1(number__5);
			(2, 6,0):action_alu_help_2_0(number__6);
			(2, 6,1):action_alu_help_2_1(number__6);
			(2, 7,0):action_alu_help_2_0(number__7);
			(2, 7,1):action_alu_help_2_1(number__7);
			(2, 8,0):action_alu_help_2_0(number__8);
			(2, 8,1):action_alu_help_2_1(number__8);
			(2, 9,0):action_alu_help_2_0(number__9);
			(2, 9,1):action_alu_help_2_1(number__9);
			(2,10,0):action_alu_help_2_0(number_10);
			(2,10,1):action_alu_help_2_1(number_10);
			(2,11,0):action_alu_help_2_0(number_11);
			(2,11,1):action_alu_help_2_1(number_11);
			(2,12,0):action_alu_help_2_0(number_12);
			(2,12,1):action_alu_help_2_1(number_12);
			(2,13,0):action_alu_help_2_0(number_13);
			(2,13,1):action_alu_help_2_1(number_13);
			(2,14,0):action_alu_help_2_0(number_14);
			(2,14,1):action_alu_help_2_1(number_14);
			(2,15,0):action_alu_help_2_0(number_15);
			(2,15,1):action_alu_help_2_1(number_15);
			(2,16,0):action_alu_help_2_0(number_16);
			(2,16,1):action_alu_help_2_1(number_16);
			(2,17,0):action_alu_help_2_0(number_17);
			(2,17,1):action_alu_help_2_1(number_17);
			(2,18,0):action_alu_help_2_0(number_18);
			(2,18,1):action_alu_help_2_1(number_18);
			(2,19,0):action_alu_help_2_0(number_19);
			(2,19,1):action_alu_help_2_1(number_19);
			(2,20,0):action_alu_help_2_0(number_20);
			(2,20,1):action_alu_help_2_1(number_20);
			(2,21,0):action_alu_help_2_0(number_21);
			(2,21,1):action_alu_help_2_1(number_21);
			(2,22,0):action_alu_help_2_0(number_22);
			(2,22,1):action_alu_help_2_1(number_22);
			(2,23,0):action_alu_help_2_0(number_23);
			(2,23,1):action_alu_help_2_1(number_23);
			(2,24,0):action_alu_help_2_0(number_24);
			(2,24,1):action_alu_help_2_1(number_24);
			(2,25,0):action_alu_help_2_0(number_25);
			(2,25,1):action_alu_help_2_1(number_25);
			(2,26,0):action_alu_help_2_0(number_26);
			(2,26,1):action_alu_help_2_1(number_26);
			(2,27,0):action_alu_help_2_0(number_27);
			(2,27,1):action_alu_help_2_1(number_27);
			(2,28,0):action_alu_help_2_0(number_28);
			(2,28,1):action_alu_help_2_1(number_28);
			(2,29,0):action_alu_help_2_0(number_29);
			(2,29,1):action_alu_help_2_1(number_29);
			(2,30,0):action_alu_help_2_0(number_30);
			(2,30,1):action_alu_help_2_1(number_30);
			(2,31,0):action_alu_help_2_0(number_31);
			(2,31,1):action_alu_help_2_1(number_31);
			(3, 0,0):action_alu_help_3_0(number__0);
			(3, 0,1):action_alu_help_3_1(number__0);
			(3, 1,0):action_alu_help_3_0(number__1);
			(3, 1,1):action_alu_help_3_1(number__1);
			(3, 2,0):action_alu_help_3_0(number__2);
			(3, 2,1):action_alu_help_3_1(number__2);
			(3, 3,0):action_alu_help_3_0(number__3);
			(3, 3,1):action_alu_help_3_1(number__3);
			(3, 4,0):action_alu_help_3_0(number__4);
			(3, 4,1):action_alu_help_3_1(number__4);
			(3, 5,0):action_alu_help_3_0(number__5);
			(3, 5,1):action_alu_help_3_1(number__5);
			(3, 6,0):action_alu_help_3_0(number__6);
			(3, 6,1):action_alu_help_3_1(number__6);
			(3, 7,0):action_alu_help_3_0(number__7);
			(3, 7,1):action_alu_help_3_1(number__7);
			(3, 8,0):action_alu_help_3_0(number__8);
			(3, 8,1):action_alu_help_3_1(number__8);
			(3, 9,0):action_alu_help_3_0(number__9);
			(3, 9,1):action_alu_help_3_1(number__9);
			(3,10,0):action_alu_help_3_0(number_10);
			(3,10,1):action_alu_help_3_1(number_10);
			(3,11,0):action_alu_help_3_0(number_11);
			(3,11,1):action_alu_help_3_1(number_11);
			(3,12,0):action_alu_help_3_0(number_12);
			(3,12,1):action_alu_help_3_1(number_12);
			(3,13,0):action_alu_help_3_0(number_13);
			(3,13,1):action_alu_help_3_1(number_13);
			(3,14,0):action_alu_help_3_0(number_14);
			(3,14,1):action_alu_help_3_1(number_14);
			(3,15,0):action_alu_help_3_0(number_15);
			(3,15,1):action_alu_help_3_1(number_15);
			(3,16,0):action_alu_help_3_0(number_16);
			(3,16,1):action_alu_help_3_1(number_16);
			(3,17,0):action_alu_help_3_0(number_17);
			(3,17,1):action_alu_help_3_1(number_17);
			(3,18,0):action_alu_help_3_0(number_18);
			(3,18,1):action_alu_help_3_1(number_18);
			(3,19,0):action_alu_help_3_0(number_19);
			(3,19,1):action_alu_help_3_1(number_19);
			(3,20,0):action_alu_help_3_0(number_20);
			(3,20,1):action_alu_help_3_1(number_20);
			(3,21,0):action_alu_help_3_0(number_21);
			(3,21,1):action_alu_help_3_1(number_21);
			(3,22,0):action_alu_help_3_0(number_22);
			(3,22,1):action_alu_help_3_1(number_22);
			(3,23,0):action_alu_help_3_0(number_23);
			(3,23,1):action_alu_help_3_1(number_23);
			(3,24,0):action_alu_help_3_0(number_24);
			(3,24,1):action_alu_help_3_1(number_24);
			(3,25,0):action_alu_help_3_0(number_25);
			(3,25,1):action_alu_help_3_1(number_25);
			(3,26,0):action_alu_help_3_0(number_26);
			(3,26,1):action_alu_help_3_1(number_26);
			(3,27,0):action_alu_help_3_0(number_27);
			(3,27,1):action_alu_help_3_1(number_27);
			(3,28,0):action_alu_help_3_0(number_28);
			(3,28,1):action_alu_help_3_1(number_28);
			(3,29,0):action_alu_help_3_0(number_29);
			(3,29,1):action_alu_help_3_1(number_29);
			(3,30,0):action_alu_help_3_0(number_30);
			(3,30,1):action_alu_help_3_1(number_30);
			(3,31,0):action_alu_help_3_0(number_31);
			(3,31,1):action_alu_help_3_1(number_31);
			(4, 0,0):action_alu_help_4_0(number__0);
			(4, 0,1):action_alu_help_4_1(number__0);
			(4, 1,0):action_alu_help_4_0(number__1);
			(4, 1,1):action_alu_help_4_1(number__1);
			(4, 2,0):action_alu_help_4_0(number__2);
			(4, 2,1):action_alu_help_4_1(number__2);
			(4, 3,0):action_alu_help_4_0(number__3);
			(4, 3,1):action_alu_help_4_1(number__3);
			(4, 4,0):action_alu_help_4_0(number__4);
			(4, 4,1):action_alu_help_4_1(number__4);
			(4, 5,0):action_alu_help_4_0(number__5);
			(4, 5,1):action_alu_help_4_1(number__5);
			(4, 6,0):action_alu_help_4_0(number__6);
			(4, 6,1):action_alu_help_4_1(number__6);
			(4, 7,0):action_alu_help_4_0(number__7);
			(4, 7,1):action_alu_help_4_1(number__7);
			(4, 8,0):action_alu_help_4_0(number__8);
			(4, 8,1):action_alu_help_4_1(number__8);
			(4, 9,0):action_alu_help_4_0(number__9);
			(4, 9,1):action_alu_help_4_1(number__9);
			(4,10,0):action_alu_help_4_0(number_10);
			(4,10,1):action_alu_help_4_1(number_10);
			(4,11,0):action_alu_help_4_0(number_11);
			(4,11,1):action_alu_help_4_1(number_11);
			(4,12,0):action_alu_help_4_0(number_12);
			(4,12,1):action_alu_help_4_1(number_12);
			(4,13,0):action_alu_help_4_0(number_13);
			(4,13,1):action_alu_help_4_1(number_13);
			(4,14,0):action_alu_help_4_0(number_14);
			(4,14,1):action_alu_help_4_1(number_14);
			(4,15,0):action_alu_help_4_0(number_15);
			(4,15,1):action_alu_help_4_1(number_15);
			(4,16,0):action_alu_help_4_0(number_16);
			(4,16,1):action_alu_help_4_1(number_16);
			(4,17,0):action_alu_help_4_0(number_17);
			(4,17,1):action_alu_help_4_1(number_17);
			(4,18,0):action_alu_help_4_0(number_18);
			(4,18,1):action_alu_help_4_1(number_18);
			(4,19,0):action_alu_help_4_0(number_19);
			(4,19,1):action_alu_help_4_1(number_19);
			(4,20,0):action_alu_help_4_0(number_20);
			(4,20,1):action_alu_help_4_1(number_20);
			(4,21,0):action_alu_help_4_0(number_21);
			(4,21,1):action_alu_help_4_1(number_21);
			(4,22,0):action_alu_help_4_0(number_22);
			(4,22,1):action_alu_help_4_1(number_22);
			(4,23,0):action_alu_help_4_0(number_23);
			(4,23,1):action_alu_help_4_1(number_23);
			(4,24,0):action_alu_help_4_0(number_24);
			(4,24,1):action_alu_help_4_1(number_24);
			(4,25,0):action_alu_help_4_0(number_25);
			(4,25,1):action_alu_help_4_1(number_25);
			(4,26,0):action_alu_help_4_0(number_26);
			(4,26,1):action_alu_help_4_1(number_26);
			(4,27,0):action_alu_help_4_0(number_27);
			(4,27,1):action_alu_help_4_1(number_27);
			(4,28,0):action_alu_help_4_0(number_28);
			(4,28,1):action_alu_help_4_1(number_28);
			(4,29,0):action_alu_help_4_0(number_29);
			(4,29,1):action_alu_help_4_1(number_29);
			(4,30,0):action_alu_help_4_0(number_30);
			(4,30,1):action_alu_help_4_1(number_30);
			(4,31,0):action_alu_help_4_0(number_31);
			(4,31,1):action_alu_help_4_1(number_31);
			(5, 0,0):action_alu_help_5_0(number__0);
			(5, 0,1):action_alu_help_5_1(number__0);
			(5, 1,0):action_alu_help_5_0(number__1);
			(5, 1,1):action_alu_help_5_1(number__1);
			(5, 2,0):action_alu_help_5_0(number__2);
			(5, 2,1):action_alu_help_5_1(number__2);
			(5, 3,0):action_alu_help_5_0(number__3);
			(5, 3,1):action_alu_help_5_1(number__3);
			(5, 4,0):action_alu_help_5_0(number__4);
			(5, 4,1):action_alu_help_5_1(number__4);
			(5, 5,0):action_alu_help_5_0(number__5);
			(5, 5,1):action_alu_help_5_1(number__5);
			(5, 6,0):action_alu_help_5_0(number__6);
			(5, 6,1):action_alu_help_5_1(number__6);
			(5, 7,0):action_alu_help_5_0(number__7);
			(5, 7,1):action_alu_help_5_1(number__7);
			(5, 8,0):action_alu_help_5_0(number__8);
			(5, 8,1):action_alu_help_5_1(number__8);
			(5, 9,0):action_alu_help_5_0(number__9);
			(5, 9,1):action_alu_help_5_1(number__9);
			(5,10,0):action_alu_help_5_0(number_10);
			(5,10,1):action_alu_help_5_1(number_10);
			(5,11,0):action_alu_help_5_0(number_11);
			(5,11,1):action_alu_help_5_1(number_11);
			(5,12,0):action_alu_help_5_0(number_12);
			(5,12,1):action_alu_help_5_1(number_12);
			(5,13,0):action_alu_help_5_0(number_13);
			(5,13,1):action_alu_help_5_1(number_13);
			(5,14,0):action_alu_help_5_0(number_14);
			(5,14,1):action_alu_help_5_1(number_14);
			(5,15,0):action_alu_help_5_0(number_15);
			(5,15,1):action_alu_help_5_1(number_15);
			(5,16,0):action_alu_help_5_0(number_16);
			(5,16,1):action_alu_help_5_1(number_16);
			(5,17,0):action_alu_help_5_0(number_17);
			(5,17,1):action_alu_help_5_1(number_17);
			(5,18,0):action_alu_help_5_0(number_18);
			(5,18,1):action_alu_help_5_1(number_18);
			(5,19,0):action_alu_help_5_0(number_19);
			(5,19,1):action_alu_help_5_1(number_19);
			(5,20,0):action_alu_help_5_0(number_20);
			(5,20,1):action_alu_help_5_1(number_20);
			(5,21,0):action_alu_help_5_0(number_21);
			(5,21,1):action_alu_help_5_1(number_21);
			(5,22,0):action_alu_help_5_0(number_22);
			(5,22,1):action_alu_help_5_1(number_22);
			(5,23,0):action_alu_help_5_0(number_23);
			(5,23,1):action_alu_help_5_1(number_23);
			(5,24,0):action_alu_help_5_0(number_24);
			(5,24,1):action_alu_help_5_1(number_24);
			(5,25,0):action_alu_help_5_0(number_25);
			(5,25,1):action_alu_help_5_1(number_25);
			(5,26,0):action_alu_help_5_0(number_26);
			(5,26,1):action_alu_help_5_1(number_26);
			(5,27,0):action_alu_help_5_0(number_27);
			(5,27,1):action_alu_help_5_1(number_27);
			(5,28,0):action_alu_help_5_0(number_28);
			(5,28,1):action_alu_help_5_1(number_28);
			(5,29,0):action_alu_help_5_0(number_29);
			(5,29,1):action_alu_help_5_1(number_29);
			(5,30,0):action_alu_help_5_0(number_30);
			(5,30,1):action_alu_help_5_1(number_30);
			(5,31,0):action_alu_help_5_0(number_31);
			(5,31,1):action_alu_help_5_1(number_31);
			(6, 0,0):action_alu_help_6_0(number__0);
			(6, 0,1):action_alu_help_6_1(number__0);
			(6, 1,0):action_alu_help_6_0(number__1);
			(6, 1,1):action_alu_help_6_1(number__1);
			(6, 2,0):action_alu_help_6_0(number__2);
			(6, 2,1):action_alu_help_6_1(number__2);
			(6, 3,0):action_alu_help_6_0(number__3);
			(6, 3,1):action_alu_help_6_1(number__3);
			(6, 4,0):action_alu_help_6_0(number__4);
			(6, 4,1):action_alu_help_6_1(number__4);
			(6, 5,0):action_alu_help_6_0(number__5);
			(6, 5,1):action_alu_help_6_1(number__5);
			(6, 6,0):action_alu_help_6_0(number__6);
			(6, 6,1):action_alu_help_6_1(number__6);
			(6, 7,0):action_alu_help_6_0(number__7);
			(6, 7,1):action_alu_help_6_1(number__7);
			(6, 8,0):action_alu_help_6_0(number__8);
			(6, 8,1):action_alu_help_6_1(number__8);
			(6, 9,0):action_alu_help_6_0(number__9);
			(6, 9,1):action_alu_help_6_1(number__9);
			(6,10,0):action_alu_help_6_0(number_10);
			(6,10,1):action_alu_help_6_1(number_10);
			(6,11,0):action_alu_help_6_0(number_11);
			(6,11,1):action_alu_help_6_1(number_11);
			(6,12,0):action_alu_help_6_0(number_12);
			(6,12,1):action_alu_help_6_1(number_12);
			(6,13,0):action_alu_help_6_0(number_13);
			(6,13,1):action_alu_help_6_1(number_13);
			(6,14,0):action_alu_help_6_0(number_14);
			(6,14,1):action_alu_help_6_1(number_14);
			(6,15,0):action_alu_help_6_0(number_15);
			(6,15,1):action_alu_help_6_1(number_15);
			(6,16,0):action_alu_help_6_0(number_16);
			(6,16,1):action_alu_help_6_1(number_16);
			(6,17,0):action_alu_help_6_0(number_17);
			(6,17,1):action_alu_help_6_1(number_17);
			(6,18,0):action_alu_help_6_0(number_18);
			(6,18,1):action_alu_help_6_1(number_18);
			(6,19,0):action_alu_help_6_0(number_19);
			(6,19,1):action_alu_help_6_1(number_19);
			(6,20,0):action_alu_help_6_0(number_20);
			(6,20,1):action_alu_help_6_1(number_20);
			(6,21,0):action_alu_help_6_0(number_21);
			(6,21,1):action_alu_help_6_1(number_21);
			(6,22,0):action_alu_help_6_0(number_22);
			(6,22,1):action_alu_help_6_1(number_22);
			(6,23,0):action_alu_help_6_0(number_23);
			(6,23,1):action_alu_help_6_1(number_23);
			(6,24,0):action_alu_help_6_0(number_24);
			(6,24,1):action_alu_help_6_1(number_24);
			(6,25,0):action_alu_help_6_0(number_25);
			(6,25,1):action_alu_help_6_1(number_25);
			(6,26,0):action_alu_help_6_0(number_26);
			(6,26,1):action_alu_help_6_1(number_26);
			(6,27,0):action_alu_help_6_0(number_27);
			(6,27,1):action_alu_help_6_1(number_27);
			(6,28,0):action_alu_help_6_0(number_28);
			(6,28,1):action_alu_help_6_1(number_28);
			(6,29,0):action_alu_help_6_0(number_29);
			(6,29,1):action_alu_help_6_1(number_29);
			(6,30,0):action_alu_help_6_0(number_30);
			(6,30,1):action_alu_help_6_1(number_30);
			(6,31,0):action_alu_help_6_0(number_31);
			(6,31,1):action_alu_help_6_1(number_31);
			(7, 0,0):action_alu_help_7_0(number__0);
			(7, 0,1):action_alu_help_7_1(number__0);
			(7, 1,0):action_alu_help_7_0(number__1);
			(7, 1,1):action_alu_help_7_1(number__1);
			(7, 2,0):action_alu_help_7_0(number__2);
			(7, 2,1):action_alu_help_7_1(number__2);
			(7, 3,0):action_alu_help_7_0(number__3);
			(7, 3,1):action_alu_help_7_1(number__3);
			(7, 4,0):action_alu_help_7_0(number__4);
			(7, 4,1):action_alu_help_7_1(number__4);
			(7, 5,0):action_alu_help_7_0(number__5);
			(7, 5,1):action_alu_help_7_1(number__5);
			(7, 6,0):action_alu_help_7_0(number__6);
			(7, 6,1):action_alu_help_7_1(number__6);
			(7, 7,0):action_alu_help_7_0(number__7);
			(7, 7,1):action_alu_help_7_1(number__7);
			(7, 8,0):action_alu_help_7_0(number__8);
			(7, 8,1):action_alu_help_7_1(number__8);
			(7, 9,0):action_alu_help_7_0(number__9);
			(7, 9,1):action_alu_help_7_1(number__9);
			(7,10,0):action_alu_help_7_0(number_10);
			(7,10,1):action_alu_help_7_1(number_10);
			(7,11,0):action_alu_help_7_0(number_11);
			(7,11,1):action_alu_help_7_1(number_11);
			(7,12,0):action_alu_help_7_0(number_12);
			(7,12,1):action_alu_help_7_1(number_12);
			(7,13,0):action_alu_help_7_0(number_13);
			(7,13,1):action_alu_help_7_1(number_13);
			(7,14,0):action_alu_help_7_0(number_14);
			(7,14,1):action_alu_help_7_1(number_14);
			(7,15,0):action_alu_help_7_0(number_15);
			(7,15,1):action_alu_help_7_1(number_15);
			(7,16,0):action_alu_help_7_0(number_16);
			(7,16,1):action_alu_help_7_1(number_16);
			(7,17,0):action_alu_help_7_0(number_17);
			(7,17,1):action_alu_help_7_1(number_17);
			(7,18,0):action_alu_help_7_0(number_18);
			(7,18,1):action_alu_help_7_1(number_18);
			(7,19,0):action_alu_help_7_0(number_19);
			(7,19,1):action_alu_help_7_1(number_19);
			(7,20,0):action_alu_help_7_0(number_20);
			(7,20,1):action_alu_help_7_1(number_20);
			(7,21,0):action_alu_help_7_0(number_21);
			(7,21,1):action_alu_help_7_1(number_21);
			(7,22,0):action_alu_help_7_0(number_22);
			(7,22,1):action_alu_help_7_1(number_22);
			(7,23,0):action_alu_help_7_0(number_23);
			(7,23,1):action_alu_help_7_1(number_23);
			(7,24,0):action_alu_help_7_0(number_24);
			(7,24,1):action_alu_help_7_1(number_24);
			(7,25,0):action_alu_help_7_0(number_25);
			(7,25,1):action_alu_help_7_1(number_25);
			(7,26,0):action_alu_help_7_0(number_26);
			(7,26,1):action_alu_help_7_1(number_26);
			(7,27,0):action_alu_help_7_0(number_27);
			(7,27,1):action_alu_help_7_1(number_27);
			(7,28,0):action_alu_help_7_0(number_28);
			(7,28,1):action_alu_help_7_1(number_28);
			(7,29,0):action_alu_help_7_0(number_29);
			(7,29,1):action_alu_help_7_1(number_29);
			(7,30,0):action_alu_help_7_0(number_30);
			(7,30,1):action_alu_help_7_1(number_30);
			(7,31,0):action_alu_help_7_0(number_31);
			(7,31,1):action_alu_help_7_1(number_31);
		}
        const default_action = action_no_action();
        size = 512;
	}
	
	table conflict_table_0{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
		/*const entries = {
			(  0 &&&   1,   1 &&&   1, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_conflict();
			(  0 &&&   2,   2 &&&   2, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_conflict();
		}*/
        const default_action = action_continue();
        size = conflict_table_size;
    }
	
	Register<bit<16>,bit<16>>(num_of_variable,1000) register_variable_record; 		/*这个是变量记录仪，记录了这个变量分配在哪一层，0意味着没分配*/
	RegisterAction<bit<16>, bit<16>, bit<16>>(register_variable_record) register_variable_record_read = { 
        void apply(inout bit<16> value_r, out bit<16> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<16>, bit<16>, bit<16>>(register_variable_record) register_variable_record_write = { 
        void apply(inout bit<16> value_r){ 
            value_r = hdr.formula.layer;
        } 
    };
	
	@pragma stage 0
	action action_table_index_read_0(){
		hdr.formula.help = hdr.formula.layer;
	}
	
	@pragma stage 0
	action action_table_index_read_1(){
		hdr.formula.help = hdr.formula.layer + 1025;
	}
	
	@pragma stage 0
	action action_table_index_read_2(){
		hdr.formula.help = hdr.formula.layer + 2050;
	}
	
	@pragma stage 0
	action action_table_index_read_0_plus(){
		hdr.formula.help = hdr.formula.layer + 1;
	}
	
	@pragma stage 0
	action action_table_index_read_1_plus(){
		hdr.formula.help = hdr.formula.layer + 1026;
	}
	
	@pragma stage 0
	action action_table_index_read_2_plus(){
		hdr.formula.help = hdr.formula.layer + 2051;
	}
	
	@pragma stage 0
	table table_calculate_table_index_read{
        key = { hdr.formula.table_index: 	exact;
				hdr.formula.find_or_unit: 	exact;}
        actions = {
			action_table_index_read_1;
			action_table_index_read_2;
            action_table_index_read_0;
			action_table_index_read_0_plus;
			action_table_index_read_1_plus;
			action_table_index_read_2_plus;
        }
		const entries = {
		(0,0):		action_table_index_read_0();
		(1,0):		action_table_index_read_1();
		(2,0):		action_table_index_read_2();
		(0,1):		action_table_index_read_0_plus();
		(1,1):		action_table_index_read_1_plus();
		(2,1):		action_table_index_read_2_plus();
		(10,0):		action_table_index_read_0_plus();
		(11,0):		action_table_index_read_1_plus();
		(12,0):		action_table_index_read_2_plus();
		(10,1):		action_table_index_read_0_plus();
		(11,1):		action_table_index_read_1_plus();
		(12,1):		action_table_index_read_2_plus();
		}
        const default_action = action_table_index_read_0();
        size = 12;
    }
	
	@pragma stage 0
	action action_table_index_write_0(){
		hdr.formula.id_now = hdr.formula.id_now;
		hdr.formula.help = hdr.formula.layer + 1;
	}
	
	@pragma stage 0
	action action_table_index_write_1(){
		hdr.formula.id_now = hdr.formula.id_now;
		hdr.formula.help = hdr.formula.layer + 1026;
	}
	
	@pragma stage 0
	action action_table_index_write_2(){
		hdr.formula.id_now = hdr.formula.id_now;
		hdr.formula.help = hdr.formula.layer + 2051;
	}
	
	@pragma stage 0
	table table_calculate_table_index_write{
        key = { hdr.formula.table_index: 	exact;}
        actions = {
			action_table_index_write_1;
			action_table_index_write_2;
            action_table_index_write_0;
        }
		const entries = {
		    0:		action_table_index_write_0();
		    1:		action_table_index_write_1();
		    2:		action_table_index_write_2();
		   10:		action_table_index_write_0();
		   11:		action_table_index_write_1();
		   12:		action_table_index_write_2();
		}
        const default_action = action_table_index_write_0();
        size = 6;
    }
	
	@pragma stage 0
	action action_register_variable_record_read(){
		hdr.formula.help = register_variable_record_read.execute(hdr.formula.id_now);
	}
	
	@pragma stage 0
	action action_register_variable_record_write(){
		register_variable_record_write.execute(hdr.formula.id_now);
	}
	
	@pragma stage 0
	table table_register_variable_record{
        key = { hdr.formula.op: 			exact;}
        actions = {
			action_register_variable_record_read;
			action_register_variable_record_write;
            action_no_action;
        }
		const entries = {
			FIND_ID_TO_SET:				action_register_variable_record_read();
			FIND_ID_TO_SET_DONE:		action_register_variable_record_write();
			UNIT_ID_SET:				action_register_variable_record_write();
		}
        const default_action = action_no_action();
        size = 3;
    }
	
	
	//*************这里往上是stage0的东西*************************//
	
	//*************这里往下是stage1的东西*************************//
	table conflict_table_1{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = conflict_table_size;
    }
	
	Register<bit<16>,bit<16>>(num_of_variable,0) register_layer_record; 		/*这个是层数记录仪，记录了这一层分配了什么变量*/
	RegisterAction<bit<16>, bit<16>, bit<16>>(register_layer_record) register_layer_record_read = { 
        void apply(inout bit<16> value_r, out bit<16> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<16>, bit<16>, bit<16>>(register_layer_record) register_layer_record_write = { 
        void apply(inout bit<16> value_r){ 
            value_r = hdr.formula.id_now;
        } 
    };
	
	@pragma stage 1
	action action_register_layer_record_read(){
		hdr.formula.id_now = register_layer_record_read.execute(hdr.formula.layer);
	}
	
	@pragma stage 1
	action action_register_layer_record_write(){
		register_layer_record_write.execute(hdr.formula.layer);
	}
	
	@pragma stage 1
	table table_register_layer_record{
        key = { hdr.formula.op: 	exact;}
        actions = {
			action_register_layer_record_read;
			action_register_layer_record_write;
            action_no_action;
        }
		const entries = {
			GO_BACK:					action_register_layer_record_read();
			GO_BACK_DONE:				action_register_layer_record_read();
			GO_BACK_TIME:				action_register_layer_record_read();
			FINISH_THIS_LAYER:			action_register_layer_record_read();
			FIND_ID_TO_SET_DONE:		action_register_layer_record_write();
		}
        const default_action = action_no_action();
        size = 5;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_0; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_0) register_conflict_table_value_0_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_0) register_conflict_table_value_0_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[0].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_0; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_0) register_conflict_table_assigned_0_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_0) register_conflict_table_assigned_0_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[0].assigned;
        } 
    };
	
	Register<bit<16>,bit<16>>(value_register_size,0) register_clause_head_to_v_id; 
	RegisterAction<bit<16>, bit<16>, bit<16>>(register_clause_head_to_v_id) register_clause_head_to_v_id_read = { 
        void apply(inout bit<16> value_r, out bit<16> read_value){ 
            read_value = value_r;
        } 
    }; 
	//*************这里往上是stage1的东西*************************//
	
	//*************这里往下是stage2的东西*************************//
	table conflict_table_2{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
		/*const entries = {
			(  0 &&& 128, 128 &&& 128, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_conflict();
			(128 &&& 128, 128 &&& 128, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_conflict();
		}*/
        const default_action = action_continue();
        size = conflict_table_size;
    }
	
	Register<bit<8>,bit<16>>(num_of_variable,0) register_value_record; 		/*这个是状态记录仪，记录了这个变量分配了什么值*/
	RegisterAction<bit<8>, bit<16>, bit<8>>(register_value_record) register_value_record_read = { 
        void apply(inout bit<8> value_r, out bit<8> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<8>, bit<16>, bit<8>>(register_value_record) register_value_record_write = { 
        void apply(inout bit<8> value_r){ 
            value_r = hdr.formula.value_to_set;
        } 
    };
	
	@pragma stage 2
	action action_register_value_record_read(){
		hdr.formula.value_to_set = register_value_record_read.execute(hdr.formula.id_now);
	}
	
	@pragma stage 2
	action action_register_value_record_write(){
		register_value_record_write.execute(hdr.formula.id_now);
	}
	
	@pragma stage 2
	table table_register_value_record{
        key = { hdr.formula.op: 	exact;}
        actions = {
			action_register_value_record_read;
			action_register_value_record_write;
            action_no_action;
        }
		const entries = {
			GO_BACK:					action_register_value_record_read();
			FIND_ID_TO_SET_DONE:		action_register_value_record_write();
			UNIT_ID_SET:				action_register_value_record_write();
		}
        const default_action = action_no_action();
        size = 3;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_1; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_1) register_conflict_table_value_1_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_1) register_conflict_table_value_1_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[1].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_1; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_1) register_conflict_table_assigned_1_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_1) register_conflict_table_assigned_1_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[1].assigned;
        } 
    };
	//*************这里往上是stage2的东西*************************//
	
	//*************这里往下是stage3的东西*************************//
	action action_unit(bit<16> unit_id, bit<8> value_to_set){
		hdr.formula.if_conflict = 1;
		hdr.formula.if_continue = 0;
		hdr.formula.id_now = unit_id;
		hdr.formula.value_to_set = value_to_set;
	}
	
	table unit_table_0_0{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
		/*const entries = {
			(  1 &&&   1,   1 &&&  33, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_unit(5,1);
			(  1 &&&   1,   1 &&&  17, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_unit(4,1);
		}*/
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	action action_find_id_to_set_find(){
		hdr.formula.value_to_set = 0;
		hdr.formula.if_op_done = 1;
	}
	
	action action_find_id_to_set_no_find(){
		hdr.formula.id_now = hdr.formula.id_now + 1;
	}
	
	table table_find_id_help{
        key = { hdr.formula.help: exact;}
        actions = {
			action_find_id_to_set_find;
			action_find_id_to_set_no_find;
            @defaultonly action_no_action;
        }
		const entries = {
			0:action_find_id_to_set_find();
			1:action_find_id_to_set_no_find();
		}
        const default_action = action_no_action();
        size = 2;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_2; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_2) register_conflict_table_value_2_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_2) register_conflict_table_value_2_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[2].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_2; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_2) register_conflict_table_assigned_2_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_2) register_conflict_table_assigned_2_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[2].assigned;
        } 
    };
	
	@pragma stage 3
	action action_go_back_end(){
		hdr.formula.op = END_UNSAT;
		hdr.formula.if_op_done = 1;
	}
	
	@pragma stage 3
	action action_go_back_nothing(){
		hdr.formula.help = hdr.formula.help;
	}
	
	@pragma stage 3
	table table_go_back_if_end{
        key = { hdr.formula.layer:				exact;
				hdr.formula.value_to_set: 		exact;}
        actions = {
			action_go_back_end;
            action_go_back_nothing;
        }
		const entries = {
			(0,1):action_go_back_end();
		}
        const default_action = action_go_back_nothing();
        size = 2;
    }
	//*************这里往上是stage3的东西*************************//
	
	//*************这里往下是stage4的东西*************************//
	table unit_table_0_1{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
		/*const entries = {
			(  1 &&&   1,   1 &&&   9, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_unit(3,1);
		}*/
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_3; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_3) register_conflict_table_value_3_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_3) register_conflict_table_value_3_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[3].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_3; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_3) register_conflict_table_assigned_3_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_3) register_conflict_table_assigned_3_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[3].assigned;
        } 
    };
	
	@pragma stage 4
	action action_go_back_set_value_to_1(){
		hdr.formula.value_to_set = 1;
		hdr.formula.if_op_done = 1;
	}
	
	@pragma stage 4
	action action_go_back_sub_layer_1(){
		hdr.formula.layer = hdr.formula.layer - 1;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 4
	table table_go_back_check{
        key = { hdr.formula.value_to_set: 		exact;}
        actions = {
			action_go_back_set_value_to_1;
			action_go_back_sub_layer_1;
        }
		const entries = {
			0:action_go_back_set_value_to_1();
			1:action_go_back_sub_layer_1();
		}
        const default_action = action_go_back_sub_layer_1();
        size = 2;
    }
	
	Register<bit<16>,bit<16>>(value_register_size,0) register_clause_id_to_head; 		/*这个head*/
	RegisterAction<bit<16>, bit<16>, bit<16>>(register_clause_id_to_head) register_clause_id_to_head_read = { 
        void apply(inout bit<16> value_r, out bit<16> read_value){ 
            read_value = value_r;
        } 
    }; 
	
	
	//*************这里往上是stage4的东西*************************//
	
	//*************这里往下是stage5的东西*************************//
	action action_go_back_search() {
		hdr.formula.help = meta.back_track.target;
	}
	
	@pragma stage 5
	table table_go_back_set{
        key = { meta.back_track.h1: 	exact;
				meta.back_track.h2: 	exact;}
        actions = {
			action_go_back_search;
			@defaultonly action_no_action;
        }
		const entries = {
			(0,1):	action_go_back_search();
		}
        const default_action = action_no_action();
        size = 2;
    }
	
	@pragma stage 5
	table unit_table_0_2{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	action action_find_id_to_set_sat(){
		hdr.formula.op = END_SAT;
		hdr.formula.if_op_done = 1;
	}
	
	@pragma stage 5
	table table_find_id_to_set_sat{
        key = { hdr.formula.help: exact;}
        actions = {
			action_find_id_to_set_sat;
            @defaultonly action_no_action;
        }
		const entries = {
			0:action_find_id_to_set_sat();
		}
        const default_action = action_no_action();
        size = 1;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_4; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_4) register_conflict_table_value_4_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_4) register_conflict_table_value_4_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[4].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_4; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_4) register_conflict_table_assigned_4_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_4) register_conflict_table_assigned_4_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[4].assigned;
        } 
    };
	
	action action_table_go_back_check_time_self() {
		hdr.formula.table_index = 254;
		hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
		hdr.formula.if_op_done = 1;
	}
	
	action action_table_go_back_check_time_drump() {
		hdr.formula.layer = hdr.formula.help;
		hdr.formula.if_op_done = 1;
	}
	
	@pragma stage 5
	table table_go_back_check_time{
        key = { hdr.formula.help: exact;}
        actions = {
			action_table_go_back_check_time_self;
            @defaultonly action_table_go_back_check_time_drump;
        }
		const entries = {
			-1:action_table_go_back_check_time_self();
		}
        const default_action = action_table_go_back_check_time_drump();
        size = 1;
    }
	//*************这里往上是stage5的东西*************************//
	
	//*************这里往下是stage6的东西*************************//
	
	action action_go_back_search_end(){
		hdr.formula.if_op_done = 1;
	}
	
	action action_go_back_search_add(){
		hdr.formula.clause_id = hdr.formula.clause_id + 1;
	}
	
	@pragma stage 6
	table table_go_back_search{
        key = { meta.back_track.id: exact;}
        actions = {
			action_go_back_search_end;
            @defaultonly action_go_back_search_add;
        }
		const entries = {
			-1:action_go_back_search_end();
		}
        const default_action = action_go_back_search_add();
        size = 1;
    }
	
	table unit_table_1_0{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_5; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_5) register_conflict_table_value_5_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_5) register_conflict_table_value_5_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[5].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_5; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_5) register_conflict_table_assigned_5_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_5) register_conflict_table_assigned_5_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[5].assigned;
        } 
    };
		
	@pragma stage 6
	action action_variable_table_index_calculate_0(){
		hdr.formula.help = hdr.formula.id_now + 0;
	}
	
	@pragma stage 6
	action action_variable_table_index_calculate_1(){
		hdr.formula.help = hdr.formula.id_now + 1025;
	}
	
	@pragma stage 6
	action action_variable_table_index_calculate_2(){
		hdr.formula.help = hdr.formula.id_now + 2050;
	}
	
	@pragma stage 6
	table table_variable_table_index_calculate{
        key = { hdr.formula.table_index: 	exact;}
        actions = {
			action_variable_table_index_calculate_0;
			action_variable_table_index_calculate_1;
            action_variable_table_index_calculate_2;
        }
		const entries = {
		    0:		action_variable_table_index_calculate_0();
		    1:		action_variable_table_index_calculate_1();
		    2:		action_variable_table_index_calculate_2();
		   10:		action_variable_table_index_calculate_0();
		   11:		action_variable_table_index_calculate_1();
		   12:		action_variable_table_index_calculate_2();
		}
        const default_action = action_variable_table_index_calculate_0();
        size = 6;
    }
	//*************这里往上是stage6的东西*************************//
	
	//*************这里往下是stage7的东西*************************//
	table unit_table_1_1{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_6; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_6) register_conflict_table_value_6_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_6) register_conflict_table_value_6_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[6].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_6; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_6) register_conflict_table_assigned_6_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_6) register_conflict_table_assigned_6_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[6].assigned;
        } 
    };
		
	Register<bit<8>,bit<16>>(segment_index_register_size,50) register_conflict_table_segment_index; 		/*这个段索引*/
	RegisterAction<bit<8>, bit<16>, bit<8>>(register_conflict_table_segment_index) register_conflict_table_segment_index_read = { 
        void apply(inout bit<8> value_r, out bit<8> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<8>, bit<16>, bit<8>>(register_conflict_table_segment_index) register_conflict_table_segment_index_write = { 
        void apply(inout bit<8> value_r){ 
            value_r = hdr.formula.segment_index;
        } 
    };
	
	@pragma stage 7
	action action_register_conflict_table_segment_index_read(){
		hdr.formula.segment_index = register_conflict_table_segment_index_read.execute(hdr.formula.help);
	}
	
	@pragma stage 7
	action action_register_conflict_table_segment_index_write(){
		register_conflict_table_segment_index_write.execute(hdr.formula.help);
	}
	
	@pragma stage 7
	table table_register_conflict_table_segment_index{
        key = { hdr.formula.op: 	exact;}
        actions = {
			action_register_conflict_table_segment_index_read;
			action_register_conflict_table_segment_index_write;
            action_no_action;
        }
		const entries = {
			READ_INDEX:					action_register_conflict_table_segment_index_read();
			WRITE_INDEX:				action_register_conflict_table_segment_index_write();
		}
        const default_action = action_no_action();
        size = 3;
    }
	//*************这里往上是stage7的东西*************************//
	
	//*************这里往下是stage8的东西*************************//
	table unit_table_1_2{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
		/*const entries = {
			(  0 &&&   0,   4 &&&  36, 
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0,
			   0 &&&   0,   0 &&&   0):action_unit(5,1);
		}*/
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	Register<bit<32>,bit<16>>(value_register_size,0) register_conflict_table_value_7; 		/*这个value*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_7) register_conflict_table_value_7_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_value_7) register_conflict_table_value_7_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[7].value;
        } 
    };
	
	Register<bit<32>,bit<16>>(assigned_register_size,0) register_conflict_table_assigned_7; 		/*这个assigned*/
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_7) register_conflict_table_assigned_7_read = { 
        void apply(inout bit<32> value_r, out bit<32> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<32>, bit<16>, bit<32>>(register_conflict_table_assigned_7) register_conflict_table_assigned_7_write = { 
        void apply(inout bit<32> value_r){ 
            value_r = hdr.formula_data[7].assigned;
        } 
    };
		
	Register<bit<8>,bit<16>>(position_index_register_size,50) register_conflict_table_position_index; 		/*这个位索引*/
	RegisterAction<bit<8>, bit<16>, bit<8>>(register_conflict_table_position_index) register_conflict_table_position_index_read = { 
        void apply(inout bit<8> value_r, out bit<8> read_value){ 
            read_value = value_r;
        } 
    }; 
	RegisterAction<bit<8>, bit<16>, bit<8>>(register_conflict_table_position_index) register_conflict_table_position_index_write = { 
        void apply(inout bit<8> value_r){ 
            value_r = hdr.formula.position_index;
        } 
    };
	
	@pragma stage 8
	action action_register_conflict_table_position_index_read(){
		hdr.formula.position_index = register_conflict_table_position_index_read.execute(hdr.formula.help);
	}
	
	@pragma stage 8
	action action_register_conflict_table_position_index_write(){
		register_conflict_table_position_index_write.execute(hdr.formula.help);
	}
	
	@pragma stage 8
	table table_register_conflict_table_position_index{
        key = { hdr.formula.op: 	exact;}
        actions = {
			action_register_conflict_table_position_index_read;
			action_register_conflict_table_position_index_write;
        }
		const entries = {
			READ_INDEX:					action_register_conflict_table_position_index_read();
			WRITE_INDEX:				action_register_conflict_table_position_index_write();
		}
        size = 2;
    }
	//*************这里往上是stage8的东西*************************//
	
	//*************这里往下是stage9的东西*************************//
	table unit_table_2_0{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	@pragma stage 9
	action action_table_index_write_op_done(){
		hdr.formula.if_op_done = 1;
	}
	
	@pragma stage 9
	table table_table_index_write_op_done{
        key = { hdr.formula.table_index: 	exact;}
        actions = {
            action_table_index_write_op_done;
        }
		const entries = {
			0:		action_table_index_write_op_done();
			1:		action_table_index_write_op_done();
			2:		action_table_index_write_op_done();
		}
        const default_action = action_table_index_write_op_done();
        size = 12;
    }
	//*************这里往上是stage9的东西*************************//
	
	//*************这里往下是stage10的东西*************************//
	table unit_table_2_1{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
        const default_action = action_no_action();
        size = unit_table_size;
    }
	
	@pragma stage 10
	action action_port_change_to_server(){
		ig_tm_md.ucast_egress_port = send_to_server;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_table_to_0(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.table_index = 0;
	}
	
	@pragma stage 10
	action action_port_change_to_self(){
		ig_tm_md.ucast_egress_port = send_to_self;
	}
	
	@pragma stage 10
	action action_port_change_to_switch_3(){
		ig_tm_md.ucast_egress_port = send_to_switch_3;
	}
	
	@pragma stage 10
	action action_port_change_to_switch_1(){
		ig_tm_md.ucast_egress_port = send_to_switch_1;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_table_to_1(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.table_index = 1;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_table_to_2(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.table_index = 2;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_table_to_10(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.table_index = 10;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_table_to_255(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.table_index = 255;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_continue_to_0(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.if_continue = 0;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_continue_to_1_and_if_op_done_to_0(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.if_continue = 1;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_continue_to_0_and_check_table_to_11(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.if_continue = 0;
		hdr.formula.table_index = 11;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_continue_to_0_and_check_table_to_12(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.if_continue = 0;
		hdr.formula.table_index = 12;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_continue_to_0_and_check_table_to_255(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.if_continue = 0;
		hdr.formula.table_index = 255;
	}
	
	@pragma stage 10
	action action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255(){
		ig_tm_md.ucast_egress_port = send_to_self;
		hdr.formula.if_conflict = 0;
		hdr.formula.table_index = 255;
	}
	
	@pragma stage 10
	table table_port_change{
        key = { hdr.formula.op: 			exact;
				hdr.formula.table_index: 	exact;
				hdr.formula.if_continue: 	exact;
				hdr.formula.if_conflict: 	exact;}
        actions = {
			action_port_change_to_server;
			action_port_change_to_self_and_change_table_to_0;
			action_port_change_to_self_and_change_table_to_1;
			action_port_change_to_self_and_change_table_to_2;
			action_port_change_to_self_and_change_table_to_10;
			action_port_change_to_self_and_change_table_to_255;
			action_port_change_to_self_and_change_continue_to_0;
			action_port_change_to_self_and_change_continue_to_1_and_if_op_done_to_0;
			action_port_change_to_self_and_change_continue_to_0_and_check_table_to_11;
			action_port_change_to_self_and_change_continue_to_0_and_check_table_to_12;
			action_port_change_to_self_and_change_continue_to_0_and_check_table_to_255;
			action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255;
            action_port_change_to_self;
            action_port_change_to_switch_1;
            action_port_change_to_switch_3;
        }
		const entries = {
			(END_SAT,               255,0,0):		action_port_change_to_server();
			(END_UNSAT,             255,0,0):		action_port_change_to_server();
			(FIND_ID_TO_SET,        255,0,0):		action_port_change_to_self();
			(FIND_ID_TO_SET_DONE,   255,0,0):		action_port_change_to_self_and_change_table_to_0();
			(UNIT_ID_SET,           255,0,0):		action_port_change_to_self_and_change_table_to_0();
			(READ_CONFLICT_TABLE,     0,0,0):		action_port_change_to_self();
			(READ_INDEX,              0,0,0):		action_port_change_to_self();
			(CALCULATE_VALUE,         0,0,0):		action_port_change_to_self();
			(CHECK_CONFLICT_TABLE_0,  0,1,0):		action_port_change_to_self_and_change_continue_to_0();
			(CHECK_CONFLICT_TABLE_0,  0,0,1):		action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255();
			(WRITE_CONFLICT_TABLE,    0,0,0):		action_port_change_to_self_and_change_table_to_1();
			(READ_CONFLICT_TABLE,     1,0,0):		action_port_change_to_self();
			(READ_INDEX,              1,0,0):		action_port_change_to_self();
			(CALCULATE_VALUE,         1,0,0):		action_port_change_to_self();
			(CHECK_CONFLICT_TABLE_1,  1,1,0):		action_port_change_to_self_and_change_continue_to_0();
			(CHECK_CONFLICT_TABLE_1,  1,0,1):		action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255();
			(WRITE_CONFLICT_TABLE,    1,0,0):		action_port_change_to_self_and_change_table_to_2();
			(READ_CONFLICT_TABLE,     2,0,0):		action_port_change_to_self();
			(READ_INDEX,              2,0,0):		action_port_change_to_self();
			(CALCULATE_VALUE,         2,0,0):		action_port_change_to_self();
			(CHECK_CONFLICT_TABLE_2,  2,1,0):		action_port_change_to_self_and_change_continue_to_0();
			(CHECK_CONFLICT_TABLE_2,  2,0,1):		action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255();
			(WRITE_CONFLICT_TABLE,    2,0,0):		action_port_change_to_self_and_change_table_to_10();
			(READ_CONFLICT_TABLE,    10,0,0):		action_port_change_to_self();
			(READ_INDEX,             10,0,0):		action_port_change_to_self();
			(CALCULATE_VALUE,        10,0,0):		action_port_change_to_self();
			(CHECK_UNIT_TABLE_0,     10,0,0):		action_port_change_to_self_and_change_continue_to_0_and_check_table_to_11();
			(CHECK_UNIT_TABLE_0,     10,0,1):		action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255();
			(READ_CONFLICT_TABLE,    11,0,0):		action_port_change_to_self();
			(READ_INDEX,             11,0,0):		action_port_change_to_self();
			(CALCULATE_VALUE,        11,0,0):		action_port_change_to_self();
			(CHECK_UNIT_TABLE_1,     11,0,0):		action_port_change_to_self_and_change_continue_to_0_and_check_table_to_12();
			(CHECK_UNIT_TABLE_1,     11,0,1):		action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255();
			(READ_CONFLICT_TABLE,    12,0,0):		action_port_change_to_self();
			(READ_INDEX,             12,0,0):		action_port_change_to_self();
			(CALCULATE_VALUE,        12,0,0):		action_port_change_to_self();
			(CHECK_UNIT_TABLE_2,     12,0,0):		action_port_change_to_self_and_change_continue_to_0();
			(CHECK_UNIT_TABLE_2,     12,0,1):		action_port_change_to_self_and_change_conflict_to_0_and_check_table_to_255();
			(FINISH_THIS_LAYER,      12,0,0):		action_port_change_to_self_and_change_table_to_255();
			(FINISH_THIS_LAYER,      10,0,0):		action_port_change_to_self_and_change_table_to_255();
			(GO_BACK,               255,0,0):		action_port_change_to_self();
			(GO_BACK_DONE,          255,0,0):		action_port_change_to_self();
			(GO_BACK_TIME,          255,0,0):		action_port_change_to_self();
			(GO_BACK_SEARCH,        255,0,0):		action_port_change_to_self();
			(GO_BACK_CHECK,         255,0,0):		action_port_change_to_self();
			(GO_BACK_CHECK,         254,0,0):		action_port_change_to_self();
		}
        const default_action = action_port_change_to_server();
        size = 100;
    }
	//*************这里往上是stage10的东西*************************//
	
	//*************这里往下是stage11的东西*************************//
	table unit_table_2_2{
        key = { hdr.formula_data[0].value : ternary;
                hdr.formula_data[0].assigned: ternary;
                hdr.formula_data[1].value : ternary;
                hdr.formula_data[1].assigned: ternary;
                hdr.formula_data[2].value : ternary;
                hdr.formula_data[2].assigned: ternary;
                hdr.formula_data[3].value : ternary;
                hdr.formula_data[3].assigned: ternary;
				hdr.formula_data[4].value : ternary;
                hdr.formula_data[4].assigned: ternary;
				hdr.formula_data[5].value : ternary;
                hdr.formula_data[5].assigned: ternary;
				hdr.formula_data[6].value : ternary;
                hdr.formula_data[6].assigned: ternary;
				hdr.formula_data[7].value : ternary;
                hdr.formula_data[7].assigned: ternary;}
        actions = {
            drop; l3_switch;action_unit;
            @defaultonly action_no_action;
        }
        const default_action = action_no_action();
        size = unit_table_size;
    } 
	
	@pragma stage 11
	action action_op_change_to_FIND_ID_TO_SET_DONE(){
		hdr.formula.op = FIND_ID_TO_SET_DONE;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_READ_CONFLICT_TABLE(){
		hdr.formula.op = READ_CONFLICT_TABLE;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_READ_INDEX(){
		hdr.formula.op = READ_INDEX;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CALCULATE_VALUE(){
		hdr.formula.op = CALCULATE_VALUE;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CHECK_CONFLICT_TABLE_0(){
		hdr.formula.op = CHECK_CONFLICT_TABLE_0;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CHECK_CONFLICT_TABLE_1(){
		hdr.formula.op = CHECK_CONFLICT_TABLE_1;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CHECK_CONFLICT_TABLE_2(){
		hdr.formula.op = CHECK_CONFLICT_TABLE_2;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CHECK_UNIT_TABLE_0(){
		hdr.formula.op = CHECK_UNIT_TABLE_0;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CHECK_UNIT_TABLE_1(){
		hdr.formula.op = CHECK_UNIT_TABLE_1;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_CHECK_UNIT_TABLE_2(){
		hdr.formula.op = CHECK_UNIT_TABLE_2;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_UNIT_ID_SET(){
		hdr.formula.op = UNIT_ID_SET;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_WRITE_CONFLICT_TABLE(){
		hdr.formula.op = WRITE_CONFLICT_TABLE;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_FIND_ID_TO_SET(){
		hdr.formula.op = FIND_ID_TO_SET;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_GO_BACK(){
		hdr.formula.op = GO_BACK;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_GO_BACK_plus(){
		hdr.formula.op = GO_BACK;
		hdr.formula.table_index = 255;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_GO_BACK_TIME(){
		hdr.formula.op = GO_BACK_TIME;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_GO_BACK_SEARCH(){
		hdr.formula.op = GO_BACK_SEARCH;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_GO_BACK_CHECK(){
		hdr.formula.op = GO_BACK_CHECK;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_GO_BACK_DONE(){
		hdr.formula.op = GO_BACK_DONE;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	action action_op_change_to_FINISH_THIS_LAYER(){
		hdr.formula.op = FINISH_THIS_LAYER;
		hdr.formula.if_op_done = 0;
	}
	
	@pragma stage 11
	table table_op_change{
        key = { hdr.formula.op: 		exact;
				hdr.formula.table_index: 	exact;
				hdr.formula.mode_switch: 	exact;}
        actions = {
			action_op_change_to_FIND_ID_TO_SET_DONE;
			action_op_change_to_READ_CONFLICT_TABLE;
			action_op_change_to_READ_INDEX;
			action_op_change_to_CALCULATE_VALUE;
			action_op_change_to_CHECK_CONFLICT_TABLE_0;
			action_op_change_to_CHECK_CONFLICT_TABLE_1;
			action_op_change_to_CHECK_CONFLICT_TABLE_2;
			action_op_change_to_WRITE_CONFLICT_TABLE;
			action_op_change_to_FIND_ID_TO_SET;
			action_op_change_to_CHECK_UNIT_TABLE_0;
			action_op_change_to_CHECK_UNIT_TABLE_1;
			action_op_change_to_CHECK_UNIT_TABLE_2;
			action_op_change_to_UNIT_ID_SET;
			action_op_change_to_FINISH_THIS_LAYER;
			action_op_change_to_GO_BACK;
			action_op_change_to_GO_BACK_DONE;
			action_op_change_to_GO_BACK_TIME;
			action_op_change_to_GO_BACK_SEARCH;
			action_op_change_to_GO_BACK_CHECK;
            @defaultonly action_no_action;
			action_op_change_to_GO_BACK_plus;
        }
		const entries = {
			(FIND_ID_TO_SET,        255,0):action_op_change_to_FIND_ID_TO_SET_DONE();
			(FIND_ID_TO_SET_DONE,     0,0):action_op_change_to_READ_CONFLICT_TABLE();
			(UNIT_ID_SET,             0,0):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     0,0):action_op_change_to_READ_INDEX();
			(READ_INDEX,              0,0):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         0,0):action_op_change_to_CHECK_CONFLICT_TABLE_0();
			(CHECK_CONFLICT_TABLE_0,  0,0):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_0,255,0):action_op_change_to_GO_BACK();
			(WRITE_CONFLICT_TABLE,    1,0):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     1,0):action_op_change_to_READ_INDEX();
			(READ_INDEX,              1,0):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         1,0):action_op_change_to_CHECK_CONFLICT_TABLE_1();
			(CHECK_CONFLICT_TABLE_1,  1,0):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_1,255,0):action_op_change_to_GO_BACK();
			(WRITE_CONFLICT_TABLE,    2,0):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     2,0):action_op_change_to_READ_INDEX();
			(READ_INDEX,              2,0):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         2,0):action_op_change_to_CHECK_CONFLICT_TABLE_2();
			(CHECK_CONFLICT_TABLE_2,  2,0):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_2,255,0):action_op_change_to_GO_BACK();
			(WRITE_CONFLICT_TABLE,   10,0):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,    10,0):action_op_change_to_CHECK_UNIT_TABLE_0();
			(CHECK_UNIT_TABLE_0,     11,0):action_op_change_to_READ_CONFLICT_TABLE();
			(CHECK_UNIT_TABLE_0,    255,0):action_op_change_to_UNIT_ID_SET();
			(READ_CONFLICT_TABLE,    11,0):action_op_change_to_CHECK_UNIT_TABLE_1();
			(CHECK_UNIT_TABLE_1,     12,0):action_op_change_to_READ_CONFLICT_TABLE();
			(CHECK_UNIT_TABLE_1,    255,0):action_op_change_to_UNIT_ID_SET();
			(READ_CONFLICT_TABLE,    12,0):action_op_change_to_CHECK_UNIT_TABLE_2();
			(CHECK_UNIT_TABLE_2,     12,0):action_op_change_to_FINISH_THIS_LAYER();
			(CHECK_UNIT_TABLE_2,    255,0):action_op_change_to_UNIT_ID_SET();
			(FINISH_THIS_LAYER,     255,0):action_op_change_to_FIND_ID_TO_SET();
			(GO_BACK,               255,0):action_op_change_to_GO_BACK_DONE();
			(GO_BACK_DONE,          255,0):action_op_change_to_FIND_ID_TO_SET_DONE();
			(FIND_ID_TO_SET,        255,1):action_op_change_to_FIND_ID_TO_SET_DONE();
			(FIND_ID_TO_SET_DONE,     0,1):action_op_change_to_READ_CONFLICT_TABLE();
			(UNIT_ID_SET,             0,1):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     0,1):action_op_change_to_READ_INDEX();
			(READ_INDEX,              0,1):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         0,1):action_op_change_to_CHECK_CONFLICT_TABLE_0();
			(CHECK_CONFLICT_TABLE_0,  0,1):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_0,255,1):action_op_change_to_GO_BACK();
			(WRITE_CONFLICT_TABLE,    1,1):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     1,1):action_op_change_to_READ_INDEX();
			(READ_INDEX,              1,1):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         1,1):action_op_change_to_CHECK_CONFLICT_TABLE_1();
			(CHECK_CONFLICT_TABLE_1,  1,1):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_1,255,1):action_op_change_to_GO_BACK();
			(WRITE_CONFLICT_TABLE,    2,1):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     2,1):action_op_change_to_READ_INDEX();
			(READ_INDEX,              2,1):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         2,1):action_op_change_to_CHECK_CONFLICT_TABLE_2();
			(CHECK_CONFLICT_TABLE_2,  2,1):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_2,255,1):action_op_change_to_GO_BACK();
			(WRITE_CONFLICT_TABLE,   10,1):action_op_change_to_FINISH_THIS_LAYER();
			(FINISH_THIS_LAYER,     255,1):action_op_change_to_FIND_ID_TO_SET();
			(GO_BACK,               255,1):action_op_change_to_GO_BACK_DONE();
			(GO_BACK_DONE,          255,1):action_op_change_to_FIND_ID_TO_SET_DONE();
			(FIND_ID_TO_SET,        255,2):action_op_change_to_FIND_ID_TO_SET_DONE();
			(FIND_ID_TO_SET_DONE,     0,2):action_op_change_to_READ_CONFLICT_TABLE();
			(UNIT_ID_SET,             0,2):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     0,2):action_op_change_to_READ_INDEX();
			(READ_INDEX,              0,2):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         0,2):action_op_change_to_CHECK_CONFLICT_TABLE_0();
			(CHECK_CONFLICT_TABLE_0,  0,2):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_0,255,2):action_op_change_to_GO_BACK_TIME();
			(WRITE_CONFLICT_TABLE,    1,2):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     1,2):action_op_change_to_READ_INDEX();
			(READ_INDEX,              1,2):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         1,2):action_op_change_to_CHECK_CONFLICT_TABLE_1();
			(CHECK_CONFLICT_TABLE_1,  1,2):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_1,255,2):action_op_change_to_GO_BACK_TIME();
			(WRITE_CONFLICT_TABLE,    2,2):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,     2,2):action_op_change_to_READ_INDEX();
			(READ_INDEX,              2,2):action_op_change_to_CALCULATE_VALUE();
			(CALCULATE_VALUE,         2,2):action_op_change_to_CHECK_CONFLICT_TABLE_2();
			(CHECK_CONFLICT_TABLE_2,  2,2):action_op_change_to_WRITE_CONFLICT_TABLE();
			(CHECK_CONFLICT_TABLE_2,255,2):action_op_change_to_GO_BACK_TIME();
			(WRITE_CONFLICT_TABLE,   10,2):action_op_change_to_READ_CONFLICT_TABLE();
			(READ_CONFLICT_TABLE,    10,2):action_op_change_to_CHECK_UNIT_TABLE_0();
			(CHECK_UNIT_TABLE_0,     11,2):action_op_change_to_READ_CONFLICT_TABLE();
			(CHECK_UNIT_TABLE_0,    255,2):action_op_change_to_UNIT_ID_SET();
			(READ_CONFLICT_TABLE,    11,2):action_op_change_to_CHECK_UNIT_TABLE_1();
			(CHECK_UNIT_TABLE_1,     12,2):action_op_change_to_READ_CONFLICT_TABLE();
			(CHECK_UNIT_TABLE_1,    255,2):action_op_change_to_UNIT_ID_SET();
			(READ_CONFLICT_TABLE,    12,2):action_op_change_to_CHECK_UNIT_TABLE_2();
			(CHECK_UNIT_TABLE_2,     12,2):action_op_change_to_FINISH_THIS_LAYER();
			(CHECK_UNIT_TABLE_2,    255,2):action_op_change_to_UNIT_ID_SET();
			(FINISH_THIS_LAYER,     255,2):action_op_change_to_FIND_ID_TO_SET();
			(GO_BACK_TIME,          255,2):action_op_change_to_GO_BACK_SEARCH();
			(GO_BACK_SEARCH,        255,2):action_op_change_to_GO_BACK_CHECK();
			(GO_BACK_CHECK,         255,2):action_op_change_to_UNIT_ID_SET();
			(GO_BACK_CHECK,         254,2):action_op_change_to_GO_BACK_plus();
			(GO_BACK,               255,2):action_op_change_to_GO_BACK_DONE();
			(GO_BACK_DONE,          255,2):action_op_change_to_FIND_ID_TO_SET_DONE();
			
		}
        const default_action = action_no_action();
        size = 200;
    }
	
	//*************这里往上是stage11的东西*************************//
	
    /* The algorithm */
    apply {
        
		if(hdr.formula.isValid())
		{
			//*************这里往下是stage0的东西*************************//
            if(hdr.formula.op == CHECK_CONFLICT_TABLE_0)
			{
				conflict_table_0.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_100 = hdr.formula_data_cir.k_100 + 1;
			}
			else if(hdr.formula.op == FIND_ID_TO_SET)
			{
				table_register_variable_record.apply();
				//hdr.formula.help = hdr.formula.help - hdr.formula.layer;
				//hdr.formula.help = hdr.formula.help >> 15;
				//table_find_id_help.apply();
				//hdr.formula.help = hdr.formula.id_all - hdr.formula.id_now;
				//table_find_id_to_set_sat.apply();
			}
			else if(hdr.formula.op == CALCULATE_VALUE)
			{
				table_alu_help.apply();
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == FIND_ID_TO_SET_DONE)
			{
				table_register_variable_record.apply();
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.find_or_unit = 0;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == UNIT_ID_SET)
			{
				table_register_variable_record.apply();
				//hdr.formula.find_or_unit = 1;
				//table_register_value_record.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				meta.back_track.target = register_variable_record_read.execute(hdr.formula.id);
				//meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				//meta.back_track.h1 = meta.back_track.target;
				//meta.back_track.h2 = meta.back_track.target;
				//meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				//meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				//meta.back_track.h1 = meta.back_track.h1 >> 15;
				//meta.back_track.h2 = meta.back_track.h2 >> 15;
				//table_go_back_set.apply();
				//table_go_back_search.apply();
			}
			ig_tm_md.ucast_egress_port = send_to_self;
			//*************这里往上是stage0的东西*************************//
			
			//*************这里往下是stage1的东西*************************//
			if(hdr.formula.op == CHECK_CONFLICT_TABLE_1)
			{
				conflict_table_1.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_101 = hdr.formula_data_cir.k_101 + 1;
			}
			else if(hdr.formula.op == FIND_ID_TO_SET)
			{
				//table_register_variable_record.apply();
				hdr.formula.help = hdr.formula.help - hdr.formula.layer;
				hdr.formula_data_cir.k_10 = hdr.formula_data_cir.k_10 + 1;
				//hdr.formula.help = hdr.formula.help >> 15;
				//table_find_id_help.apply();
				//hdr.formula.help = hdr.formula.id_all - hdr.formula.id_now;
				//table_find_id_to_set_sat.apply();
			}
			else if(hdr.formula.op == FIND_ID_TO_SET_DONE)
			{
				//table_register_variable_record.apply();
				table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.find_or_unit = 0;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == UNIT_ID_SET)
			{
				//table_register_variable_record.apply();
				hdr.formula.find_or_unit = 1;
				//table_register_value_record.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == FINISH_THIS_LAYER)
			{
				table_register_layer_record.apply();
				//hdr.formula.id_now = hdr.formula.id_now + 1;
				//hdr.formula.layer = hdr.formula.layer + 1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK)
			{
				table_register_layer_record.apply();
				//table_register_value_record.apply();
				//table_go_back_if_end.apply();
				//table_go_back_check.apply();
			}
			else if(hdr.formula.op == GO_BACK_DONE)
			{
				table_register_layer_record.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_TIME)
			{
				table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
				//hdr.formula.help = register_clause_id_to_head_read.execute(hdr.formula.clause_id);
				//hdr.formula.clause_id = hdr.formula.help;
				//hdr.formula.help = -1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				//meta.back_track.target = register_variable_record_read.execute(meta.back_track.id);
				meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				//meta.back_track.h1 = meta.back_track.target;
				//meta.back_track.h2 = meta.back_track.target;
				//meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				//meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				//meta.back_track.h1 = meta.back_track.h1 >> 15;
				//meta.back_track.h2 = meta.back_track.h2 >> 15;
				//table_go_back_set.apply();
				//table_go_back_search.apply();
			}
			//*************这里往上是stage1的东西*************************//
			
			//*************这里往下是stage2的东西*************************//
			if(hdr.formula.op == CHECK_CONFLICT_TABLE_2)
			{
				conflict_table_2.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_102 = hdr.formula_data_cir.k_102 + 1;
			}
			else if(hdr.formula.op == FIND_ID_TO_SET)
			{
				//table_register_variable_record.apply();
				//hdr.formula.help = hdr.formula.help - hdr.formula.layer;
				hdr.formula.help = hdr.formula.help >> 15;
				//table_find_id_help.apply();
				//hdr.formula.help = hdr.formula.id_all - hdr.formula.id_now;
				//table_find_id_to_set_sat.apply();
			}
			else if(hdr.formula.op == FIND_ID_TO_SET_DONE)
			{
				//table_register_variable_record.apply();
				//table_register_layer_record.apply();
				table_register_value_record.apply();
				//hdr.formula.find_or_unit = 0;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == UNIT_ID_SET)
			{
				//table_register_variable_record.apply();
				//hdr.formula.find_or_unit = 1;
				table_register_value_record.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == FINISH_THIS_LAYER)
			{
				//table_register_layer_record.apply();
				hdr.formula.id_now = hdr.formula.id_now + 1;
				//hdr.formula.layer = hdr.formula.layer + 1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK)
			{
				//table_register_layer_record.apply();
				table_register_value_record.apply();
				//hdr.formula_data_cir.k_30 = hdr.formula_data_cir.k_30 + 1;
				//table_go_back_if_end.apply();
				//table_go_back_check.apply();
			}
			else if(hdr.formula.op == GO_BACK_DONE)
			{
				//table_register_layer_record.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_31 = hdr.formula_data_cir.k_31 + 1;
			}
			else if(hdr.formula.op == GO_BACK_TIME)
			{
				//table_register_layer_record.apply();
				table_register_value_record.apply();
				//hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
				//hdr.formula.help = register_clause_id_to_head_read.execute(hdr.formula.clause_id);
				//hdr.formula.clause_id = hdr.formula.help;
				//hdr.formula.help = -1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				//meta.back_track.target = register_variable_record_read.execute(meta.back_track.id);
				//meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				meta.back_track.h1 = meta.back_track.target;
				meta.back_track.h2 = meta.back_track.target;
				hdr.formula.id     = meta.back_track.id;
				//meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				//meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				//meta.back_track.h1 = meta.back_track.h1 >> 15;
				//meta.back_track.h2 = meta.back_track.h2 >> 15;
				//table_go_back_set.apply();
				//table_go_back_search.apply();
			}
			//*************这里往上是stage2的东西*************************//
			
			//*************这里往下是stage3的东西*************************//
			if(hdr.formula.op == CHECK_UNIT_TABLE_0)
			{
				unit_table_0_0.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_200 = hdr.formula_data_cir.k_200 + 1;
			}
			else if(hdr.formula.op == FIND_ID_TO_SET)
			{
				//table_register_variable_record.apply();
				//hdr.formula.help = hdr.formula.help - hdr.formula.layer;
				//hdr.formula.help = hdr.formula.help >> 15;
				table_find_id_help.apply();
				//hdr.formula.help = hdr.formula.id_all - hdr.formula.id_now;
				//table_find_id_to_set_sat.apply();
			}
			else if(hdr.formula.op == FIND_ID_TO_SET_DONE)
			{
				//table_register_variable_record.apply();
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				hdr.formula.find_or_unit = 0;
				hdr.formula_data_cir.k_11 = hdr.formula_data_cir.k_11 + 1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == UNIT_ID_SET)
			{
				//table_register_variable_record.apply();
				//hdr.formula.find_or_unit = 1;
				//table_register_value_record.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_12 = hdr.formula_data_cir.k_12 + 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == FINISH_THIS_LAYER)
			{
				//table_register_layer_record.apply();
				//hdr.formula.id_now = hdr.formula.id_now + 1;
				hdr.formula.layer = hdr.formula.layer + 1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				table_go_back_if_end.apply();
				//table_go_back_check.apply();
			}
			else if(hdr.formula.op == GO_BACK_TIME)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
				//hdr.formula.help = register_clause_id_to_head_read.execute(hdr.formula.clause_id);
				//hdr.formula.clause_id = hdr.formula.help;
				//hdr.formula.help = -1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				//meta.back_track.target = register_variable_record_read.execute(meta.back_track.id);
				//meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				//meta.back_track.h1 = meta.back_track.target;
				//meta.back_track.h2 = meta.back_track.target;
				meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				//meta.back_track.h1 = meta.back_track.h1 >> 15;
				//meta.back_track.h2 = meta.back_track.h2 >> 15;
				//table_go_back_set.apply();
				//table_go_back_search.apply();
			}
			//*************这里往上是stage3的东西*************************//
			
			//*************这里往下是stage4的东西*************************//
			if(hdr.formula.op == CHECK_UNIT_TABLE_0)
			{
				unit_table_0_1.apply();
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == FIND_ID_TO_SET)
			{
				//table_register_variable_record.apply();
				//hdr.formula.help = hdr.formula.help - hdr.formula.layer;
				//hdr.formula.help = hdr.formula.help >> 15;
				//table_find_id_help.apply();
				hdr.formula.help = hdr.formula.id_all - hdr.formula.id_now;
				//table_find_id_to_set_sat.apply();
			}
			else if(hdr.formula.op == FIND_ID_TO_SET_DONE)
			{
				//table_register_variable_record.apply();
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.find_or_unit = 0;
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == FINISH_THIS_LAYER)
			{
				//table_register_layer_record.apply();
				//hdr.formula.id_now = hdr.formula.id_now + 1;
				//hdr.formula.layer = hdr.formula.layer + 1;
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				//table_go_back_if_end.apply();
				table_go_back_check.apply();
			}
			else if(hdr.formula.op == GO_BACK_TIME)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
				hdr.formula.help = register_clause_id_to_head_read.execute(hdr.formula.clause_id);
				//hdr.formula.clause_id = hdr.formula.help;
				//hdr.formula.help = -1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				//meta.back_track.target = register_variable_record_read.execute(meta.back_track.id);
				//meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				//meta.back_track.h1 = meta.back_track.target;
				//meta.back_track.h2 = meta.back_track.target;
				//meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				//meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				meta.back_track.h1 = meta.back_track.h1 >> 15;
				meta.back_track.h2 = meta.back_track.h2 >> 15;
				//table_go_back_set.apply();
				//table_go_back_search.apply();
			}
			//*************这里往上是stage4的东西*************************//
			
			//*************这里往下是stage5的东西*************************//
			if(hdr.formula.op == CHECK_UNIT_TABLE_0)
			{
				unit_table_0_2.apply();
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				hdr.formula_data_cir.k_30 = hdr.formula_data_cir.k_30 + 1;
				//table_go_back_if_end.apply();
				//table_go_back_check.apply();
			}
			else if(hdr.formula.op == FIND_ID_TO_SET)
			{
				//table_register_variable_record.apply();
				//hdr.formula.help = hdr.formula.help - hdr.formula.layer;
				//hdr.formula.help = hdr.formula.help >> 15;
				//table_find_id_help.apply();
				//hdr.formula.help = hdr.formula.id_all - hdr.formula.id_now;
				table_find_id_to_set_sat.apply();
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == GO_BACK_TIME)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
				//hdr.formula.help = register_clause_id_to_head_read.execute(hdr.formula.clause_id);
				hdr.formula.clause_id = hdr.formula.help;
				hdr.formula_data_cir.k_32 = hdr.formula_data_cir.k_32 + 1;
				//hdr.formula.help = -1;
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				//meta.back_track.target = register_variable_record_read.execute(meta.back_track.id);
				//meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				//meta.back_track.h1 = meta.back_track.target;
				//meta.back_track.h2 = meta.back_track.target;
				//meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				//meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				//meta.back_track.h1 = meta.back_track.h1 >> 15;
				//meta.back_track.h2 = meta.back_track.h2 >> 15;
				table_go_back_set.apply();
				hdr.formula_data_cir.k_33 = hdr.formula_data_cir.k_33 + 1;
				//table_go_back_search.apply();
			}
			else if(hdr.formula.op == GO_BACK_CHECK)
			{
				table_go_back_check_time.apply();
				hdr.formula_data_cir.k_34 = hdr.formula_data_cir.k_34 + 1;
			}
			//*************这里往上是stage5的东西*************************//
			
			//*************这里往下是stage6的东西*************************//
			if(hdr.formula.op == CHECK_UNIT_TABLE_1)
			{
				unit_table_1_0.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_201 = hdr.formula_data_cir.k_201 + 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == READ_INDEX)
			{
				table_variable_table_index_calculate.apply();
				//table_register_conflict_table_segment_index.apply();
				//table_register_conflict_table_position_index.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_INDEX)
			{
				table_variable_table_index_calculate.apply();
				//table_register_conflict_table_segment_index.apply();
				//table_register_conflict_table_position_index.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_TIME)
			{
				//table_register_layer_record.apply();
				//table_register_value_record.apply();
				//hdr.formula.value_to_set = hdr.formula.value_to_set ^ 1;
				//hdr.formula.help = register_clause_id_to_head_read.execute(hdr.formula.clause_id);
				//hdr.formula.clause_id = hdr.formula.help;
				hdr.formula.help = -1;
				hdr.formula.id = 1000;
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == GO_BACK_SEARCH)
			{
				//meta.back_track.target = register_variable_record_read.execute(meta.back_track.id);
				//meta.back_track.id = register_clause_head_to_v_id_read.execute(hdr.formula.clause_id);
				//meta.back_track.h1 = meta.back_track.target;
				//meta.back_track.h2 = meta.back_track.target;
				//meta.back_track.h1 = meta.back_track.h1 - hdr.formula.help; 
				//meta.back_track.h2 = meta.back_track.h2 - hdr.formula.layer; 
				//meta.back_track.h1 = meta.back_track.h1 >> 15;
				//meta.back_track.h2 = meta.back_track.h2 >> 15;
				//table_go_back_set.apply();
				table_go_back_search.apply();
			}
			//*************这里往上是stage6的东西*************************//
			
			//*************这里往下是stage7的东西*************************//
			if(hdr.formula.op == CHECK_UNIT_TABLE_1)
			{
				unit_table_1_1.apply();
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == READ_INDEX)
			{
				//table_variable_table_index_calculate.apply();
				table_register_conflict_table_segment_index.apply();
				//table_register_conflict_table_position_index.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_INDEX)
			{
				//table_variable_table_index_calculate.apply();
				table_register_conflict_table_segment_index.apply();
				//table_register_conflict_table_position_index.apply();
				//hdr.formula.if_op_done = 1;
			}
			//*************这里往上是stage7的东西*************************//
			
			//*************这里往下是stage8的东西*************************//
			if(hdr.formula.op == CHECK_UNIT_TABLE_1)
			{
				unit_table_1_2.apply();
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				register_conflict_table_value_7_write.execute(hdr.formula.help);
				//table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.op == READ_INDEX)
			{
				//table_variable_table_index_calculate.apply();
				//table_register_conflict_table_segment_index.apply();
				hdr.formula.position_index = register_conflict_table_position_index_read.execute(hdr.formula.help);//table_register_conflict_table_position_index.apply();
				//hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_INDEX)
			{
				//table_variable_table_index_calculate.apply();
				//table_register_conflict_table_segment_index.apply();
				register_conflict_table_position_index_write.execute(hdr.formula.help);//table_register_conflict_table_position_index.apply();
				//hdr.formula.if_op_done = 1;
			}
			//*************这里往上是stage8的东西*************************//
			
			//*************这里往下是stage9的东西*************************//
			if(hdr.formula.op == READ_CONFLICT_TABLE)
			{
				//table_calculate_table_index_read.apply();
				//hdr.formula_data[0].assigned = register_conflict_table_assigned_0_read.execute(hdr.formula.help);
				//hdr.formula_data[0].value = register_conflict_table_value_0_read.execute(hdr.formula.help);
				//hdr.formula_data[1].assigned = register_conflict_table_assigned_1_read.execute(hdr.formula.help);
				//hdr.formula_data[1].value = register_conflict_table_value_1_read.execute(hdr.formula.help);
				//hdr.formula_data[2].assigned = register_conflict_table_assigned_2_read.execute(hdr.formula.help);
				//hdr.formula_data[2].value = register_conflict_table_value_2_read.execute(hdr.formula.help);
				//hdr.formula_data[3].assigned = register_conflict_table_assigned_3_read.execute(hdr.formula.help);
				//hdr.formula_data[3].value = register_conflict_table_value_3_read.execute(hdr.formula.help);
				//hdr.formula_data[4].assigned = register_conflict_table_assigned_4_read.execute(hdr.formula.help);
				//hdr.formula_data[4].value = register_conflict_table_value_4_read.execute(hdr.formula.help);
				//hdr.formula_data[5].assigned = register_conflict_table_assigned_5_read.execute(hdr.formula.help);
				//hdr.formula_data[5].value = register_conflict_table_value_5_read.execute(hdr.formula.help);
				//hdr.formula_data[6].assigned = register_conflict_table_assigned_6_read.execute(hdr.formula.help);
				//hdr.formula_data[6].value = register_conflict_table_value_6_read.execute(hdr.formula.help);
				//hdr.formula_data[7].assigned = register_conflict_table_assigned_7_read.execute(hdr.formula.help);
				//hdr.formula_data[7].value = register_conflict_table_value_7_read.execute(hdr.formula.help);
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_CONFLICT_TABLE)
			{
				//table_calculate_table_index_write.apply();
				//register_conflict_table_assigned_0_write.execute(hdr.formula.help);
				//register_conflict_table_value_0_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_1_write.execute(hdr.formula.help);
				//register_conflict_table_value_1_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_2_write.execute(hdr.formula.help);
				//register_conflict_table_value_2_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_3_write.execute(hdr.formula.help);
				//register_conflict_table_value_3_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_4_write.execute(hdr.formula.help);
				//register_conflict_table_value_4_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_5_write.execute(hdr.formula.help);
				//register_conflict_table_value_5_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_6_write.execute(hdr.formula.help);
				//register_conflict_table_value_6_write.execute(hdr.formula.help);
				//register_conflict_table_assigned_7_write.execute(hdr.formula.help);
				//register_conflict_table_value_7_write.execute(hdr.formula.help);
				table_table_index_write_op_done.apply();
			}
			else if(hdr.formula.if_op_done == 1)
			{
				;
			}
			else if(hdr.formula.op == CHECK_UNIT_TABLE_2)
			{
				unit_table_2_0.apply();
				hdr.formula.if_op_done = 1;
				hdr.formula_data_cir.k_202 = hdr.formula_data_cir.k_202 + 1;
			}
			else if(hdr.formula.op == READ_INDEX)
			{
				//table_variable_table_index_calculate.apply();
				//table_register_conflict_table_segment_index.apply();
				//table_register_conflict_table_position_index.apply();
				hdr.formula.if_op_done = 1;
			}
			else if(hdr.formula.op == WRITE_INDEX)
			{
				//table_variable_table_index_calculate.apply();
				//table_register_conflict_table_segment_index.apply();
				//table_register_conflict_table_position_index.apply();
				hdr.formula.if_op_done = 1;
			}
			//*************这里往上是stage9的东西*************************//
			
			//*************这里往下是stage10的东西*************************//
			if(hdr.formula.if_op_done == 1)
			{
				table_port_change.apply();
			}
			else if(hdr.formula.op == CHECK_UNIT_TABLE_2)
			{
				unit_table_2_1.apply();
				hdr.formula.if_op_done = 1;
			}
			//*************这里往上是stage10的东西*************************//
			
			//*************这里往下是stage11的东西*************************//
			if(hdr.formula.if_op_done == 1)
			{
				table_op_change.apply();
			}
			else if(hdr.formula.op == CHECK_UNIT_TABLE_2)
			{
				unit_table_2_2.apply();
				hdr.formula.if_op_done = 1;
			}
			//*************这里往上是stage11的东西*************************//
		}
	}
}

/*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout headers                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
	apply{
		pkt.emit(hdr);
	}
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

/***********************  P A R S E R  **************************/

parser EgressParser(packet_in      pkt,
    /* User */
    out headers          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout headers                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

/*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout headers                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.formula);
        pkt.emit(hdr.formula_data);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
