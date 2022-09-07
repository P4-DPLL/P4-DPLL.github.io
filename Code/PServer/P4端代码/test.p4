/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86DD;
const bit<16> ETHERTYPE_P4SA = 0x5555;

typedef bit<16> tcpPort_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  egressSpec_t;

const int  ipv4_mask_length = 24;
const int  ipv4_length = 32;
const int  sharing_ratio = 256;
const int  M = 4;
const int  m = 2;


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_t {
    bit<48>  dst_addr;
    bit<48>  src_addr;
    bit<16>  ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header formula_t {
    bit<4>  table_index;
    bit<1>  if_conflict;
    bit<1>  if_found_unit_clause;
    bit<1>  polarity;
    bit<1>  clause_or_conflict;
    bit<256> assigned;
    bit<256> value;
    bit<16> unit_variable_id;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
 
 
/***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_t         ethernet;
    vlan_tag_h         vlan_tag;
    ipv4_h             ipv4;
}

struct headers {
    ethernet_t     ethernet;
    formula_t      formula;
	vlan_tag_h         vlan_tag;
    ipv4_h             ipv4;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
}

/***********************  P A R S E R  **************************/

parser IngressParser(packet_in      pkt,
    /* User */
    out headers          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID :  parse_vlan_tag;
            ETHERTYPE_IPV4 :  parse_ipv4;
			ETHERTYPE_P4SA :  parse_p4sa;
            default        :  accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4 :  parse_ipv4;
            default: accept;
        }
    }
	
	state parse_p4sa {
        pkt.extract(hdr.formula);
        transition accept;
    }


    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
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
		
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    action l3_switch(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    action action_conflict() {
        hdr.formula.if_conflict = 1;
    }
    action action_continue() {
        hdr.formula.if_conflict = 0;
    } 
    action unit_clause_action(bit<16> vid,bit<1> pol){
        hdr.formula.unit_variable_id = vid;
        hdr.formula.if_found_unit_clause = 1;
        hdr.formula.polarity = pol;
    }
    table unit_clause_table_1{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_2{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_3{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_4{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_5{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_6{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_7{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_8{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }    
    table unit_clause_table_9{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_10{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_11{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_12{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_13{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_14{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_15{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }
    table unit_clause_table_16{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;unit_clause_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }    
    
    table conflict_table_1{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_2{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_3{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_4{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_5{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_6{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_7{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_8{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_9{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_10{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_11{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_12{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_13{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_14{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_15{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }
    table conflict_table_16{
        key = { hdr.formula.value : ternary;
                hdr.formula.assigned: ternary;}
        actions = {
            drop; l3_switch;action_conflict;
            @defaultonly action_continue;
        }
        const default_action = action_continue();
        size = 512;
    }    
    
    /* The algorithm */
    apply {

        if(hdr.formula.clause_or_conflict==0){
            if(hdr.formula.table_index==1)
            {
                unit_clause_table_1.apply();
            }
            else if(hdr.formula.table_index==2){                
                unit_clause_table_2.apply();
            }
            else if(hdr.formula.table_index==3){
                unit_clause_table_3.apply();
            }
            else if(hdr.formula.table_index==4){
                unit_clause_table_4.apply();
            }
            else if(hdr.formula.table_index==5){
                unit_clause_table_5.apply();
            }
            else if(hdr.formula.table_index==6){
                unit_clause_table_6.apply();
            }
             else if(hdr.formula.table_index==7){                
                unit_clause_table_7.apply();
            }
            else if(hdr.formula.table_index==8){
                unit_clause_table_8.apply();
            }
        }
        else
        {
            if(hdr.formula.table_index==1){
               conflict_table_1.apply();
            }
            else if(hdr.formula.table_index==2){
               conflict_table_2.apply();
            }
            else if(hdr.formula.table_index==3){
               conflict_table_3.apply();
            }
            else if(hdr.formula.table_index==4){
                conflict_table_4.apply();
            }
            else if(hdr.formula.table_index==5){
               conflict_table_5.apply();
            }
            else if(hdr.formula.table_index==6){
               conflict_table_6.apply();
            }
            else if(hdr.formula.table_index==7){
               conflict_table_7.apply();
            }
            else if(hdr.formula.table_index==8){
               conflict_table_8.apply();
            }

        }

        ig_tm_md.ucast_egress_port = 160;

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
        pkt.emit(hdr);
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
