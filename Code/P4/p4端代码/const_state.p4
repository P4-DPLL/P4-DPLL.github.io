const bit<32> number__0 = 0b00000000000000000000000000000001;
const bit<32> number__1 = 0b00000000000000000000000000000010;
const bit<32> number__2 = 0b00000000000000000000000000000100;
const bit<32> number__3 = 0b00000000000000000000000000001000;
const bit<32> number__4 = 0b00000000000000000000000000010000;
const bit<32> number__5 = 0b00000000000000000000000000100000;
const bit<32> number__6 = 0b00000000000000000000000001000000;
const bit<32> number__7 = 0b00000000000000000000000010000000;
const bit<32> number__8 = 0b00000000000000000000000100000000;
const bit<32> number__9 = 0b00000000000000000000001000000000;
const bit<32> number_10 = 0b00000000000000000000010000000000;
const bit<32> number_11 = 0b00000000000000000000100000000000;
const bit<32> number_12 = 0b00000000000000000001000000000000;
const bit<32> number_13 = 0b00000000000000000010000000000000;
const bit<32> number_14 = 0b00000000000000000100000000000000;
const bit<32> number_15 = 0b00000000000000001000000000000000;
const bit<32> number_16 = 0b00000000000000010000000000000000;
const bit<32> number_17 = 0b00000000000000100000000000000000;
const bit<32> number_18 = 0b00000000000001000000000000000000;
const bit<32> number_19 = 0b00000000000010000000000000000000;
const bit<32> number_20 = 0b00000000000100000000000000000000;
const bit<32> number_21 = 0b00000000001000000000000000000000;
const bit<32> number_22 = 0b00000000010000000000000000000000;
const bit<32> number_23 = 0b00000000100000000000000000000000;
const bit<32> number_24 = 0b00000001000000000000000000000000;
const bit<32> number_25 = 0b00000010000000000000000000000000;
const bit<32> number_26 = 0b00000100000000000000000000000000;
const bit<32> number_27 = 0b00001000000000000000000000000000;
const bit<32> number_28 = 0b00010000000000000000000000000000;
const bit<32> number_29 = 0b00100000000000000000000000000000;
const bit<32> number_30 = 0b01000000000000000000000000000000;
const bit<32> number_31 = 0b10000000000000000000000000000000;

const bit<32> num_of_variable     = 1024;
const bit<16> conflict_table_size = 1024;
const bit<16> unit_table_size     = 1024;

const bit<32> value_register_size          = 12301;
const bit<32> assigned_register_size       = 12301;
const bit<32> segment_index_register_size  = 12301;
const bit<32> position_index_register_size = 12301;

const bit<9> send_to_self     = 160;
const bit<9> send_to_server   = 160;
const bit<9> send_to_switch_1 =  68;
const bit<9> send_to_switch_2 =  68;
const bit<9> send_to_switch_3 =  68;

const bit<8> FIND_ID_TO_SET = 			 10;
const bit<8> FIND_ID_TO_SET_DONE = 		 11;
const bit<8> UNIT_ID_SET = 				 12;

const bit<8> CHECK_CONFLICT_TABLE_0 = 	100;
const bit<8> CHECK_CONFLICT_TABLE_1 = 	101;
const bit<8> CHECK_CONFLICT_TABLE_2 = 	102;

const bit<8> READ_CONFLICT_TABLE  = 	210;
const bit<8> READ_INDEX =            	211;
const bit<8> CALCULATE_VALUE =        	212;
const bit<8> WRITE_CONFLICT_TABLE = 	213;

const bit<8> GO_BACK = 					 30;
const bit<8> GO_BACK_DONE = 			 31;

const bit<8> CHECK_UNIT_TABLE_0 = 	200;
const bit<8> CHECK_UNIT_TABLE_1 = 	201;
const bit<8> CHECK_UNIT_TABLE_2 = 	202;

const bit<8> FINISH_THIS_LAYER = 		40;

const bit<8> END_SAT = 					255;
const bit<8> END_UNSAT = 				254;

const bit<8> WRITE_INDEX = 		50;



