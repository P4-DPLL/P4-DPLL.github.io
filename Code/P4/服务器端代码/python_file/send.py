#!/usr/bin/env python
from __future__ import print_function
import argparse
import sys
import socket
import random
import struct
import re
import time
import json

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers
import readline



#const bit<8>  OP_FOR_V     = 0x02;   // for_v
#const bit<8>  OP_FOR_C     = 0x03;   // for_c
#const bit<8>  OP_UNSAT     = 0x04;   // sat
#const bit<8>  OP_SAT       = 0x05;   // unsat

dic = {1:'A' ,2:'B' ,3:'C' ,4:'D' ,5:'E' ,6:'F' ,7:'G' ,8:'H'}

class P4_SAT(Packet):
    name = "P4_SAT"
    fields_desc = [ BitField("if_continue",       0, 8),
                    BitField("if_conflict",       0, 8),
                    BitField("if_have_check_data",0, 8),
                    BitField("value_to_set",      0, 8),
                    BitField("find_or_unit",      0, 8),
                    BitField("op",                0, 8),
                    BitField("if_op_done",        0, 8),
                    BitField("table_index",       0, 8),
                    BitField("segment_index" ,    0, 8),
                    BitField("position_index",    0, 8),
                    BitField("id_now",            0, 16),
                    BitField("id_all",            0, 16),
                    BitField("layer" ,            0, 16),
                    BitField("help" ,             0, 16),
                    BitField("clause_id" ,        0, 16)]

class P4_SAT_DATA(Packet):
    name = "P4_SAT_DATA"
    fields_desc = [ BitField("value",0,32),
                    BitField("assigned",0,32),
                    BitField("reverse",0,7),
                    BitField("if_have_check_data",0,1)]

class P4_SAT_WRITE_DATA(Packet):
    name = "P4_SAT_WRITE_DATA"
    fields_desc = [ BitField("segment",0,8),
                    BitField("position",0,8)]

iface = 'enp26s0f0'
bind_layers(Ether, P4_SAT, type=0x5555)
bind_layers(P4_SAT, P4_SAT_DATA, if_have_check_data=1)

def send_solver_paket(id_all=8):
    pkt = Ether(dst='00:54:00:00:00:00', type=0x5555) 
    pkt = pkt / P4_SAT(op=10, if_have_check_data=1, table_index=255, layer = 0, id_all=id_all) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=1) / P4_SAT_DATA(value=0, assigned=0, if_have_check_data=0)
    print("---------------------")
    #pkt.show()
    pkt=srp1(pkt, iface=iface)
    #pkt.show()
    while pkt[P4_SAT].op != 255 and pkt[P4_SAT].op != 254:
        pkt=srp1(pkt, iface=iface, verbose=0)

result=[]
file_variates=open("data/runtime/variates.json","r")
variates=json.load(file_variates)
file_variates.close()
file_tables=open("data/runtime/tables.json","r")
tables=json.load(file_tables)
file_tables.close()
file_clauses=open("data/runtime/clauses.json","r")
clauses=json.load(file_clauses)
file_clauses.close()
print("*****************************")
print("variates:",len(variates))
print("clauses:",len(clauses))
print("tables:",len(tables))
print("*****************************")
for i in range(100):
    time_start=time.time()
    send_solver_paket(len(variates))
    time_end=time.time()
    result.append(time_end-time_start)

answer=0

for i in range(100):
    answer=answer+result[i]
    
answer=answer/100
print(answer)
results=[answer,result]
string = str(sys.argv[1])
string = string[17:]
string = string[:-4]
string="data/result/results"+string+".json"
file_results = open(string,"w")
json.dump(results,file_results)
file_results.close()











