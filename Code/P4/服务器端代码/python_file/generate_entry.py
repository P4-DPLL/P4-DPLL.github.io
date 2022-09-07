#!/usr/bin/env python
from __future__ import print_function
import argparse
import sys
import socket
import random
import struct
import re
import json

from scapy.all import sendp, send, srp1, sniff
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers
import readline

def generate_entry():
    file=open("data/runtime/tables.json","r")
    tables=json.load(file)
    file.close()
    for i in range(len(tables)):
        variables = tables[i][0]
        clauses = tables[i][1]
        conflict_table=[]
        unit_table1=[]
        unit_table2=[]
        unit_table3=[]
        unit_table1_c=[]
        unit_table2_c=[]
        unit_table3_c=[]
        for j in range(len(clauses)):
            value       =[0,0,0,0,0,0,0,0]
            value1      =[0,0,0,0,0,0,0,0]
            value2      =[0,0,0,0,0,0,0,0]
            value3      =[0,0,0,0,0,0,0,0]
            assigned    =[0,0,0,0,0,0,0,0]
            assigned1   =[0,0,0,0,0,0,0,0]
            assigned2   =[0,0,0,0,0,0,0,0]
            assigned3   =[0,0,0,0,0,0,0,0]
            for k in range(len(clauses[j][1])):
                variable = clauses[j][1][k]
                index=variables.index(abs(variable))
                segment=(int)(index/32)
                position=index%32
                assigned[segment]=assigned[segment]|(1<<position)
                if k != 0:
                    assigned1[segment]=assigned1[segment]|(1<<position)
                if k != 1:
                    assigned2[segment]=assigned2[segment]|(1<<position)
                if k != 2:
                    assigned3[segment]=assigned3[segment]|(1<<position)
                if variable < 0:
                    value[segment]=value[segment]|(1<<position)
                    if k!= 0:
                        value1[segment]=value1[segment]|(1<<position)
                    if k!= 1:
                        value2[segment]=value2[segment]|(1<<position)
                    if k!= 2:
                        value3[segment]=value3[segment]|(1<<position)
            if not([value,assigned,assigned,assigned] in conflict_table):
                conflict_table.append([value,assigned,assigned,assigned])
                if not([value1,assigned1,assigned1,assigned] in unit_table1_c) and len(clauses[j][1]) >= 1:
                    unit_table1.append([value1,assigned1,assigned1,assigned,abs(clauses[j][1][0]),abs(clauses[j][1][0])/clauses[j][1][0]])
                    unit_table1_c.append([value1,assigned1,assigned1,assigned])
                if not([value2,assigned2,assigned2,assigned] in unit_table2_c) and len(clauses[j][1]) >= 2:
                    unit_table2.append([value2,assigned2,assigned2,assigned,abs(clauses[j][1][1]),abs(clauses[j][1][1])/clauses[j][1][1]])
                    unit_table2_c.append([value2,assigned2,assigned2,assigned])
                if not([value3,assigned3,assigned3,assigned] in unit_table3_c) and len(clauses[j][1]) >= 3:
                    unit_table3.append([value3,assigned3,assigned3,assigned,abs(clauses[j][1][2]),abs(clauses[j][1][2])/clauses[j][1][2]])
                    unit_table3_c.append([value3,assigned3,assigned3,assigned])
        file=open("python_file/table_clear_and_write.py","a")
        file.write("\n")
        for j in range(len(conflict_table)):
            string = "bfrt.control.pipe.Ingress.conflict_table_" + str(i) + ".add_with_action_conflict("
            for k in range(7):
                string = string + "formula_data" + str(k) + "_value=" + str(conflict_table[j][0][k]) + ","
                string = string + "formula_data" + str(k) + "_value_mask=" + str(conflict_table[j][1][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned=" + str(conflict_table[j][2][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned_mask=" + str(conflict_table[j][3][k]) + ","
            string = string + "formula_data" + str(7) + "_value=" + str(conflict_table[j][0][7]) + ","
            string = string + "formula_data" + str(7) + "_value_mask=" + str(conflict_table[j][1][7]) + ","
            string = string + "formula_data" + str(7) + "_assigned=" + str(conflict_table[j][2][7]) + ","
            string = string + "formula_data" + str(7) + "_assigned_mask=" + str(conflict_table[j][3][7]) + ")\n"
            file.write(string)
        for j in range(len(unit_table1)):
            string = "bfrt.control.pipe.Ingress.unit_table_" + str(i) + "_0.add_with_action_unit("
            for k in range(8):
                string = string + "formula_data" + str(k) + "_value=" + str(unit_table1[j][0][k]) + ","
                string = string + "formula_data" + str(k) + "_value_mask=" + str(unit_table1[j][1][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned=" + str(unit_table1[j][2][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned_mask=" + str(unit_table1[j][3][k]) + ","
            string = string + "unit_id=" + str(int(unit_table1[j][4]-1)) + ","
            string = string + "value_to_set=" + str(int(0.5+0.5*unit_table1[j][5])) + ")\n"
            file.write(string)
        for j in range(len(unit_table2)):
            string = "bfrt.control.pipe.Ingress.unit_table_" + str(i) + "_1.add_with_action_unit("
            for k in range(8):
                string = string + "formula_data" + str(k) + "_value=" + str(unit_table2[j][0][k]) + ","
                string = string + "formula_data" + str(k) + "_value_mask=" + str(unit_table2[j][1][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned=" + str(unit_table2[j][2][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned_mask=" + str(unit_table2[j][3][k]) + ","
            string = string + "unit_id=" + str(int(unit_table2[j][4]-1)) + ","
            string = string + "value_to_set=" + str(int(0.5+0.5*unit_table2[j][5])) + ")\n"
            file.write(string)
        for j in range(len(unit_table3)):
            string = "bfrt.control.pipe.Ingress.unit_table_" + str(i) + "_2.add_with_action_unit("
            for k in range(8):
                string = string + "formula_data" + str(k) + "_value=" + str(unit_table3[j][0][k]) + ","
                string = string + "formula_data" + str(k) + "_value_mask=" + str(unit_table3[j][1][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned=" + str(unit_table3[j][2][k]) + ","
                string = string + "formula_data" + str(k) + "_assigned_mask=" + str(unit_table3[j][3][k]) + ","
            string = string + "unit_id=" + str(int(unit_table3[j][4]-1)) + ","
            string = string + "value_to_set=" + str(int(0.5+0.5*unit_table3[j][5])) + ")\n"
            file.write(string)
        file.close()
    file=open("python_file/table_clear_and_write.py","a")
    file.write("\n")
    file_variates=open("data/runtime/variates.json","r")
    variates=json.load(file_variates)
    for i in range(len(variates)):
        for j in range(len(variates[i])):
            string = "bfrt.control.pipe.Ingress.register_conflict_table_segment_index.add(" + str(variates[i][j][0]*1025+i) + "," + str((int)(variates[i][j][1]/32)) + ")\n"
            file.write(string)
            string = "bfrt.control.pipe.Ingress.register_conflict_table_position_index.add(" + str(variates[i][j][0]*1025+i) + "," + str((int)(variates[i][j][1]%32)) + ")\n"
            file.write(string)
    file_variates.close()
    file.close()

