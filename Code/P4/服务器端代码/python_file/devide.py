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

clauses=[]
tables=[]
Num_of_variate=0
Num_of_clause=0
variates=[]

def read_formula(index=0):
    file_to_open="data/formula_all/" + str(index) + ".txt"
    formula = open(file_to_open,"r")
    line = formula.readline()
    a=line.split()
    while a[0] == 'c':
        line = formula.readline()
        a=line.split()
    Num_of_variate = int(a[2])
    Num_of_clause  = int(a[3])
    clause=[]
    for i in range(0,Num_of_clause):
        line = formula.readline()
        a=line.split()
        for j in range(0,len(a)):
            a[j]=int(a[j])
        clause.append(a[:-1])
    for i in range(len(clause)):
        clauses.append([i,clause[i]])
    formula.close();
    file_clauses = open("data/runtime/clauses.json","w")
    json.dump(clauses,file_clauses)
    file_clauses.close()
    for i in range(Num_of_variate):
        variates.append([])

def devide_table(index=0):
    read_formula(index)
    len_of_table=1023
    width_of_table=256
    num_of_table=50
    num_of_assigned_clause=0
    while num_of_assigned_clause != len(clauses):
        table_v=[]
        table_c=[]
        for i in range(len(clauses)):
            v_not_in_this_table=0
            if clauses[i] != 0 :
                for j in range(len(clauses[i][1])):
                    if not(abs(clauses[i][1][j]) in table_v):
                        v_not_in_this_table=v_not_in_this_table+1
                if (v_not_in_this_table + len(table_v) <= width_of_table) and (len(table_c)<=len_of_table):
                    for j in range(len(clauses[i][1])):
                        if not(abs(clauses[i][1][j]) in table_v):
                            table_v.append(abs(clauses[i][1][j]))
                            variates[abs(clauses[i][1][j])-1].append([len(tables),table_v.index(abs(clauses[i][1][j]))])
                    table_c.append(clauses[i])
                    clauses[i]=0
                    num_of_assigned_clause=num_of_assigned_clause+1
        tables.append([table_v,table_c])
    file_tables = open("data/runtime/tables.json","w")
    json.dump(tables,file_tables)
    file_tables.close()
    file_variates = open("data/runtime/variates.json","w")
    json.dump(variates,file_variates)
    file_variates.close()



