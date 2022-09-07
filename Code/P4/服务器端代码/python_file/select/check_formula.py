#!/usr/bin/env python
from __future__ import print_function
import argparse
import sys
import socket
import random
import struct
import re
import json

import readline

clauses=[]
tables=[]
Num_of_variate=0
Num_of_clause=0
variates=[]

def read_formula(index=' '):
    file_to_open=str(index)
    formula = open(file_to_open,"r")
    line = formula.readline()
    a=line.split()
    while a[0] == 'c':
        line = formula.readline()
        a=line.split()
    global Num_of_variate
    global Num_of_clause
    Num_of_variate = int(a[2])
    Num_of_clause  = int(a[3])
    if Num_of_variate >= 768:
        quit()
    if Num_of_clause >= 3096:
        quit()
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

def devide_table(index=' '):
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
    return len(tables),Num_of_variate,Num_of_clause



