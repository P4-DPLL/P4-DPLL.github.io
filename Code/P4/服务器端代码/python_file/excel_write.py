import xlsxwriter
import json
import sys

workbook = xlsxwriter.Workbook("data/result/p4_dpll_result.xlsx")
worksheet = workbook.add_worksheet()
data=["id","v","c","time"]
worksheet.write_row(0,0,data)
for i in range(71):
    string="data/formula/" + str(i) + ".txt"
    formula = open(string,"r")
    line = formula.readline()
    a=line.split()
    while a[0] == 'c':
        line = formula.readline()
        a=line.split()
    Num_of_variate = int(a[2])
    Num_of_clause  = int(a[3])
    formula.close()
    string="data/result/results"+str(i)+".json"
    file_results = open(string,"r")
    results=json.load(file_results)
    file_results.close()
    worksheet.write_row(i+1,0,[i,Num_of_variate,Num_of_clause,results[0]])
workbook.close()