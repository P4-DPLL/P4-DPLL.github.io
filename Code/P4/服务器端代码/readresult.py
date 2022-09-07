import time
import os
import xlwt
import xlrd
import xlutils.copy
path = "result/runresult/data/formula_all_old"
files = os.listdir(path)
data = xlrd.open_workbook('data.xls')
ws = xlutils.copy.copy(data)
table = ws.get_sheet('p4')
i = 1
for file in files:
    
    print(file + '_'+str(i))
    findex = int(file.rstrip('.txt'))
    f = path + "/"+file
    formula = open(f,"r")
    line = formula.readline()
    if line!='':
        a1 = line.split()
        #line = formula.readline()
        #a2 = line.split()
        #a[1] = a[1].lstrip('0m')
        #a[1] = a[1].rstrip('s')
        c1 = float(a1[0])/1000000
        #c2 = float(a2[0]) / 1000
        table.write(findex+1,4,c1)
        #table.write(findex+1,5,c2)
        #table.write(findex+1,4,c1-c2)
        
        #print(c)
        #print("ok")
    formula.close()
    i=i+1
ws.save('data.xls')
