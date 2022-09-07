import time
import os
import xlwt
import xlrd
import xlutils.copy
path = "result/compileentry"
files = os.listdir(path)
data = xlrd.open_workbook('data.xls')
ws = xlutils.copy.copy(data)
table = ws.get_sheet('pserver')
i = 1
for file in files:
    
    print(file + '_'+str(i))
    i=i+1
    findex = int(file.rstrip('.txt'))
    f = path + "/"+file
    formula = open(f,"r")
    content = formula.read()
    pos = content.find("real")
    pos1 = content.find("user")
    if pos!=-1:
        
        mystr = content[pos:pos1]
        pos = mystr.find("m")
        pos1 = mystr.find("s")
        mystr = mystr[pos+1:pos1]
        mytime = float(mystr)


        
        table.write(findex+1,8,mytime)
        
        #print(c)
        #print("ok")
    formula.close()
ws.save('data.xls')
