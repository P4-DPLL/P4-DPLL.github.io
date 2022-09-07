import os
def main():
    file = open("setup.py","w")
    formula = open("formula.txt","r")
    line = formula.readline()
    a=line.split()
    while a[0] == 'c':
        line = formula.readline()
        a=line.split()
    Num_of_variate = int(a[2])
    Num_of_clause  = int(a[3])
    clause=[]#记录公式情况
    #读取公式，并将公式记录在列表clause中，clause中的每个元素是一个列表,记录一个子句
    for i in range(0,Num_of_clause):
        line = formula.readline()
        a=line.split()
        for j in range(0,len(a)):
            a[j]=int(a[j])
        clause.append(a)
    table=[]#记录table划分情况
    variables=[]#记录变量对应的table位置
    for i in range(0,Num_of_variate+1):
        variables.append([])
    reg=len(clause)#reg表示clause条数
    t=0
    ii = 1
    conflict_tables = []#记录所有的conflict table
    conflict_table = []#记录conflict table里面的entry
    unit_clause_tables = []
    unit_clause_table = []
    while reg > 0:
        divide=[]
        conflict_table  = []
        unit_clause_table = []
        t=0#t表示表里面的conflict_table_entry条数
        tt = 0#tt表示unit_clause_table条数
        for i in range(0,len(clause)):#遍历每一个子句
            entry = 0
            mask = 0
            k=0#k表示clause[i]中的变量在divide中的变量个数，之后用于判断k是否等于len(clause[i])-1
            for j in range(0,len(clause[i])-1):#遍历clause[i]里面的每一个变量，因为每个clause是以0为结尾的，0是每个clause里的一个无效元素，所以需要-1
                if(not(abs(clause[i][j]) in divide) and len(divide)<256):
                    divide.append(abs(clause[i][j]))
                    k=k+1
                    index = divide.index(abs(clause[i][j]))
                    variables[abs(clause[i][j])].append([len(table),index])
                elif(abs(clause[i][j]) in divide):
                    k=k+1
            if(k==(len(clause[i])-1) and k!=0 and t+1<1024 and tt+len(clause[i])<1024):#clause[i]里面的每个variable都找到划分
                reg=reg-1#clause条数--
                #写conlict table entry
                for s in range(0,len(clause[i])-1):
                    index = divide.index(abs(clause[i][s]))
                    if clause[i][s]<0:
                        entry = entry + (1<<index)
                    mask = mask + (1<<index)
                tmp = [entry,mask,mask,mask]
                if not(tmp in conflict_table):
                    t=t+1#conflict table entry 条数++
                    conflict_table.append(tmp)
                    file.write("p4.pipe.Ingress.conflict_table_"+str(ii)+".add_with_action_conflict(value="+str(entry)+",value_mask="+str(mask)+",assigned="+str(mask)+",assigned_mask="+str(mask)+")"+"\n")

                
                
                #写unit_clause_table entry
                for s in range(0,len(clause[i])-1):
                    value = 0
                    value_mask = 0
                    assigned = 0
                    assigned_mask = 0
                    vid = abs(clause[i][s])
                    pol = 1
                    if(clause[i][s]<0):
                        pol = 0
                    index = divide.index(abs(clause[i][s]))
                    assigned_mask = assigned_mask + (1 << index)
                    for t in range(0,len(clause[i])-1):
                        if t==s:
                            continue
                        index = divide.index(abs(clause[i][t]))
                        if(clause[i][t]<0):
                            value = value + (1 << index)
                        value_mask = value_mask + (1 << index)
                        assigned = assigned + (1 << index)
                        assigned_mask = assigned_mask + (1 << index)
                    tmp = [value,value_mask,assigned,assigned_mask]
                    if not(tmp in unit_clause_table):
                        tt = tt + 1 
                        unit_clause_table.append(tmp)
                        file.write("p4.pipe.Ingress.unit_clause_table_"+str(ii)+".add_with_unit_clause_action(value="+str(value)+",value_mask="+str(value_mask)+",assigned="+str(assigned)+",assigned_mask="+str(assigned_mask)+",vid="+str(vid)+",pol="+str(pol)+")"+"\n")
                        
                clause[i] = [0]
            if t>=1023 or tt>=1023:
                break

                    




        conflict_tables.append(conflict_table)
        unit_clause_tables.append(unit_clause_table)
        table.append(divide)
        ii = ii+1
    #print(len(table))    
    #print("Table: ")
    #for t in table:
    #    print(t)
    #print("variables: ")
    #for v in variables:
    #    print(v)
    file = open("formula.txt","a")

    file.write("\n"+str(len(table))+"\n")
    for t in  table:
        for x in t:
            file.write(str(x)+" ");
        file.write("0 \n")
    #file.write("-1 \n")
    for i in range(1,Num_of_variate+1):
        for ic in variables[i]:
            file.write(str(ic[0])+" ")
        file.write("-1\n")
    #file.write("-2\n")
    formula.close()
    file.close()
    file = open( "tmpsetup.py", "r" )
    fileadd = open("setup.py","r")
    content = file.read()
    contentadd = fileadd.read()
    file.close()
    fileadd.close()
    pos = content.find( "#add_position" )
    if pos != -1:
        content = content[:pos] + contentadd + content[pos:]
        file = open( "setup.py", "w" )
        file.write( content )
        file.close()
        #print ("OK")
if __name__=="__main__":
    main()
