/*******************************************************/
/*****为了能够正确运行pserver程序，需要首先在p4端编译运行test.p4程序，并激活端口********/
./mybuild.sh     ///////编译运行test.p4文件，运行完test.p4文件之后，需要激活p4端的相应端口，使得p4端能和服务器端正常交互（收发包）

p4端代码文件说明：
    test.p4: p4端的主程序，需要提前在可编程交换机上运行，通过mybuild.sh脚本文件运行
    formula_all文件夹： 保存sat formula文件的文件夹
    formula.txt: 用于保存sat formula信息
    setup.sh: 用于将setup.py中的流表项装入可编程交换机中
    build.sh: 用于编译p4文件
    run.sh: 用于在可编程交换机上运行p4文件
    mybuild.sh: 用于在可编程交换机上编译运行test.p4的脚本文件
    setup.py: 用于保存流表项的文件
    tmpsetup.py: 用于将sat formula文件写入setup.py流表项的备份文件
    mywrite.py: 用于将sat formula公式转换成setup.py流表项文件（不需要主动运行，通过服务器远程控制