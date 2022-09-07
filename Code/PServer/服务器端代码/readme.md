/******************************************************/
0. 为了能正确的运行pserver代码，需要首先安装好dpdk环境，使得服务器可以正常的收发包
    ./testx.sh



1. 服务器端代码说明
    1）test.cpp: 基于dpdk收发包编写的服务器端主程序，包括dpll算法控制组件的全部逻辑，并通过dpdk收发包与p4端进行交互，获取p4端的判定结果
    2）runentry.sh: 用于远程控制可编程交换机，在运行主程序（test.p4）之前，提前远程控制p4端将sat formula的数据转换成流表项，并装载到可编程交换中
    3) testx.sh 批量处理，用于远程控制p4进行初始化、运行test主程序、读取最终结果到result中
    3) Makefile用于编译test.cpp
    4) result文件夹，记录每个公式的运行时间以及初始化时间（转换编译流表项时间）
        a. compileentry: 用于记录每个公式转换编译流表项时间
        b. runresult: 用于记录每个公式运行时间
    5) initdata文件夹：用于保存初始sat公式（在testx.sh的脚本文件处理逻辑下，initdata中文件的命名格式为1.txt, 2.txt, 3.txt, ..., 999.txt
    6) processdata文件夹 包含处理中间数据的若干py文件
        a. readcompiletime.py 用于读取编译时间
        b. runresult.py 读取每个公式的运行时间

        

