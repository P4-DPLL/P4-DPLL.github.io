0. dpll算法在服务器端的实现

    
1. 代码文件说明：
    Makefile: 用于编译solver.cpp
    solver.cpp: dpll算法主程序，求解sat formula,求解5次后计算平均值，并将结果写入result.txt
    run.sh 批量处理formula中的文件，并将结果写入result文件夹中