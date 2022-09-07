#! /bin/bash
#i=1
#for file in `ls formula_else` #注意此处这是两个反引号，表示运行系统命令
#do
#    echo $file
#    timeout 30s  ./solver < "formula_else/$file"
#    cp result.txt "result_else/$file"
#done
for i in `seq $1 $2`
do
    echo $i >> log1.txt
    timeout 60s ./solver < "formula_all/$i.txt"
    cp result.txt "result/$i.txt"
    echo $i
done

