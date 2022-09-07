#! /bin/bash
for i in  `seq  $1 $2`#注意此处这是两个反引号，表示运行系统命令
do
    { time ./runentry.sh "$i.txt"; } 2> "result/compileentry/$i.txt"
    > result.txt
    sudo timeout 10s ./build/test < "initdata/$i.txt"
    cp result.txt "result/runresult/$i.txt"
    echo $i >> log.txt
done





