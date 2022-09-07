#!/bin/bash


i=1
for k in `ls -Sr data/formula_all/*.txt`
do
	if [[ $i -le 15000 ]];then
		
		echo $k$i
		i=$(($i+1))
	
    else

		if [ -f $k ]; then
		
			cp python_file/table_clear.py python_file/table_clear_and_write.py

			{ time timeout 40s python3 python_file/control.py $k; } 2> "result/pythonresult/$k"

			chmod 755 shell/transfer_file.sh
			dos2unix shell/transfer_file.sh
			{ time ./shell/transfer_file.sh; } 2> "result/transfileresult/$k"

			wait

			chmod 755 shell/run_bfshell.sh
			dos2unix shell/run_bfshell.sh
			{ time ./shell/run_bfshell.sh; } 2> "result/compileresult/$k"

			wait

			cp $k formula.txt
			sudo timeout 20s ./build/send < formula.txt
			cp result.txt "result/runresult/$k"
			#sudo python3 python_file/send.py $k
			
			echo $k$i
			echo $k$i >> log.txt
			i=$(($i+1))
		fi
	fi

done