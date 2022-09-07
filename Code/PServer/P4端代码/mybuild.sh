$SDE_INSTALL/bin/bf_kdrv_mod_load $SDE_INSTALL
source ../set_sde.bash 
#编译运行程序
./../p4_build.sh test.p4
./../run_switchd.sh -p test
