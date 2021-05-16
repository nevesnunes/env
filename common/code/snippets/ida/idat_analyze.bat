@echo off
cls

set IDA_PATH="UDPATE THE PATH TO IDA TEXT INTERFACE .exe"

set arg1=%1

set idc_file=%tmp%\moo.idc
echo #include ^<idc.idc^>>%idc_file%
echo static main()>>%idc_file%
echo {>>%idc_file%
echo set_inf_attr(INF_AF, get_inf_attr(INF_AF) ^| AF_DODATA);>>%idc_file%
@rem speed up here ; AF_USED Analyze and create all xrefs
echo set_inf_attr(INF_AF, get_inf_attr(INF_AF) ^& (~AF_USED));>>%idc_file%
echo auto_wait();>>%idc_file%
echo qexit(0);>>%idc_file%
echo }>>%idc_file%

set ida_opt_second_args=-DOPCODE_BYTES=8 -DGRAPH_OPCODE_BYTES=8 -DGRAPH_SHOW_LINEPREFIXES=YES

@rem The selected loader will load all segments without asking
set IDA_LOADALL=1

%IDA_PATH% -c -A -S%idc_file% %ida_opt_second_args% %arg1%
