# Including library paths in binary
-Wl,--enable-new-dtags -Wl,-rpath,$ORIGIN/lib

# Including library paths in env
export LD_LIBRARY_PATH=/home/whatever/weird/libs${LD_LIBRARY_PATH+:${LD_LIBRARY_PATH}}
