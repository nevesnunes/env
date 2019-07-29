foo = $(wildcard *.md)

bar : $(foo) script.sh
./script.sh $(foo) 
