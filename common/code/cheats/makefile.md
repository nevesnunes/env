# debug

```bash
# trace command line invocations
make SHELL='sh -x'

# print expanded value of variable
echo 'print: ; @echo "$(VAR)"' | make -f Makefile -f - print
```

```make
$(if $(shell echo $(3) 1>&2),,)
```

- ~/code/guides/ctf/sasdf---ctf/writeup/2018/HackOver/rev/flagmaker/README.md
