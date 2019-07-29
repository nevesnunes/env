# REPL

https://ipython.org/ipython-doc/stable/interactive/qtconsole.html

# Debugging

ipython
```
%xmode Verbose

%debug
||
%pdb on
```

pdb
```
h
l
args
!import sys ;; p sys.argv
up, down, where # stack manipulation

# breakpoints
break divide, denominator == 0 # Set breakpoint in divide function only if denominator is 0
clear [bpnumber]
(Pdb) commands 1
(com) args
(com) p "Inside divide()"
(com) end
(Pdb) c
```

print(type(foo))
print(foo.__dict__)

~/bin/post_mortem.py

# Trace

python -m trace -trace foo.py
python -m trace --listfuncs --trackcalls foo.py

# Imports

https://alex.dzyoba.com/blog/python-import/

# Install local package

```bash
pip3 install --upgrade --force pip setuptools wheel
(
cd dir_with_setup.sh
python3 setup.py sdist
pip3 install .
)
```

# Override system site-packages

```bash
python2 -c '
  import sys
  sys.path.insert(0,"'"$OVERRIDE_PATH"'")
  execfile("'"$(command -v $FILE)"'")
'
```

# Testing

python -m unittest discover project_directory "*_test.py"


# Debug

traceback.print_stack()

# Trace (increasing granularity)
python2 -m trace -T _
python2 -m trace -l _
python2 -m trace --ignore-dir=$(python -c 'import sys ; print(":".join(sys.path)[1:])') -t _

# venv, ensurepip

https://bugzilla.redhat.com/show_bug.cgi?id=1464570

```
pip install --ignore-installed --upgrade pip setuptools && \
cat <<EOF > requirements.txt
appdirs==1.4.0
packaging==16.8
pyparsing==2.1.10
setuptools==39.2.0
six==1.10.0
EOF && \
pip wheel -r requirements.txt && \
mv *.whl /usr/lib/python3.6/ensurepip/_bundled/.
```

# type checking

https://github.com/python/mypy
`mypy --strict`

# packaging

pip install -r requirements.txt --target=python_modules
PYTHONPATH=python_modules python myscript.py

https://docs.python.org/3/tutorial/venv.html
https://docs.pipenv.org/en/latest/
https://github.com/jazzband/pip-tools/
https://github.com/sdispater/poetry

https://github.com/pyinstaller/pyinstaller
https://github.com/Nuitka/Nuitka

https://medium.com/knerd/the-nine-circles-of-python-dependency-hell-481d53e3e025

# hex

```bash
addr=200.0.10.1; python -c "
import socket; 
print(socket.inet_aton('$addr'))"
# b'\xc8\x00\n\x01'

addr=200.0.10.1; python -c "
import socket, struct;
print(struct.unpack('<L', socket.inet_aton('$addr'))[0])"
# 17432776

addr=200.0.10.1; python -c "
import socket, struct; 
print(hex(struct.unpack('<L', socket.inet_aton('$addr'))[0])[2:10].upper().zfill(8))"
# 010A00C8

# References
# https://docs.python.org/3/library/struct.html
```

# +

pycharm
https://github.com/psf/black

numpy, pandas, django, sqlalchemy, requests
scipy, sklearn, pandas, cvxpy, pytorch, Keras
Django does routing, forms, ORM, templates, APIs, GIS

https://stackoverflow.com/questions/18671528/processpoolexecutor-from-concurrent-futures-way-slower-than-multiprocessing-pool
