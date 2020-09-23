# +

pycharm
https://github.com/psf/black

numpy, pandas, django, sqlalchemy, requests
scipy, sklearn, pandas, cvxpy, pytorch, Keras
Django does routing, forms, ORM, templates, APIs, GIS

https://stackoverflow.com/questions/18671528/processpoolexecutor-from-concurrent-futures-way-slower-than-multiprocessing-pool

```bash
python3 -c '
import inspect
a=1
b=2
c=f"""
   foo {a}
   bar {b}
   """
print(inspect.cleandoc(c))
'
# foo 1
# bar 2

flask-unsign --sign --cookie "{'end': '2020-07-13 10:59:59+0000'}" --secret 'Time' --legacy
```

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

ipdb
```python
import ipdb
ipdb.set_trace()

VALUE_MAX_LEN = 1024
def clean_value(value):
    if isinstance(value, str) and len(value) > VALUE_MAX_LEN:
        value = value[:VALUE_MAX_LEN] + " [and more {} bytes]".format(len(value) - VALUE_MAX_LEN)
    elif isinstance(value, list) and len(value) > VALUE_MAX_LEN:
        tail_len = len(value) - VALUE_MAX_LEN
        value = value[:VALUE_MAX_LEN]
        value.append("[and more {} elements]".format(tail_len))
    return value
def clean(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and len(value) > VALUE_MAX_LEN:
                data[key] = clean_value(value)
            elif isinstance(value, list):
                data[key] = clean_value(value)
                for i, item in enumerate(data[key]):
                    data[key][i] = clean(item)
            elif isinstance(value, dict):
                data[key] = clean(value)
    return clean_value(data)
pp [ "{}: {}".format(x, clean(getattr(o, x))) for o in [foo] for x in dir(o) ]
```

pdb
```
h
l
args
!import sys ;; p sys.argv
up, down, where # stack manipulation

# conditional breakpoints
break divide, denominator == 0 # Set breakpoint in divide function only if denominator is 0
clear [bpnumber]

# eval expression on break
(Pdb) commands 1
(com) args
(com) p "Inside divide()"
(com) end
(Pdb) c

# https://stackoverflow.com/questions/36579554/how-can-i-extract-local-variables-from-a-stack-trace
ipdb> !import sys
ipdb> !tb = sys.exc_info()[2]
ipdb> p tb.tb_next.tb_frame.f_locals
```

```python
with ipdb.launch_ipdb_on_exception():
    main()

print(dir(foo))
print(type(foo))
print(foo.__dict__)

traceback.print_stack()
```

~/.pdbrc
~/bin/post_mortem.py

https://ikhlestov.github.io/pages/languages/python/packages/ipdb/
https://stackoverflow.com/questions/3702675/how-to-print-the-full-traceback-without-halting-the-program

# Trace

```bash
python -m trace -trace foo.py
python -m trace --listfuncs --trackcalls foo.py

# increasing granularity
python -m trace -T _
python -m trace -l _
python -m trace --ignore-dir=$(python -c 'import sys; print(":".join(sys.path)[1:])') -t _
```

https://pymotw.com/2/sys/tracing.html

# Imports

https://alex.dzyoba.com/blog/python-import/

# Install local package

```bash
pip3 setup.py install --user
# ||
pip3 install --upgrade --force pip setuptools wheel
(
cd dir_with_setup.sh
python3 setup.py sdist
pip3 install .
)
```

### Create setup.py

```python
from setuptools import setup, find_packages
setup(
    name="HelloWorld",
    version="0.1",
    packages=find_packages(),
)
```

https://setuptools.readthedocs.io/en/latest/setuptools.html

# Save dependency list

```bash
pip freeze > requirements.txt
# On checkout
pip install -r requirements.txt
```

# Install remote dependency not in PyPI

```bash
pip install git+git://github.com/$user/$repository
```

# Override system site-packages

```bash
python2 -c '
  import sys
  sys.path.insert(0,"'"$OVERRIDE_PATH"'")
  execfile("'"$(command -v $FILE)"'")
'
```

# venv, ensurepip

https://bugzilla.redhat.com/show_bug.cgi?id=1464570

```bash
pip install --ignore-installed --upgrade pip setuptools && \
cat <<EOF > requirements.txt
appdirs==1.4.0
packaging==16.8
pyparsing==2.1.10
setuptools==39.2.0
six==1.10.0
EOF
pip wheel -r requirements.txt && \
mv *.whl /usr/lib/python3.6/ensurepip/_bundled/.
```

# packaging

```bash
pip install -r requirements.txt --target=python_modules
PYTHONPATH=python_modules python myscript.py
```

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

```python
# Python 2
"7368616b6564".decode("hex")
print "\x73 \x68 \x61 \x6b \x65 \x64"

# Python 2 + 3
bytearray.fromhex("7368616b6564").decode()

# Python 3
bytes.fromhex('7368616b6564').decode('utf-8')
print("\x73 \x68 \x61 \x6b \x65 \x64")
```

# Testing

```bash
python -m unittest discover project_directory "*_test.py"
# ||
pytest --cov=dir/
```

# Profiling, Benchmarking

```bash
# e.g. 100000 loops, best of 3: 4.86 usec per loop
python -mtimeit -s 'xs=range(10)' 'map(hex, xs)'
```

# Dissassembly

```python
import dis
listComp = compile('[f(x) for x in xs]', 'listComp', 'eval')
dis.dis(listComp)
listComp.co_consts
dis.dis(listComp.co_consts[0])
```

# Memory Allocation / Storage

```python
class DummyNum(object):
    """Dummy class"""
    __slots__ = 'n',

    def __init__(self, n):
        self.n = n
```

```bash
# On terminal 1
python3
# >>> s = b"qweqweqweqwe";

# On terminal 2
gcore "$(pidof python3)"
```

# Comparisons

### generator expression vs list comprehension vs map

list comprehension more efficient if lambda used in map

generator expression is lazy
list comprehension is not lazy
python2
    list comprehension does not create scope
    map is not lazy
        alternative: itertools.imap
python3
    map is lazy => when benchmarking, force all values to be computed
        e.g. `list(map(f,xs))`

-- https://stackoverflow.com/questions/1247486/list-comprehension-vs-map

# http

```bash
python2 -m SimpleHTTPServer 8123
python3 -m http.server 8123
```

# env

```bash
# Create
mkdir -p ~/share/venv
cd ~/share/venv/
python3 -m venv foo
# Note: packages will be installed in user path if specified in `pip.conf`, therefore override it
cd foo
printf '%s' '[install]
user = false
' > ./pip.conf

# Start
. ~/share/venv/foo/bin/activate

# Install dependencies
pip install angr
# Validation
find ~/share/venv/foo/lib/ -maxdepth 3 -mmin -5

# End
. ~/share/venv/foo/bin/deactivate
```

https://github.com/mozilla/crawl-prep/blob/master/setup-python-venv.sh

# ipython notebooks (ipynb)

```bash
jupyter notebook
```

`/!\` Python files on same directory as notebook must not contain errors, as jupyter automatically loads them and fails to load kernel on errors

### converting

```bash
jupytext --to py notebook.ipynb                 # convert notebook.ipynb to a .py file
jupytext --to notebook notebook.py              # convert notebook.py to an .ipynb file with no outputs
jupytext --to notebook --execute notebook.md    # convert notebook.md to an .ipynb file and run it
jupytext --update --to notebook notebook.py     # update the input cells in the .ipynb file and preserve outputs and metadata
jupytext --set-formats ipynb,py notebook.ipynb  # Turn notebook.ipynb into a paired ipynb/py notebook
jupytext --sync notebook.ipynb                  # Update all paired representations of notebook.ipynb
```

# type checking

```python
from typing import List

def foo(grid: List[List[str]]) -> int:
    # ...
```

```bash
pyre init
pyre
# ||
mypy --strict
```

https://github.com/python/mypy

# foreign functions (ffi)

```python
import ctypes
libc = ctypes.CDLL('libc.so.6')
libc.usleep(300000)
```

# process execution

```
subprocess.run(args, *, stdin=None, input=None, stdout=None, stderr=None, capture_output=False, shell=False, cwd=None, timeout=None, check=False, encoding=None, errors=None, text=None, env=None, universal_newlines=None, **other_popen_kwargs)

Run the command described by args. Wait for command to complete, then return a CompletedProcess instance.
```

https://docs.python.org/3/library/subprocess.html

# module imports

```
main.py
mypackage/
    __init__.py
    mymodule.py
    myothermodule.py
```

```python
# On myothermodule.py
from .mymodule import as_int
# On main.py
from mypackage.myothermodule import add
```

https://stackoverflow.com/questions/16981921/relative-imports-in-python-3
https://chrisyeh96.github.io/2017/08/08/definitive-guide-python-imports.html

# generate markdown from csv

```python
import pandas as pd

df = pd.DataFrame({"A": [1, 2, 3],
                   "B": [1.1, 2.2, 3.3]},
                    index =['a', 'a', 'b'])
print(df.to_markdown())
```

# jail

- `eval() / exec() / compile()`: execute any python code
- `globals() / locals() / vars()`: finding useful variables
- `getattr() / setattr()`: call object.banned(), e.g. `getattr(object, "ban"+"ned")`
- `"A""B" == "AB"`: alternative for `+`
    - https://github.com/OpenToAllCTF/Tips#python-jails
- blind
    ```python
    cmd = '''
    python -c "__import__('time').sleep({} if open('/home/nullcon/flagpart1.txt').read({})[-1:] == '{}' else 0)"
    '''.format(SLEEP_TIME, index, letter)
    ```
- altenative for `__builtins__` or `import`
    ```python
    classes = {}.__class__.__base__.__subclasses__()
    # e.g. 49 = warnings.catch_warnings
    b = classes[49]()._module.__builtins__
    m = b['__import__']('os')
    m.system("foo")
    ```
    - https://gynvael.coldwind.pl/n/python_sandbox_escape
