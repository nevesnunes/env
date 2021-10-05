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

# Try older versions

```bash
docker run -it --rm -v $(pwd):/tmp/foo:z python:3.5-slim sh
```

# Performance

- Use JIT compiler: [PyPy](https://www.pypy.org/)

# REPL

https://ipython.org/ipython-doc/stable/interactive/qtconsole.html

# Debugging

```bash
python3 -m pdb -c continue foo.py
```

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

gdb
- https://www.podoliaka.org/2016/04/10/debugging-cpython-gdb/
```
gdb /usr/bin/python3 -p 1234

(gdb) py-bt
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
print(getattr(foo, x))
print(type(foo))
print(foo.__dict__)

traceback.print_stack()
```

- ~/.pdbrc
- ~/bin/post_mortem.py

- https://ikhlestov.github.io/pages/languages/python/packages/ipdb/
- https://stackoverflow.com/questions/3702675/how-to-print-the-full-traceback-without-halting-the-program

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

### Modules

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

- [!] Avoid importing module with same name as another visible file
    - e.g. Given `foo.so`, `foo.py`, `import foo` may load `foo.so`
        - https://stackoverflow.com/questions/65356321/creating-a-python-module-using-ctypes#65356321

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

# Install offline dependencies

```bash
pip wheel -r requirements.txt -w ./dependencies
# ||
pip download -r requirements.txt -d ./dependencies

pip install --no-index --find-links ./dependencies "$package_name"

# Using [python-pypi-mirror](https://pypi.org/project/python-pypi-mirror/)
pip install --trusted-host "$http_server" -i "http://$http_server:$http_server_default_port/simple" "$package_name"
```

# Install remote dependency not in PyPI

```bash
pip install git+git://github.com/$user/$repository
```

# Force install in path

```bash
env PYTHONPATH=/usr/lib/python3.8/site-packages python3.8 -m pip install --ignore-installed foo
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

https://stackoverflow.com/questions/714063/importing-modules-from-parent-folder
https://medium.com/knerd/the-nine-circles-of-python-dependency-hell-481d53e3e025

# hex

- parsing
    - ~/bin/hex2bin.py
    - ~/bin/hex2char.py
    - ~/bin/hexwords2bin.py
- format
    ```
    >>> '{:#010x}'.format(3)
    '0x00000003'
    >>> f'{3:#010x}'
    '0x00000003'
    ```

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

# References:
# - https://docs.python.org/3/library/struct.html
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
tracemalloc

psutils.virtual_memory().used

# https://stackoverflow.com/questions/449560/how-do-i-determine-the-size-of-an-object-in-python
# ~/code/snippets/py/getsize.py
pprint.pprint({k: getsize(v) for k, v in locals().items() if not isinstance(v, type(__builtins__)) and not isinstance(v, types.Fun
ctionType) and not isinstance(v, type)})

# e.g. 100000 loops, best of 3: 4.86 usec per loop
python -mtimeit -s 'xs=range(10)' 'map(hex, xs)'
```

# Disassembly, decompilation

- [GitHub \- zrax/pycdc: C\+\+ python bytecode disassembler and decompiler](https://github.com/zrax/pycdc)

- header format
    - **[..3.3]**
        - version + `0d 0a` (4 bytes)
        - modification timestamp (4 bytes)
    - **[3.3..3.7]**
        - version + `0d 0a` (4 bytes)
        - modification timestamp (4 bytes)
        - file size (4 bytes)
    - **[3.7..]**
        - version + `0d 0a` (4 bytes)
        - bit field (4 bytes)
            - if 0, then 3rd word is timestamp, 4th word is file size
            - if lowest bit 1, then 3rd to 4th word are 64-bit file hash
- bytecode versions
    - https://github.com/google/pytype/blob/master/pytype/pyc/magic.py
    - https://github.com/python/cpython/blob/master/Lib/importlib/_bootstrap_external.py
    - validation:
        ```bash
        python3.6 -m compileall foo.py
        python3.6 -c 'import imp;print(int.from_bytes(imp.get_magic()[:2], "little"))'
        # 0xd33 => 3379
        ```
    - `[!]` 3.6 bytecode header is 12 bytes
        - e.g. `diff <(xxd -l32 __pycache__/checker1.cpython-36.pyc) <(xxd -l32 __pycache__/checker1.cpython-38.pyc)`
            ```diff
            1,2c1,2
            < 00000000: 330d 0d0a 0885 1660 ac01 0000 e300 0000  3......`........
            < 00000010: 0000 0000 0000 0000 0002 0000 0040 0000  .............@..
            ---
            > 00000000: 550d 0d0a 0000 0000 0885 1660 ac01 0000  U..........`....
            > 00000010: e300 0000 0000 0000 0000 0000 0000 0000  ................
            ```
    - https://reverseengineering.stackexchange.com/questions/23522/decompiling-python-files-valueerror

```bash
# Finding script filenames
# 1. debug until script loaded
# 2. make full memory dump
# 3. floss and grep `\.py$`

# From PyInstaller
python python_exe_unpack.py -i foo.exe

# From pyc
python -c '
import dis, marshal, sys, uncompyle6
f = open(sys.argv[1], "rb")
f.seek(16) # skip 16 byte header (in case of invalid magic bytes)
co = marshal.load(f)
print(dis.dis(co)) # bytecode
f2 = open(sys.argv[2], "w")
uncompyle6.main.decompile(3.7, co, f2, showast=False) # source
' foo
```

```python
import dis
list_compiled = compile('[f(x) for x in xs]', 'listComp', 'eval')
# ||
list_compiled = compile('[f(x) for x in xs]', 'listComp', 'exec')
dis.dis(list_compiled)

def foo(): return 123
foo.__code__.co_code
# b'd\x01S\x00'
dis.dis(foo.__code__.co_code)
# 0 LOAD_CONST               1 (1)
# 2 RETURN_VALUE
foo.__code__.co_consts
# (None, 123)

# python2
foo.func_code.co_consts
```

- https://nedbatchelder.com/blog/200804/the_structure_of_pyc_files.html
- https://late.am/post/2012/03/26/exploring-python-code-objects.html
- http://www.mingzhehu.cn/static/posts/20200211-PythonBytecodeDisassembler.html
    - https://docs.python.org/3/library/importlib.html#importlib.util.MAGIC_NUMBER
    - [PEP 552 \-\- Deterministic pycs \| Python\.org](https://www.python.org/dev/peps/pep-0552)

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
target=
mkdir -p ~/code/venv
cd ~/code/venv/
python3 -m venv "$target"
# Note: packages will be installed in user path if specified in `pip.conf`, therefore override it
cd "$target"
printf '%s' '[install]
user = false
' > ./pip.conf

# Start
. ~/code/venv/"$target"/bin/activate

# Install dependencies
pip install wheel
pip install angr ipdb pwntools
pip install -U six==1.13.0
# Validation
find ~/code/venv/foo/lib/ -maxdepth 3 -mmin -5

# End
. ~/code/venv/foo/bin/deactivate
```

https://github.com/mozilla/crawl-prep/blob/master/setup-python-venv.sh

# ipython notebooks (ipynb)

```bash
jupyter notebook
```

`[!]` Python files on same directory as notebook must not contain errors, as jupyter automatically loads them and fails to load kernel on errors

### converting

```bash
jupytext --to py notebook.ipynb                 # convert notebook.ipynb to a .py file
jupytext --to notebook notebook.py              # convert notebook.py to an .ipynb file with no outputs
jupytext --to notebook --execute notebook.md    # convert notebook.md to an .ipynb file and run it
jupytext --update --to notebook notebook.py     # update the input cells in the .ipynb file and preserve outputs and metadata
jupytext --set-formats ipynb,py notebook.ipynb  # Turn notebook.ipynb into a paired ipynb/py notebook
jupytext --sync notebook.ipynb                  # Update all paired representations of notebook.ipynb
```

# docstrings

- https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html

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

k = ctypes.windll.kernel32
k.SetFileAttributesW(filename, 2)

foo = CDLL('./foo.so')
foo.bar.argtypes = [c_uint64, c_uint64]
foo.bar.restype = c_uint32
foo.bar(1, 2)

# https://docs.python.org/3.9/library/ctypes.html#fundamental-data-types
foo = ctypes.c_uint32(bar)
print(foo.value)
```

# process execution

```
subprocess.run(args, *, stdin=None, input=None, stdout=None, stderr=None, capture_output=False, shell=False, cwd=None, timeout=None, check=False, encoding=None, errors=None, text=None, env=None, universal_newlines=None, **other_popen_kwargs)

Run the command described by args. Wait for command to complete, then return a CompletedProcess instance.
```

https://docs.python.org/3/library/subprocess.html

# generate markdown from csv

```python
import pandas as pd

df = pd.DataFrame({"A": [1, 2, 3],
                   "B": [1.1, 2.2, 3.3]},
                    index =['a', 'a', 'b'])
print(df.to_markdown())
```

# regex escape

```
>>> re.match(".*'.*", "1\n' OR 1=1--")
>>>
>>> re.search(".*'.*", "1\n' OR 1=1--")
<re.Match object; span=(2, 12), match="' OR 1=1--">
```

# deobfuscation

- [GitHub \- landaire/unfuck: Python 2\.7 bytecode d̶e̶o̶b̶f̶u̶s̶c̶a̶t̶o̶r unfucker](https://github.com/landaire/unfuck)

# jail

- `eval() / exec() / compile()`: execute any python code
- `globals() / locals() / vars()`: finding useful variables, using built-ins
    - [CTFtime\.org / Really Awesome CTF 2020 / Puffer Overflow](https://ctftime.org/task/11928)
- `getattr() / setattr()`: call object.banned(), e.g. `getattr(object, "ban"+"ned")`
- `"A""B" == "AB"`: alternative for `+`
- blind
    ```python
    cmd = '''
    python -c "__import__('time').sleep({} if open('/home/nullcon/flagpart1.txt').read({})[-1:] == '{}' else 0)"
    '''.format(SLEEP_TIME, index, letter)
    ```
- altenative for `__builtins__` or `import`
    ```python
    # Listing keys to find classes
    ''.__dir__()
    # ||
    hasattr('', '__class__')
    # ||
    [print(i,x,dir(x)) for i,x in enumerate(().__class__.__base__.__subclasses__())]

    # Take classes
    classes = ().__class__.__base__.__subclasses__()
    # ||
    classes = {}.__class__.__base__.__subclasses__()
    # ||
    classes = {}.__class__.__bases[0]__.__subclasses__()
    # ||
    classes = ''.__class__.__mro__[1].__subclasses__()

    # Pick class with imports
    # - e.g. 49 = warnings.catch_warnings
    b = classes[49]()._module.__builtins__
    m = b['__import__']('os')
    m.system("ls")
    # ||
    ''.__class__.__mro__[-1].__subclasses__()[71]._Printer__setup.__globals__['os'].system("ls")
    # - http://wapiflapi.github.io/2013/04/22/plaidctf-pyjail-story-of-pythons-escape.html

    print(eval(eval('"alles.__".'+str(print.__class__)[9]+'ppe'+'r()')+'code__.co_consts'))
    # - [CTFtime\.org / ALLES! CTF 2020 / Pyjail ATricks / Writeup](https://ctftime.org/writeup/23289)
    ```
- alternative for chars
    ```python
    print(str(print.__class__))
    # "<class 'builtin_function_or_method'>"
    # 'b' : 'str(print.__class__)[8]',
    eval.__doc__
    # 'Evaluate the given source in the context of globals and locals.\n\nThe source may be a string representing a Python expression\nor a code object as returned by compile().\nThe globals must be a dictionary and locals can be any mapping,\ndefaulting to the current globals and locals.\nIf only globals is given, locals defaults to it.'
    ```

- https://book.hacktricks.xyz/misc/basic-python/bypass-python-sandboxes
- https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/
- [Breaking Out of a Python Sandbox · Issue \#6 · se162xg/notes · GitHub](https://github.com/se162xg/notes/issues/6)
- [GitHub \- OpenToAllCTF/Tips: Useful tips by OTA CTF members \- Python jails](https://github.com/OpenToAllCTF/Tips#python-jails)
- https://gynvael.coldwind.pl/n/python_sandbox_escape
- https://kmh.zone/blog/2021/02/07/ti1337-plus-ce/

### type coercion

```python
not 1
# False
not not 1
# True
+False
# 0
+True
# 1
```

# memoization

- https://docs.python.org/3/library/functools.html#functools.lru_cache

# signed int, 2s-complement

```python
import ctypes
>>> ctypes.c_uint(-1)
c_uint(4294967295)
>>> ctypes.c_uint(0xffffffff)
c_uint(4294967295)
>>> ctypes.c_uint(0xffffffff + 1)
c_uint(0)
>>> ctypes.c_uint64(0xffffffff + 1)
c_ulong(4294967296)
>>> ctypes.c_uint32(0xffffffff + 1)
c_uint(0)
>>> ctypes.c_uint16(0xffffffff + 1)
c_ushort(0)
```
