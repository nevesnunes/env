# lint

```bash
perl -c foo.pl
```

# debug

```perl
use strict;
use warnings;

my $ftstr = eval { $numFormatter->format_number($tstr, 2, 1); };
$DB::single = 1 if $@;
```

```bash
perl -MCPAN -e "CPAN::Shell->notest('install', 'Devel::DumpTrace')"
perl -MCPAN -e "CPAN::Shell->notest('install', 'Devel::Trace')"
perl -MCPAN -e "CPAN::Shell->notest('install', 'Hash::SafeKeys')"

perl -d:DumpTrace foo.pl
perl -d:Trace foo.pl
PERLDB_OPTS="RemotePort=localhost:12345" perl -d foo.pl
PERLDB_OPTS="NonStop AutoTrace" perl -d foo.pl
PERLDB_OPTS="NonStop AutoTrace frame=31" perl -d foo.pl
PERLDB_OPTS="NonStop AutoTrace LineInfo=D:\foo.txt" perl -d foo.pl
perl -d -e 'source /c/Temp/perldb_commands.txt' foo.pl

# break on die or warn with custom REPL
# Reference: https://metacpan.org/pod/Carp::REPL
perl -MCPAN -e "CPAN::Shell->notest('install', 'Carp::REPL')"
perl -MCarp::REPL=warn foo.pl
```

```bash
# break on die or warn with debugger
# Reference: https://metacpan.org/pod/PadWalker
perl -MCPAN -e "CPAN::Shell->notest('install', 'PadWalker')"
perl -d foo.pl
```

In source:

```perl
$SIG{__DIE__} = sub { $DB::single = 1; die @_; };
```

In debugger:

```
DB<1> y 1
```

### perldb

```
# stack backtrace
T

# eval with pretty=print
x 3 map { $_->{_implicit} eq 1 } @{$elem->{_content}}

# help all
|h h
```

- https://perldoc.perl.org/perldebug.html#Debugger-Commands
- https://perldoc.perl.org/perldebguts.html#Frame-Listing-Output-Examples

### issues on windows

- https://www.perlmonks.org/?node_id=516028

# package management

```
perl -MCPAN -e shell
cpan[1]> o conf commit
```

```ps1
sls -CaseSensitive '(\$VERSION\s*=|version->declare|require_version).*1.38'
```

- http://blogs.perl.org/users/grinnz/2018/04/a-guide-to-versions-in-perl.html

### cpan - build modules on windows

- https://www.perlmonks.org/?node_id=583586
- https://www.perlmonks.org/?node_id=496624
- https://www.perlmonks.org/?displaytype=print;replies=1;node_id=496901

### manual build

```bash
perl Makefile.PL
make
ppm install Foo::Bar
```

# file types

```ps1
gci -Recurse -File -Exclude *.pm,*.pod,*.pl
```

- auto
    - .packlist
    - foo.bs
    - foo.dll
    - foo.exp
    - foo.lib
    - foo.pdb

# docs

```bash
perldoc -f function_foo
```

- https://github.com/OpusVL/perldoc.perl.org-engine
- https://perldoc.perl.org/perlop.html#Quote-and-Quote-like-Operators

# cheatsheet

```perl
# stdin
my $input = <STDIN>;
chomp $input;

# command line parameters
my $input = $ARGV[0];
```

```
CONTEXTS  SIGILS  ref        ARRAYS        HASHES
void      $scalar SCALAR     @array        %hash
scalar    @array  ARRAY      @array[0, 2]  @hash{'a', 'b'}
list      %hash   HASH       $array[0]     $hash{'a'}
          &sub    CODE
          *glob   GLOB       SCALAR VALUES
                  FORMAT     number, string, ref, glob, undef
REFERENCES
\      reference       $$foo[1]       aka $foo->[1]
$@%&*  dereference     $$foo{bar}     aka $foo->{bar}
[]     anon. arrayref  ${$$foo[1]}[2] aka $foo->[1]->[2]
{}     anon. hashref   ${$$foo[1]}[2] aka $foo->[1][2]
\()    list of refs
                       SYNTAX
OPERATOR PRECEDENCE    foreach (LIST) { }     for (a;b;c) { }
->                     while   (e) { }        until (e)   { }
++ --                  if      (e) { } elsif (e) { } else { }
**                     unless  (e) { } elsif (e) { } else { }
! ~ \ u+ u-            given   (e) { when (e) {} default {} }
=~ !~
* / % x                 NUMBERS vs STRINGS  FALSE vs TRUE
+ - .                   =          =        undef, "", 0, "0"
<< >>                   +          .        anything else
named uops              == !=      eq ne
< > <= >= lt gt le ge   < > <= >=  lt gt le ge
== != <=> eq ne cmp ~~  <=>        cmp
&
| ^             REGEX MODIFIERS       REGEX METACHARS
&&              /i case insensitive   ^      string begin
|| //           /m line based ^$      $      str end (bfr \n)
.. ...          /s . includes \n      +      one or more
?:              /x /xx ign. wh.space  *      zero or more
= += last goto  /p preserve           ?      zero or one
, =>            /a ASCII    /aa safe  {3,7}  repeat in range
list ops        /l locale   /d  dual  |      alternation
not             /u Unicode            []     character class
and             /e evaluate /ee rpts  \b     boundary
or xor          /g global             \z     string end
                /o compile pat once   ()     capture
DEBUG                                 (?:p)  no capture
-MO=Deparse     REGEX CHARCLASSES     (?#t)  comment
-MO=Terse       .   [^\n]             (?=p)  ZW pos ahead
-D##            \s  whitespace        (?!p)  ZW neg ahead
-d:Trace        \w  word chars        (?<=p) ZW pos behind \K
                \d  digits            (?<!p) ZW neg behind
CONFIGURATION   \pP named property    (?>p)  no backtrack
perl -V:ivsize  \h  horiz.wh.space    (?|p|p)branch reset
                \R  linebreak         (?<n>p)named capture
                \S \W \D \H negate    \g{n}  ref to named cap
                                      \K     keep left part
FUNCTION RETURN LISTS
stat      localtime    caller         SPECIAL VARIABLES
 0 dev    0 second      0 package     $_    default variable
 1 ino    1 minute      1 filename    $0    program name
 2 mode   2 hour        2 line        $/    input separator
 3 nlink  3 day         3 subroutine  $\    output separator
 4 uid    4 month-1     4 hasargs     $|    autoflush
 5 gid    5 year-1900   5 wantarray   $!    sys/libcall error
 6 rdev   6 weekday     6 evaltext    $@    eval error
 7 size   7 yearday     7 is_require  $$    process ID
 8 atime  8 is_dst      8 hints       $.    line number
 9 mtime                9 bitmask     @ARGV command line args
10 ctime               10 hinthash    @INC  include paths
11 blksz               3..10 only     @_    subroutine args
12 blcks               with EXPR      %ENV  environment
```

- https://perldoc.pl/perlcheat

# testing

- https://metacpan.org/pod/distribution/Test-Harness/bin/prove
    - http://testanything.org/
- https://perldoc.perl.org/Test/More.html

# case studies

- unsafe eval with quoted argument
    - CVE-2021-22204 - bypass with escaped quote + newline = multi-line string containing backslash, concatenated with evaluated shellexec, last closing quote commented out
- [CGI Security Holes \- Phrack 49](~/code/doc/zines/phrack/49/8.txt)
