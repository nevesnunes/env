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

- https://github.com/OpusVL/perldoc.perl.org-engine
- https://perldoc.perl.org/perlop.html#Quote-and-Quote-like-Operators

# cheatsheet

- https://perldoc.pl/perlcheat

# testing

- https://metacpan.org/pod/distribution/Test-Harness/bin/prove
    - http://testanything.org/
- https://perldoc.perl.org/Test/More.html


