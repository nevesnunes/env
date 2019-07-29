# C
export CC=gcc

# Go
export GOROOT=/mingw64/lib/go
export GOPATH=$HOME/opt/gopath

# Perl
export PERL5LIB=/c/MinGW/msys/1.0/lib/perl5/site_perl/5.8:/c/MinGW/msys/1.0/lib/perl5/vendor_perl/5.8

# Java
export JAVA_HOME=/c/Program\ Files/Java/jdk1.8.0_141
export M2_HOME=/c/ProgramData/chocolatey/lib/maven/apache-maven-3.6.1
export MAVEN_HOME="$M2_HOME"
export CATALINA_HOME=/c/ProgramData/chocolatey/lib/Tomcat/tools/apache-tomcat-9.0.19

# Python
export PYTHONIOENCODING='utf8'

# Editors
export VISUAL='vim'
export EDITOR="$VISUAL"
export SUDO_EDITOR="$VISUAL"
export SVN_EDITOR="$VISUAL"

# +
export FZF_DEFAULT_OPTS='--bind=ctrl-j:accept,ctrl-k:kill-line,ctrl-u:preview-page-down,ctrl-i:preview-page-up --border --color=16,border:7'
export TESSDATA_PREFIX=$HOME/opt/msys64/mingw32/share
export WALKMOD_HOME=$HOME/opt/walkmod

export PATH=$PATH:$JAVA_HOME/bin:$MAVEN_HOME/bin:$WALKMOD_HOME/bin:$HOME/bin:$HOME/opt/sox:$HOME/opt/gopath/bin
