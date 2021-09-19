# +

- [maven](./maven.md)
- [gradle](./gradle.md)

```java
Pattern.compile("date\\(.*\\)").matcher(value).find()
    
File dump = new File("D:\\dump");
try{
    PrintWriter writer = new PrintWriter("D:\\asdf", "UTF-8");
    writer.println(clazz.toString());
    writer.println(name.toString());
    writer.close();
} catch (IOException e) {
	return "";
}

return clazz.toString() + " ---- " + name.toString();
```

# Build

```bash
srcs=
classesDir=
jarDir=
javac -cp "$jarDir/*" "$srcs"
jar -cvfe Foo.jar MainClassFoo "$classesDir/"
```

# Running

```bash
# Working directory hierarchy:
# ~/code/wip/javawip/build/classes/java/main
# └── javawip
#     ├── App.class
#     └── FormLargestNum.class
java javawip.FormLargestNum
```

# Debugging

```ps1
& "C:\Program Files\Java\jdk1.8.0_151\bin\jdb" -connect "com.sun.jdi.SocketAttach:hostname=localhost,port=1043"
```

```
stop in com.foo.Bar.doBaz
stop at com.foo.Bar:305
next

locals
dump fooObject

eval ((com.fasterxml.jackson.databind.ObjectMapper) java.lang.Thread.currentThread().getContextClassLoader().loadClass("com.fasterxml.jackson.databind.ObjectMapper").newInstance()).writerWithDefaultPrettyPrinter().writeValueAsString(foo)

eval String.class.getProtectionDomain().getCodeSource().getLocation()
eval String.class.getResource('/' + String.class.getName().replace('.', '/') + ".class");
```

### Debug info

Variable info required to resolve values in IDE debugger

```bash
# Generate LineNumberTable
javac -g:lines
# Generate LocalVariableTable
javac -g:vars
# Generate all info
javac -g

# Validation
javap -l | grep 'LineNumberTable\|LocalVariableTable'
```

https://synyx.de/blog/java-deep-dive-class-file-format-for-debug-information/
    https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.12

# Processes

```
eclipse
\_ /usr/bin/java [...] org.eclipse.equinox.launcher.Main
    \_ /usr/bin/java [...] foo.Bar (Run as: Java Application)
    \_ /usr/bin/java [...] org.eclipse.jdt.internal.junit.runner.RemoteTestRunner (Run as: JUnit Test)
```

Picked up by `visualvm`

# configure java

```ps1
"D:\jre1.8.0_77\bin\javaw.exe" -Xbootclasspath/a:"D:\jre1.8.0_77\bin\..\lib\deploy.jar" -Djava.locale.providers=HOST,JRE,SPI -Duser.home="C:\Users\foo" com.sun.deploy.panel.ControlPanel
```

### disable updates

On tab Update, uncheck: Check for Updates Automatically

# classpath

Add jvm flags:

`-classpath, -Xbootclasspath`

<a name="parse_classpath"></a>
Parse classpath:

```bash
jinfo 1234 | grep 'java.class.path'
# ||
jcmd 1234 VM.command_line | grep 'java.class.path'
# ||
jcmd 1234 VM.system_properties | grep 'java.class.path'
```

Confirm the class is in jars:

```bash
java -jar ./jfind.jar 'com.foo.*' .
```

|| Check if process has file handles for jars:

```bash
/usr/sbin/lsof -p 1234 | grep 'foo\|\.jar$'
```

|| Check if war finished copying over to webapps/ before app server start

- shutdown tomcat, clean caches, restart tomcat

Invariants:

- Only one version of a given dependency should be present in the classpath

Reference:

https://docs.oracle.com/en/java/javase/11/troubleshoot/diagnostic-tools.html#GUID-085D7019-5A14-4F58-A385-FB6E200B3DC1

# web app

```
$CATALINA_BASE/webapps/$APP/META-INF/context.xml
WebContent/WEB-INF/lib/
WebContent/WEB-INF/classes/
WebContent/WEB-INF/*context.xml
src/main/resources/
src/main/webapp/WEB-INF/spring/appServlet/*context.xml
```

web.xml

```xml
<resource-ref id="123">
    <res-ref-name>fooSource</res-ref-name>
    <res-type>javax.sql.DataSource</res-type>
    <res-auth>Container</res-auth>
    <res-sharing-scope>Shareable</res-sharing-scope>
</resource-ref>
```

=> jconsole > JMX beans > JNDI path fooSource

# Encodings

https://docs.oracle.com/javase/7/docs/technotes/tools/solaris/native2ascii.html

# Check environment variables

```java
System.getProperties()
```

# JSON serialize

```java
com.fasterxml.jackson.databind.ObjectMapper jsonObjectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
return jsonObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(doc);
```

# Spring

- org.springframework.web.client.RestTemplate.doExecute
    - https://dzone.com/articles/logging-spring-rest-apis
- properties
    - org.springframework.util.PropertyPlaceholderHelper.parseStringValue(String, PlaceholderResolver, Set<String>)
- https://stackoverflow.com/questions/8490852/spring-transactional-isolation-propagation

# PermGen, Heap

```bash
jstat –gc $java_pid
```

http://www.eclipse.org/mat/

- Run > Debug Configurations
    - `-XX:MaxPermSize=512m`

### Dynamic Instrumentation

[GitHub \- hluwa/Wallbreaker: 🔨 Break Java Reverse Engineering form Memory World!](https://github.com/hluwa/Wallbreaker)

### Extract Thread Dump from Heap Dump

```bash
java -jar ~/opt/obadiah/build/libs/obadiah-1.2.4.jar ./foo.hprof
```

# Optimize memory usage

```
-XX:+UseStringDeduplication -XX:+PrintStringDeduplicationStatistics
```

https://blog.codecentric.de/en/2014/08/string-deduplication-new-feature-java-8-update-20-2/

# Monitoring

```bash
jconsole
```

# Deadlock

```bash
jstack $pid
```

~/code/snippets/java/Deadlock.java

# Profiling

- Run the JUnit tests once, to create the run configuration
- Edit the Run Configuration (Run->Run Configurations...)
- In the Test tab check the box 'Keep JUnit running after test when debugging'
- Rerun the test (with Debug). This will run the tests, but importantly, leave the JVM around, so that you can attach to it using JVisualVM.

ftp://ftp.informatik.uni-stuttgart.de/pub/library/medoc.ustuttgart_fi/FACH-0184/FACH-0184.pdf

https://stackoverflow.com/questions/6846049/profiling-a-running-java-application-in-command-line

# Testing

https://docs.spring.io/spring/docs/current/spring-framework-reference/testing.html#spring-mvc-test-framework
https://www.soapui.org/load-testing/concept.html

### jvm explorer

http://www.jvmmonitor.org/doc/

### jvisualvm

http://visualvm.java.net/eclipse-launcher.html

eclipse
- Run As > Run Configuration > Arguments > VM arguments > Add the below
    ```
    -Djava.rmi.server.hostname=hostname -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.port=10001
    ```

```ps1
visualvm.exe --jdkhome "C:\Software\Java\jdk1.6.0" --userdir "C:\Temp\visualvm_userdir"
```

File > Add JMX Connection > In connection text box > localhost:10001

double-click on class > Instances pane > for each instance of class:

- fields
- references

heap allocation:

- Instances view > Compute Retained Sizes

./java.oql

```
webapp > class loader > boot class loader

If an object instantiated by the boot class loader were to hold a reference to an object instantiated by the webapp’s class loader then that would lead to the scenario described above, where the webapp’s class loader would remain referenced and therefore ineligible for garbage collection.
Eventually after the nth redeploy of the web-application a PermGen java.lang.OutOfMemoryError error will occur, as the class loader for each deployment of the application remains in memory until the heap is exhausted.

select x from org.apache.catalina.loader.WebappClassLoader x
```

https://cdivilly.wordpress.com/tag/outofmemoryerror/

# Tomcat debug

```bash
export JPDA_SUSPEND=y
${TOMCAT_HOME}/bin/catalina.sh jpda
```

localhost.log
```
SEVERE [localhost-startStop-1] org.apache.catalina.core.StandardContext.listenerStart Exception sending context initialized event to listener instance of class [com.opentext.ecm.container.JdsLifecycle]
        java.lang.UnsatisfiedLinkError: no ds_jni in java.library.path
```
=>
- LD_LIBRARY_PATH
    - setenv.sh, startup.sh

# jdbc, mybatis

dao.sqlSession.configuration.environment.dataSource.dataSource.url

### mappings

org.apache.ibatis.binding.MapperMethod.execute(SqlSession, Object[])
org.apache.ibatis.executor.CachingExecutor.query(MappedStatement, Object, RowBounds, ResultHandler, CacheKey, BoundSql)
org.apache.ibatis.executor.SimpleExecutor.doQuery(MappedStatement, Object, RowBounds, ResultHandler, BoundSql)
org.apache.ibatis.executor.statement.PreparedStatementHandler.query(Statement, ResultHandler)

### table, model inferred

org.apache.ibatis.executor.resultset.DefaultResultSetHandler.handleResultSets(Statement)

# logging

```java
final MyService mock = Mockito.mock(MyService.class, Mockito.withSettings().verboseLogging());
```

http://logging.apache.org/log4j/1.2/manual.html#defaultInit

```
-Dlog4j.debug -Dlog4j.configuration=file:/c:/foobar.xml
```

NOTE: Only 1 config is loaded. If >1 projects in server, first run project's config is loaded

```
-Djava.util.logging.config.file=/c/Users/foo/.m2/conf/logging/logging.properties
-Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
-Djaxp.debug=1
```

# local datasource

context.xml

```xml
<Resource name="jdbc/foo" auth="Container" type="javax.sql.DataSource"
    maxActive="20" maxIdle="10" maxWait="-1"
    username="system" password="SECRET" driverClassName="oracle.jdbc.OracleDriver"
    url="jdbc:oracle:thin:@localhost:1521:foo"/>
```

web.xml

```xml
<resource-ref>
    <description>DB Connection</description>
    <res-ref-name>jdbc/foo</res-ref-name>
    <res-type>javax.sql.DataSource</res-type>
    <res-auth>Container</res-auth>
</resource-ref>
```

# h2

http://localhost:8082
jdbc:h2:mem:testdb
file://~/code/snippets/java/PersistenceServiceConfig.java

jdbc:h2:tcp://localhost//C:\Users\foo

# tracing

```
D:\opt\btrace-bin-1.3.11\bin\btrace.bat 10764 D:\bin\btrace\AllCallsAgent.java -v
# ||
/d/opt/btrace-bin-1.3.11/bin/btracec *.java

-javaagent:D:\opt\btrace-bin-1.3.11\build\btrace-agent.jar=noServer=true,debug=false,trusted=true,script=D:\bin\btrace\com\sun\btrace\samples\AllCallsAgent.class,scriptOutputFile=D:\btrace.out
-javaagent:/tmp/btrace/build/btrace-agent.jar=noServer=true,debug=false,trusted=true,script=/tmp/btrace/com/sun/btrace/samples/AllCallsAgent.class,scriptOutputFile=/tmp/btrace.out
```

https://github.com/btraceio/btrace/blob/bf48290d06193e0f28c904183cb3e15906fa14f7/src/share/classes/com/sun/btrace/BTraceUtils.java

Reproducable:

1. dir for script
2. make compiled script
3. pass jvm option
    - || attach with jvm pid

```ps1
# btrace
$env:JAVA_HOME="D:\foo\jdk-7u80-windows-x64"

# javaw PID
.\btrace.bat 18032 C:\Users\foo\AllCalls1.java -v
```

# jsp

https://tomcat.apache.org/tomcat-7.0-doc/jasper-howto.html

# jvm options

```bash
# version: any
jps -lvm

# version: <=7
jinfo -flags $PID
jinfo -sysprops $PID

# version: >=8
jcmd -l
jcmd $PID VM.system_properties
jcmd $PID VM.flags
```

# code dump

### Java >= 9

-XX:+CreateCoredumpOnCrash

### Java <= 8, Windows

-XX:+CreateMinidumpOnCrash

### Java <= 8, Linux

```bash
# Generate core dump
sudo gcore -o dump $PID
# ||
sudo gdb -p $PID -batch -ex generate-core-file

# Convert core dump to heap dump
sudo $JVM_USED_WHILE_GCORE_HOME/bin/jmap -dump:format=b,file=$OUTPUT_HPROF_FILE $JVM_USED_WHILE_GCORE_HOME/bin/java $CORE_FILE_PATH
```

# debug

- symbols: libjvm.so

```bash
java -agentlib:jdwp=transport=dt_shmem,address=jdbconn,server=y,suspend=n MyClass
java -agentlib:jdwp=transport=dt_socket,address=localhost:29010,server=y,suspend=y MyClass
```

UNIX:

```bash
jdb -attach localhost:29010
```

Windows:

```ps1
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=29010
```

```
-dbgtrace
-sourcepath ~/dev/remote/src/main/java/
```

````
catch java.io.FileNotFoundException
stop at com.stackify.debug.rest.HelloController:123
stop in com.stackify.debug.rest.HelloController.hello(java.lang.String)
run

step
step up
next

threads
thread 0x9
where

# if compiled with `-g`
locals
print [local]
dump [local]

help
eval <expr>               -- evaluate expression (same as print)
set <lvalue> = <expr>     -- assign new value to field/variable/array element

catch all
ignore all

trace go methods
untrace

# dump source
list

# dump thread stack
where
````

- https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/tooldescr011.html
- https://www.infoq.com/articles/Troubleshooting-Java-Memory-Issues/

# Oracle (HotSpot) JVM - Flight Recording

On java 7:

```
-XX:+UnlockCommercialFeatures
-XX:+FlightRecorder
```

On java 8:

```bash
$JAVA_HOME/bin/jcmd $pid VM.unlock_commercial_features
$JAVA_HOME/bin/jcmd $pid JFR.start duration=1800s settings=profile filename=recording.jfr
```

# Thread dump

```bash
# java8
jcmd $JAVA_PID Thread.print /tmp/thread_dump.log
# ||
jstack -m -l $JAVA_PID > /tmp/thread_dump.log
# ||
jstack -J-d64 -m -l $JAVA_PID > /tmp/thread_dump.log
# || process is hanged
jstack -F -m -l $JAVA_PID > /tmp/thread_dump.log
# ||
sudo -u $USER_OF_JAVA_PID jstack $JAVA_PID
# ||
kill -s SIGQUIT $JAVA_PID
# ||
kill -3 $JAVA_PID
```

```bash
# repeat 5x, check threads with same call stack
jstack -m -l $JAVA_PID > /tmp/thread_dump.log
# ||
# https://github.com/patric-r/jvmtop

# https://www.cubrid.org/blog/how-to-monitor-java-garbage-collection/
# https://docs.oracle.com/javase/7/docs/technotes/tools/share/jstat.html
jstat -gc $pid 1234
# ||
# if many LGCC = Allocation Failure => GC kicked in due to full heap
jstat -gccause $pid 1234
```

```
sudo gdb -pid 1234
(gdb) gcore /tmp/jvm.core
(gdb) detach
(gdb) quit
||
(gdb) thread apply all bt full
=>
gdb -p 1234 -ex 'set confirm off' -ex 'thread apply all bt full' -ex 'quit' > /tmp/gdb_bt_1234
||
set confirm off
set pagination off
set logging on
set logging file /tmp/gdb_bt.log
set logging overwrite on
thread apply all bt full
||
gdb -q <<EOF
file ./program
run arg1 arg2
bt full
quit
EOF

# stack:
# (gdb) bt -f 1234
# (gdb) p struct_from_stack
```

```bash
kill -3 1234
|| IBM JVM
kill -QUIT 1234
strace -C -ttt -T -f -s 9999 -p 1234 -o /tmp/strace_1234
# PTRACE_ATTACH operation not permitted
grep '^TracerPid:' /proc/*/status | grep -v ':.0'
=>
cat /proc/$TRACER_PID/cmdline

# TODO: doesn't work
# https://unix.stackexchange.com/questions/385771/writing-to-stdin-of-a-process
# TODO: mkpipe/mkfifo, then gdb to open fd 0 with pipe
ls -la /proc/1234/fd
0 -> /dev/pts/1
=>
echo 'y' > /dev/pts/1

jcmd $JAVA_PID VM.system_properties

jcmd $JAVA_PID Thread.print > /tmp/thread_dump.log
# ||
top -n 1 -H -p 1234 > /tmp/top_1234
for ((i=1;i<=5;i++)); do sudo -u foo jcmd 1234 Thread.print > /tmp/thread_dump_1234_$i.txt; sleep 2; done

jcmd $JAVA_PID GC.class_histogram > /tmp/class_histogram.log

# :) better performance
# e.g. heap size ~= 4G
# - jmap ~= 1h execution time
# - jcmd ~= 5m execution time
# with full gc:
jcmd $JAVA_PID GC.heap_dump /tmp/heap_dump.hprof
# without full gc:
# - https://stackoverflow.com/questions/23393480/can-heap-dump-be-created-for-analyzing-memory-leak-without-garbage-collection
jcmd $JAVA_PID GC.heap_dump -all /tmp/heap_dump.hprof
# => unable to open socket file: target process not responding or HotSpot VM not loaded
sudo -u foo jcmd $JAVA_PID Thread.print > /tmp/thread_dump.log

# TODO: Native memory tracking
# - https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/tooldescr007.html
```

```
$ jcmd <pid> help
<pid>:
com.sun.tools.attach.AttachNotSupportedException: Unable to open socket file: target process not responding or HotSpot VM not loaded
        at sun.tools.attach.LinuxVirtualMachine.<init>(LinuxVirtualMachine.java:106)
        at sun.tools.attach.LinuxAttachProvider.attachVirtualMachine(LinuxAttachProvider.java:63)
        at com.sun.tools.attach.VirtualMachine.attach(VirtualMachine.java:213)
        at sun.tools.jcmd.JCmd.executeCommandForPid(JCmd.java:140)
        at sun.tools.jcmd.JCmd.main(JCmd.java:129)

# You need to do as the same user, but the followning error might occured due to the /etc/sudoers settings.
$ sudo -u foo jcmd <pid> help
Sorry, user <username> is not allowed to execute '/usr/bin/jcmd <pid> help' as tomcat on <hostname>.

# if you're allowed to use the `su`, switch to the pid owner and then issue the `jcmd`.
# You may also need to add the shell option (-s) if that user uses /sbin/nologin.
$ sudo su -s /bin/sh - tomcat -c "jcmd <pid> help"
# ||
$ su -l hdfs -c "jcmd -l"
<pid>:
The following commands are available:
VM.native_memory
GC.rotate_log
ManagementAgent.stop
ManagementAgent.start_local
ManagementAgent.start
Thread.print
GC.class_histogram
GC.heap_dump
GC.run_finalization
GC.run
VM.uptime
VM.flags
VM.system_properties
VM.command_line
VM.version
help

- https://gist.github.com/tachesimazzoca/01a366026b6eb5c3341a13fc55c35a15
- https://community.cloudera.com/t5/Community-Articles/How-to-collect-threaddump-using-jcmd-and-analyse-it/ta-p/248391
```

https://confluence.atlassian.com/confkb/how-to-analyze-thread-dumps-788039144.html

### Analysis

```bash
dos2unix ./foo.threads
java -jar ~/opt/tda/tda.jar
```

# heap dump

```bash
pgrep java | xargs -d'\n' -n1 -I{} sh -c '
    dump_file=$(mktemp) && \
    echo "Dump file: $dump_file, Process: "'{}'
    jmap -F -dump:file="$dump_file" '{}
```

```bash
# @server
mknod backpipe p;
tail -f -n +1 backpipe | ssh "${SSH_CLIENT%%\ *}" 'cat - > ~/out.dump'
# || if ssh client isn't running sshd
tail -f -n +1 backpipe | nc localhost 60123
# ||
tar -czf - backpipe | nc localhost 60123
# @client
ssh foo -R 60123:127.0.0.1:60123 -N
~/bin/receive-tcp-message.ps1 -Port 60123 > ./dump
# ||
# https://github.com/besimorhino/powercat
. ./powercat.ps1
powercat -l -p 60123 -of ./dump
# ?||
ssh foo@bar:60123 tar -xzf - -C ./dump
# @server
( \
    trap 'rm -f backpipe' EXIT INT QUIT TERM && \
    jmap -F -dump:file=backpipe 5225 \
);

jhat -debug 1 "$dump_file"
jmap -permgen "$dump_file"

# JDK JVM Options
# -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp

# OpenJDK JVM Options
# -verbose:gc –XX:+PrintGCDetails –XX:+PrintGCTimeStamps –Xloggc:<app path>/gc.log
```

# native debugging

```
(gdb) break Java_jnidemo_JNIDemoJava_nativeAllocate

(gdb) set step-mode on
(gdb) set step-mode onQuit
(gdb) s

(gdb) thread 2
#8  0x00007f7348cba806 in Java_jnidemo_JNIDemoJava_nativeCrash (
    env=0x7f73a4012a00, obj=0x7f73ad6ef980) at src/cpp/JNIDemo.c:11
(gdb) frame 8

(gdb) handle SIGSEGV nostop noprint pass

- https://medium.com/@pirogov.alexey/gdb-debug-native-part-of-java-application-c-c-libraries-and-jdk-6593af3b4f3f

# Instrument `getrlimit` || `setrlimit` calls
# https://blog.overops.com/native-java-debugging-on-alpine-linux-gdb-openjdk-and-the-mysterious-unknown-signal/
# http://hg.openjdk.java.net/jdk8/jdk8/hotspot/file/87ee5ee27509/src/os/linux/vm/os_linux.cpp#l4896
    os::init_2()
    if (MaxFDLimit)
    =>
    (gdb) break os::init_2
    (gdb) c
    (gdb) set MaxFDLimit = 0
    (gdb) c

# Prepare environment for jvm quirks: https://blog.overops.com/native-java-debugging-on-alpine-linux-gdb-openjdk-and-the-mysterious-unknown-signal/
(gdb) handle SIGSEGV nostop noprint pass
(gdb) handle SIGBUS nostop noprint pass
(gdb) handle SIGFPE nostop noprint pass
(gdb) handle SIGPIPE nostop noprint pass
(gdb) handle SIGILL nostop noprint pass

# TODO: test with multi-threaded app, check if all threads stop
(gdb) thread apply all interrupt
||
https://sourceware.org/gdb/onlinedocs/gdb/Break-Commands.html
break foo if x>0
commands
silent
printf "x is %d\n",x
cont
end
||
(gdb) thread apply all break
(gdb) thread apply all continue
||
https://sourceware.org/gdb/onlinedocs/gdb/Signals.html
Using watchdog that sends SIGUSR1:
(gdb) handle SIGUSR1 nopass stop
(gdb) c
||
https://www-zeuthen.desy.de/unix/unixguide/infohtml/gdb/All_002dStop-Mode.html
http://crossbridge.io/docs/gdb_nonstop.html
(gdb) set scheduler-locking on
```

# Performance

verify logs

patterns
- app server config - timeout sockets
- gc activity from {heap dump, thread dumps}
- young/tenured generation size from {heap dump, thread dumps}
- cpu usage from {heap dump, thread dumps}
- retained heap = 30%, TaskProcessorThreadPool (Busy Monitor)
- long running threads
    - http-nio-8080-exec - waiting on db or idle

metrics
- database - disk i/o, network i/o
- gc logs
    jcmd 1234 PerfCounter.print
- profiling during load
    1. HPROF -> JVM flags
    2. Java Flight Recording (JFR)
		- JVM flags
			```
			-XX:+UnlockCommercialFeatures -XX:+FlightRecorder
			-XX:FlightRecorderOptions=loglevel=info
			-XX:StartFlightRecording=delay=20s,duration=60s,name=MyRecording,filename=C:\TEMP\myrecording.jfr,settings=profile
			||
			-XX:+UnlockCommercialFeatures -XX:+FlightRecorder
			-XX:FlightRecorderOptions=defaultrecording=true,dumponexit=true,dumponexitpath=C:\demos\dumponexit.jfr
			||
			-XX:+UnlockCommercialFeatures -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints -XX:+FlightRecorder
			```
		- jcmd
			```bash
			# ? jcmd 1234 VM.unlock_commercial_features
			jcmd 1234 JFR.start name=MyRecording settings=profile delay=20s duration=2m filename=C:\TEMP\myrecording.jfr
			jcmd 1234 JFR.check
			jcmd 1234 JFR.stop
			jcmd 1234 JFR.dump name=MyRecording filename=C:\TEMP\myrecording.jfr
			# ! Analyse dump with JMC parser
			```
    3. Attach to JVM at runtime
		- https://github.com/jvm-profiling-tools/async-profiler
			```bash
			./profiler.sh -d 10 -e alloc -o summary,flat `pidof java`
			```
		- https://github.com/patric-r/jvmtop
    4. OS-Level -> perf report thread ids -(xref)-> jcmd thread dump ids
		- ~/code/doc/java/srecon18americas_slides_goldshtein.pdf
		```bash
		git clone https://github.com/BrendanGregg/FlameGraph
		sudo perf record -F 97 -g -p `pidof java` -- sleep 10
		sudo perf script \
			| FlameGraph/stackcollapse-perf.pl \
			| FlameGraph/flamegraph.pl \
			> flame.svg
		```
	5. OS-Level -> BCC probes
		```bash
		# Enumeration
		tplist -p $(pidof java) | grep 'hotspot.*gc'
		nm -C $(find /usr/lib/debug -name libjvm.so.debug) | grep 'card.*table'
		# Trace
		trace 'r:/usr/bin/bash:readline "%s", retval'
		LIBJVM=$(find /usr/lib -name libjvm.so)
		funccount -p $(pidof java) "$LIBJVM:*do_collection*"
		# Heap
		funccount -p $(pidof java) u:$LIBJVM:object__alloc
		argdist -p $(pidof java) -C "u:$LIBJVM:object__alloc():char*:arg2"
		```
	- https://github.com/epickrram/grav
    - https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/tooldescr006.html
    - http://blog2.vorburger.ch/2018/08/how-to-profile-performance-and-memory.html
    - https://www.oracle.com/technetwork/oem/soa-mgmt/con10912-javaflightrecorder-2342054.pdf

jvm flags for GC logging
    -XX:+PrintClassHistogram
    -XX:+PrintGCDetails
    -XX:+PrintGCDateStamps
    -XX:+PrintGCTimeStamps
    -Xloggc:/tmp/gc.log
    -XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=100M
        - https://blog.codecentric.de/en/2014/01/useful-jvm-flags-part-8-gc-logging/
    -XX:+HeapDumpBeforeFullGC -XX:+PrintHeapAtGC
        - https://blogs.oracle.com/poonam/how-do-i-find-whats-getting-promoted-to-my-old-generation

jvm flags for incremental GC
    Validation:
    ```bash
    # Add: -XX:+PrintFlagsFinal
    # ||
    jcmd $pid VM.flags
    # ||
    jinfo -flag UseCompressedOops $pid

    jmap -heap
    ```
    For web interfaces:
    -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode
    ||
    -XX:+UseConcMarkSweepGC -XX:+CMSParallelRemarkEnabled
    || For batch / distributed processing:
    -XX:+UseParallelOldGC
    -XX:+UseAdaptiveSizePolicy
    ||
    -XX:-UseAdaptiveSizePolicy
    -XX:+NewRatio=2 (old generation occupies 2/3)
    -XX:+NewRatio=3 (old generation occupies 3/4)
    ```bash
    objdump -t "$JAVA_HOME/jre/lib/amd64/server/libjvm.so | grep CMSParallelRemarkEnabled
    # ||
    strings "$JAVA_HOME/jre/lib/amd64/server/libjvm.so | grep CMSParallelRemarkEnabled
    ```
    ```ps1
    sls CMSParallelRemarkEnabled $env:JAVA_HOME\jre\bin\server\jvm.dll
    ```
    - https://blog.sokolenko.me/2014/11/javavm-options-production.html
    - https://stackoverflow.com/questions/6236726/whats-the-difference-between-parallelgc-and-paralleloldgc

jvm flags for shorter but more frequent GC events
    -XX:NewSize=200m -XX:MaxNewSize=200m

systemd service for progressive shutdown
    generic watchdog
        https://www.medo64.com/2019/01/systemd-watchdog-for-any-service/
        https://superuser.com/questions/689017/can-systemd-detect-and-kill-hung-processes
        https://stackoverflow.com/questions/39679067/systemd-http-health-check
    socket healthcheck via http polling
        https://gist.github.com/samyranavela/f1e4ae0d360a2054259aa2457bb293b8
    https://github.com/LorbusChris/greenboot

xref broken pipe connections + tcpdump
    RST packet sent by server or client
    client timeout

xref jvm heap flags + heap dump size + free sys mem
    -Xmn
    -Xms = -Xmx
        ```
        :( It makes memory consumption more predictable, however you will either pick too much or too little. Too little heap will result in OOME. But too much heap causes longer GC pauses. In case of Xms < Xmx JVM tries to reduce heap size to the point GC is as fast and as infrequent as possible (or actually: as configured)
        -- Java Performance: The Definitive Guide
        :) Chapter 5, page 122 still reads "That [setting Xms == Xmx] makes GC slightly more efficient, because it never needs to figure out whether the heap should be resized." Though that's assuming you know how big your heap needs to be (the author recommends 30% filled after full GC) so you don't waste time on big heap.
        ```
    -XX:MaxMetaspaceSize
    -XX:+HeapDumpOnOutOfMemoryError
    -XX:HeapDumpPath="/tmp"

xref long-lived thread + many allocations under thread
    strace -f => thread id = pid
    https://github.com/irockel/tda
        For large files: split -b 200m catalina.out
    [xref] https://help.mulesoft.com/s/article/How-to-identify-top-CPU-consumer-threads-and-hotspots-effectively-using-the-TTOP-utility-on-Linux?ui-force-components-controllers-recordGlobalValueProvider.RecordGvp.getRecord=1&r=7

cpu load average increasing
    [ ] check cumulative load - e.g. many threads at 5% each could be over 100% CPU
    [ ] hypothesis: oom
        [ ] use MAT to generate dominator tree
            report: leak_suspects, report page: Heap Dump Overview
            i.e. reveals the keep-alive dependencies among objects, so it becomes very easy to identify the ones responsible for retaining the biggest chunks of memory
            - https://stackoverflow.com/questions/24888121/how-to-identify-holder-of-reference-to-object-in-java-memory-analyzer-using-heap
        thread calling VMThread::run(), symbol `_ZN8VMThread4loopEv` => executes garbage collection (GC)
        thread calling SafepointSynchronize::begin() => waiting for GC
        - https://docs.oracle.com/javase/10/troubleshoot/troubleshoot-process-hangs-and-loops.htm#JSTGD341
    [ ] hypothesis: loop
        [ ] xref disk i/o
        RUNNABLE state => most likely state for threads that are busy and possibly looping
            given many threads dumps, check if state is always RUNNABLE and stack has same function calls
            check if many calls to Thread.sleep()

issues
    a. excessive GC cycles going on
        e.g. web requests with high memory usage
    b. many Application threads active
    c. infinite loops or excessive backend calls
    d. deadlocks, concurrent access to non thread-safe objects
        ```
        Because of the context switching (>400,000 cs/sec) that is causing the load I assume that the parkNanos call is in the neighborhood of where to look for fixes.

        "ajp-apr-8200-exec-107" #3671 daemon prio=5 os_prio=0 tid=0x00007f62a007f800 nid=0x3adc waiting on condition [0x00007f624d4a6000]
           java.lang.Thread.State: TIMED_WAITING (parking)
                at sun.misc.Unsafe.park(Native Method)
                - parking to wait for  <0x00000000ed8dfbe0> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)
                at java.util.concurrent.locks.LockSupport.parkNanos(LockSupport.java:215)
        ...
        The problem was that a return value of zero was treated as a non-blocking read that returned no data rather than as EOF. That meant that the socket was put straight back into the Poller only for the Poller to trigger a read event immediately for EOF and so the loop continued.
        ```
        - https://bz.apache.org/bugzilla/show_bug.cgi?id=58151
    - http://karunsubramanian.com/java/4-things-you-need-to-know-about-cpu-utilization-of-your-java-application/

# Garbage Collector

https://github.com/chewiebug/GCViewer
~/opt/gcviewer-1.35.jar

Debugging - `-XX:+PrintTenuringDistribution`

Benchmarking

https://databricks.com/blog/2015/05/28/tuning-java-garbage-collection-for-spark-applications.html
https://www.cubrid.org/blog/how-to-tune-java-garbage-collection

References

https://www.petefreitag.com/articles/gctuning/
https://docs.oracle.com/javase/8/docs/technotes/guides/vm/gctuning/sizing.html
https://www.oracle.com/technetwork/java/javase/gc-tuning-6-140523.html
https://docs.oracle.com/cd/E19900-01/819-4742/abeik/index.html
http://javaeesupportpatterns.blogspot.com/2013/02/java-8-from-permgen-to-metaspace.html

https://dzone.com/articles/understanding-garbage-collection-log
http://karunsubramanian.com/websphere/troubleshooting-gc-step-by-step-instructions-to-analyze-verbose-gc-logs/
https://www.oracle.com/technetwork/java/javase/gc-tuning-6-140523.html

# Remote debug

~/jstatd.all.policy

```
grant codebase "file:${java.home}/../lib/tools.jar" {
   permission java.security.AllPermission;
};
```

```bash
jstatd -p 39999 -J-Djava.security.policy=/home/foo/jstatd.all.policy -J-Djava.rmi.server.logCalls=true
```

https://www.toptal.com/java/hunting-memory-leaks-in-java#enabling-remote-connection-for-the-jvm

```bash
java -jar foo.jar \
    -Dcom.sun.management.jmxremote.ssl=false \
    -Dcom.sun.management.jmxremote.authenticate=false \
    -Dcom.sun.management.jmxremote.port=9010 \
    -Dcom.sun.management.jmxremote.rmi.port=9011 \
    -Djava.rmi.server.hostname=localhost \
    -Dcom.sun.management.jmxremote.local.only=false
```

https://docs.oracle.com/javase/7/docs/technotes/guides/rmi/faq.html#domain

---

https://docs.oracle.com/javase/6/docs/technotes/tools/share/jmap.html#options
https://docs.oracle.com/javase/6/docs/technotes/tools/share/jhat.html#options

Java Memory Profiler
monitor memory
    jmx based tools - jconsole
        jvisualvm

```bash
env _JAVA_OPTIONS="-Djavax.net.debug=all"
env _JAVA_OPTIONS="-Djavax.net.debug=ssl"

env _JAVA_OPTIONS="-Dcom.sun.net.ssl.checkRevocation=false -Dsun.security.ssl.allowUnsafeRenegotiation=true"
env _JAVA_OPTIONS="-Djavax.net.ssl.Keystore="
```

# Weak References, Soft References

Comparisons:

SoftReference - released on OOM
WeakHashMap - mappings which you want to disappear when their keys disappear, released on GC
    e.g. `WeakHashMap<Thread, ActiveThreadMetaData>`
Cache - mappings which you want to disappear when their values disappear
    e.g. `Map<K, SoftReference<V>>`

Use cases:

- For holding additional (often expensively calculated but reproducible) information about specific objects that you cannot modify directly, and whose lifecycle you have little control over. WeakHashMap is a perfect way of holding these references: the key in the WeakHashMap is only weakly held, and so when the key is garbage collected, the value can be removed from the Map too, and hence be garbage collected.
- For implementing some kind of eventing or notification system, where "listeners" are registered with some kind of coordinator, so they can be informed when something occurs – but where you don't want to prevent these listeners from being garbage collected when they come to the end of their life. A WeakReference will point to the object while it is still alive, but point to "null" once the original object has been garbage collected.

```java
WeakReference<Object> ref = cache.get(obj);
Object cached = (ref != null) ? ref.get() : null;
if (cached != null) {
    return cached;
}
else {
    cache.put(obj, new WeakReference(obj));
    return obj;
}
```

https://stackoverflow.com/questions/24109126/java-racing-against-the-garbage-collector
https://docs.oracle.com/javase/7/docs/api/java/util/WeakHashMap.html

# Synchronization

bucket lists: With put(), because two new entries might get added to the same bucket list and the scheduler might decide to switch threads in the middle, one of the entries might disappear.
resize (doubling the size of the hash table to reduce the depth of the bucket chains): put() could get a chain using the old table, but that chain could be assigned to a different bucket by the time the new entry is attached.
-- http://blog.kdgregory.com/2012/03/synchronizing-put-is-not-sufficient.html

=> ConcurrentHashMap + synchronized modifications of values || immutable values
    Each bucket can be independently locked by locking the very first node in the bucket. Read operations do not block, and update contentions are minimized.
    https://dzone.com/articles/concurrenthashmap-isnt-always-enough
    https://dzone.com/articles/how-concurrenthashmap-works-internally-in-java

### Thread pool

https://docs.oracle.com/javase/7/docs/api/java/util/concurrent/ExecutorService.html
    && AtomicInteger

# Lifecycle

https://docs.oracle.com/javase/1.5.0/docs/guide/misc/threadPrimitiveDeprecation.html

jdb

```
threads
thread 0x1
eval Thread.currentThread().interrupt()
eval throw new RuntimeException("boom")
eval return
```

### With classes and sources 

[](#parse_classpath)

```bash
mvn dependency:build-classpath

jdb -classpath $CP -sourcepath ../src/main/java
```

# major/minor version

```bash
od -An -t d1 -j 6 -N 2 foo.class
# ||
javap -verbose foo.class -cp foo.jar | grep major
```

```ps1
$f="foo.class"; (get-content $f -raw -encoding byte)[6..7]
```

| Java version | Major version |
|-------------:|:--------------|
| 1.2 | 46 |
| 1.3 | 47 |
| 1.4 | 48 |
|   5 | 49 |
|   6 | 50 |
|   7 | 51 |
|   8 | 52 |
|   9 | 53 |
|  10 | 54 |
|  11 | 55 |

https://stackoverflow.com/questions/1096148/how-to-check-the-jdk-version-used-to-compile-a-class-file

# constant pool

```
invokedynamic	0:apply (Lorg/assertj/core/util/introspection/FieldSupport;Ljava/lang/String;Ljava/lang/Class;)Ljava/util/function/Function; (165)
    165)CONSTANT_InvokeDynamic[18](bootstrap_method_attr_index = 0, name_and_type_index = 164)
    164)CONSTANT_NameAndType[12](name_index = 162, signature_index = 163)
    162)CONSTANT_Utf8[1]("apply")
    163)CONSTANT_Utf8[1]("(Lorg/assertj/core/util/introspection/FieldSupport;Ljava/lang/String;Ljava/lang/Class;)Ljava/util/function/Function;")
```

# Standard streams

http://www.java-gaming.org/index.php?topic=37191.0
https://www.javaworld.com/article/2071275/when-runtime-exec---won-t.html?page=2
=>
```java
Process process = Runtime.getRuntime().exec(command);
// ...
int processExitCode = process.waitFor();

if (in.ready()) {
    while ((line = in.readLine()) != null) {
        // ...
    }
}

// ||
int len;
int size = 1024;
byte[] buf;
if (is instanceof ByteArrayInputStream) {
    size = is.available();
    buf = new byte[size];
    len = is.read(buf, 0, size);
} else {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    buf = new byte[size];
    while ((len = is.read(buf, 0, size)) != -1)
        bos.write(buf, 0, len);
    buf = bos.toByteArray();
}
return buf;
```

# Java 8

### repl

```bash
cmd='
Stream.of(
    "os.arch","os.name","os.version"
).forEach(
    s -> System.out.println(System.getProperty(s)));
' && \
    f=$(mktemp) && \
    printf '%s\n/exit' "$cmd" > "$f" && \
    /c/Program\ Files/Java/jdk-11.0.6/bin/jshell.exe --feedback concise "$f"; \
    rm -f "$f"
```

https://stackoverflow.com/questions/46426526/how-to-run-a-jshell-file
https://stackoverflow.com/questions/46739870/how-to-execute-java-jshell-command-as-inline-from-shell-or-windows-commandline

### streams

```
jshell> Stream.of("foo",1.033333333333333333333f,2,new ArrayList<Integer>()).map(Object::toString).forEach(System.out::println)
foo
1.0333333
2
[]
```

# Java 9

https://github.com/codeFX-org/demo-java-9-migration
https://tiny.cc/java-9-migration

### repl

```bash
. ~/.profile-jdk11
jshell -v
# ||
printf '/exit' | jshell --feedback concise foo.java
```

### profile

```xml
<activation>
    <jdk>[9,)</jdk>
</activation>
<properties>
    <maven.compiler.release>[9,)</maven.compiler.release>
</properties>
```

### report internal dependencies

```bash
jdeps -summary foo.jar
jdeps --jdk-internals -recursive --class-path 'lib/*'
```

```xml
<build>
    <plugin>
        <artifactId>maven-surefire-plugin
        <configuration>
            <argLine>
                --add-exports, 
                --add-opens=java.base/java.lang=ALL-UNNAMED, 
                --permit-illegal-access

<build>
    <plugin>
        <artifactId>maven-compiler-plugin
        <configuration>
            <compilerArgs>
                <arg>--add-modules=java.xml.bind
```

### split packages

=> classloader loads one module, misses dependencies from second module

put both artifacts on classpath
--patch-module

### runtime images

jlink

### module system

http://openjdk.java.net/projects/jigsaw/spec/sotms/#readability

On `module-info.java`:

```java
// explicit dependencies (<=> between jars)
module foo {
    requires transitive bar
}

// encapsulation (defeats reflection)
module foo {
    exports foo.bar
}
```

# runnable jar

```bash
# Create
echo 'Main-Class: com.mypackage.MyClass' > MANIFEST.MF \
	&& jar cmvf MANIFEST.MF babyrev.jar -C com .

# Enumerate
find . -type f -iname '*.jar' -exec sh -c '
manifest=$(jar tf "{}" | grep -m 1 -i manifest.mf)
test -n "$manifest" \
	&& unzip -p "{}" "$manifest" \
	| grep -i main-class \
	&& echo "{}"
' \; 2>/dev/null
```

# decompilation

- fernflower
	- https://github.com/JetBrains/intellij-community/blob/master/plugins/java-decompiler/engine/README.md
	- mirror
		- https://github.com/fesh0r/fernflower
- procyon
	- https://github.com/mstrobel/procyon
		- `./gradlew :Procyon.Decompiler:fatJar -x test`
	- GUI
		- https://github.com/Konloch/bytecode-viewer
			- if: given class directory, create [jar](#runnable-jar)
		- https://github.com/deathmarine/Luyten

```bash
find . -type f -iname '*.jar' | \
xargs -I{} sh -c '
    echo "Jar: $1"
    jar -tf "$1"
' _ {}

# Given jar
mkdir -p ./out && \
	find . -type f -iname '*.jar' | \
	xargs -I{} java -jar ~/share/opt/fernflower/build/libs/fernflower.jar {} ./out/

# Given class directory `classes`
mkdir -p ./out && \
	java -jar ~/share/opt/fernflower/build/libs/fernflower.jar ./classes/ ./out/
# ||
find ./classes/ -iname '*.class' | \
	sort | \
	while read -r i; do 
		d=$(dirname "$i")
		mkdir -p ./out/"$d"
		java -jar ~/share/opt/fernflower/build/libs/fernflower.jar "$i" ./out/"$d"/
	done
```

# remote method invocation (RMI)

https://medium.com/@afinepl/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d

# GUI

- [Java Swing Tutorial \- javatpoint](https://www.javatpoint.com/java-swing)

# jail

- https://github.com/w181496/CTF/tree/master/wctf2020/thymeleaf
	```
	(0).toString().charAt(0).toChars(99)%5b0%5d.toString()+(0).toString().charAt(0).toChars(117)%5b0%5d.toString()+(0).toString().charAt(0).toChars(114)%5b0%5d.toString()+(0).toString().charAt(0).toChars(108)%5b0%5d.toString()+(0).toString().charAt(0).toChars(32)%5b0%5d.toString()+
	```
