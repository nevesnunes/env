#!/usr/bin/env python2
 
# so what's the deal and what is this?
 
# it turns out that Linux has an interesting feature in prctl that allows any process to register itself as the child set_child_subreaper
# you know when a parent's process dies before the process and how it gets reparented to pid 1 then?
# it apprently turns out any process can take that role
# as in any decendants of this process will now reparent to this process instead of pid 1
# allowing this process to wait for them
 
# this essentially means you can use this to create a wrapper process that 'undaemonzies' a daemon, id est it angelizes it.
# that is this python script that should really be written in C.
# it expects a command line invocation as argument that double forks, but the double fork now reparents itself to the process itself
# allowing it to wait on it and collect its exit status.
# so you can use this with daemontools et alia to deal with those pesky services that always background themselves
# similarly to djb's fghack except it's not a hack, it's reliable
# it works 100% of the time in theory and collects the exit status and forwards it
# on Linux anyway, this uses Linux specific features
 
# in its simplest form, it just takes as argument a command to run, runs it, expects this command to daemonize itself to the background
# and then waits for _all_ daemons it generates and exits when the last one exits with its exist status
 
# if you want to wait for a specific daemon there are two options:
#   you provide a --pidfile PIDFILE argument before the actual command line
#   it will read the pidfile to determine the pid to wait on after the command returns and has daemonized itself
#   and written itself to the pidfile, it MUST thus write to the pidfile before it returns
# - this pidfile can contain multiple pids, each on a single line
 
#   or you provide a --shcode SHELLCODE argument before the actual command line
# - this code will be executed with as sh -c and its stdout will be interpreted as pids to wait on
# - this can again contain multiple pids per line
 
# apart from that, this program just forwards the signals it gets to the processes it is waiting on.
 
import prctl
import subprocess
import os
import sys
import signal
import setproctitle
import errno
 
usage = "usage: [ --pidfile PIDFILE | --shcode SHELLCODE ] command args ..."
# list of signals we are going to forward to the daemons
forwarding_signals = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2]
 
def improper_args ():
    sys.stderr.write(usage + '\n')
    exit(2)
 
def print_help ():
    sys.stdout.write(usage + '\n')
 
# takes a list of pids we are waiting on and produces a signal handler
# this signal handler just forwards the signal to all the pids
# if given None instead a list then we forward to all children
def make_signal_forwarder ( waitpids ):
    def signal_forwarder ( signum, _ ):
        for waitpid in waitpids:
            os.kill(waitpid, signum)
   
    return signal_forwarder
 
# wait for appropriate processes and return the exit status of the last one to die
# if there is no list of processes supplied or None then we simply wait for all child processes
def wait_processes ( waitpids = None ):
    exitstat  = 111
    for pid in waitpids:
        try:
            _, exitstat = os.waitpid(pid, 0)
       
        # the exception handling is because we need to try again if os.waitpid is interrupted
        # this happens when we forward the signal
        except OSError as e:
            if e.errno != errno.EINTR: raise
            else:
                exitstat = wait_processes ( waitpids )
   
    return exitstat
 
def main ():
    setproctitle.setproctitle('angelize')
    global waidpids
   
    pidfile   = None
    shcode    = None
    waitpids  = None
   
    args = sys.argv[1:]
 
    if not args:
        improper_args()
   
    first = args[0]
   
    if first == '--pidfile':
        if not args[1:]:
            improper_args()
       
        pidfile = args[1]
        commandline = args[2:]
   
    elif first == '--shcode':
        if not args[1:]:
            improper_args()
       
        shcode = args[1]
        commandline  = args[2:]
   
    elif first == '--help':
        print_help()
        exit()
   
    elif first[0:1] == '-':
        improper_args()
   
    else:
        commandline = args
   
   
    if not commandline:
        improper_args()
   
    # very important, we register with Linux to become the subreaper of the the descendant process tree
    # anything double forking from this point will reparent to this process, not pid1  
    prctl.set_child_subreaper(True)
   
    # we call the actual command that is expected to daemonize itself
    # if it exits with an error we assume the damonization some-how failed and exit with the same error
    errcode = subprocess.call(commandline)
    if errcode != 0: exit(errcode)
   
    if pidfile:
        with open(pidfile) as fp:
            waitpids = [ int(line.strip()) for line in fp ]
 
    elif shcode:
        waitpids = [ int(line.strip()) for line in subprocess.check_output(['sh', '-c', shcode]).split('\n') if line.strip() ]
   
    else:
        import psutil
        waitpids = [ child.pid for child in psutil.Process().children() ]
   
    signal_forwarder = make_signal_forwarder(waitpids)
   
    for signum in forwarding_signals:
        signal.signal(signum, signal_forwarder)
 
    exit(wait_processes(waitpids))
 
if __name__ == '__main__': main()
