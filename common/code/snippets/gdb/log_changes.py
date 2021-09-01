#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gdb
import operator

cs_instances = []

# This module helps generate a complete log of the call stack of a breakpoint.
# It can also record the value of some variables.

# Get a table horizontal line
def get_hline(length):
    s = ''
    for x in range(0, length):
        s = s + '─'

    return s

def print_instances():
    print("Caller stat:")
    count = 0

    for cs in cs_instances:
        color = "\033[38;5;202m"
        if cs.enabled:
            color = "\033[38;5;44m"

        print(color+" ["+str(count)+"]\033[39;0m: "+cs.position)
        count += 1

    print("\n")

def print_hints(instance):
    print(" ")
    for line in instance.hits:
        print(line["name"])
    print(" ")

def print_table_sep(fs, step):
    chars = [('┌', '┬', '┐'), ('├','┼','┤'), ('│','│','│'), ('└', '┴', '┘')]

    s = chars[step][0]

    for f in fs:
        s += get_hline(f+1)+chars[step][1]

    print(s.rstrip(chars[step][1]) + chars[step][2])

def print_table_row(fs, values):
    s = '│'
    for i in range(len(fs)):
        s += ' '+(str(values[i])+' ').ljust(fs[i], ' ')+'│'

    print(s)

def print_stats(instance):
    callers = {}

    largest_n = 1
    largest_s = len("Name " )
    largest_id = max(3, len(str(len(instance.hits))))

    # Count them
    for line in instance.hits:
        first = line[1]
        if first["name"] in callers:
            callers[first["name"]] += 1
            largest_s = max(largest_s, len(first["name"]))
            largest_n = max(largest_n, callers[first["name"]])
        else:
            callers[first["name"]] = 1

    # Sort them
    s = sorted(callers.items(), key = operator.itemgetter(1))

    count_width = max(len("Count "), len(str(largest_n)))

    columns = [largest_id, count_width, largest_s]

    # Add a pretty header
    print_table_sep(columns, 0)
    print_table_row(columns, ["Id", "Count", "Name"])
    print_table_sep(columns, 1)

    # Print them
    for i in range(len(s)):
        line = s[i]
        print_table_row(columns, [i, line[1], line[0]])

    # Add a pretty footer
    print_table_sep(columns, 3)

def join_args(args, begin):
    ret = ""
    for i in range(begin, len(args)):
        ret = ret + args[i] + " "

    return ret.strip()

def register_print(ins, statement):
    ins.statements.append(statement)

def display_print(cs):
    column_count = len(cs.statements)
    column_width = []
    header       = []

    print("z")
    for i in range(column_count):
        column_width.append(5) # 5 is the minimum width

    print("a")
    # Compute the column width and sanitize
    for i in range(len(cs.prints)):
        ins = cs.prints[i]
        print("b")
        for j in range(len(ins)):
            print("c")
            col = ins[j]
            content = str(col).strip()
            ins[j] = content
            print("c2 "+content)
            column_width[j] = max(column_width[j], len(content) + 1)
            print("d")

    # Print the header
    for i in range(column_count):
        print("e")
        s = cs.statements[i]
        print("e2 "+str(column_width[i])+" "+str(len(s)))
        header.append(s[min(column_width[i], len(s)-1)])
        print("e3")

    print("f")
    print_table_sep(column_width,   0   )
    print_table_row(column_width, header)
    print_table_sep(column_width,   1   )

    # The content
    for ins in cs.prints:
        print_table_row(column_width, ins)

    # The footer
    print_table_sep(column_width, 3)

class CallerStatBreakpoint(gdb.Breakpoint):
    def __init__(self, position):
        super(CallerStatBreakpoint, self).__init__(position, gdb.BP_BREAKPOINT,
                                                 internal = False)

        self.position = position
        self.hits = []
        self.prints = []
        self.statements = []

        cs_instances.append(self)

    def record_stack_trace(self):
        #TODO support all threads
        #for thread in gdb.selected_inferior().threads():
            #thread.switch()
            #print_thread(thread.num)

        thread = gdb.selected_thread()

        f = gdb.newest_frame()

        print_hits = []

        # Execute all the prints
        for s in self.statements:
            print_hits.append(gdb.execute("print "+str(s), to_string=True))

        self.prints.append(print_hits)

        hit = []

        # Record the stack
        while f is not None:
            framename = gdb.Frame.name(f)
            hit.append({"name": framename})

            f = gdb.Frame.older(f)

        self.hits.append(hit)

    def stop(self):
        self.record_stack_trace()
        return False

class CallerStat (gdb.Command):
    """Manage repetitive print statements"""

    def __init__ (self):
        super (CallerStat, self).__init__ ("log", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        args = arg.split(' ')

        if arg == "" or not args:
            print_instances()
        elif args[0] == "remove":
            print("Removing "+args[1])
            cs = cs_instances[int(args[1])]
            cs.delete()
            cs_instances.remove(int(args[1]))
        elif args[0] == "add":
            CallerStatBreakpoint(args[1])
        elif args[0] == "enable":
            cs = cs_instances[int(args[1])]
            cs.enabled = True
            print_instances()
        elif args[0] == "disable":
            cs = cs_instances[int(args[1])]
            cs.enabled = False
            print_instances()
        elif args[0] == "caller":
            cs = cs_instances[int(args[1])]
            print_stats(cs)
        elif args[0] == "dump":
            cs = cs_instances[int(args[1])]
            print_hints(cs)
        elif args[0] == "print":
            cs = cs_instances[int(args[1])]
            register_print(cs, join_args(args, 2))
        elif args[0] == "show":
            cs = cs_instances[int(args[1])]
            display_print(cs)
        else:
            CallerStatBreakpoint(args[0])

CallerStat()
