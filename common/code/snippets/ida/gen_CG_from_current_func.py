# python 2.x, like in IDA

# dennis(a)yurichev.com

# you will want to change this:

MAX_DEPTH=5
MAX_EDGES=100
GV_FNAME="c:\\tmp\\1.gv"

# (partially) copypasted from https://reverseengineering.stackexchange.com/questions/13627/ida-python-list-all-imported-functions
import idaapi, ida_nalt
import pickle, os.path

#print ida_nalt.get_root_filename()
input_fname=ida_nalt.get_input_file_path()
pickle_fname=input_fname+".pickle"

edges={}

def get_edges():
    global edges, pickle_fname

    def imp_cb(ea, name, ord):
        global names
        if name:
            names.append([name,ea])
        #print "imp_cb() name=", name
        return True

    nimps = idaapi.get_import_module_qty()

    def process_func1 (ea):
        funcs=set()
        t=get_first_cref_to(ea)
        while t!=BADADDR:
            funcs.add(idaapi.get_func_name(t))
            t=get_next_cref_to(ea, t)
        return list(funcs)

    #print "** imports:"
    # process imports
    for i in xrange(0, nimps):
        global names
        name = idaapi.get_import_module_name(i)
        if not name:
            continue

        #print "*** name", name
        names=[]
        idaapi.enum_import_names(i, imp_cb)
        for n in names:
            call_from=process_func1 (n[1])
            for c in call_from:
                #print c, "->", name+".dll!"+n[0]
                if c!=None:
                    d=name+".dll!"+n[0]
                    if c not in edges:
                        edges[c]=set()
                    edges[c].add(d)

    # process all functions
    def process_func2 (ea):
        funcs=set()
        t=get_first_cref_to(ea)
        while t!=BADADDR:
            funcs.add(idaapi.get_func_name(t))
            t=get_next_cref_to(ea, t)
        return list(funcs)
    
    #print "** functions:"
    for ea in Segments():
        for funcea in Functions(SegStart(ea), SegEnd(ea)):
            call_from=process_func2(funcea)
            for c in call_from:
                if c==None:
                    continue
                d=idaapi.get_func_name(funcea)
                #print c, "->", d
                if c not in edges:
                    edges[c]=set()
                edges[c].add(d)
    with open(pickle_fname, 'wb') as f:
        # Pickle the 'data' dictionary using the highest protocol available.
        pickle.dump(edges, f, pickle.HIGHEST_PROTOCOL)
        print pickle_fname+" saved for future use"

if os.path.isfile(pickle_fname):
    with open(pickle_fname, 'rb') as f:
        edges = pickle.load(f)
        print pickle_fname+" loaded"
else:
    get_edges()

pairs=set()
cur_addr = idc.ScreenEA()
cur_func=GetFunctionName(cur_addr)

visited=set()
edges_worked_out=0
functions=set()

def get_descending_edges(start, cur_depth):
    global edges_worked_out
    if start in visited:
        return
    if start not in edges:
        return
    visited.add(start)
    for target in edges[start]:
        if cur_depth<MAX_DEPTH:
            if edges_worked_out+1 == MAX_EDGES:
                print "warning: more edges exist! raise limit..."

            if edges_worked_out < MAX_EDGES:
                functions.add(start)
                functions.add(target)
                if (cur_depth+1 == MAX_DEPTH) and (target in edges) and (len(edges[target])>0):
                    pairs.add((start, target+" -> ..."))
                else:
                    pairs.add((start, target))
                edges_worked_out=edges_worked_out+1
                get_descending_edges(target, cur_depth+1)

get_descending_edges(cur_func, 0)

print "finish"
print "functions=", list(functions)

f=open(GV_FNAME, "w")

f.write ("digraph tst {\n")
f.write ("rankdir=\"LR\"\n");
f.write ("\"" + cur_func + "\" [peripheries=2];\n");
for pair in pairs:
    f.write ("\""+pair[0]+"\" -> \""+pair[1]+"\";\n")
f.write ("}\n")
f.close()

print GV_FNAME+" written"
