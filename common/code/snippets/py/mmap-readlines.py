import mmap

def lines(m):
    line = m.readline()
    while line:
        yield line.decode("utf-8").rstrip("\n")
        line = m.readline()
        
def filelines(path):
    with open(path, "rb") as f:
        return lines(mmap.mmap(f.fileno(), 0,  prot=mmap.PROT_READ))