import sys
import subprocess

def make_extension_array(extension):
    old_array = subprocess.run( \
            'gsettings get org.gnome.shell enabled-extensions', \
            shell=True, \
            stdout=subprocess.PIPE).stdout
    return old_array[:-2].decode(encoding='UTF-8') + ", '" + extension + "']"

if __name__ == '__main__':
    EXTENSION = sys.argv[1]
    print(EXTENSION)
    NEW_ARRAY = make_extension_array(EXTENSION)
    print(NEW_ARRAY)
