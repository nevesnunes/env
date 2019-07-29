# Good compression
#### Note: -z is very slow
lrzip -vv -S '.zpaq.lrz' -z -L9 -p $(nproc) -U file

# List groups
cat /etc/group

# Find dupes by md5
find dir -type f -exec md5sum {} \+ | sort > md5-index; \
  awk '{print $1}' md5-index | uniq -c | awk '$1>1 {print $2}' > md5-dupes

# Tail in separate terminal
mkfifo fifo
tail -Rf fifo
echo "text" 1>fifo

# My backup
rsync -uva

# Split & Join
split --bytes=2G file splitted
cat splitted* > joined

# Lowerify filenames
prename 'y/A-Z/a-z/' *

# Format/Flash USB disk the right way!
cfdisk -z /dev/sdX

# Copy always files of a certain type
rsync --ignore-times -rv --include '*/' --include '*.js' --exclude '*' src/ target/

# Make iso
mkisofs -r -N -allow-leading-dots -d -J -T -o target.iso target

# Mount iso for wine
1) Configure folder (tmp/cdrom/) in winecfg > Drives > d: (Advanced > Type > CD-ROM)
2) mount -o loop x.iso tmp/cdrom/
x) mount -t iso9660 -o ro x.iso tmp/cdrom/

# Convert flac to mp3
ffmpeg -i in.flac -ab 320k -map_metadata 0 -id3v2_version 3 out.mp3

# Convert bin to iso+wav
bchunk -w x.bin x.cue y

# Extract broken zip
bsdtar xf zipfile

# Extract broken rar
unrar e -kb

# Extract tar
tar -zxvf data.tar.gz

# Find broken symlinks and remove them
find . -type l -a ! \( -xtype b -o -xtype c -o -xtype d -o -xtype p -o -xtype f -o -xtype s -o -xtype l \) 2>/dev/null -exec rm '{}' \;

# Smart cp
https://github.com/Feh/nocache

nice -n19 ionice -c3 nocache rsync -uva

# Multiple files
find <source> -iname "*jpg" -printf 'cp "%p" <target>\n' >> do.sh
find . -iname "*dbg*" -exec rename _dbg.txt .txt '{}' \;

# Replace string in files
sed -i 's/old-word/new-word/g' *.txt
find . -name "*.txt" -print0 | xargs -0 sed -i '' -e 's/foo/bar/g'

# Strip leading zeros
awk '{gsub ("^0*", "", $0); gsub ("/0*", "/", $0); print}'

# SVG to PNG
for i in *.svg ; do inkscape -z -f "${i}" -w48 -h48 -e "${i%.svg}.png" ; done

# Grep multiple pdfs
find /path -name '*.pdf' -exec sh -c 'pdftotext "{}" - | grep --with-filename --label="{}" --color "your pattern"' \;

# Converting OpenFonts to TrueTypeFonts
#!/usr/local/bin/fontforge
# Quick and dirty hack: converts a font to truetype (.ttf)
Print("Opening "+$1);
Open($1);
Print("Saving "+$1:r+".ttf");
Generate($1:r+".ttf");
Quit(0);

Save the script as otf2ttf.sh and type:

    fontforge -script otf2ttf.sh FONTNAME.otf

If you want to convert many .otf fonts in a directory to .ttf fonts, type (thanks sw!):

    for i in *.otf; do fontforge -script otf2ttf.sh $i; done

# Convert PCD to PNG
find . -name "*.pcd" -type f -exec convert '{}[5]' ../../pngs/'{}'.png \;
