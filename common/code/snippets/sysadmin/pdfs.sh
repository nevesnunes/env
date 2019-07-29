# start with a bunch of PNG images of your zine pages
# convert them all to PDF
for i in *.png
   do
   	  # imagemagick is the best thing in the world
      convert $i $i.pdf
   done

# pdftk is awesome for combining pdfs into a single pdf
pdftk *.pdf cat output zine.pdf

# pdfmod is a GUI that lets you reorder pages
pdfmod zine.pdf

# pdfcrop lets you add margins to the pdf. this is good because otherwise the
# printer will cut off stuff at the edges
pdfcrop --margin '29 29 29 29' zine.pdf zine-intermediate.pdf

# pdfjam is this wizard tool that lets you take a normal ordered pdf and turn
# it into something you can print as a booklet on a regular printer.
# no more worrying about photocopying machines
pdfjam --booklet true --landscape --suffix book --letterpaper --signature 12 --booklet true --landscape zine-intermediate.pdf -o zine-booklet.pdf
