#!/usr/bin/env python2.7

"""
Extract title from PDF file.

Depends on: pyPDF, PDFMiner.

Usage:

    find . -name "*.pdf" |  xargs -I{} pdftitle -d tmp --rename {}
"""

import getopt
import os
import re
import string
import subprocess
import sys
import unidecode

from pyPdf import PdfFileReader
from pyPdf.utils import PdfReadError

from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser 
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams, LTTextBox, LTTextLine

__all__ = ['pdf_title']

MIN_CHARS=6

def sanitize(filename):
    """Turn string to valid file name.
    """
    # Preserve letters with diacritics
    filename = unidecode.unidecode(filename.encode('utf-8').decode('utf-8'))
    print filename

    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    return "".join([c for c in filename if c in valid_chars])

def meta_title(filename):
    """Title from pdf metadata.
    """
    try:
        docinfo = PdfFileReader(file(filename, 'rb')).getDocumentInfo()
        if docinfo is None:
            return ""
        return docinfo.title if docinfo.title else ""
    except PdfReadError:
        return ""

def junk_line(line):
    """Judge if a line is not appropriate for a title.
    """
    too_small = len(line.strip()) < MIN_CHARS
    has_no_words = bool(re.search(r'^[ 0-9-]+[ -]+[ 0-9-]+|^unknown$|^title$|^untitled$', line.strip().lower()))
    is_copyright_info = bool(re.search(r'technical\s+report|proceedings|preprint|to\s+appear|submission|integrated.*conference|transactions\s+on|symposium\s+on|downloaded\s+from\s+http', line.lower()))
    return too_small or has_no_words or is_copyright_info

def empty_str(s):
    return len(s.strip()) == 0

def pdf_text(filename):
    fp = open(filename, 'rb')
    parser = PDFParser(fp)
    doc = PDFDocument(parser, "")
    parser.set_document(doc)
    rsrcmgr = PDFResourceManager()
    laparams = LAParams()
    device = PDFPageAggregator(rsrcmgr, laparams=laparams)
    interpreter = PDFPageInterpreter(rsrcmgr, device)

    for page in PDFPage.create_pages(doc):
        interpreter.process_page(page)
        layout = device.get_result()
        text = ""
        for lt_obj in layout:
            if isinstance(lt_obj, LTTextBox) or isinstance(lt_obj, LTTextLine):
                text += lt_obj.get_text() + '\n'

        # Only parse the first page
        return text

def title_start(lines):
    for i, line in enumerate(lines):
        if not empty_str(line) and not junk_line(line):
            return i
    return 0

def title_end(lines, start, max_lines=2):
    for i, line in enumerate(lines[start+1:start+max_lines+1], start+1):
        if empty_str(line):
            return i
    return start + 1

def text_title(filename):
    """Extract title from PDF's text.
    """
    lines = pdf_text(filename).strip().split('\n')

    i = title_start(lines)
    j = title_end(lines, i)
    text = ' '.join(line.strip() for line in lines[i:j])

    # Strip dots, which conflict with os.path's splittext()
    text = re.sub(r'\.', "", text)

    return text

def valid_title(title):
    return not empty_str(title) and not junk_line(title) and empty_str(os.path.splitext(title)[1])

def pdftotext_title(filename):
    """Extract title using `pdftotext`
    """
    command = 'pdftotext {} -'.format(re.sub(' ', '\\ ', filename))
    process = subprocess.Popen([command], \
            shell=True, \
            stdout=subprocess.PIPE, \
            stderr=subprocess.PIPE)
    out, err = process.communicate()
    lines = out.strip().split('\n')

    i = title_start(lines)
    j = title_end(lines, i)
    text = ' '.join(line.strip() for line in lines[i:j])

    # Strip dots, which conflict with os.path's splittext()
    text = re.sub(r'\.', "", text)

    return text

def pdf_title(filename):
    title = meta_title(filename)
    if valid_title(title):
        return title

    title = text_title(filename)
    if valid_title(title):
        return title

    title = pdftotext_title(filename)
    if valid_title(title):
        return title

    return os.path.basename(os.path.splitext(filename)[0])

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], 'nd:', ['dry-run', 'rename'])

    dry_run = False
    rename = False
    target_dir = "."

    for opt, arg in opts:
        if opt in ['-n', '--dry-run']:
            dry_run = True
        elif opt in ['--rename']:
            rename = True
        elif opt in ['-d']:
            target_dir = arg

    if len(args) == 0:
        print "Usage: %s [-d output] [--dry-run] [--rename] filenames" % sys.argv[0]
        sys.exit(1)

    for filename in args:
        title = pdf_title(filename)
        if rename:
            new_name = os.path.join(target_dir, sanitize(' '.join(title.split())) + ".pdf")
            print "%s => %s" % (filename, new_name)
            if not dry_run:
                if os.path.exists(new_name):
                    print "*** Target %s already exists! ***" % new_name
                else:
                    os.rename(filename, new_name)
        else:
            print title
