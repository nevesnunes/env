#!/usr/bin/python3
#
# consolefontsdump.py
# A python script to gather screenshots of all installed Linux console fonts
# Copyright (C) 2012  Alexandre A. de Verteuil
#
# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# <a href="http://sam.zoy.org/wtfpl/COPYING">http://sam.zoy.org/wtfpl/COPYING</a> for more details.
#
# Run this script in a newly created directory. It will use the
# current working directory to dump all of the output PNG files.


import os
import sys
import logging
import optparse
import subprocess


LOGFILE = './consolefontsdump.log'
FONTSDIR = '/usr/share/kbd/consolefonts'


E_ERROR = 1


logging.basicConfig(filename=LOGFILE, filemode='w',
                    format='%(asctime)s %(message)s', level=logging.DEBUG)


def main():
    logging.info('+++++   Starting   +++++')

    if not os.access('/dev/fb0', os.R_OK):
        print('Can\'t read /dev/fb0, maybe sudo?')
        print('Exiting.')
        sys.exit(E_ERROR)

    fontslist = get_fonts_list()
    logging.debug('fontslist = ' + '\n'.join(fontslist))

    try:
        # Remove non-default terminal settings such as customized colors.
        subprocess.call(['reset'])
        # Hide the blinking cursor. \e[?25h makes it visible again.
        print('\033[?25l')
        for font in fontslist:
            font = os.path.basename(font).replace('.gz', '', 1)
            logging.info('processing ' + font)
            if font.endswith('.cp'):
                # Some fonts (.cp.gz) contain 3 fonts.
                # -8, -14 or -16 must be specified.
                heights = ['8', '14', '16']
            else:
                heights = [None]

            for height in heights:
                setfont = ['setfont']
                if height is not None:
                    setfont += ['-' + height]  # Prepend "-" to height argument.
                setfont += [font]
                returnvalue = subprocess.call(setfont)
                if returnvalue &gt; 0:
                    raise Exception('failed "{}"'.format(' '.join(args)))
                subprocess.call(['clear'])

                ## This is the part you would change if you want to
                ## generate images with custom text.
                print('{} {}'.format(font, height if height is not None else ''))
                subprocess.call(['showconsolefont', '-v'])

                # if height is set, add it in parenthesis in the filename.
                filename = (font
                         + ('(' + height + ')' if height is not None else '')
                         + '.png')
                logging.debug('output : {}'.format(filename))
                with open(filename, 'wb') as pngfile:
                    p1 = subprocess.Popen(['fbdump'],
                                          stdout=subprocess.PIPE)
                    p2 = subprocess.Popen(['pnmcrop', '-black', '-margin=8'],
                                          stdin=p1.stdout,
                                          stdout=subprocess.PIPE)
                    p3 = subprocess.Popen(['pnm2png'],
                                          stdin=p2.stdout,
                                          stdout=pngfile)
                    p1.stdout.close()
                    p2.stdout.close()
                    if p3.wait() &gt; 0:
                        raise Exception('failed creating a picture of "{}".'
                                        .format(font))
        logging.info('-----  Done  -----')
    except KeyboardInterrupt:
        print('Keyboard interrupt caught. Exiting.')
        sys.exit()
    finally:
        # Reset default font and cursor visibility on exit.
        print('\033[?25h')
        subprocess.call('setfont')


def get_fonts_list():
    usage = 'usage: %prog [fontname [...]]'
    parser = optparse.OptionParser(usage=usage)
    (options, args) = parser.parse_args()
    if not args:
        return [x for x in os.listdir(FONTSDIR) if x.endswith('.gz')]
    else:
        return args


main()
