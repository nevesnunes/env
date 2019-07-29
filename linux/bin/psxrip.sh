#!/usr/bin/env bash
#
#  This is a script to create a .bin image with corresponding .cue out of your
#  PSX game discs as backup and/or for usage with emulators.
#
#  Run-time requirements: cdrdao
#
#  This script is partly based upon the "wesnoth-optipng" script from the
#  Battle for Wesnoth team.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2 or,
#  at your option any later version. This program is distributed in the
#  hope that it will be useful, but WITHOUT ANY WARRANTY.

PSXDIR=$HOME/psxrip
DRIVE=/dev/sr0

report_absent_tool()
{
	echo "$1 is not present in PATH. $(basename ${0}) requires it in order to work properly."
	if [ -n "$2" ]; then
		echo "You can obtain $1 at <${2}>."
	fi
	exit -1
}

print_help()
{
cat << EOSTREAM
Script for ripping PSX game discs into .bin files with corresponding .cue files.

Usage:
  $(basename ${0}) [{--outputdir} <value>] [{--drive} <value>] [{--no-subchan] [{--help|-h}] [filename]

The parameter [filename] is mandatory. Without it, the script will abort. Plain
spaces in the filename are prohibited!

Available switches:
  --drive       Define the device to be used. If this parameter is not
                provided, /dev/sr0 will be used.

  --help / -h   Displays this help text.

  --no-subchan  Don't extract subchannel data. Subchannel data might be
                required for some PSX copy protection though it *could* create
                problems. Retry with this parameter set if any problems occur
                when trying to use the resulting image.

  --outputdir   Define the folder in which the resulting image should be saved.
                If the folder does not exist, it will be created. If no
                --outputdir parameter is given, the folder ~/psxrip will be
                used.

This tool requires cdrdao (http:/usr/cdrdao.sourceforge.net/) to be installed and
available in PATH.
EOSTREAM
}

# go through provided parameters
while [ "${1}" != "" ]; do
	if [ "${1}" = "--drive" ]; then
		DRIVE=$2
		shift 2
	elif [ "${1}" = "--outputdir" ]; then
		PSXDIR=$2
		shift 2
	elif [ "${1}" = "--nosubchan" ]; then
		NOSUBCHAN="true"
		shift 2
	elif [ "${1}" = "--help" ] || [ "${1}" = "-h" ]; then
		print_help
		exit 0
	elif [ "${2}" != "" ] ; then
		echo "ERROR: Inval id usage. Displaying help:"
		echo ""
		print_help
		exit -1
	else
		IMAGENAME=$1
		shift
	fi
done

# check for required dependencies
which cdrdao &> /dev/null ||
	report_absent_tool cdrdao 'http:/usr/cdrdao.sourceforge.net/'

# output recognized parameters
echo "Program "$(basename ${0})" called. The following parameters will be used for"
echo "creating an image of a PSX disc:"
echo "Folder for saving images: "$PSXDIR
echo "Drive used for reading the image: "$DRIVE
echo "Resulting filenames: "$PSXDIR"/"$IMAGENAME"[.bin|.cue]"
if [ "$NOSUBCHAN" = "true" ]; then
	echo "Not extracting subchan data."
else
	echo "Extracting subchan data."
fi
echo ""

# check if imagename is defined
if [ "$IMAGENAME" = "" ]; then
	echo "ERROR: Invalid usage. Found no name for resulting image. Displaying help:"
	echo ""
	print_help
	exit -1
fi

# create dir for resulting image if it does not exist yet
if ! [ -d "$PSXDIR" ]; then
	echo "outputdir not found, creating folder: "$PSXDIR
	echo ""
	mkdir -p $PSXDIR
fi

echo "starting ripping the disc"
echo ""
# final commandline for reading the disc and creating the image
if [ "$NOSUBCHAN" = "true" ]; then
	cdrdao read-cd --read-raw --datafile $PSXDIR/$IMAGENAME.bin --device $DRIVE --driver generic-mmc-raw $PSXDIR/$IMAGENAME.toc
else
	cdrdao read-cd --read-raw --read-subchan rw_raw --datafile $PSXDIR/$IMAGENAME.bin --device $DRIVE --driver generic-mmc-raw $PSXDIR/$IMAGENAME.toc
fi
toc2cue $PSXDIR/$IMAGENAME.toc $PSXDIR/$IMAGENAME.cue
