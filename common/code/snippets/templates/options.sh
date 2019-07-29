#!/bin/bash

# Retrieve all the flags preceeding a subcommand
while [[ $# -gt 0 ]]; do
	if [[ $1 =~ ^- ]]; then
		# Convert combined short options into multiples short options (e.g. `-qb' to `-q -b')
		if [[ $1 =~ ^-[a-z]{2,} ]]; then
			param=$1
			shift
			set -- ${param:0:2} -${param:2} $@
			unset param
		fi
		case $1 in
			-h | --help) cmd="help" ; shift; continue ;;
			-v | --verbose) VERBOSE=true ; shift; continue ;;
			*) err $EX_USAGE "Unknown option '$1'" ;;
		esac
	else
		break
	fi
done

# No combined options
while [ "$1" != "" ]; do
    case $1 in
        -f | --file )
					shift
          filename=$1
          ;;
        -i | --interactive )
          interactive=1
          ;;
        -h | --help )
					usage
          exit
          ;;
        * )
					usage
          exit 1
    esac
    shift
done
