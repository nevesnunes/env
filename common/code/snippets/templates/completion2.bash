# a file containing job names
export AUTOSYS_JOBFILE=~/.autosysjobs

# complete autosys jobs using the job file
_autosysjobs()
{
  local cur=${COMP_WORDS[COMP_CWORD]}
  [ ! -z ${AUTOSERV} ] && \
    COMPREPLY=( $( compgen -W "$(cat ${AUTOSYS_JOBFILE}_${AUTOSERV})" -- $cur ) )
  return 0
}

# complete sendevent
_sendevent()
{
  local cur=${COMP_WORDS[COMP_CWORD]}
  local prev=${COMP_WORDS[COMP_CWORD-1]}

  case "$prev" in
   -S)
     COMPREPLY=( $( compgen -W "$(cat $AUTOSYS_HOSTFILE)" -- $cur ) )
     return 0
     ;;
   -E)
     COMPREPLY=( $( compgen -W "STARTJOB KILLJOB DELETEJOB \
                    FORCE_STARTJOB JOB_ON_ICE JOB_OFF_ICE \
                    JOB_ON_HOLD JOB_OFF_HOLD CHANGE_STATUS \
                    STOP_DEMON CHANGE_PRIORITY COMMENT \
                    ALARM SET_GLOBAL SEND_SIGNAL" -- $cur ) )
     return 0
     ;;
   -s)
     COMPREPLY=( $( compgen -W "RUNNING STARTING SUCCESS \
                    FAILURE INACTIVE TERMINATED" -- $cur ) )
     return 0
     ;;
   -J)
     _autosysjobs
     ;;
  esac

  # completing an option
  if [[ "$cur" == -* ]]; then
          COMPREPLY=( $( compgen -W "-E -S -A -J -s -P \
                       -M -q -G -C -U -T -K" -- $cur ) )
  fi
}
complete -F _sendevent sendevent

# complete autorep
_autorep()
{
  local cur=${COMP_WORDS[COMP_CWORD]}
  local prev=${COMP_WORDS[COMP_CWORD-1]}

  case "$prev" in
   -J)
      _autosysjobs
     ;;
  esac

  # completing an option
  if [[ "$cur" == -* ]]; then
          COMPREPLY=( $( compgen -W "-J -d -s -q -o \
                    -w -r -L -z -G -M -D" -- $cur ) )
  fi
}
complete -F _autorep autorep
