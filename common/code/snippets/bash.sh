#!/usr/bin/env bash

function errexit() {
  local err=$?
  local code="${1:-1}"
  echo "Error: '${BASH_COMMAND}' exited with status $err(${BASH_SOURCE[1]}:${BASH_LINENO[0]})"
  # Print out the stack trace described by $function_stack
  if [ ${#FUNCNAME[@]} -gt 2 ]
  then
    for ((i=1;i<${#FUNCNAME[@]}-1;i++))
    do
      echo "  at ${FUNCNAME[$i]} (${BASH_SOURCE[$i+1]}:${BASH_LINENO[$i]}"
    done
  fi
  echo "Exiting with status: ${code}"
  exit "${code}"
}
trap 'errexit' ERR

# Propagate to functions, expansions and subshells.
set -o errtrace
