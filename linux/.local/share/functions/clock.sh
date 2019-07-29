function alarm() {
  local startDate=$(date +"%s")
  local finalDate=$(date -d "$1" +"%s")
  if [[ -n $finalDate ]]; then
    shift
    countdown $(($finalDate - $startDate)) $@
  fi
}

function countdown() {
    local finalDate=$(($(date +%s) + $1));
    while [ "$finalDate" -ge $(date +%s) ]; do 
        ## Is this more than 24h away?
        local days=$(($(($(( $finalDate - $(date +%s))) * 1 )) / 86400))
        echo -ne "$days day(s) and $(date -u --date @$(($finalDate - $(date +%s))) +%H:%M:%S)\r"; 
        sleep 0.1
    done

    shift
    message="Time's up!"
    if [ $# -ne 0 ]; then
      message="$@"
    fi

    notify-send "$message"
}

function stopwatch() {
    local finalDate=$(date +%s); 
    while true; do 
        local days=$(($(($(date +%s) - finalDate)) / 86400))
        echo -ne "$days day(s) and $(date -u --date @$(($(date +%s) - $finalDate)) +%H:%M:%S)\r";
        sleep 0.1
    done
}
