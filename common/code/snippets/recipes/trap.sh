# See: https://unix.stackexchange.com/a/322213/318118
cleanup() {
  err=$?
  rm -f foo
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM
