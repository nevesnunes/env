f() {
  find . -iname '*'"$*"'*'
}

g() {
  grep -rin -- "$*"
}
