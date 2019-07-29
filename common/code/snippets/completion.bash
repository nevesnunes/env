_telnet() {
  COMPREPLY=()
  local cur
  cur=$(_get_cword)
  local completions
  IFS='' read -r -d '' completions <<'EOF'
10.10.10.10
10.10.10.11
10.20.1.3
EOF

  COMPREPLY=( $( compgen -W "$completions" -- "$cur" ) )
  return 0
}
complete -F _telnet telnet
