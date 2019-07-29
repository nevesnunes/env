INPUT=$(mktemp -u)
mkfifo -m 600 "$INPUT"
OUTPUT=$(mktemp -u)
mkfifo -m 600 "$OUTPUT"

(cat "$INPUT" | nc -U "$SKT_PATH" > "$OUTPUT") &
NCPID=$!

exec 4>"$INPUT"
exec 5<"$OUTPUT"

echo "$POST_LINE" >&4
read -u 5 -r RESPONSE;
echo "Response: '$RESPONSE'"
