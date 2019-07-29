files=($(find ~/bin/functions -iname '*.sh'))
for file in "${files[@]}"; do
  source "$file"
done
