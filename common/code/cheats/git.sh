# Deleting commits
git rebase -i HEAD^
# ||
# order
# 1. r
# 2. fixup/squash
# 3. fixup/squash
git rebase -i HEAD~3
  # optional
  git rebase --edit-todo
  git rebase --continue
  git rebase origin master

# Deny push --force
# ~/code/snippets/git/pre-receive.deny-force-push-to-branches
# https://gist.github.com/pixelhandler/5718585
git config --system receive.denyDeletes true
git config --system receive.denyNonFastForwards true

git log -G 'source_searches_cwd' general.c
git diff 3185942a~ 3185942a general.c

# Add existing repository to remote
git remote add github git@github.com:n
evesnunes/foo.git
git remove -v
git push github master

# Apply gitignore changes
git rm --cached -f -r .
git add -A
git status

# Remove directories
git clean -fd

# Remove ignored files
git clean -fX

# Remove ignored and non-ignored files
git clean -fx
