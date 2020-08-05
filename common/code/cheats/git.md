# Deleting commits

```bash
# order
# 1. r
# 2. fixup/squash
# 3. fixup/squash
git rebase -i HEAD^
# ||
git rebase -i HEAD~3

# [optional]
git rebase --edit-todo
git rebase --continue
git rebase origin master

# up to root
git rebase -i --root master
```

### Changing author

```bash
# order
# 1. e
git rebase -i HEAD^

git commit --amend --author="foo <>"
git rebase --continue
git push --force
```

# Deny push --force

```bash
git config --system receive.denyDeletes true
git config --system receive.denyNonFastForwards true

git log -G 'source_searches_cwd' general.c
git diff 3185942a~ 3185942a general.c
```

- [Git pre\-push hook to prevent force pushing master branch · GitHub](https://gist.github.com/pixelhandler/5718585)
    - ~/code/snippets/git/pre-receive.deny-force-push-to-branches

# Add existing repository to remote

```bash
git remote add github git@github.com:nevesnunes/foo.git
git remove -v
git push github master
```

# Apply gitignore changes

```bash
git rm --cached -f -r .

git add -A
git status
```

# Remove objects

```bash
# directories
git clean -fd

# ignored files
git clean -fX

# ignored and non-ignored files
git clean -fx
```

# interactive mode

- patch: pick hunks (i.e. blocks of lines) to add to commit
    - stage: `e` = pick lines in current hunk

```bash
git add --patch ./foo
git commit -m '.'
```

https://stackoverflow.com/questions/1085162/commit-only-part-of-a-file-in-git
https://stackoverflow.com/questions/6276752/can-i-split-an-already-split-hunk-with-git

# cherry-pick

- copies commits from one branch to another branch

### Pull request

```bash
# 1. Update devel, to ensure you have the commit to cherry pick:
git checkout devel
git --fetch upstream
git merge upstream/devel
git checkout $old_release_from_stable
git pull
git checkout -b cherry-pick/2.5/$pr_number_from_devel
git cherry-pick -x $sha_from_devel

# 2. Add a changelog entry for the change, and commit it

# 3. Push your branch to your fork:
git push origin cherry-pick/2.5/$pr_number_from_devel

# 4. Submit PR for cherry-pick/2.5/$pr_number_from_devel against the stable-2.5 branch
```

### Multiple commits

```bash
git checkout $devel_branch
# reset branch to f (currently includes a)
git reset --hard f
# rebase every commit after b and transplant it onto a
git rebase --onto a b
```

https://stackoverflow.com/questions/1670970/how-to-cherry-pick-multiple-commits/12646996#12646996

# gitlab ci local

```bash
(
cd ~/opt
wget https://s3.amazonaws.com/gitlab-runner-downloads/master/binaries/gitlab-runner-linux-amd64
chmod +x gitlab-runner-linux-amd64
)
gitlab-runner register --executor docker --docker-image foo
# Input: gitlab-ci.yml job name = foo
gitlab-runner exec docker --docker-pull-policy="if-not-present" ...
gitlab-runner exec shell foo
```

[gitlab\-runner exec: easily test builds locally \(\#312\) · Issues · GitLab\.org / gitlab\-runner · GitLab](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/312)

# explaining - case studies

https://lobste.rs/s/bxvx44/explain_git_with_d3
https://lobste.rs/s/nv7p4k/dancing_git_how_explain_git_depth
[How to teach Git | Hacker News](https://news.ycombinator.com/item?id=18919599)
[Learn Git Branching | Hacker News](https://news.ycombinator.com/item?id=5937994)
[A successful Git branching model \(2010\) | Hacker News](https://news.ycombinator.com/item?id=15376841)
[Oh shit, git: Getting myself out of bad situations | Hacker News](https://news.ycombinator.com/item?id=15951825)
[Some bad Git situations and how I got myself out of them | Hacker News](https://news.ycombinator.com/item?id=12459755)

# bisect

### manually marked by user

```bash
# begin
git bisect start
git bisect good 012345678
git bisect bad 012345679

# for each automatic checkout
git bisect good
# ||
git bisect bad

# end
git bisect reset
```

### automatically marked by script

```bash
git bisect start 012345678 012345679
git bisect run ./test.sh
```

For each automatic checkout:

- on exit status = 0, mark checkout as `good`
- on exit status > 0, mark checkout as `bad`

# submodules

```bash
# Add reference in main repository
git submodule add git@github.com:foo.git foo
cd foo
git checkout foo_branch
cd ..
git add -A
commit -va

# On another main repository checkout
git pull
git submodule update --init --recursive
```
