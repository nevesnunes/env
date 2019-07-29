https://github.com/git-tips/tips

# The "I forgot something in my last commit" Trick

# first: stage the changes you want incorporated in the previous commit
 
git commit --amend -C HEAD
# ||
git commit --amend -m 'add some stuff and the other stuff i forgot before'

# The "Oh crap I didn't mean to commit yet" Trick

# undo last commit and bring changes back into staging (i.e. reset to the commit one before HEAD)
git reset --soft HEAD^

# The "That commit sucked! Start over!" Trick

# undo last commit and destroy those awful changes you made (i.e. reset to the commit one before HEAD)
git reset --hard HEAD^

# The "Oh no I should have been working in a branch" Trick

# takes staged changes and 'stashes' them for later, and reverts to HEAD. 
git stash
 
# creates new branch and switches to it, then takes the stashed changes and stages them in the new branch. fancy!
git stash branch new-branch-name 	

# The "OK, which commit broke the build!?" Trick

git bisect start # to initiate a bisect
git bisect bad # to tell bisect that the current rev is the first spot you know was broken.
git bisect good some_tag_or_rev_that_you_knew_was_working
git bisect run unittest_runner_of_choice
git bisect reset

# The "I have merge conflicts, but I know that one version is the correct one" Trick, a.k.a. "Ours vs. Theirs"

git checkout master
git merge a_branch
git status -s
git checkout --theirs conflict.txt
git add conflict.txt
git commit
 
# Sometimes during a merge you want to take a file from one side wholesale.
# The following aliases expose the ours and theirs commands which let you
# pick a file(s) from the current branch or the merged branch respectively.

# N.b. the function is there as hack to get $@ doing
# what you would expect it to as a shell user.
# Add the below to your .gitconfig for easy ours/theirs aliases. 
# ours = "!f() { git checkout --ours $@ && git add $@; }; f"
# theirs = "!f() { git checkout --theirs $@ && git add $@; }; f"

# The "Workaround Self-signed Certificates" Trick

# This trick should no longer be necessary for using Stash, so long as you have the certificate for DEVLAN Domain Controller Certificate Authority installed.

# Issue: When attempting to clone (or any other command that interacts with the remote server) git by default validates 
# the presented SSL certificate by the server. Our server's certificate is not valid and therefore git exits out with an error.
# Resolution(Linux): For a one time fix, you can use the env command to create an environment variable of GIT_SSL_NO_VERIFY=TRUE. 
env GIT_SSL_NO_VERIFY=TRUE git command arguments

# If you don't want to do this all the time, you can change your git configuration:
git config --global http.sslVerify false

# Split a subdirectory into a new repository/project
git clone ssh://stash/proj/mcplugins.git
cd mcplugins
git checkout origin/master -b mylib
git filter-branch --prune-empty --subdirectory-filter plugins/mylib mylib
git push ssh://stash/proj/mylib.git mylib:master
