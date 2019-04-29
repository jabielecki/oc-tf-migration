#!/bin/bash
#
# The legal Linux Foundation (LF) requirement is to squash the entire history into a single huge commit and
# include the person who signs off the change of code ownership.
# But LF agreed to use `git replace` method to allow devs to easily browse the actual history.
# The `git replace` can be quite easily deleted and then restored.
#
set -x
mydir=$(dirname "$0")
branch=${1:-master}
# remove replacements from previous runs
git for-each-ref --format='delete %(refname)' refs/replace | git update-ref --stdin
# checkout is without that cumbersome warning about detached HEAD
git checkout -f "origin/$branch" --detach
git branch -D "$branch"
git checkout --orphan "$branch"
git config user.name "$2"
git config user.email "$3"
git commit -F $mydir/initial-commit-msg.txt
git replace "$branch" "origin/$branch"
