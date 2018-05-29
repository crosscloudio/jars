#!/usr/bin/env bash

# pull hooks from main project.
git archive --remote=git@gitlab.crosscloud.me:CrossCloud/client.git HEAD git-commit-hooks | tar -x

# link to git
ln -s git-commit-hooks/pre-commit.py .git/hooks/
