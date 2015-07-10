#!/bin/bash
# The documentation for this is in hg-to-git-README.txt.
set -euo pipefail 
IFS=$'\n\t'

while read p; do 
    echo $p
    hg --repository $1 export --git -r $p \
      | python tools/hg-to-git-am.py $1 \
      | tee am-log \
      | git am --whitespace=nowarn --committer-date-is-author-date
done
