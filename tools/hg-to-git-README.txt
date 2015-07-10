The hg-to-git  tool converts commits to Mozilla's mozilla-central Mercurial
repository to commits to a standalone mozilla::pkix git repository. This tool
tries to ensure that the git commits are as similar to the original commits to
mozilla-central as possible, except:

   * In mozill-central, mozilla::pkix is in the subdirectory security/pkix
     (was security/insanity); in the git repository, we strip off that
     path prefix.
   * Any changes to files outside of security/pkix (and security/insanity)
     are discarded, because they are not part of mozilla::pkix.
   * A link to the mozilla-central changeset on https://hg.mozilla.org
     and links to the bugs on https://bugzilla.mozilla.org are appended to
     commit message during the conversion. (Such links are not needed in
     mozilla-central commits because Mozilla's web tools synthesize these
     links automatically similar to the way that hg-to-git.py does.)
   * The committer and commiter date represent who imported the Mercurial
     commits into the git repository and when, not who committed the changes
     to mozilla-central and when.

usage:

   tools/hg-to-git.sh <mozilla-central> < <list-of-revisions> > <log>

e.g.:

   # track the changes to mozilla-central on a branch other than master
   git checkout -b mozilla-central

   # import the revisions
   tools/hg-to-git.sh ../firefox/mozilla-central < ../firefox/revisions.txt > log

Where revisions.txt contains a list of revision numbers containing changes
to security/pkix (and/or security/insanity, for old revisions):

   (cd ../firefox/mozilla-central ; \
    hg log -M -removed -r "ancestors(.)" --template "{node}\n" \
           security/pkix security/insanity \
      | grep -v a555f10c40e553030345ced1bab3088533c5119b \
      > ../revisions.txt)

The -M argument filters out merge commits. Commit
a555f10c40e553030345ced1bab3088533c5119b is skipped because its metadata
indicates that it updated some files in libwebpki, but it actually didn't; see
https://bugzilla.mozilla.org/show_bug.cgi?id=1037220#c13.

You need to omit any revisions that have already been imported.

