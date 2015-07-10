#!/usr/bin/env python
# The documentation for this is in hg-to-git-README.txt.
from __future__ import print_function
import os
import re
import subprocess
import sys
from cStringIO import StringIO

def stop(msg):
    print("Error: %s" % msg, file=sys.stderr)
    sys.exit(1)

def parse_line(line, regex):
    match = re.match(regex, line)
    if not match:
       stop('Error: expected "%s", got "%s"' % (regex, line));
    return match.groups()

def hg_patch_to_git_patch(hg_repo, hg_patch):
    # XXX: hg 3.0.1's "hg cat" doesn't understand the --repository argument,
    # so we have to change to the HG repo directory instead.
    os.chdir(hg_repo)

    lines = hg_patch.split('\n')

    # HG metadata at the top of the patch
    parse_line(lines[0], '# HG changeset patch$')
    author = parse_line(lines[1], '# User (.+ <.+>)$')[0]
    parse_line(lines[2], '# Date .+$')
    date = parse_line(lines[3], '#      (.+)$')[0]
    hg_hash = parse_line(lines[4], '# Node ID (.+)$')[0]
    # skip remaining metadata
    i = 5
    while i < len(lines) and lines[i].startswith('#'):
        i += 1
       
    # Commit message
    commit_msg = []
    while i < len(lines):
        if lines[i].startswith('diff --git'):
            break
        commit_msg.append(lines[i])
        i += 1

    # Remove blank lines at the end of the commit message.
    while commit_msg and not commit_msg[-1].strip():
        del commit_msg[-1]

    if not commit_msg:
        stop('no commit essage');

    # Separate amendments to the commit message from the hand-written part
    commit_msg.append("")
    
    # Append links to all the bugs mentioned in the first line of the commit
    # message to the commit message.
    for bug in re.findall('bug ([1-9](?:[0-9]*))', commit_msg[0], re.I):
       commit_msg.append(
         'BUG=https://bugzilla.mozilla.org/show_bug.cgi?id=%s' % bug)

    commit_msg.append("")

    # Append a link to the mozilla-central commit to the commit message.
    # The short node ID is the first 12 characters of the node ID.
    commit_msg.append(
      'Imported-from: https://hg.mozilla.org/mozilla-central/rev/%s'
          % (hg_hash[0:12]))

    diff_lines = filter_diffs(lines[i:], hg_hash)
   
    if not diff_lines:
        stop('No relevant changes in patch')

    # XXX Do I have to worry about text encoding here?
    print('From: %s' % author)
    print('Date: %s' % date)
    print('Subject: %s' % commit_msg[0])

    if (len(commit_msg) > 1):
        print()
        print('\n'.join(commit_msg[1:]))

    # Add a git note like hg-fast-export does
    print()
    print('---')
    print()
    print('Notes (hg):')
    print('    %s' % hg_hash)
    print()

    print('\n'.join(diff_lines))
   
def substitute_path(old_path):
    '''If old_path identifies a file under security/insanity/ or security/pkix
       then returns the path without the security/insanity or security/pkix prefix.
      
       If old_path identifies /dev/null then returns '/dev/null'. ('/dev/null' is
       used as the original file path when a file is new; it is used as the new
       file path when the file is removed.)
      
       Otherwise, the path identifies a file that is not within mozilla::pkix,
       in which case this function returns None.
    '''
    match = re.match('([ab])/security/(?:insanity|pkix)/(.+)$', old_path)
    if not match:
       if old_path == '/dev/null':
          return old_path
       return None

    return '%s/%s' % (match.group(1), match.group(2))
    return result

def unprefixed_path(path):
    if path == '/dev/null':
        return path
        
    return path[2:]
    
def filter_diffs(diff, hg_hash):
    result = []
    i = 0
    while i < len(diff):
        try:
            old_a, old_b = parse_line(diff[i], 'diff --git ([^ ]+) (.+)$')
        except ValueError:
            stop(diff[i] + (", line %d" % i))

        i += 1

        new_a = substitute_path(old_a)
        new_b = substitute_path(old_b)

        if (not new_a) and (not new_b):
            # The diff does not affect mozilla::pkix at all so ignore it.
            while i < len(diff) and not(diff[i].startswith('diff --git')):
                i += 1
            continue

        # Moves from a directory outside of mozilla::pkix and moves to a
        # directory outside of mozilla::pkix are treated like file additions
        # and file deletions, respectively. Additions and deletions use the
        # same file name in the "diff --git" command for both the source and
        # destination.
        diff_src = new_a if new_a else new_b
        diff_dest = new_b if new_b else new_a
            
        # Copy the metadata for the diff, substituting names.

        synthesize_patch = (not new_a) or (not new_b)
        if not synthesize_patch:
            result.append('diff --git a/%s b/%s' % (unprefixed_path(new_a), unprefixed_path(new_b)))
            while i < len(diff) and not(diff[i].startswith('diff --git')):
                if not synthesize_patch:
                    result.append(diff[i].replace(unprefixed_path(old_a),
                                                  unprefixed_path(new_a))
                                         .replace(unprefixed_path(old_b),
                                                  unprefixed_path(new_b)))
                was_plus_plus_plus = diff[i].startswith('+++')
                i += 1
                if was_plus_plus_plus:
                    break
        elif not new_a:
            # Synthesized file addition from a move from outside mozilla::pkix.
            print("hg cat -r " + hg_hash + " " + unprefixed_path(old_b), file=sys.stderr)
            file_contents = subprocess.Popen(
                    ["hg", "cat", "-r", hg_hash, unprefixed_path(old_b)],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    stdin=subprocess.PIPE,
                    env={'PATH': os.environ['PATH']}).communicate()[0]
            result.append('diff --git a/%s b/%s' % (unprefixed_path(new_b), unprefixed_path(new_b)))
            result.append("new file mode 100644")
            result.append("--- /dev/null")
            result.append("+++ " + new_b)
            lines = []
            for line in file_contents.split('\n'):
                lines.append("+" + line)
            result.append("@@ -0,0 +1,%d @@" % (len(lines)))
            result = result + lines
            for line in result:
                print(line, file=sys.stderr)
        else:
            # Synthesized file removal from a move to outside mozilla::pkix.
            result.append('diff --git a/%s b/%s' % (unprefixed_path(new_a), unprefixed_path(new_a)))
            result.append("deleted file mode 100644")
            result.append("--- " + new_a)
            result.append("+++ /dev/null")
            # TODO: result.append("@@ -0,0 +1,%d" % (len(lines)))

        while i < len(diff) and not(diff[i].startswith('diff --git')):
            if not synthesize_patch:
                # Copy the actual diff, verbatim.               
                result.append(diff[i])
            i += 1

    return result

if __name__ == '__main__':
    hg_patch_to_git_patch(sys.argv[1], sys.stdin.read())
