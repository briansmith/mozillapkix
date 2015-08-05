[![Build Status](https://travis-ci.org/briansmith/mozillapkix.svg?branch=feature%2Fopenssl)](https://travis-ci.org/briansmith/mozillapkix)

THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.



What is mozilla::pkix?
======================

mozilla::pkix is a library that validates certificates according to RFC 5280,
RFC 6960, and related specifications. It is has been used in Firefox since
July 2014 to do certificate verification for TLS connections and other things.
I wrote a little more about it in
[insanity::pkix: A New Certificate Path Building & Validation Library](https://briansmith.org/insanity-pkix).

mozilla::pkix was designed with a very strong focus on memory safety and is
designed from the beginning to reduce the likelihood of buffer overflow,
use-after-free, and other vulnerabilities.

mozilla::pkix does not implement any cryptography on its own. Instead, the
caller of ```BuildCertChain``` supplies a ```TrustDomain``` object that
implements the cryptography. An adapter for
BoringSSL/OpenSSL/LibreSSL/[ring](https://github.com/briansmith/ring) is
provided; see [pkix/pkixlibcrypto.h](include/pkix/pkixlibcrypto.h). There is
also an adapter for NSS that Firefox uses.

Similarly, mozilla::pkix does not have its own certificate trust database.
Instead, it asks the ```TrustDomain``` which objects to trust. The idea is that
different certificate trust databases can be used depending on the operating
system or other factors.



How do I use it?
================

More documentation is coming. For now, look at the documentation in the header
files, particularly [pkix/pkix.h](include/pkix/pkix.h),
[pkix/pkixtypes.h](include/pkix/pkixtypes.h), and
[pkix/pkixlibcrypto.h](include/pkix/pkixlibcrypto.h). The functions you need to
call are ```BuildCertChain``` and ```CheckCertHostname```, both declared in
[pkix/pkix.h](include/pkix/pkix.h). The interface you need to implement is
```TrustDomain``` defined in [pkix/pkixtypes.h](include/pkix/pkixtypes.h).

To integrate it in your program, add [include] to your include path, then
```#include "pkix/pkix.h"```. Compile and link all the source files in [lib],
except for ```pkixnss.cpp``` (if you are not using NSS) and
```pkixlibcrypto.cpp``` (if you are not using OpenSSL). Note that all the
mozilla::pkix code is in the ```mozilla::pkix``` namespace.



Building
========

For now, look at how the online automated testing (linked below) do it.



Contributing
============

Patches Welcome! Suggestions:

* An XCode project. (I have a Visual Studio 2013/2015 project that I just
  need to clean up and check in.)
* Language bindings for safer (than C) systems programming languages like
  Haskell, OCaml, Rust, and Swift. (I am working on a Rust language binding
  now.)
* Language bindings for Python, JavaScript (node.js), etc.
* Adapters for more cryptography libraries, especially the
  operating-system-provided libraries on iOS, Mac OS X, Android, and Windows.
* Adapters for native operating system certificate databases, especially on
  Windows, Mac OS X, iOS, and Android.
* Support for more platforms in the continuous integration, such as Android
  and iOS.
* Static analysis and fuzzing in the continuous integration.



License
=======

See [LICENSE](LICENSE). Briefly, you may use mozilla::pkix under your choice of
the Apache 2.0 License or the MPL 2.0 License. Note in particular that the
MPL 2.0 license lets you redistribute mozilla::pkix under the GPL 2.0, the
LGPL 2.1, or the AGPL 3.0
[as part of a larger work](https://www.mozilla.org/MPL/2.0/#distribution-of-a-larger-work).




Online Automated Testing
========================

Travis CI is used for Linux and Mac OS X:

<table>
<tr><th>OS</th><th>Arch.</th><th>Compilers</th><th>Status</th>
<tr><td>Linux</td>
    <td>x86, x64<td>GCC 4.8, 4.9, 5; Clang 3.4, 3.5, 3.6</td>
    <td rowspan=2><a title="Build Status" href=https://travis-ci.org/briansmith/mozillapkix><img src=https://travis-ci.org/briansmith/mozillapkix.svg?branch=feature/openssl></a>
</tr>
<tr><td>Mac OS X x64</td>
    <td>x86, x64</td>
    <td>Apple Clang 6.0 (based on Clang 3.5)</td>
</tr>
</table>

In addition, Mozilla runs mozilla::pkix's tests, and several more tests that
can't be easily separated from Firefox, as part of Firefox's continuous
integration process, on Android (2.3 & 4.0 on ARM, 4.2 on x86),
FirefoxOS (ARM), Linux (x86 and x64), Mac (x64), and Windows (x86 and x64).



Bug Reporting
=============

Please file bugs in the
[issue tracker](https://github.com/briansmith/mozillapkix/issues). If you think
you've found a security vulnerability that affects Firefox then Mozilla would
probably appreciate it if you report the bug privately to them. Regardless, I
am happy to take *any* kind of bug report as a pull request that fixes it
and/or adds a test for the issue, or as an issue filed in the public issue
tracker here on GitHub. **Do NOT report any security vulnerability privately to
me.**
