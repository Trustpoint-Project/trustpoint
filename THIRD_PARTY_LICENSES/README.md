# Third-party notices

Trustpoint's MIT license does not replace the licenses of bundled components.
Keep this directory and the adjacent asset notices when redistributing source
or images. Versions below describe the checked-in assets, independently of the
Python dependency versions.

| Distributed component | Files | License text / origin |
| --- | --- | --- |
| ReDoc 2.0.0 from installed drf-yasg, with CSP nonce and local-logo substitutions | `trustpoint/static/js/redoc-csp.min.js` | Adjacent `redoc-csp.min.js.NOTICES.txt`; reproduce with `uv run python tests/scripts/build_redoc_csp.py` |
| Workflow editor: CodeMirror, Lezer, YAML and transitive browser dependencies | `trustpoint/static/js/workflows2/editor_bundle.js` | Adjacent `editor_bundle.js.NOTICES.txt`, generated from esbuild inputs and installed package license files; exact versions appear in that notice |
| Bootstrap 5.3.2, including CSS and JavaScript | `trustpoint/static/css/bootstrap.min.css`, `trustpoint/static/js/bootstrap.bundle.min.js` | [MIT](vendor/bootstrap-5.3.2.txt), [upstream tag](https://github.com/twbs/bootstrap/blob/v5.3.2/LICENSE) |
| Popper 2.11.8, included by Bootstrap's bundle | `trustpoint/static/js/bootstrap.bundle.min.js` | [MIT](vendor/popper-2.11.8.txt), [upstream tag](https://github.com/floating-ui/floating-ui/blob/v2.11.8/LICENSE.md) |
| Bootstrap Icons 1.11.3 and derived SVG sprite | `trustpoint/static/css/bootstrap-icons.min.css`, `trustpoint/static/css/fonts/bootstrap-icons.woff*`, `trustpoint/static/img/icons.svg` | [MIT](vendor/bootstrap-icons-1.11.3.txt), [upstream tag](https://github.com/twbs/icons/blob/v1.11.3/LICENSE) |
| Chart.js 4.4.2 | `trustpoint/static/js/chart.js` | [MIT](vendor/chart.js-4.4.2.txt), [upstream tag](https://github.com/chartjs/Chart.js/blob/v4.4.2/LICENSE.md) |
| @kurkle/color 0.3.2, included by Chart.js | `trustpoint/static/js/chart.js` | [MIT](vendor/kurkle-color-0.3.2.txt), [upstream tag](https://github.com/kurkle/color/blob/v0.3.2/LICENSE.md) |
| Adapted Django admin theme | `trustpoint/static/js/theme.js` | [BSD-3-Clause](vendor/django-theme.txt), [upstream license](https://github.com/django/django/blob/6.0.4/LICENSE); the copied file does not establish its original Django version |
| Quicksand font | `trustpoint/static/css/fonts/Quicksand.woff2` | SIL OFL 1.1, including the reserved font name: `trustpoint/static/css/fonts/OFL.txt` |
| PlantUML MIT edition 1.2025.2 | `docs/source/plantuml-mit-1.2025.2.jar` | `docs/source/LICENSE-mit-plantuml` and [runtime acknowledgements](vendor/plantuml-runtime-notices.txt); these notices alone do not establish the license inventory of every embedded component |
| uv 0.13.6 (container binary) | `/bin/uv`, `/bin/uvx` | [MIT](vendor/uv-MIT.txt) OR [Apache-2.0](vendor/uv-APACHE.txt), [upstream](https://github.com/astral-sh/uv/tree/0.13.6) |
| python-qrcode | Installed Python package | [Existing review](python-qrcode.md), installed package license files |

## Additional Python package notices

These upstream license texts supplement packages whose wheels omit notice files.
They are retained as notices alongside the distribution, without build-time
version checks.

| Package | License text | Source |
| --- | --- | --- |
| django-q2 1.11.0 | [Full notice](vendor/django-q2-1.11.0.txt) | [Upstream release](https://raw.githubusercontent.com/GDay/django-q2/v1.11.0/LICENSE) |
| sphinxcontrib-applehelp 2.0.0 | [Full notice](vendor/sphinxcontrib-applehelp-2.0.0.txt) | [Upstream release](https://raw.githubusercontent.com/sphinx-doc/sphinxcontrib-applehelp/2.0.0/LICENCE.rst) |
| sphinxcontrib-devhelp 2.0.0 | [Full notice](vendor/sphinxcontrib-devhelp-2.0.0.txt) | [Upstream release](https://raw.githubusercontent.com/sphinx-doc/sphinxcontrib-devhelp/2.0.0/LICENCE.rst) |
| sphinxcontrib-htmlhelp 2.1.0 | [Full notice](vendor/sphinxcontrib-htmlhelp-2.1.0.txt) | [Upstream release](https://raw.githubusercontent.com/sphinx-doc/sphinxcontrib-htmlhelp/2.1.0/LICENCE.rst) |
| sphinxcontrib-qthelp 2.0.0 | [Full notice](vendor/sphinxcontrib-qthelp-2.0.0.txt) | [Upstream release](https://raw.githubusercontent.com/sphinx-doc/sphinxcontrib-qthelp/2.0.0/LICENCE.rst) |
| sphinxcontrib-serializinghtml 2.0.0 | [Full notice](vendor/sphinxcontrib-serializinghtml-2.0.0.txt) | [Upstream release](https://raw.githubusercontent.com/sphinx-doc/sphinxcontrib-serializinghtml/2.0.0/LICENCE.rst) |

## Build and distribution

From `trustpoint/workflows2/frontend`, run `npm ci` and `npm run build` to rebuild
the editor and its adjacent notice file. The build retains legal comments and
collects full license texts from the npm packages contributing bundled inputs.
Missing license files fail the build. `npm run check` verifies that the committed
bundle and notices match a fresh build; license CI runs this check.

Docker includes this directory at
`/var/www/html/trustpoint/THIRD_PARTY_LICENSES` and ships the generated editor
notices beside the JavaScript. Keep these notices when redistributing copies.
Existing Python license checks and the image SBOM workflow remain in place.

## Docker binary package review

Reviewed on 2026-10-29 using the existing arm64 verification image
`sha256:a964e31b70e8…`. Its package-install steps match the current Dockerfile;
subsequent changes removed reporting code, without changing these packages.
The image contains 223 installed Debian packages. Every package has a readable
`/usr/share/doc/<package>/copyright`, including the directly installed packages
below and their dependencies. CPython's notice is installed at
`/usr/local/lib/python3.14/LICENSE.txt`. No duplicate license-export system is
needed to retain these existing files.

| Direct package | Installed version | Primary license terms |
| --- | --- | --- |
| opensc | 0.26.1-2 | LGPL-2.1-or-later |
| sudo | 1.9.16p2-3+deb13u2 | ISC; additional per-file terms |
| apt-utils | 3.0.3 | GPL-2.0-or-later |
| nginx | 1.26.3-3+deb13u10 | BSD-2-Clause; additional per-file terms |
| gettext | 0.23.1-2 | GPL-3.0-or-later; libraries also have LGPL terms |
| locales | 2.41-12+deb13u4 | glibc: LGPL-2.1-or-later; additional data/file terms |
| git | 1:2.47.3-0+deb13u1 | GPL-2.0; additional per-file terms |
| build-essential | 12.12 | GPL-2.0-or-later; installs separately licensed compiler/tool packages |
| cmake | 3.31.6-2 | BSD-3-Clause; additional bundled-component terms |
| libssl-dev | 3.5.7-1~deb13u3 | OpenSSL: Apache-2.0; additional per-file terms |
| libseccomp-dev | 2.6.0-2 | LGPL-2.1 |
| softhsm2 | 2.6.1-3 | BSD-2-Clause; additional per-file terms |
| libpkcs11-proxy0 | 0.4.1-3 | LGPL-2.0-or-later; additional per-file terms |
| curl | 8.14.1-2+deb13u7 | curl license; additional per-file terms |
| ca-certificates | 20250419+deb13u1 | GPL-2.0-or-later scripts and MPL-2.0 certificate data |
| gnupg | 2.4.7-21+deb13u1 | GPL-3.0-or-later; additional per-file terms |
| postgresql-client-18 | 18.6-1.pgdg13+2 | PostgreSQL license; additional per-file terms |

The table summarizes primary terms, rather than replacing each package's full
per-file copyright information. Transitive packages include GCC 14.2.0-19,
GNU Make, Bash, glibc, Readline, GnuTLS and other libraries with their own
licenses and exceptions. Notice presence was checked for all 223 packages; this
was not a file-by-file licensing audit of all their contents.

Two upstream notice references use filenames absent from Debian's common-license
directory: gzip refers to `GFDL-3`, and GnuPG packages refer to `GPL-2.0`.
The relevant texts are present as `GFDL-1.3` and `GPL-2`; the notices themselves
have not been modified. Preserve `/usr/share/doc` and
`/usr/share/common-licenses` when reducing the image.

The copied `uv` and `uvx` both identify as 0.13.6, targeting
`aarch64-unknown-linux-musl`; their main MIT/Apache notices are included above.
Their statically linked Rust/native dependencies, including musl, still need a
separate notice inventory. The uv project's own dual license does not establish
the terms of every linked component.

**Remaining release requirement:** establish and document access to the exact
corresponding source for copyleft binaries in the published image, including
Debian/PGDG patches and applicable build material. Publishing a matching source
archive beside each release image is the recommended approach. Keeping license
texts or linking to a current upstream repository alone does not establish this.
See the [GNU guidance on binary/source distribution](https://www.gnu.org/licenses/gpl-faq.en.html#SourceAndBinaryOnDifferentSites)
and [Debian's copyright-file policy](https://www.debian.org/doc/debian-policy/ch-docs.html#copyright-information).
This review has not prepared or published those source archives. Package
versions must be rechecked for the final release image: the floating base tag,
`apt-get upgrade` and unpinned apt packages can change the resolved versions.

## Remaining review

The unused BMFTR logo has been removed. Confirm the provenance of any externally
supplied branding or third-party content in diagrams/screenshots. Review the
PlantUML JAR's embedded dependencies against its upstream sources, and review
the actual release image's SBOM and applicable source-distribution obligations.
These are provenance questions that automated license checks cannot settle.
