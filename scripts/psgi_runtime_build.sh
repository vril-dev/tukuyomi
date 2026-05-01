#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${ROOT_DIR}/build/Dockerfile.psgi-runtime"
BUILD_CONTEXT="${ROOT_DIR}/build"
RUNTIME_DATA_DIR="${TUKUYOMI_RUNTIME_DATA_DIR:-${ROOT_DIR}/data}"
VER="${VER:-}"
RUNTIME_ID="${RUNTIME:-}"
ARG1="${1:-}"

runtime_to_ver() {
  case "${1}" in
    perl536) printf '5.36\n' ;;
    perl538) printf '5.38\n' ;;
    perl540) printf '5.40\n' ;;
    *)
      echo "[psgi-build][ERROR] unsupported RUNTIME=${1} (expected perl536, perl538, or perl540)" >&2
      exit 1
      ;;
  esac
}

if [[ -z "${VER}" ]]; then
  if [[ -n "${RUNTIME_ID}" ]]; then
    VER="$(runtime_to_ver "${RUNTIME_ID}")"
  elif [[ -n "${ARG1}" ]]; then
    case "${ARG1}" in
      perl536|perl538|perl540)
        VER="$(runtime_to_ver "${ARG1}")"
        ;;
      *)
        VER="${ARG1}"
        ;;
    esac
  else
    VER="5.38"
  fi
fi

case "${VER}" in
  5.36|5.38|5.40) ;;
  *)
    echo "[psgi-build][ERROR] unsupported VER=${VER} (expected 5.36, 5.38, or 5.40)" >&2
    exit 1
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "[psgi-build][ERROR] docker is required" >&2
  exit 1
fi

runtime_id="perl${VER/./}"
runtime_dir="${RUNTIME_DATA_DIR}/psgi/binaries/${runtime_id}"
rootfs_dir="${runtime_dir}/rootfs"
image_tag="tukuyomi/psgi-runtime:${runtime_id}-local"
container_name=""

cleanup() {
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

flatten_arch_lib_dir() {
  local from_dir="$1"
  local to_dir="$2"
  local subdir
  local source_path
  local base_name

  [[ -d "${from_dir}" && -d "${to_dir}" ]] || return 0
  subdir="$(basename "${from_dir}")"

  while IFS= read -r source_path; do
    base_name="$(basename "${source_path}")"
    if [[ -e "${to_dir}/${base_name}" || -L "${to_dir}/${base_name}" ]]; then
      continue
    fi
    ln -s "${subdir}/${base_name}" "${to_dir}/${base_name}"
  done < <(find "${from_dir}" -maxdepth 1 \( -type f -o -type l \) | sort)
}

rm -rf "${runtime_dir}"
mkdir -p "${rootfs_dir}"

docker build \
  --build-arg "PERL_VERSION=${VER}" \
  -f "${DOCKERFILE}" \
  -t "${image_tag}" \
  "${BUILD_CONTEXT}"

container_name="$(docker create "${image_tag}")"
docker export "${container_name}" | tar -C "${rootfs_dir}" -xf -

flatten_arch_lib_dir "${rootfs_dir}/lib/x86_64-linux-gnu" "${rootfs_dir}/lib"
flatten_arch_lib_dir "${rootfs_dir}/usr/lib/x86_64-linux-gnu" "${rootfs_dir}/usr/lib"
flatten_arch_lib_dir "${rootfs_dir}/lib/aarch64-linux-gnu" "${rootfs_dir}/lib"
flatten_arch_lib_dir "${rootfs_dir}/usr/lib/aarch64-linux-gnu" "${rootfs_dir}/usr/lib"

version_line="$(docker run --rm "${image_tag}" perl -e 'print $^V')"
module_probe_list="$(
  cat <<'EOF'
Archive::Tar
Archive::Zip
Authen::SASL
Cache::File
Cache::Memcached
CGI
CGI::Compile
CGI::PSGI
CGI::Parse::PSGI
Crypt::DSA
Crypt::SSLeay
DBD::SQLite
DBD::mysql
DBI
Digest::MD5
Digest::SHA
Digest::SHA1
File::Copy::Recursive
File::Temp
GD
HTML::Entities
HTML::Parser
IO::Compress::Gzip
IO::Socket::SSL
IO::Uncompress::Gunzip
Image::Size
Imager
IPC::Run
JSON
List::Util
MIME::Base64
Mozilla::CA
Net::SMTP
Net::SSLeay
Plack
SOAP::Lite
Safe
Starman
Storable
Text::Balanced
Time::HiRes
URI
XML::Atom
XML::LibXML
XML::LibXML::SAX
XML::Parser
XML::SAX
XML::SAX::Expat
XMLRPC::Lite
XMLRPC::Transport::HTTP
XMLRPC::Transport::HTTP::Plack
YAML::Tiny
EOF
)"
modules_raw="$(docker run --rm -i -e "MODULE_PROBE_LIST=${module_probe_list}" "${image_tag}" perl <<'PERL'
use strict;
use warnings;
use ExtUtils::Installed;

my %candidates;
for my $module (ExtUtils::Installed->new->modules) {
  next if !defined $module || $module eq '';
  next if $module !~ /\A[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\z/;
  $candidates{$module} = 1;
}

for my $module (split /\n/, $ENV{MODULE_PROBE_LIST} // '') {
  next if $module !~ /\A[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\z/;
  $candidates{$module} = 1;
}

for my $module (sort keys %candidates) {
  my $path = $module;
  $path =~ s{::}{/}g;
  $path .= '.pm';
  my $ok = eval { require $path; 1 };
  print "$module\n" if $ok;
}
PERL
)"

MODULES_RAW="${modules_raw}" python3 - <<'PY' >"${runtime_dir}/modules.json"
import json
import os

modules = []
seen = set()
for line in os.environ.get("MODULES_RAW", "").splitlines():
    line = line.strip()
    if not line:
        continue
    line = line.lower()
    if line in seen:
        continue
    seen.add(line)
    modules.append(line)
json.dump(modules, fp=os.sys.stdout, indent=2)
os.sys.stdout.write("\n")
PY

cat >"${runtime_dir}/runtime.json" <<EOF
{
  "runtime_id": "${runtime_id}",
  "display_name": "Perl ${VER}",
  "detected_version": "${version_line}",
  "perl_path": "data/psgi/binaries/${runtime_id}/perl",
  "starman_path": "data/psgi/binaries/${runtime_id}/starman",
  "source": "bundled"
}
EOF

cat >"${runtime_dir}/perl" <<'EOF'
#!/usr/bin/env sh
set -eu

SELF_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
ROOTFS="${SELF_DIR}/rootfs"

find_loader() {
  for candidate in \
    "${ROOTFS}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" \
    "${ROOTFS}/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
    "${ROOTFS}/lib64/ld-linux-x86-64.so.2" \
    "${ROOTFS}/lib/ld-linux-aarch64.so.1"
  do
    if [ -x "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  found="$(find "${ROOTFS}" -maxdepth 4 -type f -name 'ld-linux-*.so.*' | sort | head -n 1)"
  if [ -n "${found}" ]; then
    printf '%s\n' "${found}"
    return 0
  fi
  return 1
}

PERL_BIN=""
for candidate in \
  "${ROOTFS}/usr/local/bin/perl" \
  "${ROOTFS}/usr/bin/perl"
do
  if [ -x "${candidate}" ]; then
    PERL_BIN="${candidate}"
    break
  fi
done
if [ -z "${PERL_BIN}" ]; then
  echo "[psgi-perl-wrapper][ERROR] perl binary not found in ${ROOTFS}" >&2
  exit 1
fi

LIB_PATH=""
append_lib_path() {
  if [ -d "$1" ]; then
    if [ -n "${LIB_PATH}" ]; then
      LIB_PATH="${LIB_PATH}:"
    fi
    LIB_PATH="${LIB_PATH}$1"
  fi
}
for dir in \
  "${ROOTFS}/lib" \
  "${ROOTFS}/lib64" \
  "${ROOTFS}/usr/lib" \
  "${ROOTFS}/usr/local/lib" \
  "${ROOTFS}/usr/local/lib/perl5"/*/*/CORE \
  "${ROOTFS}/usr/local/lib/perl5"/*/CORE
do
  append_lib_path "${dir}"
done

PERL5LIB=""
append_perl5lib() {
  if [ -d "$1" ]; then
    case ":${PERL5LIB}:" in
      *":$1:"*) return 0 ;;
    esac
    if [ -n "${PERL5LIB}" ]; then
      PERL5LIB="${PERL5LIB}:"
    fi
    PERL5LIB="${PERL5LIB}$1"
  fi
}
append_perl_tree() {
  for version_dir in "$1"/[0-9]*; do
    [ -d "${version_dir}" ] || continue
    for arch_dir in "${version_dir}"/*-linux-gnu; do
      append_perl5lib "${arch_dir}"
    done
    append_perl5lib "${version_dir}"
  done
}
for base_dir in \
  "${ROOTFS}/usr/local/lib/perl5/site_perl" \
  "${ROOTFS}/usr/local/lib/perl5/vendor_perl" \
  "${ROOTFS}/usr/local/lib/perl5"
do
  append_perl_tree "${base_dir}"
done
export PERL5LIB
export PATH="${SELF_DIR}:${ROOTFS}/usr/local/bin:${ROOTFS}/usr/bin:${PATH}"

LOADER="$(find_loader || true)"
if [ -n "${LOADER}" ]; then
  exec "${LOADER}" --library-path "${LIB_PATH}" "${PERL_BIN}" "$@"
fi
LD_LIBRARY_PATH="${LIB_PATH}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" exec "${PERL_BIN}" "$@"
EOF

cat >"${runtime_dir}/starman" <<'EOF'
#!/usr/bin/env sh
set -eu

SELF_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
ROOTFS="${SELF_DIR}/rootfs"

STARMAN_BIN=""
for candidate in \
  "${ROOTFS}/usr/local/bin/starman" \
  "${ROOTFS}/usr/bin/starman"
do
  if [ -f "${candidate}" ]; then
    STARMAN_BIN="${candidate}"
    break
  fi
done
if [ -z "${STARMAN_BIN}" ]; then
  echo "[psgi-starman-wrapper][ERROR] starman script not found in ${ROOTFS}" >&2
  exit 1
fi

exec "${SELF_DIR}/perl" "${STARMAN_BIN}" "$@"
EOF

chmod 755 "${runtime_dir}/perl" "${runtime_dir}/starman"

echo "[psgi-build] built ${runtime_id} -> data/psgi/binaries/${runtime_id}"
