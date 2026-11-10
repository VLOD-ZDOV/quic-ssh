#!/bin/sh
# Signs a draft release made by CI and publishes it: `qsh update` installs
# only releases whose SHA256SUMS carries this signature.
#   scripts/sign-release.sh vX.Y.Z
# The key is QSH_RELEASE_KEY (default ~/.ssh/id_ed25519); its public half must
# be in src/release.rs. Never forward an agent holding it to other hosts:
# anyone who can use the agent can sign a release (or add it with ssh-add -c).
set -eu
tag=${1:?usage: scripts/sign-release.sh vX.Y.Z}
key=${QSH_RELEASE_KEY:-$HOME/.ssh/id_ed25519}
repo=VLOD-ZDOV/quic-ssh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

gh release download "$tag" --repo "$repo" --dir "$tmp"
cd "$tmp"
[ "$(head -n 1 SHA256SUMS)" = "# version $tag" ] || { echo "SHA256SUMS is not for $tag" >&2; exit 1; }
# Every file of the draft must be the one listed (and nothing unlisted).
grep -v '^#' SHA256SUMS | sha256sum -c --quiet
for f in *; do
    case $f in SHA256SUMS | SHA256SUMS.sig) continue ;; esac
    grep -q "  $f\$" SHA256SUMS || { echo "$f is in the release but not in SHA256SUMS" >&2; exit 1; }
done
cat SHA256SUMS
printf 'Sign and publish %s? [y/N] ' "$tag"
read -r answer
[ "$answer" = y ] || exit 1

rm -f SHA256SUMS.sig
ssh-keygen -Y sign -f "$key" -n qsh-release SHA256SUMS
printf 'release %s\n' "$(awk '{ print $1 " " $2 }' "$key.pub")" > signers
ssh-keygen -Y verify -f signers -I release -n qsh-release -s SHA256SUMS.sig < SHA256SUMS
gh release upload "$tag" --repo "$repo" --clobber SHA256SUMS.sig
gh release edit "$tag" --repo "$repo" --draft=false --latest
echo "published $tag"
