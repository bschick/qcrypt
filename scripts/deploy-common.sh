# scripts/deploy-common.sh — shared bash helpers for the apps/{web,server}
# deploy wrapper scripts.
#
# Source after the caller has set `set -euo pipefail`. Functions are
# parameter-driven (no globals beyond COMMON_VALUE_FLAGS), so callers can
# safely re-source on multiple invocations.

# Flags that take a separate-token value (i.e. `--flag value`, not just
# `--flag` boolean or `--flag=value` self-contained). Used by
# detect_subcommand and remove_subcommand_from_args to skip past values
# when scanning for positionals. Update if either deploy.mjs grows a new
# value-taking flag.
COMMON_VALUE_FLAGS="--prod --lambda --profile --region --build-dir --comment --version --print-limit --manifest-key --cache-control --cf-distribution --expiration-days"

# Echoes "1" if --prod (with or without =value) is present in args, else "0".
is_prod_mode() {
   for arg in "$@"; do
      case "$arg" in
         --prod|--prod=*)
            echo 1
            return 0
            ;;
      esac
   done
   echo 0
}

# Scan args for `--<flag> value` or `--<flag>=value`. Echoes the value or
# the empty string if not found. Used by callers that need to know what
# value the user passed for a flag *before* deploy.mjs sees the args
# (e.g. for the SSO probe's --profile).
resolve_flag() {
   local flag=$1
   shift
   local prev=""
   for arg in "$@"; do
      if [ "$prev" = "$flag" ]; then
         echo "$arg"
         return 0
      fi
      case "$arg" in
         "$flag"=*)
            echo "${arg#"$flag="}"
            return 0
            ;;
      esac
      prev="$arg"
   done
   echo ""
}

# Echoes the first positional (non-flag) arg in $@, skipping over values
# for known flag-with-value options listed in COMMON_VALUE_FLAGS. Echoes
# empty if there is no positional. Useful for picking per-command DEFAULTS.
detect_subcommand() {
   local expect_value=0
   for arg in "$@"; do
      if [ $expect_value -eq 1 ]; then
         expect_value=0
         continue
      fi
      case " $COMMON_VALUE_FLAGS " in
         *" $arg "*)
            expect_value=1
            continue
            ;;
      esac
      case "$arg" in
         -*)
            ;;  # boolean flag or --foo=bar
         *)
            echo "$arg"
            return 0
            ;;
      esac
   done
   echo ""
}

# Sets the global array ARGS_WITHOUT_SUBCMD to a copy of $@ with the first
# occurrence of `subcmd` removed. Flag-with-value pairs are kept intact —
# only a positional matching `subcmd` is dropped, so `--comment subcmd`
# (where the value happens to share the subcommand name) is preserved.
# Caller is responsible for invoking after detect_subcommand.
remove_subcommand_from_args() {
   local subcmd=$1
   shift
   ARGS_WITHOUT_SUBCMD=()
   if [ -z "$subcmd" ]; then
      ARGS_WITHOUT_SUBCMD=("$@")
      return 0
   fi
   local removed=0
   local expect_value=0
   for arg in "$@"; do
      if [ $expect_value -eq 1 ]; then
         ARGS_WITHOUT_SUBCMD+=("$arg")
         expect_value=0
         continue
      fi
      case " $COMMON_VALUE_FLAGS " in
         *" $arg "*)
            ARGS_WITHOUT_SUBCMD+=("$arg")
            expect_value=1
            continue
            ;;
      esac
      if [ $removed -eq 0 ] && [ "$arg" = "$subcmd" ]; then
         removed=1
         continue
      fi
      ARGS_WITHOUT_SUBCMD+=("$arg")
   done
}

# Print a copy-pasteable macOS Chrome launch command alongside the SSO
# device URL when chrome_profile is set. Pass-through everything else so
# the user still sees aws's normal output.
sso_login_with_chrome_hint() {
   local profile=$1
   local chrome_profile=$2
   aws --profile "$profile" sso login --use-device-code 2>&1 | while IFS= read -r line; do
      printf '%s\n' "$line"
      if [ -n "$chrome_profile" ] && [[ "$line" =~ (https://[^[:space:]]*device[^[:space:]]*) ]]; then
         local url="${BASH_REMATCH[1]}"
         echo
         echo "  -> To open this URL in the right Chrome profile, run on your"
         echo "     local macOS terminal:"
         echo "       open -na \"Google Chrome\" --args --profile-directory='$chrome_profile' '$url'"
         echo
      fi
   done
}

# Echoes the most recent tag reachable from HEAD
# (`git describe --tags --abbrev=0`), or empty if the working tree has no
# tags or isn't a git repo.
git_latest_tag() {
   git describe --tags --abbrev=0 2>/dev/null || true
}

# Inject --comment as a wrapper default for deploy/bdeploy/rollback. If
# the user didn't supply --comment AND the working tree has a git tag,
# push `--comment <tag>` into DEFAULTS so versions/manifests are labelled
# with the code that shipped. Otherwise no-op (deploy.mjs's own default
# of '' applies).
default_comment_from_git_tag() {
   local tag
   tag="$(git_latest_tag)"
   if [ -n "$tag" ]; then
      default_unless_user_supplied --comment "$tag" "$@"
   fi
}

# Returns 0 if --<flag> appears in args (with or without a value), else 1.
# Used to distinguish "user explicitly passed --foo ''" (presence; suppress
# any wrapper default) from "user didn't pass --foo" (absence; ok to inject).
flag_present() {
   local flag=$1
   shift
   for arg in "$@"; do
      case "$arg" in
         "$flag"|"$flag"=*)
            return 0
            ;;
      esac
   done
   return 1
}

# Append `flag value` to the global DEFAULTS array unless the user already
# supplied that flag in their args. yargs treats repeated `--foo X --foo Y`
# as an array (and for `type: number` may sum the values), so wrappers MUST
# avoid injecting a default flag that the user has also passed — otherwise
# the deploy.mjs side sees a corrupted value. Presence-based check (not
# value-based) so `--foo ''` correctly suppresses the default.
default_unless_user_supplied() {
   local flag=$1
   local value=$2
   shift 2
   if ! flag_present "$flag" "$@"; then
      DEFAULTS+=("$flag" "$value")
   fi
}

# Verify the SSO session for `profile` is live; trigger device-code login
# (with optional chrome-profile hint) if not. No-op when profile is empty
# — deploy.mjs will hard-error on its own with a clearer message in that
# case.
do_sso_check() {
   local profile=$1
   local chrome_profile=${2:-}
   if [ -z "$profile" ]; then
      return 0
   fi
   if ! aws --profile "$profile" sts get-caller-identity >/dev/null 2>&1; then
      sso_login_with_chrome_hint "$profile" "$chrome_profile"
   fi
}
