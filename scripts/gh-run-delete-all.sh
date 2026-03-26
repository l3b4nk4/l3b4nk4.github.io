#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Delete all GitHub Actions workflow runs for the current repository.

Usage:
  ./scripts/gh-run-delete-all.sh [--yes] [--repo OWNER/REPO]

Options:
  --yes              Skip the confirmation prompt.
  --repo OWNER/REPO  Override the repository instead of inferring it from git.
  --help             Show this help message.
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

infer_repo() {
  local remote
  remote="$(git remote get-url origin 2>/dev/null || true)"

  if [[ -z "$remote" ]]; then
    echo "error: could not infer repository from git remote 'origin'" >&2
    exit 1
  fi

  remote="${remote%.git}"
  remote="${remote#git@github.com:}"
  remote="${remote#https://github.com/}"
  remote="${remote#http://github.com/}"

  if [[ "$remote" != */* ]]; then
    echo "error: unsupported remote URL format: $remote" >&2
    exit 1
  fi

  printf '%s\n' "$remote"
}

confirm_delete() {
  local repo="$1"
  local reply

  read -r -p "Delete all workflow runs for ${repo}? [y/N] " reply
  case "$reply" in
    y|Y|yes|YES)
      ;;
    *)
      echo "Aborted."
      exit 0
      ;;
  esac
}

main() {
  local repo=""
  local assume_yes="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes)
        assume_yes="true"
        shift
        ;;
      --repo)
        if [[ $# -lt 2 ]]; then
          echo "error: --repo requires OWNER/REPO" >&2
          exit 1
        fi
        repo="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "error: unknown argument: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  require_command git
  require_command gh

  if [[ -z "$repo" ]]; then
    repo="$(infer_repo)"
  fi

  if [[ "$assume_yes" != "true" ]]; then
    confirm_delete "$repo"
  fi

  mapfile -t run_ids < <(
    gh api --paginate "repos/${repo}/actions/runs?per_page=100" \
      --jq '.workflow_runs[].id'
  )

  if [[ ${#run_ids[@]} -eq 0 ]]; then
    echo "No workflow runs found for ${repo}."
    exit 0
  fi

  echo "Deleting ${#run_ids[@]} workflow runs from ${repo}..."

  local deleted=0
  local failed=0
  local run_id

  for run_id in "${run_ids[@]}"; do
    if gh run delete "$run_id" -R "$repo" >/dev/null 2>&1; then
      deleted=$((deleted + 1))
      echo "Deleted run ${run_id}"
    else
      failed=$((failed + 1))
      echo "Failed to delete run ${run_id}" >&2
    fi
  done

  echo "Done. Deleted: ${deleted}. Failed: ${failed}."

  if [[ $failed -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
