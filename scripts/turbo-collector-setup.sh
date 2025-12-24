#!/usr/bin/env bash
# Auto-detecting installer for SentinelOne Collector (Scalyr Agent 2)
# Detects OS and runs the appropriate platform-specific installer
# Author: Steve VanAllen
# Last Updated: 12-24-25

set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# Detect OS
detect_os() {
  if [[ ! -r /etc/os-release ]]; then
    die "Cannot detect OS: /etc/os-release not found"
  fi

  # shellcheck disable=SC1091
  . /etc/os-release

  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"

  # Normalize OS_ID (handle variations)
  case "${OS_ID}" in
    ubuntu)
      if [[ "${OS_VERSION_ID:-}" == "24.04" ]]; then
        echo "ubuntu24.04"
        return 0
      elif [[ "${OS_VERSION_ID:-}" == "22.04" ]]; then
        echo "ubuntu22.04"
        return 0
      else
        die "Unsupported Ubuntu version: ${OS_VERSION_ID:-} (only 22.04 and 24.04 LTS are supported)"
      fi
      ;;
    rocky|rhel|centos|almalinux)
      if [[ "${OS_VERSION_ID:-}" == "9"* ]]; then
        echo "rocky9"
        return 0
      else
        die "Unsupported ${OS_ID} version: ${OS_VERSION_ID:-} (only 9.x is supported)"
      fi
      ;;
    *)
      die "Unsupported OS: ID='${OS_ID}' VERSION_ID='${OS_VERSION_ID:-}' (supported: Ubuntu 22.04, 24.04, Rocky Linux 9)"
      ;;
  esac
}

# Install prerequisites (curl + ca-certificates) using the appropriate package manager
install_prereqs() {
  local os_type="$1"

  case "${os_type}" in
    ubuntu24.04|ubuntu22.04)
      if ! command -v curl >/dev/null 2>&1 || ! command -v ca-certificates >/dev/null 2>&1; then
        echo "Installing prerequisites (curl, ca-certificates) via apt..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1
        apt-get install -y curl ca-certificates >/dev/null 2>&1
      fi
      ;;
    rocky9)
      if ! command -v curl >/dev/null 2>&1 || ! command -v ca-certificates >/dev/null 2>&1; then
        echo "Installing prerequisites (curl, ca-certificates) via dnf..."
        dnf -y makecache >/dev/null 2>&1
        dnf -y install curl ca-certificates >/dev/null 2>&1
      fi
      ;;
    *)
      die "Unknown OS type: ${os_type}"
      ;;
  esac

  # Verify curl is available
  if ! command -v curl >/dev/null 2>&1; then
    die "Failed to install curl"
  fi
}

# Main execution
main() {
  # Check for root
  if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root (use: sudo bash $0)"
  fi

  echo "SentinelOne Collector (Scalyr Agent 2) - Auto-detecting installer"
  echo "=================================================================="
  echo

  # Detect OS
  echo "Detecting OS..."
  OS_TYPE="$(detect_os)"
  echo "Detected: ${OS_TYPE}"
  echo

  # Install prerequisites
  install_prereqs "${OS_TYPE}"

  # Determine which script to fetch and run
  case "${OS_TYPE}" in
    ubuntu24.04)
      SCRIPT_URL="https://raw.githubusercontent.com/sva-s1/collector/main/scripts/turbo-collector-setup-ubuntu24-04.sh"
      SCRIPT_NAME="turbo-collector-setup-ubuntu24-04.sh"
      ;;
    ubuntu22.04)
      SCRIPT_URL="https://raw.githubusercontent.com/sva-s1/collector/main/scripts/turbo-collector-setup-ubuntu22-04.sh"
      SCRIPT_NAME="turbo-collector-setup-ubuntu22-04.sh"
      ;;
    rocky9)
      SCRIPT_URL="https://raw.githubusercontent.com/sva-s1/collector/main/scripts/turbo-collector-setup-rocky9.sh"
      SCRIPT_NAME="turbo-collector-setup-rocky9.sh"
      ;;
    *)
      die "Unknown OS type: ${OS_TYPE}"
      ;;
  esac

  # Fetch and execute the platform-specific script
  echo "Fetching ${OS_TYPE} installer script..."
  SCRIPT_PATH="/tmp/${SCRIPT_NAME}"

  if ! curl -fsSL -L "${SCRIPT_URL}" -o "${SCRIPT_PATH}"; then
    die "Failed to download installer script from ${SCRIPT_URL}"
  fi

  chmod +x "${SCRIPT_PATH}"

  echo
  echo "Executing ${OS_TYPE} installer..."
  echo "=================================================================="
  echo

  # Execute the platform-specific script
  exec bash "${SCRIPT_PATH}"
}

main "$@"

