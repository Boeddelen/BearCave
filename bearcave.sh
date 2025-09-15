#!/usr/bin/env bash
# BearCave - easy to use terminal based password manager With MFA, logging and encryption
# For Linux. Dependency: openssl and oathtool (for TOTP-MFA).
# Made by: Frederik Flakne, 2025
# This is version 1.1
# GitHub: https://github.com/Boeddelen/bearcave

trap 'error "Unexpected error at line $LINENO."' ERR

# -----------------------------
# Config og globale variables
# -----------------------------
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCRIPT_DIR}/bearcave"
LOG_DIR="${BASE_DIR}/logs"
TMP_DIR="${BASE_DIR}/tmp"
USERS_DIR="${BASE_DIR}/users"
LOG_FILE="${LOG_DIR}/bearcave.log"

OPENSSL_BIN="$(command -v openssl || true)"
OATHTOOL_BIN="$(command -v oathtool || true)"

ITER=200000               # PBKDF2 iterations for openssl enc -pbkdf2
CIPHER="aes-256-cbc"      # Authenticated encryption
UMASK_PREV="$(umask)"
umask 077                 # Secure file permissions during creation

# -----------------------------
# Colors/themes
# -----------------------------
if command -v tput >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
  BLUE="$(tput setaf 4)"; MAGENTA="$(tput setaf 5)"; CYAN="$(tput setaf 6)"
  BOLD="$(tput bold)"; RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

# -----------------------------
# Init folders and logging
# -----------------------------
init_dirs() {
  mkdir -p "${LOG_DIR}" "${TMP_DIR}" "${USERS_DIR}"
  touch "${LOG_FILE}"
}

timestamp() { date +"%Y-%m-%d %H:%M:%S%z"; }

log() {
  # Level, message (no sensitive information)
  local level="$1"; shift
  local msg="$*"
  printf "[%s] [%s] %s\n" "$(timestamp)" "${level}" "${msg}" >> "${LOG_FILE}"
}

info()  { log "INFO"  "$*"; }
warn()  { log "WARN"  "$*"; }
error() { log "ERROR" "$*"; }

# -----------------------------
# Clean-up of temporary files
# -----------------------------
secure_rm() {
  # Delete file securely if possible
  local f="$1"
  [ -f "${f}" ] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -z -n 2 -- "${f}" || rm -f -- "${f}"
  else
    rm -f -- "${f}"
  fi
}

cleanup() {
  # Delete everything in TMP_DIR
  if [ -d "${TMP_DIR}" ]; then
    find "${TMP_DIR}" -maxdepth 1 -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
      secure_rm "${f}"
    done
  fi
}
trap cleanup EXIT INT TERM

# -----------------------------
# Dependancy check
# -----------------------------
check_deps() {
  if [ -z "${OPENSSL_BIN}" ]; then
    echo "${RED}OpenSSL is not present. Install openssl and try again.${RESET}"
    exit 1
  fi
  # Check to see if chosen cipher is supported
  if ! "${OPENSSL_BIN}" enc -"${CIPHER}" -help >/dev/null 2>&1; then
    echo "${RED}OpenSSL does not support cipher '${CIPHER}'. Change to supported cipher (i.e., aes-256-cbc).${RESET}"
    exit 1
  fi
  if [ -n "${OATHTOOL_BIN}" ]; then
    info "oathtool discovered; MFA available."
  else
    warn "oathtool not found; MFA remains unavailable until it is installed."
  fi
}
# Check if oathtool is installed
if ! command -v oathtool >/dev/null 2>&1; then
    echo "⚠️  'oathtool' is not installed."
    read -p "Do you want to install now? (y/n): " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        # Installing depening on distribution
        if command -v apt >/dev/null 2>&1; then
            sudo apt update && sudo apt install -y oathtool
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y oathtool
        elif command -v brew >/dev/null 2>&1; then
            brew install oath-toolkit
        else
            echo "Found no known package distributions. Install 'oathtool' manually."
            exit 1
        fi
    else
        echo "BearCave depends on 'oathtool' for MFA creation. Aborting installation."
        exit 1
    fi
fi
# -----------------------------
# Formating and input
# -----------------------------
banner() {
  echo
  echo "${BOLD}${CYAN}============ bearcave ============${RESET}"
  echo "${BOLD}${YELLOW}Fill your cave with honeycombs${RESET}"
  echo "${BLUE}Your local secure and encrypted terminal vault${RESET}"
  echo "${BOLD}${RED}v1.1${RESET}"
  echo
}

read_hidden() {
  # Read hidden input (passord/codes)
  local prompt="$1"
  local varname="$2"
  local input
  read -r -s -p "${prompt}" input
  echo
  printf -v "${varname}" '%s' "${input}"
}

# -----------------------------
# Password validation
# -----------------------------
validate_password() {
  # At least: 12 values, at least one small, one big, one numeric and one special character
  local pwd="$1"
  local ok=0
  local msg=()

  if [ "${#pwd}" -lt 12 ]; then
    msg+=("at least 12 values")
  fi
  [[ "${pwd}" =~ [a-z] ]] || msg+=("at least one small letter")
  [[ "${pwd}" =~ [A-Z] ]] || msg+=("at least one large letter")
  [[ "${pwd}" =~ [0-9] ]] || msg+=("at least one number")
  [[ "${pwd}" =~ [^a-zA-Z0-9] ]] || msg+=("at least one special character")

  if [ "${#msg[@]}" -gt 0 ]; then
    echo "${YELLOW}Password need to contain: ${msg[*]}${RESET}"
    return 1
  fi
  return 0
}

# -----------------------------
# Encryption/decryption
# -----------------------------
enc_file() {
  # enc_file <pass> <in> <out>
  local pass="$1" in="$2" out="$3"
  "${OPENSSL_BIN}" enc -"${CIPHER}" -pbkdf2 -iter "${ITER}" -salt -in "${in}" -out "${out}" -pass pass:"${pass}"
}

dec_file_to_stdout() {
  # dec_file_to_stdout <pass> <in>
  local pass="$1" in="$2"
  "${OPENSSL_BIN}" enc -"${CIPHER}" -d -pbkdf2 -iter "${ITER}" -in "${in}" -pass pass:"${pass}"
}

# -----------------------------
# User guide
# -----------------------------
user_dir() { echo "${USERS_DIR}/$1"; }

user_exists() {
  local u="$1"
  [ -d "$(user_dir "${u}")" ]
}

create_user() {
  local username="$1"
  local dir; dir="$(user_dir "${username}")"

  if user_exists "${username}"; then
    echo "${YELLOW}User already exists. Come up with something else.${RESET}"
    return 1
  fi

  mkdir -p "${dir}"
  info "Creating user: ${username}"
  echo "${GREEN}Creating user «${username}».${RESET}"

  local pwd1 pwd2
  while true; do
    read_hidden "Create main password: " pwd1
    validate_password "${pwd1}" || { continue; }
    read_hidden "Repeat the main password: " pwd2
    if [ "${pwd1}" != "${pwd2}" ]; then
      echo "${YELLOW}It has to be the exact same password to make this work. You already knew this.${RESET}"
      continue
    fi
    break
  done

  # Create a key sample that verifies the password during decryption
  local probe_plain="${TMP_DIR}/probe.$$"
  local probe_enc="${dir}/keycheck.enc"
  head -c 32 /dev/urandom > "${probe_plain}"
  enc_file "${pwd1}" "${probe_plain}" "${probe_enc}"
  secure_rm "${probe_plain}"

  # Create an empty vault and encrypt it
  local vault_plain="${TMP_DIR}/vault.$$"
  local vault_enc="${dir}/vault.json.enc"
  printf "%s\n" "[]" > "${vault_plain}"  # JSON-list with values
  enc_file "${pwd1}" "${vault_plain}" "${vault_enc}"
  secure_rm "${vault_plain}"

  echo "${GREEN}User created.${RESET}"
  info "User created: ${username}"
}

auth_user() {
  local username="$1"
  local dir; dir="$(user_dir "${username}")"
  local keycheck="${dir}/keycheck.enc"

  if ! user_exists "${username}"; then
    echo "${YELLOW}The user does not exist.${RESET}"
    return 1
  fi

  local pwd
  read_hidden "Main password: " pwd

  # Verify and decrypt using keycheck.enc
  if ! dec_file_to_stdout "${pwd}" "${keycheck}" >/dev/null 2>&1; then
    echo "${RED}Wrong password sheep! -_('-')_-.${RESET}"
    info "Login failed for ${username}"
    return 2
  fi

  # If MFA is configured and oathtool is available
  local mfa_file="${dir}/mfa_secret.enc"
  if [ -f "${mfa_file}" ]; then
    if [ -n "${OATHTOOL_BIN}" ]; then
      # decrypt Secret to variable (no disk)
      local secret
      if ! secret="$(dec_file_to_stdout "${pwd}" "${mfa_file}")"; then
        echo "${RED}Could not decrypt MFA secret.${RESET}"
        error "MFA secret decryption failed for ${username}"
        return 3
      fi
      local code
      read_hidden "MFA code (TOTP 6 numbers): " code
      # verify code with oathtool
      local expected
      expected="$("${OATHTOOL_BIN}" -b --totp "${secret}" 2>/dev/null || true)"
      if [ -z "${expected}" ] || [ "${code}" != "${expected}" ]; then
        echo "${RED}Invalid MFA code.${RESET}"
        info "MFA error for ${username}"
        return 4
      fi
    else
      echo "${YELLOW}oathtool is not installed – could not verify MFA. Log in canceled.${RESET}"
      warn "MFA was incorrect, but oathtool is missing for ${username}"
      return 5
    fi
  fi

  info "Login OK for ${username}"
  # Export password in a sub shell-context for further operations
  BEARCAVE_USER="${username}" BEARCAVE_PASS="${pwd}" user_session
}

setup_mfa() {
  local username="$1"
  local dir; dir="$(user_dir "${username}")"
  local mfa_file="${dir}/mfa_secret.enc"

  if [ -z "${OATHTOOL_BIN}" ]; then
    echo "${YELLOW}oathtool is not installed. Install to be able to use TOTP‑MFA.${RESET}"
    return 1
  fi

  local pwd
  read_hidden "Main password for ${username}: " pwd
  if ! dec_file_to_stdout "${pwd}" "${dir}/keycheck.enc" >/dev/null 2>&1; then
    echo "${RED}Wrong password sheep! -_('-')_-.${RESET}"
    return 2
  fi

  # Generate a base32-secret (compatible with oathtool)
  local secret
if command -v base32 >/dev/null 2>&1; then
  secret="$("${OPENSSL_BIN}" rand 16 | base32 | tr -d '=\n')"
elif command -v gbase32 >/dev/null 2>&1; then
  secret="$("${OPENSSL_BIN}" rand 16 | gbase32 | tr -d '=\n')"
else
  # Fallback to base64 (not recommended, but oathtool -b is tolerant)
  secret="$("${OPENSSL_BIN}" rand -base64 20 | tr -d '=\n' | tr '+/' 'AB')"
fi
  # OBS: Too strict base32, use dedicated tool. oathtool is tolerant with -b.

  # Create otpauth URL that can be used with QR (optional)
  local issuer="BearCave"
  local label="${issuer}:${username}"
  local otpauth="otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&digits=6&period=30&algorithm=SHA1"

  # Encrypt the secret
  local tmp="${TMP_DIR}/mfa.$$"
  printf "%s" "${secret}" > "${tmp}"
  enc_file "${pwd}" "${tmp}" "${mfa_file}"
  secure_rm "${tmp}"

  echo "${GREEN}MFA activated for ${username}.${RESET}"
  echo "${CYAN}Add to you authenticator, along with the secret:${RESET} ${BOLD}${secret}${RESET}"
  echo "${CYAN}otpauth-URL (for QR-generator if desired):${RESET} ${otpauth}"
  info "MFA activated for ${username}"
}

disable_mfa() {
  local username="$1"
  local dir; dir="$(user_dir "${username}")"
  local mfa_file="${dir}/mfa_secret.enc"

  local pwd
  read_hidden "Main password for ${username}: " pwd
  if ! dec_file_to_stdout "${pwd}" "${dir}/keycheck.enc" >/dev/null 2>&1; then
    echo "${RED}Wrong password sheep! -_('-')_-.${RESET}"
    return 2
  fi

  if [ -f "${mfa_file}" ]; then
    secure_rm "${mfa_file}"
    echo "${GREEN}MFA deactivated.${RESET}"
    info "MFA deactivated for ${username}"
  else
    echo "${YELLOW}MFA was not activated.${RESET}"
  fi
}

# -----------------------------
# Vault operations
# -----------------------------
vault_decrypt_to() {
  # vault_decrypt_to <user> <pass> <dest_file>
  local user="$1" pass="$2" dest="$3"
  local dir; dir="$(user_dir "${user}")"
  local vault_enc="${dir}/vault.json.enc"
  if ! dec_file_to_stdout "${pass}" "${vault_enc}" > "${dest}"; then
    return 1
  fi
}

vault_encrypt_from() {
  # vault_encrypt_from <user> <pass> <source_file>
  local user="$1" pass="$2" src="$3"
  local dir; dir="$(user_dir "${user}")"
  local vault_enc="${dir}/vault.json.enc"
  enc_file "${pass}" "${src}" "${vault_enc}"
}

vault_add_entry() {
  local user="$1" pass="$2"
  local tmp="${TMP_DIR}/vault.$$"
  if ! vault_decrypt_to "${user}" "${pass}" "${tmp}"; then
    echo "${RED}The vault is too strong! The doors simply would not barge!.${RESET}"
    error "Vault decryption failed for ${user}"
    return 1
  fi


vault_edit_entry() {
  local user="$1" pass="$2"
  local tmp="${TMP_DIR}/vault.$$"
  if ! vault_decrypt_to "${user}" "${pass}" "${tmp}"; then
    echo "${RED}The vault is too strong! The doors simply would not barge!.${RESET}"
    return 1
  fi

  # Parse all entries into an array (skip empty lines)
  mapfile -t entries < <(
    sed -e 's/^\[\(.*\)\]$/\1/' -e 's/},{/}\
{/g' "${tmp}" | grep -v '^[[:space:]]*$'
  )

  if [ "${#entries[@]}" -eq 0 ]; then
    echo "${YELLOW}No entries to edit.${RESET}"
    secure_rm "${tmp}"
    return
  fi

  echo "${CYAN}Select honeycomb to edit:${RESET}"
  local i=1
  for line in "${entries[@]}"; do
    site=$(echo "$line" | grep -o '"site":"[^"]*"' | sed 's/"site":"//;s/"$//')
    printf " %2d) %s\n" "$i" "$site"
    ((i++))
  done

  read -r -p "Enter number to edit, or [enter] to cancel: " sel
  if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#entries[@]}" ]; then
    local idx=$((sel-1))
    IFS='|' read -r site uname upass <<< "$(echo "${entries[$idx]}" | \
      awk -F'"site":"|","username":"|","password":"|"' '{print $2 "|" $4 "|" $6}')"

    # Prompt for new values, default to current
    read -r -p "Site [${site}]: " new_site
    read -r -p "Username [${uname}]: " new_uname
    read_hidden "Password [hidden, leave blank to keep]: " new_upass

    # Use old values if blank
    [ -z "$new_site" ] && new_site="$site"
    [ -z "$new_uname" ] && new_uname="$uname"
    [ -z "$new_upass" ] && new_upass="$upass"

    # Escape quotes
    new_site=$(printf '%s' "${new_site}" | sed 's/"/\\"/g')
    new_uname=$(printf '%s' "${new_uname}" | sed 's/"/\\"/g')
    new_upass=$(printf '%s' "${new_upass}" | sed 's/"/\\"/g')

    # Update entry
    entries[$idx]="{\"site\":\"${new_site}\",\"username\":\"${new_uname}\",\"password\":\"${new_upass}\"}"

    # Write back to file
    printf '[%s]\n' "$(IFS=,; echo "${entries[*]}")" > "${tmp}.new"
    vault_encrypt_from "${user}" "${pass}" "${tmp}.new"
    secure_rm "${tmp}"; secure_rm "${tmp}.new"
    echo "${GREEN}Honeycomb updated.${RESET}"
    info "Honeycomb edited for ${user}"
  else
    echo "${YELLOW}Canceled.${RESET}"
    secure_rm "${tmp}"
    return
  fi
}

vault_delete_entry() {
  local user="$1" pass="$2"
  local tmp="${TMP_DIR}/vault.$$"
  if ! vault_decrypt_to "${user}" "${pass}" "${tmp}"; then
    echo "${RED}The vault is too strong! The doors simply would not barge!.${RESET}"
    return 1
  fi

  # Parse all entries into an array (skip empty lines)
  mapfile -t entries < <(
    sed -e 's/^\[\(.*\)\]$/\1/' -e 's/},{/}\
{/g' "${tmp}" | grep -v '^[[:space:]]*$'
  )

  if [ "${#entries[@]}" -eq 0 ]; then
    echo "${YELLOW}No entries to delete.${RESET}"
    secure_rm "${tmp}"
    return
  fi

  echo "${CYAN}Select honeycomb to delete:${RESET}"
  local i=1
  for line in "${entries[@]}"; do
    site=$(echo "$line" | grep -o '"site":"[^"]*"' | sed 's/"site":"//;s/"$//')
    printf " %2d) %s\n" "$i" "$site"
    ((i++))
  done

  read -r -p "Enter number to delete, or [enter] to cancel: " sel
  if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#entries[@]}" ]; then
    local idx=$((sel-1))
    read -r -p "Are you sure you want to delete this honeycomb? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
      unset 'entries[idx]'
      # Write back to file
      # Remove empty lines, join with commas, wrap in []
      printf '[%s]\n' "$(IFS=,; echo "${entries[*]}")" > "${tmp}.new"
      vault_encrypt_from "${user}" "${pass}" "${tmp}.new"
      secure_rm "${tmp}"; secure_rm "${tmp}.new"
      echo "${GREEN}Honeycomb deleted.${RESET}"
      info "Honeycomb deleted for ${user}"
    else
      echo "${YELLOW}Canceled.${RESET}"
      secure_rm "${tmp}"
      return
    fi
  else
    echo "${YELLOW}Canceled.${RESET}"
    secure_rm "${tmp}"
    return
  fi
}

  local site uname upass
  read -r -p "Service/Side: " site
  read -r -p "Username: " uname
  read_hidden "Password (for the service): " upass

    # Prevent empty entries
  if [ -z "$site" ] || [ -z "$uname" ] || [ -z "$upass" ]; then
    echo "${YELLOW}None of the fields can be empty. Entry not added.${RESET}"
    secure_rm "${tmp}"
    return 1
  fi

  # Do not log content
  info "Adding content for user ${user}"

  # Append to JSON-list
  # Minimal JSON-handling (for simplicity)
  # Structure: [{ "site":"...", "username":"...", "password":"..." }, ...]
  # We avoid special character conflicts by using simple escaping of duplicated names
  local site_esc uname_esc upass_esc
  site_esc=$(printf '%s' "${site}" | sed 's/"/\\"/g')
  uname_esc=$(printf '%s' "${uname}" | sed 's/"/\\"/g')
  upass_esc=$(printf '%s' "${upass}" | sed 's/"/\\"/g')

  # Inset before last notation
  if grep -q '^\s*\[\s*\]\s*$' "${tmp}"; then
    printf '[{"site":"%s","username":"%s","password":"%s"}]\n' "${site_esc}" "${uname_esc}" "${upass_esc}" > "${tmp}.new"
  else
    sed '$ s/]$//' "${tmp}" > "${tmp}.new"
    printf '%s\n' ',{"site":"'"${site_esc}"'","username":"'"${uname_esc}"'","password":"'"${upass_esc}"'"}]' >> "${tmp}.new"
  fi

  vault_encrypt_from "${user}" "${pass}" "${tmp}.new"
  secure_rm "${tmp}"; secure_rm "${tmp}.new"

  echo "${GREEN}Value added. Well done!${RESET}"
}

vault_list_sites() {
  local user="$1" pass="$2"
  local tmp="${TMP_DIR}/vault.$$"
  if ! vault_decrypt_to "${user}" "${pass}" "${tmp}"; then
    echo "${RED}The vault is too strong! The doors simply would not barge!.${RESET}"
    return 1
  fi
  echo "${CYAN}Honeycombs in the vault:${RESET}"
  # Get "site"-field values
  grep -o '"site":"[^"]*"' "${tmp}" | sed 's/"site":"//;s/"$//' | nl -w2 -s'. '
  secure_rm "${tmp}"
}

vault_show_entry() {
  local user="$1" pass="$2"
  local tmp="${TMP_DIR}/vault.$$"
  if ! vault_decrypt_to "${user}" "${pass}" "${tmp}"; then
    echo "${RED}The vault is too strong! The doors simply would not barge!.${RESET}"
    return 1
  fi
  
  read -r -p "Search for honeycombs name, or hit [enter] to list all: " q
  echo "${CYAN}Honeycomb(s):${RESET}"

  # Parse all entries into an array
  mapfile -t entries < <(sed -e 's/^\[\(.*\)\]$/\1/' -e 's/},{/}\
{/g' "${tmp}")

  local filtered=()
  local i=1
  for line in "${entries[@]}"; do
    site=$(echo "$line" | grep -o '"site":"[^"]*"' | sed 's/"site":"//;s/"$//')
    uname=$(echo "$line" | grep -o '"username":"[^"]*"' | sed 's/"username":"//;s/"$//')
    upass=$(echo "$line" | grep -o '"password":"[^"]*"' | sed 's/"password":"//;s/"$//')
    if [ -z "$q" ] || [[ "${site,,}" == "${q,,}" ]] || echo "$site" | grep -i -q "$q"; then
      printf " %2d) %s\n" "$i" "$site"
      filtered+=("$site|$uname|$upass")
      ((i++))
    fi
  done

  if [ "${#filtered[@]}" -eq 0 ]; then
    echo "${YELLOW}No entries found.${RESET}"
    secure_rm "${tmp}"
    return
  fi

  # If more than one entry, let user pick
  if [ "${#filtered[@]}" -gt 1 ]; then
    read -r -p "Enter number to show details, or [enter] to cancel: " sel
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#filtered[@]}" ]; then
      IFS='|' read -r site uname upass <<< "${filtered[$((sel-1))]}"
      echo "${CYAN}Details:${RESET}"
      echo "  Site:     $site"
      echo "  Username: $uname"
      echo "  Password: $upass"
    else
      echo "${YELLOW}Canceled.${RESET}"
    fi
  elif [ "${#filtered[@]}" -eq 1 ]; then
    IFS='|' read -r site uname upass <<< "${filtered[0]}"
    echo "${CYAN}Details:${RESET}"
    echo "  Site:     $site"
    echo "  Username: $uname"
    echo "  Password: $upass"
  fi

  secure_rm "${tmp}"
}

vault_change_master_password() {
  local user="$1"
  local dir; dir="$(user_dir "${user}")"
  local oldpwd
  read_hidden "Existing main password: " oldpwd
  if ! dec_file_to_stdout "${oldpwd}" "${dir}/keycheck.enc" >/dev/null 2>&1; then
    echo "${RED}Wrong password sheep! -_('-')_-.${RESET}"
    return 1
  fi

  local new1 new2
  while true; do
    read_hidden "New main password: " new1
    validate_password "${new1}" || continue
    read_hidden "Do it again. Repeat main password: " new2
    [ "${new1}" = "${new2}" ] || { echo "${YELLOW}It has to be the exact same password to make this work. You already knew this.${RESET}"; continue; }
    break
  done

  # Re-encrypt vault and mfa Secret (if it exists) with new password
  local vault_plain="${TMP_DIR}/vault.$$"
  if ! vault_decrypt_to "${user}" "${oldpwd}" "${vault_plain}"; then
    echo "${RED}Could not open the vault for re-encryption.${RESET}"
    return 2
  fi
  vault_encrypt_from "${user}" "${new1}" "${vault_plain}"
  secure_rm "${vault_plain}"

  # Re-encrypt keycheck
  local probe_plain="${TMP_DIR}/probe.$$"
  if ! dec_file_to_stdout "${oldpwd}" "${dir}/keycheck.enc" > "${probe_plain}"; then
    echo "${RED}Could not update the key sample.${RESET}"
    return 3
  fi
  enc_file "${new1}" "${probe_plain}" "${dir}/keycheck.enc"
  secure_rm "${probe_plain}"

  # Re-encrypt mfa secret if it exits
  local mfa_file="${dir}/mfa_secret.enc"
  if [ -f "${mfa_file}" ]; then
    local mfa_plain="${TMP_DIR}/mfa.$$"
    if dec_file_to_stdout "${oldpwd}" "${mfa_file}" > "${mfa_plain}"; then
      enc_file "${new1}" "${mfa_plain}" "${mfa_file}"
      secure_rm "${mfa_plain}"
    else
      warn "Could not decrypt MFA during password change for ${user}"
    fi
  fi

  echo "${GREEN}Main password updated.${RESET}"
  info "Password change completed for ${user}"
}

delete_user() {
  local user="$1"
  local dir; dir="$(user_dir "${user}")"
  if ! user_exists "${user}"; then
    echo "${YELLOW}The user does not exist.${RESET}"
    return 1
  fi
  read -r -p "Insert username («${user}») to confirm deletion: " c
  if [ "${c}" != "${user}" ]; then
    echo "${YELLOW}Nope. That's not it. Try again.${RESET}"
    return 2
  fi
  info "Deleting user ${user}"
  rm -rf -- "${dir}"
  echo "${GREEN}User exterminated.${RESET}"
}

# -----------------------------
# Session menu after completed login
# -----------------------------
user_session() {
  local user="${BEARCAVE_USER}"
  local pass="${BEARCAVE_PASS}"

  while true; do
    echo
    echo "${BOLD}${MAGENTA}User: ${user}${RESET}"
    echo "  1) Add honeycomb"
    echo "  2) List honeycomb(s)"
    echo "  3) Show honeycomb(s)"
    echo "  4) Edit honeycomb"
    echo "  5) Delete honeycomb"
    echo "  6) Change main password"
    echo "  7) Activate MFA"
    echo "  8) Deactivate MFA"
    echo "  9) Log out"
    read -r -p "Choose: " c
    case "$c" in
      1) vault_add_entry "${user}" "${pass}" ;;
      2) vault_list_sites "${user}" "${pass}" ;;
      3) vault_show_entry "${user}" "${pass}" ;;
      4) vault_edit_entry "${user}" "${pass}" ;;
      5) vault_delete_entry "${user}" "${pass}" ;;
      6) vault_change_master_password "${user}" ;;
      7) setup_mfa "${user}" ;;
      8) disable_mfa "${user}" ;;
      9) echo "${GREEN}Logged out.${RESET}"; break ;;
      *) echo "${YELLOW}Invalid choice.${RESET}" ;;
    esac
  done
}

# -----------------------------
# Main menu
# -----------------------------
main_menu() {
  while true; do
    banner
    echo "  1) Create new user"
    echo "  2) Log in"
    echo "  3) Activate MFA for existing user"
    echo "  4) Deactivate MFA for existing user"
    echo "  5) Delete user"
    echo "  6) Exit"
    read -r -p "Choose: " choice
    case "$choice" in
      1)
        read -r -p "Username: " username
        create_user "${username}"
        ;;
      2)
        read -r -p "Username: " username
        auth_user "${username}"
        ;;
      3)
        read -r -p "Username: " username
        setup_mfa "${username}"
        ;;
      4)
        read -r -p "Username: " username
        disable_mfa "${username}"
        ;;
      5)
        read -r -p "Username: " username
        delete_user "${username}"
        ;;
      6)
        echo "${GREEN}Thank you for enjoying the peaceful tranquility of bearcave.${RESET}"
        break
        ;;
      *)
        echo "${YELLOW}Invalid choice.${RESET}"
        ;;
    esac
  done
}

# -----------------------------
# Start-up
# -----------------------------
init_dirs
check_deps
info "bearcave opened."
main_menu
info "bearcave shut."
umask "${UMASK_PREV}"