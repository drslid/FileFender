#!/usr/bin/env bash
# FileFender installer for a Debian or Ubuntu server.
#
#   curl -fsSL https://raw.githubusercontent.com/drslid/FileFender/main/install.sh | sudo bash
#
# Unattended installs read these variables (all optional except the mode-specific ones):
#   FILEFENDER_MODE=domain|duckdns|proxy   FILEFENDER_DOMAIN   FILEFENDER_ACME_EMAIL
#   FILEFENDER_DUCKDNS_TOKEN   FILEFENDER_ABUSECH_AUTH_KEY   FILEFENDER_AUTO_UPDATE=yes|no
#   FILEFENDER_TAG=stable   FILEFENDER_DIR=/opt/filefender   FILEFENDER_YES=1 (never prompt)
set -euo pipefail

main() {
  INSTALL_DIR="${FILEFENDER_DIR:-/opt/filefender}"
  IMAGE="${FILEFENDER_IMAGE:-ghcr.io/drslid/filefender}"
  preflight
  load_previous
  configure
  install_docker
  check_ports
  write_files
  start
  install_updates
  summary
}

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

interactive() { [[ -z "${FILEFENDER_YES:-}" ]] && { : </dev/tty; } 2>/dev/null; }

# ask VAR "Question" [default]: keeps a value already set in the environment.
ask() {
  local var="$1" question="$2" default="${3:-}" answer=""
  [[ -n "${!var:-}" ]] && return 0
  if interactive; then
    read -r -p "$question${default:+ [$default]}: " answer </dev/tty || true
  fi
  printf -v "$var" '%s' "${answer:-$default}"
}

ask_secret() {
  local var="$1" question="$2" answer=""
  [[ -n "${!var:-}" ]] && return 0
  if interactive; then
    read -r -s -p "$question: " answer </dev/tty || true
    echo >/dev/tty
  fi
  printf -v "$var" '%s' "$answer"
}

confirm() {
  local question="$1" default="$2" answer=""
  if interactive; then
    read -r -p "$question [$([[ $default == y ]] && echo Y/n || echo y/N)]: " answer </dev/tty || true
  fi
  answer="${answer:-$default}"
  [[ "${answer,,}" == y* ]]
}

preflight() {
  [[ $EUID -eq 0 ]] || die "run the installer as root, for example: curl -fsSL <url> | sudo bash"
  [[ -r /etc/os-release ]] || die "cannot identify the operating system"
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_CODENAME="${VERSION_CODENAME:-}"
  [[ "$OS_ID" == debian || "$OS_ID" == ubuntu ]] || die "FileFender installs on Debian or Ubuntu (found ${PRETTY_NAME:-unknown})"
  case "$(uname -m)" in
    x86_64 | aarch64) ;;
    *) die "unsupported CPU architecture $(uname -m) (amd64 or arm64 required)" ;;
  esac
  command -v systemctl >/dev/null || die "systemd is required"

  local mem_mb disk_mb
  mem_mb="$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)"
  ((mem_mb >= 1800)) || die "FileFender needs at least 2 GB of RAM: ClamAV keeps its signatures in memory"
  LOW_MEMORY=false
  if ((mem_mb < 3500)); then
    LOW_MEMORY=true
    warn "${mem_mb} MB of RAM: enabling low-memory mode (scans pause for a few seconds during signature reloads)"
  fi
  disk_mb="$(df -Pm /var/lib | awk 'NR == 2 {print $4}')"
  ((disk_mb >= 4000)) || die "at least 4 GB of free disk space is needed in /var/lib (${disk_mb} MB free)"
}

load_previous() {
  [[ -f "$INSTALL_DIR/.env" ]] || return 0
  info "Existing installation found in $INSTALL_DIR: keeping its settings"
  local line key value
  while IFS= read -r line; do
    [[ "$line" =~ ^(FILEFENDER_[A-Z_]+)=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    [[ -z "${!key:-}" ]] && printf -v "$key" '%s' "$value"
  done <"$INSTALL_DIR/.env"
  if [[ -z "${FILEFENDER_MODE:-}" ]]; then
    if [[ -n "${FILEFENDER_DUCKDNS_TOKEN:-}" ]]; then
      FILEFENDER_MODE=duckdns
    elif [[ -n "${FILEFENDER_DOMAIN:-}" ]]; then
      FILEFENDER_MODE=domain
    else
      FILEFENDER_MODE=proxy
    fi
  fi
}

public_ip() {
  curl -4 -fsS --max-time 10 https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]' || true
}

configure() {
  if [[ -z "${FILEFENDER_MODE:-}" ]]; then
    if interactive; then
      cat >/dev/tty <<'EOF'

How will clients reach FileFender?
  1) With my own domain name, HTTPS by Let's Encrypt (recommended)
  2) With a free DuckDNS name, if you have no domain
  3) Behind my existing reverse proxy (HTTP on 127.0.0.1:8080)
EOF
      local choice=""
      read -r -p "Choice [1]: " choice </dev/tty || true
      case "${choice:-1}" in
        1) FILEFENDER_MODE=domain ;;
        2) FILEFENDER_MODE=duckdns ;;
        3) FILEFENDER_MODE=proxy ;;
        *) die "unknown choice: $choice" ;;
      esac
    elif [[ -n "${FILEFENDER_DUCKDNS_TOKEN:-}" ]]; then
      FILEFENDER_MODE=duckdns
    elif [[ -n "${FILEFENDER_DOMAIN:-}" ]]; then
      FILEFENDER_MODE=domain
    else
      die "set FILEFENDER_MODE to domain, duckdns or proxy"
    fi
  fi

  case "$FILEFENDER_MODE" in
    domain)
      ask FILEFENDER_DOMAIN "Domain name pointing to this server (for example scan.example.com)"
      [[ "$FILEFENDER_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$ ]] ||
        die "invalid domain name: ${FILEFENDER_DOMAIN:-<empty>}"
      ask FILEFENDER_ACME_EMAIL "E-mail for Let's Encrypt expiry notices (optional)"
      check_dns
      ;;
    duckdns)
      local sub="${FILEFENDER_DOMAIN:-}"
      sub="${sub%.duckdns.org}"
      [[ -n "$sub" ]] || ask sub "DuckDNS subdomain (the part before .duckdns.org)"
      sub="${sub%.duckdns.org}"
      [[ "$sub" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "invalid DuckDNS subdomain: ${sub:-<empty>}"
      FILEFENDER_DOMAIN="$sub.duckdns.org"
      ask_secret FILEFENDER_DUCKDNS_TOKEN "DuckDNS token (shown on duckdns.org once signed in)"
      [[ "$FILEFENDER_DUCKDNS_TOKEN" =~ ^[A-Za-z0-9-]{20,64}$ ]] || die "the DuckDNS token looks invalid"
      ask FILEFENDER_ACME_EMAIL "E-mail for Let's Encrypt expiry notices (optional)"
      ;;
    proxy)
      FILEFENDER_DOMAIN=""
      ;;
    *) die "FILEFENDER_MODE must be domain, duckdns or proxy" ;;
  esac

  if [[ -n "${FILEFENDER_ACME_EMAIL:-}" && ! "$FILEFENDER_ACME_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
    die "invalid e-mail address: $FILEFENDER_ACME_EMAIL"
  fi

  if [[ -n "${FILEFENDER_ABUSECH_AUTH_KEY:-}" && ! "$FILEFENDER_ABUSECH_AUTH_KEY" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
    die "the abuse.ch Auth-Key looks invalid"
  fi
  FILEFENDER_TAG="${FILEFENDER_TAG:-stable}"
  [[ "$FILEFENDER_TAG" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid image tag: $FILEFENDER_TAG"
  FILEFENDER_AUTO_UPDATE="${FILEFENDER_AUTO_UPDATE:-yes}"
}

check_dns() {
  local ip resolved
  ip="$(public_ip)"
  resolved="$(getent ahostsv4 "$FILEFENDER_DOMAIN" 2>/dev/null | awk '{print $1; exit}')"
  if [[ -z "$resolved" ]]; then
    warn "$FILEFENDER_DOMAIN does not resolve yet: create an A record pointing to ${ip:-this server}"
    confirm "Continue anyway?" n || die "fix the DNS record, then run the installer again"
  elif [[ -n "$ip" && "$resolved" != "$ip" ]]; then
    warn "$FILEFENDER_DOMAIN points to $resolved, but this server is $ip"
    confirm "Continue anyway?" n || die "fix the DNS record, then run the installer again"
  fi
}

install_docker() {
  if command -v docker >/dev/null; then
    docker compose version >/dev/null 2>&1 ||
      die "Docker is installed without the Compose plugin: install docker-compose-plugin (or docker-compose-v2), then run the installer again"
    return 0
  fi
  info "Installing Docker Engine from download.docker.com"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$OS_ID $OS_CODENAME stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
  systemctl enable --now docker >/dev/null
}

check_ports() {
  local ports=(80 443)
  [[ "$FILEFENDER_MODE" == proxy ]] && ports=(8080)
  local port owner ours
  ours="$(docker ps --quiet --filter 'name=^filefender$')"
  for port in "${ports[@]}"; do
    owner="$(ss -Hltnp "sport = :$port" 2>/dev/null | awk 'NR == 1')"
    if [[ -n "$owner" ]] && ! [[ -n "$ours" && "$owner" == *docker-proxy* ]]; then
      die "port $port is already in use: $owner"
    fi
  done
  if [[ "$FILEFENDER_MODE" != proxy ]] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    if confirm "The ufw firewall is active. Allow ports 80 and 443?" y; then
      ufw allow 80/tcp >/dev/null
      ufw allow 443/tcp >/dev/null
    fi
  fi
}

write_files() {
  info "Writing $INSTALL_DIR"
  install -d -m 0750 "$INSTALL_DIR"
  local ports
  if [[ "$FILEFENDER_MODE" == proxy ]]; then
    ports='      - "127.0.0.1:8080:8080"'
  else
    ports=$'      - "80:80"\n      - "443:443"'
  fi

  local managed='^(FILEFENDER_TAG|FILEFENDER_DOMAIN|FILEFENDER_ACME_EMAIL|FILEFENDER_DUCKDNS_TOKEN|FILEFENDER_ABUSECH_AUTH_KEY|FILEFENDER_TRUST_PROXY_HEADERS|FILEFENDER_LOW_MEMORY)='
  umask 077
  {
    echo "# FileFender settings, see https://github.com/drslid/FileFender#settings"
    echo "FILEFENDER_TAG=$FILEFENDER_TAG"
    [[ -n "$FILEFENDER_DOMAIN" ]] && echo "FILEFENDER_DOMAIN=$FILEFENDER_DOMAIN"
    [[ -n "${FILEFENDER_ACME_EMAIL:-}" ]] && echo "FILEFENDER_ACME_EMAIL=$FILEFENDER_ACME_EMAIL"
    [[ -n "${FILEFENDER_DUCKDNS_TOKEN:-}" && "$FILEFENDER_MODE" == duckdns ]] && echo "FILEFENDER_DUCKDNS_TOKEN=$FILEFENDER_DUCKDNS_TOKEN"
    [[ -n "${FILEFENDER_ABUSECH_AUTH_KEY:-}" ]] && echo "FILEFENDER_ABUSECH_AUTH_KEY=$FILEFENDER_ABUSECH_AUTH_KEY"
    [[ "$FILEFENDER_MODE" == proxy ]] && echo "FILEFENDER_TRUST_PROXY_HEADERS=true"
    [[ "$LOW_MEMORY" == true ]] && echo "FILEFENDER_LOW_MEMORY=true"
    # Settings added by hand survive a re-run.
    if [[ -f "$INSTALL_DIR/.env" ]]; then
      grep -E '^FILEFENDER_[A-Z_]+=' "$INSTALL_DIR/.env" | grep -Ev "$managed" || true
    fi
  } >"$INSTALL_DIR/.env.new"
  mv "$INSTALL_DIR/.env.new" "$INSTALL_DIR/.env"
  umask 022

  cat >"$INSTALL_DIR/compose.yaml" <<EOF
# Generated by the FileFender installer. Settings live in .env.
services:
  filefender:
    image: $IMAGE:\${FILEFENDER_TAG:-stable}
    container_name: filefender
    restart: unless-stopped
    env_file: .env
    ports:
$ports
    volumes:
      - filefender-data:/data
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  filefender-data:
EOF

  cat >"$INSTALL_DIR/update.sh" <<'EOF'
#!/usr/bin/env bash
# Pulls the newest FileFender image; rolls back if the new container does not become healthy.
set -euo pipefail
cd "$(dirname "$0")"
image="$(docker compose config --images | awk 'NR == 1')"
current="$(docker inspect --format '{{.Image}}' filefender 2>/dev/null || true)"
docker compose pull --quiet
latest="$(docker image inspect --format '{{.Id}}' "$image")"
if [[ "$current" == "$latest" ]]; then
  echo "FileFender is up to date ($image)"
  exit 0
fi
if [[ -f .failed-image && "$(cat .failed-image)" == "$latest" ]]; then
  echo "skipping $latest: it already failed its health check"
  exit 0
fi
[[ -n "$current" ]] && docker tag "$current" filefender:rollback
docker compose up -d --remove-orphans
for _ in $(seq 1 60); do
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' filefender)"
  if [[ "$health" == healthy ]]; then
    echo "FileFender updated to $latest"
    rm -f .failed-image
    docker rmi filefender:rollback >/dev/null 2>&1 || true
    docker image prune -f --filter "label=org.opencontainers.image.source=https://github.com/drslid/FileFender" >/dev/null
    exit 0
  fi
  [[ "$health" == unhealthy ]] && break
  sleep 10
done
echo "the new image did not become healthy: rolling back" >&2
echo "$latest" >.failed-image
if [[ -n "$current" ]]; then
  docker tag filefender:rollback "$image"
  docker compose up -d --force-recreate
fi
exit 1
EOF
  chmod 0755 "$INSTALL_DIR/update.sh"
}

start() {
  info "Pulling $IMAGE:$FILEFENDER_TAG"
  if ! (cd "$INSTALL_DIR" && docker compose pull --quiet); then
    die "cannot pull $IMAGE:$FILEFENDER_TAG (while the repository is private, run: docker login ghcr.io)"
  fi
  info "Starting FileFender"
  (cd "$INSTALL_DIR" && docker compose up -d --remove-orphans)
  info "Waiting for the engines (the first start can take a few minutes)"
  local i
  for i in $(seq 1 120); do
    if docker exec filefender filefender healthcheck --ready >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' filefender 2>/dev/null)" != true ]]; then
      docker logs --tail 30 filefender >&2 || true
      die "the container stopped; see the logs above"
    fi
    ((i % 6 == 0)) && echo "   still starting… ($((i * 5)) s)"
    sleep 5
  done
  docker logs --tail 30 filefender >&2 || true
  die "FileFender did not become ready within 10 minutes; see: docker logs filefender"
}

install_updates() {
  if [[ "${FILEFENDER_AUTO_UPDATE,,}" != yes ]]; then
    systemctl disable --now filefender-update.timer >/dev/null 2>&1 || true
    return 0
  fi
  cat >/etc/systemd/system/filefender-update.service <<EOF
[Unit]
Description=Update FileFender to the newest image
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/update.sh
EOF
  cat >/etc/systemd/system/filefender-update.timer <<'EOF'
[Unit]
Description=Daily FileFender image update

[Timer]
OnCalendar=daily
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now filefender-update.timer >/dev/null
}

summary() {
  local url="http://127.0.0.1:8080"
  [[ "$FILEFENDER_MODE" != proxy ]] && url="https://$FILEFENDER_DOMAIN"
  if [[ "$FILEFENDER_MODE" != proxy ]]; then
    local i
    for i in $(seq 1 24); do
      curl -fsS --max-time 5 "$url/healthz" >/dev/null 2>&1 && break
      ((i == 1)) && info "Waiting for the Let's Encrypt certificate"
      sleep 5
    done
    curl -fsS --max-time 5 "$url/healthz" >/dev/null 2>&1 ||
      warn "$url is not reachable over HTTPS yet: check the DNS record and that ports 80/443 are open, then: docker logs filefender"
  fi
  local admin
  admin="$(docker exec filefender filefender admin status 2>/dev/null || true)"
  echo
  echo "FileFender is running."
  echo "  Dashboard:  $url/"
  [[ "$FILEFENDER_MODE" == proxy ]] && echo "              (point your reverse proxy to 127.0.0.1:8080)"
  if [[ "$admin" == Accounts:* ]]; then
    echo "  Accounts:   $(sed -n '1s/^Accounts: //p' <<<"$admin") (Account tab)"
  else
    echo "  Next step:  open the dashboard now and create the administrator account."
    echo "              For safety the page closes 30 minutes after start; docker restart filefender reopens it."
  fi
  echo "  API keys:   create one per application in the dashboard, API tab"
  echo "  Settings:   signature feeds, YARA, MalwareBazaar, file policy and alerts in the Settings tab"
  if [[ "${FILEFENDER_AUTO_UPDATE,,}" == yes ]]; then
    echo "  Updates:    signatures and YARA rules as set in the dashboard, image daily with rollback (filefender-update.timer)"
  fi
  echo "  Files:      $INSTALL_DIR"
}

main "$@"
