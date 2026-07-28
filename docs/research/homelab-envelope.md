# Homelab deployment envelope for the spike

## Decision
Use **puglab** as the initial host, with a **dedicated Docker Compose stack** and **dedicated bridge network** on that host. Keep the spike’s writable state on **puglab NVMe-backed `/opt/docker/ai-agents-sandbox/`**, reuse the existing **Gotify on puglab**, and allow the spike only an **outbound Manager connection** plus normal package/API egress. Do **not** start on pugnas: it has more RAM, but its documented role and live stacks are storage, downloads, and media, so putting the spike there widens blast radius into the NAS/media plane.

## Documented facts

### Host roles and hardware
- `puglab` is the documented **primary app host**, Ubuntu 24.04.4, `10.100.100.5`, Intel Core 3 **N355**, **16 GB RAM**, with Docker stacks in `/opt/stacks/` and Docker app data in `/opt/docker/`. `/mnt/nas/` is mounted there for NAS access. `/project/reference/puglab-config-copy-28-07-2026/docs/01-hardware-inventory.md:10-24`; `/project/reference/puglab-config-copy-28-07-2026/docs/02-infrastructure.md:11-31`
- `pugnas` is the documented **NAS and media host**, TrueNAS SCALE 25.10.1, `10.100.100.15`, Intel **N150**, **32 GB RAM**, with Docker stacks in `/mnt/fast/stacks/` and Docker app data in `/mnt/fast/docker/`. It also owns the `tank`, `scratch`, and `backup` storage pools/disks. `/project/reference/puglab-config-copy-28-07-2026/docs/01-hardware-inventory.md:26-46`; `/project/reference/puglab-config-copy-28-07-2026/docs/02-infrastructure.md:33-45`
- All reverse proxying lives on **puglab**, and pugnas services are exposed through **nginx on puglab**. `/project/reference/puglab-config-copy-28-07-2026/docs/02-infrastructure.md:368-374`

### Existing puglab duties
- puglab already hosts ingress and platform services: **nginx**, **certbot**, **ddns-updater**, **smtp-relay**, **duplicati**, and **authelia**. `/project/reference/puglab-config-copy-28-07-2026/stacks/infrastructure/docker-compose.yml:4-18`; `/project/reference/puglab-config-copy-28-07-2026/stacks/infrastructure/docker-compose.yml:20-34`; `/project/reference/puglab-config-copy-28-07-2026/stacks/infrastructure/docker-compose.yml:55-97`; `/project/reference/puglab-config-copy-28-07-2026/stacks/infrastructure/docker-compose.yml:99-152`
- puglab also hosts Git/CI workloads: **Gitea**, **act_runner**, **Woodpecker server**, **Woodpecker agent**. `/project/reference/puglab-config-copy-28-07-2026/stacks/git/docker-compose.yml:4-27`; `/project/reference/puglab-config-copy-28-07-2026/stacks/git/docker-compose.yml:29-37`; `/project/reference/puglab-config-copy-28-07-2026/stacks/git/docker-compose.yml:40-67`; `/project/reference/puglab-config-copy-28-07-2026/stacks/git/docker-compose.yml:69-84`
- puglab runs multiple user-facing app stacks already: **Docmost**, **Microbin**, **Koffan**, **Dindim**. `/project/reference/puglab-config-copy-28-07-2026/stacks/utility/docker-compose.yml:4-29`; `/project/reference/puglab-config-copy-28-07-2026/stacks/utility/docker-compose.yml:37-71`; `/project/reference/puglab-config-copy-28-07-2026/stacks/utility/docker-compose.yml:73-93`; `/project/reference/puglab-config-copy-28-07-2026/stacks/utility/docker-compose.yml:95-111`
- puglab also runs media-serving workloads, including **Jellyfin** and **Plex**, both reading from `/mnt/nas/...`; Jellyfin and Plex both use `/dev/dri`, and Plex uses `network_mode: host`. `/project/reference/puglab-config-copy-28-07-2026/stacks/media/docker-compose.yml:4-24`; `/project/reference/puglab-config-copy-28-07-2026/stacks/media/docker-compose.yml:26-42`

### Existing pugnas duties
- pugnas runs monitoring helpers that explicitly expose Docker observability back to puglab: a **Dozzle agent** on `7007` and a **read-only docker-socket-proxy** on `10.100.100.15:2375`, with mutating operations disabled. `/project/reference/pugnas-config-copy-28-07-2026/stacks/monitoring/docker-compose.yml:5-16`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/monitoring/docker-compose.yml:18-43`
- pugnas runs download/VPN workloads: **gluetun**, **qBittorrent**, **qui**, **mousehole**, **gluetun-qbt-watchdog**. Those stacks use `/dev/net/tun`, host-exposed torrent/UI ports, `/mnt/fast/docker/...`, and `/mnt/scratch/downloads`. `/project/reference/pugnas-config-copy-28-07-2026/stacks/downloads/docker-compose.yml:7-35`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/downloads/docker-compose.yml:39-53`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/downloads/docker-compose.yml:83-106`
- pugnas runs Servarr workloads tied to NAS media and scratch paths: **Prowlarr**, **Sonarr**, **Radarr**, **Bazarr**, **Lidarr**, with mounts into `/mnt/tank/...` and `/mnt/scratch/...`. `/project/reference/pugnas-config-copy-28-07-2026/stacks/servarr/docker-compose.yml:10-25`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/servarr/docker-compose.yml:29-49`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/servarr/docker-compose.yml:76-96`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/servarr/docker-compose.yml:126-145`; `/project/reference/pugnas-config-copy-28-07-2026/stacks/servarr/docker-compose.yml:176-195`
- pugnas utility tooling is also coupled to the download stack and qBittorrent backup data. `/project/reference/pugnas-config-copy-28-07-2026/stacks/utility/docker-compose.yml:4-30`

### Monitoring and Gotify
- The monitoring docs say Gotify is the **primary push-alert destination**, runs on **puglab**, and stores data at `/opt/docker/gotify/data`. `/project/reference/puglab-config-copy-28-07-2026/docs/04-monitoring.md:50-56`; `/project/reference/puglab-config-copy-28-07-2026/docs/services/gotify.md:11-27`
- The monitoring stack confirms **Gotify** on puglab at port `8070`, and WUD already sends notifications to `http://gotify:80`. `/project/reference/puglab-config-copy-28-07-2026/stacks/monitoring/docker-compose.yml:51-62`; `/project/reference/puglab-config-copy-28-07-2026/stacks/monitoring/docker-compose.yml:66-90`

### Herdr runtime requirements
- Herdr is documented as **“one rust binary, no electron”** and is intended to run **where the work lives**, locally or over SSH. <https://github.com/ogulcancelik/herdr/blob/master/README.md>; <https://herdr.dev/docs/how-to-work/>
- Herdr’s control plane is a **local Unix socket / named pipe**, not a remote manager listener. <https://herdr.dev/docs/socket-api/>

## Assumptions that still need measurement or confirmation
- The spike needs a **remote outbound Manager connection** over HTTPS/WSS. That is not documented in the mounted homelab configs and must be confirmed from the spike’s own runtime requirements.
- The spike does **not** need direct access to `/var/run/docker.sock`, `/dev/dri`, `/mnt/nas`, `/mnt/tank`, or `/mnt/scratch`. If it does, the isolation recommendation changes.
- The spike’s steady-state resource profile is assumed to be **small enough for puglab** if capped. No live utilization measurements were provided for either host.
- Whether the spike needs public ingress, LAN-only access, or SSH-only access is not documented in the mounted configs.

## Recommended deployment envelope

### 1) Safe initial host
**Choose `puglab` first.**

Why:
- It is already the documented **primary app host**.
- It already owns **reverse proxy**, **auth**, **notifications**, and **Git/CI**.
- It keeps the spike away from pugnas’s **NAS/media/download** data plane.
- It avoids mixing an experimental workload with the host that owns `tank`, `scratch`, VPN torrenting, and read-only Docker observability endpoints.

Trade-off:
- puglab has only **16 GB RAM** and is already running app/media stacks, so the spike must start with a strict budget.

### 2) Container runtime
Use **Docker Engine + Docker Compose** on puglab.

Why:
- Both hosts are already managed as Docker Compose stacks.
- Existing ops/monitoring assume Docker (`docker.sock`, Dozzle, WUD, Woodpecker, act_runner).
- Herdr itself does not force a containerized deployment; if included, it can run inside the same stack or on-host without introducing a second runtime.

Do not introduce Podman/Kubernetes/TrueNAS Apps for the first spike.

### 3) Network path
- Put the spike on its own bridge network, e.g. `ai-agents-sandbox_internal`.
- **Do not** use `network_mode: host`.
- **Do not** join the existing `database_network` or other shared networks unless the spike proves it needs a specific upstream.
- If a UI/API is needed, publish a single LAN port on puglab and front it with the existing **nginx on puglab**.
- If no browser UI is needed, keep it **LAN-only or SSH-only** and skip public ingress.

Safe default path:
1. client -> nginx on puglab (only if needed)
2. nginx -> spike container on dedicated bridge network
3. spike -> outbound HTTPS/WSS to Manager
4. spike -> outbound HTTPS to `gotify.puglab.im` or LAN `10.100.100.5:8070`

### 4) Storage layout
Use puglab NVMe-backed app paths only:
- stack definition: `/opt/stacks/ai-agents-sandbox/`
- persistent app state: `/opt/docker/ai-agents-sandbox/state/`
- logs: `/opt/docker/ai-agents-sandbox/logs/`
- working/cache dir: `/opt/docker/ai-agents-sandbox/work/`

Avoid for initial deployment:
- writable mounts into `/mnt/nas/`
- writable mounts into pugnas paths (`/mnt/fast`, `/mnt/tank`, `/mnt/scratch`)
- reusing Gitea/Woodpecker/monitoring volumes

Reason: puglab’s own infrastructure stack already backs up `/opt/docker` and `/opt/stacks`, but it treats pugnas data as separate mounted sources. Keeping the spike in its own `/opt/...` subtree preserves that boundary. `/project/reference/puglab-config-copy-28-07-2026/stacks/infrastructure/docker-compose.yml:99-117`

### 5) Outbound Manager connection
- Treat the Manager link as **egress-only** from the spike container.
- Allow only the documented Manager endpoint(s), ideally **TCP 443**.
- No inbound Manager callback path should be assumed unless the spike docs explicitly require it.
- If Herdr is part of the spike, keep Herdr’s own control plane local; it does not need a remote listener.

### 6) Gotify placement
Reuse the existing **Gotify on puglab**.

Reason:
- It already exists, is documented as the primary push-alert path, and is already used by monitoring/WUD.
- A second Gotify on pugnas adds needless split-brain and couples alerts to the NAS/media host.

Default integration target:
- externally: `https://gotify.puglab.im`
- fallback inside LAN: `http://10.100.100.5:8070`

I would not couple the new stack directly into the monitoring compose project just to reach `http://gotify:80` unless there is a real need for same-network service discovery.

### 7) Initial resource budget
Start with a **hard cap sized for puglab, not pugnas**:
- **CPU**: `2 vCPU` equivalent
- **Memory reservation**: `2 GiB`
- **Memory limit**: `4 GiB`
- **PIDs**: `256`
- **Persistent disk**: `20 GiB` under `/opt/docker/ai-agents-sandbox/state`
- **Scratch/log headroom**: `10 GiB`
- **GPU**: none
- **Replica count**: `1`

Why this size:
- It leaves most of puglab’s 16 GB RAM to existing ingress, CI, utility, monitoring, and media services.
- It is enough for a small spike but small enough that a runaway process should fail fast instead of starving the primary app host.

### 8) What to measure before calling it stable
Required measurements on **puglab** before or immediately after deployment:
1. **Idle headroom**: current RAM free/available, swap, and CPU load before starting the spike.
2. **Peak contention**: puglab RAM/CPU while Plex/Jellyfin are active, because both use `/dev/dri` and media paths.
3. **NVMe free space**: free bytes under `/opt` before allocating state/log dirs.
4. **Spike profile**: steady-state RSS, CPU, open files, restart count, and disk growth over at least 24h.
5. **Network**: Manager reconnect behavior, outbound bandwidth, and whether nginx ingress is needed at all.
6. **Alerts**: successful Gotify delivery for startup failure, crash loop, and Manager disconnect.

If puglab fails those measurements, the fallback host is **pugnas**, but only with the same isolation rules and a dedicated `/mnt/fast/docker/ai-agents-sandbox/` subtree, not with mounts into `tank` or `scratch`.

## Decision implications
- **Choosing puglab** favors host-role isolation and simpler ingress/alerts, but forces a conservative RAM budget.
- **Choosing pugnas** would buy RAM, but it would mix an experimental workload into the NAS/media/download plane and increase risk around storage, VPN/download automation, and shared Docker observability.
- The recommendation therefore optimizes for **blast-radius containment**, not maximum raw capacity.

## Unresolved prerequisites
1. Confirm the spike’s exact **Manager protocol, destination, and ports**.
2. Confirm whether the spike needs **public ingress**, **LAN-only ingress**, or **SSH-only** access.
3. Confirm whether the spike needs **Docker socket**, **GPU**, or **shared storage** access.
4. Measure **current puglab utilization** under normal and media-active periods.
5. Confirm whether the spike’s state under `/opt/docker/ai-agents-sandbox/` should be included in existing backup jobs or excluded as disposable.
