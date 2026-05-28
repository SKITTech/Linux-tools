import type { Lesson } from "./types";

export const LESSONS: Lesson[] = [
  // ===== BEGINNER =====
  {
    id: "b1", level: "beginner", title: "Images & Containers Basics",
    summary: "Understand the difference between an image (template) and a container (running instance).",
    body: `An **image** is a read-only template built from layered filesystems. A **container** is a runnable instance of an image with its own writable layer.

- Pull an image from a registry, run it as a container, then inspect/stop/remove it.
- Containers are ephemeral by default — any data inside disappears when removed unless you mount a volume.`,
    tryIt: [
      "docker pull nginx:alpine",
      "docker run -d --name web -p 8080:80 nginx:alpine",
      "docker ps",
      "docker logs web",
      "docker stop web && docker rm web",
    ],
    mistakes: [
      "Treating containers as persistent VMs — they aren't.",
      "Forgetting -d, so the terminal blocks on the foreground process.",
      "Using :latest in production (non-reproducible).",
    ],
    checkpoints: [
      { q: "Which command lists running containers?", choices: ["docker images", "docker ps", "docker ls", "docker run"], answer: 1, explain: "`docker ps` lists running containers; add `-a` for stopped ones." },
      { q: "What does -d do in `docker run -d`?", choices: ["Debug mode", "Detached/background", "Delete after exit", "Dry run"], answer: 1, explain: "`-d` detaches the container so it runs in the background." },
      { q: "Where does container writable data live by default?", choices: ["On the host", "In the image", "In the container's writable layer", "In a named volume"], answer: 2, explain: "Without a volume, writes go to the container's writable layer and are lost on removal." },
    ],
  },
  {
    id: "b2", level: "beginner", title: "Dockerfile Fundamentals",
    summary: "Write a minimal, correct Dockerfile.",
    body: `A Dockerfile is a script of layered instructions. Order matters for caching: put rarely-changing steps first.

\`\`\`dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
\`\`\``,
    tryIt: [
      "docker build -t myapp:1.0 .",
      "docker run --rm -p 3000:3000 myapp:1.0",
      "docker image ls myapp",
    ],
    mistakes: [
      "COPY . . before installing deps — breaks layer cache on every code change.",
      "Using `npm install` instead of `npm ci` in CI builds.",
      "Running as root (no USER directive).",
    ],
    checkpoints: [
      { q: "Why copy package.json before the rest of the source?", choices: ["Required by npm", "To preserve the install layer in cache", "Smaller image", "Faster pull"], answer: 1, explain: "Putting unchanging files first lets Docker reuse cached layers." },
      { q: "Which instruction sets the default process?", choices: ["RUN", "ENTRYPOINT/CMD", "EXPOSE", "ENV"], answer: 1, explain: "CMD (or ENTRYPOINT) defines what runs when the container starts." },
      { q: "EXPOSE publishes the port to the host?", choices: ["True", "False"], answer: 1, explain: "EXPOSE is documentation only. Use `-p` on `docker run` to publish." },
    ],
  },
  {
    id: "b3", level: "beginner", title: "Volumes",
    summary: "Persist data outside container lifecycle.",
    body: `Two main flavours:
- **Named volume** (Docker-managed): \`-v mydata:/var/lib/mysql\`
- **Bind mount** (host path): \`-v $(pwd)/data:/app/data\`

Named volumes are portable and survive container removal.`,
    tryIt: [
      "docker volume create mydata",
      "docker run -d --name db -v mydata:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=secret mysql:8",
      "docker volume ls",
      "docker volume inspect mydata",
    ],
    mistakes: [
      "Confusing -v with --mount (both work; --mount is more explicit).",
      "Bind-mounting over node_modules and breaking installs.",
      "Running `docker volume prune` without checking what's in use.",
    ],
    checkpoints: [
      { q: "Named volumes are managed by:", choices: ["The OS kernel", "Docker", "Your app", "systemd"], answer: 1, explain: "Docker creates and tracks named volumes under its data root." },
      { q: "Which survives `docker rm <container>` by default?", choices: ["Container writable layer", "Anonymous tmp", "Named volume", "stdout"], answer: 2, explain: "Named volumes outlive the container unless explicitly removed." },
      { q: "Bind mounts use a host path?", choices: ["Yes", "No"], answer: 0, explain: "Bind mounts attach an absolute host path into the container." },
    ],
  },
  {
    id: "b4", level: "beginner", title: "Networking Basics",
    summary: "Bridge networks, port publishing, and container DNS.",
    body: `Containers on the same user-defined bridge can resolve each other by **name**. The default \`bridge\` network does NOT provide name-based DNS — always create your own.`,
    tryIt: [
      "docker network create appnet",
      "docker run -d --name api --network appnet myapi:1.0",
      "docker run -d --name web --network appnet -p 8080:80 mynginx:1.0",
      "docker network inspect appnet",
    ],
    mistakes: [
      "Relying on container IPs — they change.",
      "Publishing every port instead of using an internal network.",
      "Forgetting that `-p 80:80` binds 0.0.0.0 by default (publicly exposed).",
    ],
    checkpoints: [
      { q: "Which network gives automatic DNS between containers?", choices: ["host", "default bridge", "user-defined bridge", "none"], answer: 2, explain: "User-defined bridge networks provide built-in DNS by container name." },
      { q: "`-p 8080:80` means…", choices: ["host:container", "container:host", "TCP:UDP", "ipv4:ipv6"], answer: 0, explain: "Left side is the host port, right is the container port." },
      { q: "How to restrict a published port to localhost?", choices: ["-p 80:80", "-p 127.0.0.1:80:80", "-p local:80", "--network none"], answer: 1, explain: "Prefix the host IP, e.g. `127.0.0.1:80:80`." },
    ],
  },
  {
    id: "b5", level: "beginner", title: "Docker Compose Basics",
    summary: "Declare multi-container apps in YAML.",
    body: `\`docker compose up\` reads a \`compose.yaml\` and starts all services on a shared network.

\`\`\`yaml
services:
  web:
    image: nginx:alpine
    ports: ["8080:80"]
    depends_on: [api]
  api:
    build: ./api
    environment:
      DB_URL: postgres://db/app
  db:
    image: postgres:16
    volumes: [pgdata:/var/lib/postgresql/data]
volumes:
  pgdata:
\`\`\``,
    tryIt: [
      "docker compose up -d",
      "docker compose ps",
      "docker compose logs -f api",
      "docker compose down",
    ],
    mistakes: [
      "Using `docker-compose` (v1) instead of `docker compose` (v2).",
      "Hardcoding host ports for every service.",
      "Running `down -v` and losing the DB volume.",
    ],
    checkpoints: [
      { q: "Where is the canonical compose file usually named?", choices: ["docker.yaml", "compose.yaml", "stack.yml", "dockerfile.yml"], answer: 1, explain: "Compose v2 looks for `compose.yaml` (or `docker-compose.yml` for back-compat)." },
      { q: "What does `depends_on` guarantee?", choices: ["Service is healthy", "Service is started", "Network is ready", "DB has migrated"], answer: 1, explain: "By default it only waits for the container to start, not for readiness. Use healthchecks." },
      { q: "Which command removes the stack AND named volumes?", choices: ["docker compose down", "docker compose stop", "docker compose down -v", "docker compose rm"], answer: 2, explain: "⚠️ `-v` also deletes named volumes — destructive." },
    ],
  },

  // ===== INTERMEDIATE =====
  {
    id: "i1", level: "intermediate", title: "Multi-Stage Builds",
    summary: "Shrink images by separating build and runtime stages.",
    body: `\`\`\`dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
\`\`\`
Final image contains only the compiled binary — no toolchain.`,
    tryIt: [
      "docker build -t app:slim .",
      "docker image ls app",
      "docker run --rm app:slim",
    ],
    mistakes: [
      "Forgetting `--from=<stage>` and ending up with the build toolchain in production.",
      "Naming stages but never using them.",
      "Skipping a non-root USER in the final stage.",
    ],
    checkpoints: [
      { q: "Multi-stage builds primarily reduce…", choices: ["Build time", "Image size & attack surface", "Network use", "CPU"], answer: 1, explain: "Only the final stage ships, so toolchains and intermediates are dropped." },
      { q: "How do you copy artifacts between stages?", choices: ["ADD --stage", "COPY --from=<stage>", "MOVE", "LINK"], answer: 1, explain: "`COPY --from=<stage>` pulls files from an earlier stage." },
      { q: "Distroless images include a shell?", choices: ["Yes", "No"], answer: 1, explain: "Distroless contains no shell or package manager." },
    ],
  },
  {
    id: "i2", level: "intermediate", title: "Build Cache & BuildKit",
    summary: "Speed up rebuilds with cache mounts and BuildKit features.",
    body: `Enable BuildKit (default in modern Docker). Use cache mounts and the new \`#syntax\` directive.

\`\`\`dockerfile
# syntax=docker/dockerfile:1.7
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY . .
RUN npm run build
\`\`\``,
    tryIt: [
      "DOCKER_BUILDKIT=1 docker build -t app .",
      "docker buildx build --platform linux/amd64,linux/arm64 -t app:multi --push .",
    ],
    mistakes: [
      "Invalidating cache by touching a file early in the Dockerfile.",
      "Not pinning base image tags by digest in CI.",
      "Skipping `.dockerignore` (copies node_modules into the build context).",
    ],
    checkpoints: [
      { q: "Which file shrinks the build context?", choices: [".gitignore", ".dockerignore", "Dockerfile.ignore", "build.ignore"], answer: 1, explain: "`.dockerignore` filters what is sent to the daemon." },
      { q: "`docker buildx` enables…", choices: ["GUI", "Multi-arch & advanced BuildKit features", "Docker Hub login", "Compose v3"], answer: 1, explain: "buildx is the BuildKit-powered builder with multi-platform support." },
      { q: "Cache mounts are declared with…", choices: ["VOLUME", "RUN --mount=type=cache", "CACHE", "ENV CACHE=1"], answer: 1, explain: "BuildKit cache mounts persist between builds." },
    ],
  },
  {
    id: "i3", level: "intermediate", title: "Compose Patterns",
    summary: "Profiles, healthchecks, overrides.",
    body: `- **Profiles** isolate dev-only services: \`profiles: ["dev"]\`.
- **Healthchecks** unblock \`depends_on: condition: service_healthy\`.
- **Overrides** layer extra files: \`docker compose -f compose.yaml -f compose.prod.yaml up\`.`,
    tryIt: [
      "docker compose --profile dev up",
      "docker compose -f compose.yaml -f compose.prod.yaml config",
      "docker compose exec api sh",
    ],
    mistakes: [
      "Depending on a DB without a healthcheck — app starts before DB accepts connections.",
      "Putting secrets in the compose file instead of `.env` or external secrets.",
    ],
    checkpoints: [
      { q: "Healthcheck status used with depends_on requires:", choices: ["condition: service_started", "condition: service_healthy", "wait: true", "ready: yes"], answer: 1, explain: "`service_healthy` waits for the healthcheck to pass." },
      { q: "Profiles let you…", choices: ["Encrypt secrets", "Skip services by default", "Tag images", "Use multiple networks"], answer: 1, explain: "Services with profiles only start when that profile is enabled." },
      { q: "Compose overrides are merged in:", choices: ["Alphabetical order", "Order of -f flags", "Reverse order", "Random"], answer: 1, explain: "Later `-f` files override earlier ones." },
    ],
  },
  {
    id: "i4", level: "intermediate", title: "Logging & Monitoring Basics",
    summary: "Get logs out, set sane drivers.",
    body: `- View: \`docker logs -f --tail=200 <name>\`.
- Drivers: \`json-file\` (default), \`local\`, \`journald\`, \`fluentd\`, \`gelf\`. Set globally in \`/etc/docker/daemon.json\` or per container with \`--log-driver\`.
- Cap log size to avoid filling disk: \`--log-opt max-size=10m --log-opt max-file=3\`.`,
    tryIt: [
      "docker logs -f --tail=100 web",
      "docker run -d --log-driver json-file --log-opt max-size=10m nginx",
      "docker stats",
    ],
    mistakes: [
      "Leaving the default unbounded `json-file` driver in production.",
      "Logging to files inside the container instead of stdout/stderr.",
    ],
    checkpoints: [
      { q: "Container apps should log to:", choices: ["A file in /var/log", "stdout/stderr", "syslog from inside", "the database"], answer: 1, explain: "Twelve-factor: log to stdout/stderr; the platform handles routing." },
      { q: "Which option caps log file size?", choices: ["--max=10m", "--log-opt max-size=10m", "--rotate 10m", "--size 10m"], answer: 1, explain: "Pass `--log-opt max-size=...`." },
      { q: "`docker stats` shows…", choices: ["Image history", "Live CPU/MEM/IO per container", "Build cache", "Network routes"], answer: 1, explain: "Live resource usage." },
    ],
  },
  {
    id: "i5", level: "intermediate", title: "Troubleshooting",
    summary: "A repeatable debug workflow.",
    body: `1. \`docker ps -a\` — is it running or crashed?
2. \`docker logs <name>\` — last error.
3. \`docker inspect <name>\` — config, env, mounts, exit code.
4. \`docker exec -it <name> sh\` — poke inside (if it's up).
5. \`docker events\` — daemon-level activity.`,
    tryIt: [
      "docker ps -a",
      "docker logs --tail=200 mycontainer",
      "docker inspect mycontainer | jq '.[0].State'",
      "docker exec -it mycontainer sh",
    ],
    mistakes: [
      "Removing a crashed container before reading its logs.",
      "Ignoring exit codes (137 = OOM kill, 139 = segfault).",
    ],
    checkpoints: [
      { q: "Exit code 137 usually means:", choices: ["Segfault", "OOM-killed", "Permission denied", "Network error"], answer: 1, explain: "128 + 9 (SIGKILL), commonly the OOM killer." },
      { q: "Best command to inspect mounts & env?", choices: ["docker ps", "docker inspect", "docker logs", "docker top"], answer: 1, explain: "`docker inspect` dumps the full container config as JSON." },
      { q: "`docker exec` requires the container to be:", choices: ["Stopped", "Running", "Privileged", "On host network"], answer: 1, explain: "exec attaches to a running container." },
    ],
  },

  // ===== ADVANCED =====
  {
    id: "a1", level: "advanced", title: "Security: Least Privilege & Rootless",
    summary: "Reduce blast radius.",
    body: `- Run as non-root: \`USER 1000:1000\`.
- Drop capabilities: \`--cap-drop=ALL --cap-add=NET_BIND_SERVICE\`.
- Read-only rootfs: \`--read-only --tmpfs /tmp\`.
- No new privileges: \`--security-opt=no-new-privileges\`.
- Consider **rootless Docker** so the daemon itself runs as a non-root user.
- Scan images: \`docker scout cves <image>\` or Trivy.`,
    tryIt: [
      "docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges nginx:alpine",
      "docker scout cves nginx:alpine",
    ],
    mistakes: [
      "Mounting the Docker socket into a container (`/var/run/docker.sock`) — equivalent to root on host.",
      "Using `--privileged` for convenience.",
      "Trusting `:latest` without scanning.",
    ],
    checkpoints: [
      { q: "Mounting the Docker socket into a container is…", choices: ["Safe", "A root-equivalent escape risk", "Required for compose", "Faster"], answer: 1, explain: "It gives the container full daemon control = host root." },
      { q: "Which flag drops all Linux capabilities?", choices: ["--no-caps", "--cap-drop=ALL", "--secure", "--readonly"], answer: 1, explain: "Use `--cap-drop=ALL` then `--cap-add` what you need." },
      { q: "Rootless Docker means:", choices: ["Containers can't write", "Daemon runs as non-root user", "No images", "No networking"], answer: 1, explain: "The daemon itself runs unprivileged via user namespaces." },
    ],
  },
  {
    id: "a2", level: "advanced", title: "Performance & Image Optimization",
    summary: "Smaller, faster, more cacheable images.",
    body: `- Pick minimal bases: \`alpine\`, \`distroless\`, \`scratch\`.
- Combine RUN steps to reduce layers; clean apt cache in the same layer.
- Use \`--squash\` (experimental) or multi-stage builds.
- Pin versions and digests for reproducibility.`,
    tryIt: [
      "docker history myapp:1.0",
      "docker image inspect myapp:1.0 --format '{{.Size}}'",
      "dive myapp:1.0   # third-party layer explorer",
    ],
    mistakes: [
      "Installing build tools in the runtime stage.",
      "Multiple RUN steps that each leave behind apt lists.",
    ],
    checkpoints: [
      { q: "Which base usually has the smallest footprint?", choices: ["ubuntu", "debian", "alpine", "centos"], answer: 2, explain: "Alpine is ~5MB; check for musl-vs-glibc compatibility." },
      { q: "Layer count affects:", choices: ["Pull/push perf and caching", "Container CPU", "DNS", "Network mode"], answer: 0, explain: "Each layer is fetched separately; fewer well-ordered layers = faster pulls." },
      { q: "Pinning by digest gives:", choices: ["Reproducible images", "Smaller size", "Faster build", "Better logs"], answer: 0, explain: "`image@sha256:...` is immutable." },
    ],
  },
  {
    id: "a3", level: "advanced", title: "Registries & Tagging Strategy",
    summary: "Tagging conventions that don't burn you in production.",
    body: `- Never deploy \`:latest\`.
- Use immutable tags: semantic version + git SHA, e.g. \`1.4.2-ab12cd3\`.
- Tag floating channels separately: \`1\`, \`1.4\`, \`stable\`.
- Push to a private registry with auth & retention policies.`,
    tryIt: [
      "docker login registry.example.com",
      "docker tag myapp:dev registry.example.com/team/myapp:1.4.2-ab12cd3",
      "docker push registry.example.com/team/myapp:1.4.2-ab12cd3",
    ],
    mistakes: [
      "Overwriting a tag after release (breaks rollback).",
      "Storing credentials in CI logs.",
    ],
    checkpoints: [
      { q: "Best practice for production tags?", choices: [":latest", "immutable version+sha", "branch name", "build number only"], answer: 1, explain: "Immutable, traceable tags enable safe rollback and audit." },
      { q: "Login is stored at:", choices: ["~/.docker/config.json", "/etc/docker/auth", "~/.dockerlogin", "registry cache"], answer: 0, explain: "Credentials live in `~/.docker/config.json` (or a credential helper)." },
      { q: "Floating tags like `1` should…", choices: ["Be used for deploys", "Track latest 1.x for convenience only", "Be deleted", "Be signed"], answer: 1, explain: "Floating tags are fine for dev convenience but not for deploys." },
    ],
  },
  {
    id: "a4", level: "advanced", title: "CI/CD Patterns",
    summary: "Build once, promote everywhere.",
    body: `- Build image in CI, tag with commit SHA, push to registry.
- Promote the SAME digest through environments (no rebuild per env).
- Use BuildKit cache exports (\`--cache-to type=registry,ref=...\`) to share cache across CI runners.
- Sign images (cosign) and verify at deploy.`,
    tryIt: [
      "docker buildx build --cache-to=type=registry,ref=reg/app:cache --cache-from=type=registry,ref=reg/app:cache -t reg/app:$GIT_SHA --push .",
      "cosign sign --key cosign.key reg/app:$GIT_SHA",
    ],
    mistakes: [
      "Rebuilding per environment — drift guaranteed.",
      "Caching everything inside the runner FS (slow/cold on new runners).",
    ],
    checkpoints: [
      { q: "Build once, deploy many means…", choices: ["One Dockerfile", "Same image digest promoted across envs", "Same tag latest", "Shared volume"], answer: 1, explain: "Promoting the exact same image avoids per-env drift." },
      { q: "Where can BuildKit export cache?", choices: ["S3 only", "Registry, local, inline, GHA, S3", "Memory", "Volume"], answer: 1, explain: "BuildKit supports several cache backends." },
      { q: "Image signing tool commonly used:", choices: ["gpg", "cosign", "openssl", "notary v1 (deprecated)"], answer: 1, explain: "cosign (sigstore) is the modern standard." },
    ],
  },
  {
    id: "a5", level: "advanced", title: "Orchestration Overview",
    summary: "When you outgrow plain docker/compose.",
    body: `- **Swarm** (built-in): simple, declarative services, overlay networks. Good for small teams.
- **Kubernetes**: industry standard for large-scale orchestration, richer ecosystem, steeper curve.
- **Nomad / ECS / Fly Machines**: alternatives in their niches.

Compose is great locally; for HA, scaling, rolling updates, secrets, RBAC, and self-healing, move to an orchestrator.`,
    tryIt: [
      "docker swarm init",
      "docker stack deploy -c compose.yaml app",
      "docker service ls",
    ],
    mistakes: [
      "Reaching for Kubernetes for a 2-service prototype.",
      "Treating Swarm and Kubernetes networking as identical.",
    ],
    checkpoints: [
      { q: "Built into the Docker CLI?", choices: ["Kubernetes", "Swarm", "Nomad", "ECS"], answer: 1, explain: "Swarm mode ships with Docker." },
      { q: "K8s' equivalent of a service in Swarm is roughly:", choices: ["Pod", "Deployment + Service", "ConfigMap", "Node"], answer: 1, explain: "A Deployment manages pods; a Service exposes them." },
      { q: "Compose file can deploy to Swarm via:", choices: ["docker compose up", "docker stack deploy", "docker run", "docker swarm up"], answer: 1, explain: "`docker stack deploy -c compose.yaml <name>`." },
    ],
  },
];
