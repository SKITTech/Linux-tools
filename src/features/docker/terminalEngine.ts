// Simulated Docker terminal engine.
// SECURITY: This NEVER executes real shell commands. It parses input and returns
// canned/stateful output for an in-memory sandbox. Real docker socket access is
// out of scope for this static-hosted app (see README/docs).
//
// Allowlist: only `docker` and `docker compose` are accepted; everything else
// returns "command not found" so users can't pretend to run arbitrary commands.

export interface SandboxState {
  images: { repo: string; tag: string; id: string; size: string; created: string }[];
  containers: { id: string; name: string; image: string; status: "running" | "exited"; ports: string; created: string }[];
  volumes: { name: string; driver: string }[];
  networks: { name: string; driver: string }[];
}

export const DEFAULT_STATE: SandboxState = {
  images: [
    { repo: "nginx", tag: "alpine", id: "a1b2c3d4e5f6", size: "23.5MB", created: "2 weeks ago" },
    { repo: "node", tag: "20-alpine", id: "f6e5d4c3b2a1", size: "180MB", created: "3 weeks ago" },
    { repo: "postgres", tag: "16", id: "9876543210ab", size: "420MB", created: "1 month ago" },
  ],
  containers: [],
  volumes: [{ name: "pgdata", driver: "local" }],
  networks: [
    { name: "bridge", driver: "bridge" },
    { name: "host", driver: "host" },
    { name: "none", driver: "null" },
  ],
};

const DESTRUCTIVE = [
  /system\s+prune/i,
  /\brm\s+-f/i,
  /volume\s+(rm|prune)/i,
  /image\s+prune\s+-a/i,
  /container\s+prune/i,
  /network\s+prune/i,
  /compose\s+down\s+.*-v/i,
];

export function isDestructive(input: string): boolean {
  return DESTRUCTIVE.some((r) => r.test(input));
}

const ALLOWED_HEAD = /^(docker)(\s|$)/;

function rid(n = 12) {
  const c = "0123456789abcdef";
  let s = "";
  for (let i = 0; i < n; i++) s += c[Math.floor(Math.random() * c.length)];
  return s;
}

function table(headers: string[], rows: string[][]) {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] || "").length)));
  const fmt = (cells: string[]) => cells.map((c, i) => (c || "").padEnd(widths[i] + 3)).join("");
  return [fmt(headers), ...rows.map(fmt)].join("\n");
}

export interface RunResult {
  output: string;
  exitCode: number;
  state: SandboxState;
}

export function runCommand(rawInput: string, state: SandboxState): RunResult {
  const input = rawInput.trim();
  if (!input) return { output: "", exitCode: 0, state };

  if (input === "help" || input === "--help" || input === "docker" || input === "docker --help" || input === "docker -h") {
    return {
      output:
        "Sandbox supports a subset of docker commands:\n" +
        "  docker ps [-a]\n  docker images | docker image ls\n  docker image rm|rmi <ref>\n  docker pull <image>\n  docker run [-d] [--name N] [-p H:C] <image> [cmd]\n" +
        "  docker container run|ls|rm|stop|start|logs|exec ...\n" +
        "  docker stop|start|rm <name>\n  docker logs <name>\n  docker exec -it <name> sh\n  docker volume ls|create|inspect|rm\n" +
        "  docker network ls|create|inspect|rm\n  docker build -t <tag> .\n  docker compose up|down|ps|logs\n  clear, reset\n",
      exitCode: 0, state,
    };
  }
  if (input === "clear") return { output: "__CLEAR__", exitCode: 0, state };
  if (input === "reset") return { output: "Sandbox reset.", exitCode: 0, state: structuredClone(DEFAULT_STATE) };



  if (!ALLOWED_HEAD.test(input)) {
    return { output: `sandbox: "${input.split(/\s+/)[0]}": command not allowed. Only \`docker\` and \`docker compose\` work here. Type 'help'.`, exitCode: 127, state };
  }

  const parts = input.split(/\s+/);
  // parts[0]="docker"
  const sub = parts[1];

  // docker compose ...
  if (sub === "compose") {
    return composeCommand(parts.slice(2), state);
  }

  switch (sub) {
    case undefined:
    case "":
      return { output: "Usage: docker COMMAND. Try 'docker --help' or 'help'.", exitCode: 0, state };
    case "version":
      return { output: "Docker version 26.0.0 (sandbox), build sim\nServer: simulated, no real engine.", exitCode: 0, state };
    case "info":
      return { output: `Containers: ${state.containers.length}\nImages: ${state.images.length}\nVolumes: ${state.volumes.length}\nServer: SANDBOX (no host access)`, exitCode: 0, state };
    case "ps": {
      const all = parts.includes("-a") || parts.includes("--all");
      const list = state.containers.filter((c) => all || c.status === "running");
      const rows = list.map((c) => [c.id.slice(0, 12), c.image, "\"/entrypoint\"", c.created, c.status === "running" ? "Up 5 minutes" : "Exited (0) 1 minute ago", c.ports || "", c.name]);
      return { output: table(["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"], rows), exitCode: 0, state };
    }
    case "images":
    case "image": {
      if (sub === "image" && parts[2] !== "ls") {
        if (parts[2] === "prune") {
          return { output: "Total reclaimed space: 0B (sandbox)", exitCode: 0, state };
        }
        return { output: "Usage: docker image ls", exitCode: 0, state };
      }
      const rows = state.images.map((i) => [i.repo, i.tag, i.id.slice(0, 12), i.created, i.size]);
      return { output: table(["REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"], rows), exitCode: 0, state };
    }
    case "pull": {
      const ref = parts[2];
      if (!ref) return { output: 'See "docker pull --help".', exitCode: 1, state };
      const [repo, tag = "latest"] = ref.split(":");
      const ns = { ...state, images: [...state.images] };
      if (!ns.images.find((i) => i.repo === repo && i.tag === tag)) {
        ns.images.push({ repo, tag, id: rid(), size: "50MB", created: "Just now" });
      }
      return { output: `${tag}: Pulling from library/${repo}\nDigest: sha256:${rid(40)}\nStatus: Downloaded newer image for ${repo}:${tag}\ndocker.io/library/${repo}:${tag}`, exitCode: 0, state: ns };
    }
    case "run": {
      // very small flag parser
      const flags = parts.slice(2);
      let detached = false, name = "", ports = "", image = "";
      for (let i = 0; i < flags.length; i++) {
        const f = flags[i];
        if (f === "-d" || f === "--detach") detached = true;
        else if (f === "--rm" || f === "-it" || f === "-i" || f === "-t") continue;
        else if (f === "--name") { name = flags[++i] || ""; }
        else if (f.startsWith("--name=")) { name = f.slice(7); }
        else if (f === "-p" || f === "--publish") { ports = (ports ? ports + ", " : "") + (flags[++i] || ""); }
        else if (f.startsWith("-e") || f === "--env" || f.startsWith("--env=")) { if (f === "-e" || f === "--env") i++; }
        else if (f.startsWith("-v") || f === "--volume" || f.startsWith("--volume=")) { if (f === "-v" || f === "--volume") i++; }
        else if (f.startsWith("--network") || f.startsWith("--restart") || f.startsWith("--log-driver") || f.startsWith("--log-opt") || f.startsWith("--cap-drop") || f.startsWith("--cap-add") || f.startsWith("--security-opt") || f === "--read-only") { if (!f.includes("=") && f !== "--read-only") i++; }
        else if (!f.startsWith("-") && !image) { image = f; break; }
      }
      if (!image) return { output: 'docker: "run" requires at least 1 argument. See "docker run --help".', exitCode: 1, state };
      const [repo, tag = "latest"] = image.split(":");
      const ns = { ...state, images: [...state.images], containers: [...state.containers] };
      if (!ns.images.find((i) => i.repo === repo && i.tag === tag)) {
        ns.images.push({ repo, tag, id: rid(), size: "50MB", created: "Just now" });
      }
      const id = rid();
      const cname = name || `sim_${rid(6)}`;
      const portsStr = ports ? ports.split(", ").map((p) => `0.0.0.0:${p.replace(":", "->")}/tcp`).join(", ") : "";
      ns.containers.push({ id, name: cname, image, status: "running", ports: portsStr, created: "Just now" });
      return { output: detached ? id : `(running ${cname} in foreground — Ctrl+C to stop)\n`, exitCode: 0, state: ns };
    }
    case "stop":
    case "start":
    case "restart": {
      const name = parts[2];
      if (!name) return { output: `"${sub}" requires at least 1 argument.`, exitCode: 1, state };
      const ns = { ...state, containers: state.containers.map((c) => c.name === name || c.id.startsWith(name) ? { ...c, status: sub === "stop" ? "exited" as const : "running" as const } : c) };
      const found = ns.containers.find((c) => c.name === name || c.id.startsWith(name));
      if (!found) return { output: `Error: No such container: ${name}`, exitCode: 1, state };
      return { output: name, exitCode: 0, state: ns };
    }
    case "rm": {
      const targets = parts.slice(2).filter((p) => !p.startsWith("-"));
      const force = parts.includes("-f") || parts.includes("--force");
      let ns = { ...state, containers: [...state.containers] };
      const removed: string[] = [];
      for (const t of targets) {
        const idx = ns.containers.findIndex((c) => c.name === t || c.id.startsWith(t));
        if (idx === -1) return { output: `Error: No such container: ${t}`, exitCode: 1, state };
        if (!force && ns.containers[idx].status === "running") {
          return { output: `Error response from daemon: container ${t} is running. Use -f to force.`, exitCode: 1, state };
        }
        removed.push(t);
        ns.containers.splice(idx, 1);
      }
      return { output: removed.join("\n"), exitCode: 0, state: ns };
    }
    case "logs": {
      const name = parts[parts.length - 1];
      const found = state.containers.find((c) => c.name === name || c.id.startsWith(name));
      if (!found) return { output: `Error: No such container: ${name}`, exitCode: 1, state };
      return { output: `[sandbox] starting ${found.image}\n[sandbox] listening on configured ports\n[sandbox] healthy\n`, exitCode: 0, state };
    }
    case "exec": {
      return { output: "[sandbox] exec is simulated — interactive shell not available here. Use the Ask Docker tab to learn flags.", exitCode: 0, state };
    }
    case "inspect": {
      const name = parts[2];
      const c = state.containers.find((c) => c.name === name || c.id.startsWith(name));
      if (!c) return { output: `Error: No such object: ${name}`, exitCode: 1, state };
      return { output: JSON.stringify([{ Id: c.id, Name: "/" + c.name, State: { Status: c.status, ExitCode: 0 }, Config: { Image: c.image } }], null, 2), exitCode: 0, state };
    }
    case "volume": {
      const action = parts[2];
      if (action === "ls") {
        return { output: table(["DRIVER", "VOLUME NAME"], state.volumes.map((v) => [v.driver, v.name])), exitCode: 0, state };
      }
      if (action === "create") {
        const name = parts[3] || `vol_${rid(6)}`;
        if (state.volumes.find((v) => v.name === name)) return { output: name, exitCode: 0, state };
        return { output: name, exitCode: 0, state: { ...state, volumes: [...state.volumes, { name, driver: "local" }] } };
      }
      if (action === "inspect") {
        const v = state.volumes.find((v) => v.name === parts[3]);
        if (!v) return { output: `Error: No such volume: ${parts[3]}`, exitCode: 1, state };
        return { output: JSON.stringify([{ Name: v.name, Driver: v.driver, Mountpoint: `/var/lib/docker/volumes/${v.name}/_data` }], null, 2), exitCode: 0, state };
      }
      return { output: "Usage: docker volume ls|create|inspect", exitCode: 0, state };
    }
    case "network": {
      const action = parts[2];
      if (action === "ls") {
        return { output: table(["NETWORK ID", "NAME", "DRIVER", "SCOPE"], state.networks.map((n) => [rid(12), n.name, n.driver, "local"])), exitCode: 0, state };
      }
      if (action === "create") {
        const name = parts[3] || `net_${rid(6)}`;
        if (state.networks.find((n) => n.name === name)) return { output: rid(), exitCode: 0, state };
        return { output: rid(), exitCode: 0, state: { ...state, networks: [...state.networks, { name, driver: "bridge" }] } };
      }
      if (action === "inspect") {
        const n = state.networks.find((n) => n.name === parts[3]);
        if (!n) return { output: `Error: No such network: ${parts[3]}`, exitCode: 1, state };
        return { output: JSON.stringify([{ Name: n.name, Driver: n.driver, Scope: "local", Containers: {} }], null, 2), exitCode: 0, state };
      }
      return { output: "Usage: docker network ls|create|inspect", exitCode: 0, state };
    }
    case "build": {
      const tagIdx = parts.indexOf("-t");
      const tag = tagIdx !== -1 ? parts[tagIdx + 1] : "untagged:latest";
      const [repo, t = "latest"] = tag.split(":");
      const ns = { ...state, images: [...state.images] };
      if (!ns.images.find((i) => i.repo === repo && i.tag === t)) {
        ns.images.push({ repo, tag: t, id: rid(), size: "120MB", created: "Just now" });
      }
      return { output: `[+] Building 4.2s (8/8) FINISHED\n => exporting to image\n => => writing image sha256:${rid(40)}\n => => naming to ${tag}`, exitCode: 0, state: ns };
    }
    case "tag":
    case "push":
    case "login":
      return { output: `[sandbox] '${sub}' acknowledged (no network access in sandbox).`, exitCode: 0, state };
    default:
      return { output: `docker: '${sub}' is not a docker command. See 'docker --help'.`, exitCode: 1, state };
  }
}

function composeCommand(args: string[], state: SandboxState): RunResult {
  const cmd = args[0];
  switch (cmd) {
    case "up": {
      const ns = { ...state, containers: [...state.containers] };
      ["web", "api", "db"].forEach((name) => {
        if (!ns.containers.find((c) => c.name === name)) {
          ns.containers.push({ id: rid(), name, image: name === "db" ? "postgres:16" : name === "web" ? "nginx:alpine" : "node:20-alpine", status: "running", ports: name === "web" ? "0.0.0.0:8080->80/tcp" : "", created: "Just now" });
        }
      });
      return { output: "[+] Running 3/3\n ✔ Container web   Started\n ✔ Container api   Started\n ✔ Container db    Started", exitCode: 0, state: ns };
    }
    case "down": {
      const removeVols = args.includes("-v") || args.includes("--volumes");
      const ns = { ...state, containers: state.containers.filter((c) => !["web", "api", "db"].includes(c.name)), volumes: removeVols ? state.volumes.filter((v) => v.name !== "pgdata") : state.volumes };
      return { output: `[+] Running ${removeVols ? "4/4" : "3/3"}\n ✔ Container web Removed\n ✔ Container api Removed\n ✔ Container db  Removed${removeVols ? "\n ✔ Volume pgdata Removed" : ""}`, exitCode: 0, state: ns };
    }
    case "ps":
      return { output: table(["NAME", "IMAGE", "STATUS", "PORTS"], state.containers.filter((c) => ["web", "api", "db"].includes(c.name)).map((c) => [c.name, c.image, c.status === "running" ? "Up" : "Exited", c.ports || ""])), exitCode: 0, state };
    case "logs":
      return { output: "[web]  | accepting connections on :80\n[api]  | listening on :3000\n[db]   | database system is ready to accept connections", exitCode: 0, state };
    case "build":
      return { output: "[+] Building services... done", exitCode: 0, state };
    default:
      return { output: `Usage: docker compose up|down|ps|logs|build`, exitCode: 0, state };
  }
}
