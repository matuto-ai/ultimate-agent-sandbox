import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

const config = {
  url: process.env.HUB_URL || "",
  actor: process.env.HUB_ACTOR || "pi",
  profile: process.env.HUB_PROFILE || "pi-default",
  stateFile: process.env.HUB_STATE || ".demo/pi-state.json",
  evidenceFile: process.env.HUB_EVIDENCE || "",
};

const state = { badge: "", lastSeq: 0, busy: false };

function evidence(value: Record<string, unknown>) {
  if (!config.evidenceFile) return;
  mkdirSync(dirname(config.evidenceFile), { recursive: true });
  appendFileSync(config.evidenceFile, JSON.stringify({ ts: new Date().toISOString(), ...value }) + "\n");
}

function loadState() {
  try {
    const saved = JSON.parse(readFileSync(config.stateFile, "utf8"));
    state.lastSeq = Number(saved.lastSeq || 0);
  } catch {}
}

function saveState() {
  mkdirSync(dirname(config.stateFile), { recursive: true });
  writeFileSync(config.stateFile, JSON.stringify({ lastSeq: state.lastSeq }));
}

async function raw(path: string, method = "GET", body?: unknown) {
  const response = await fetch(config.url + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(state.badge ? { "X-Room-Badge": state.badge } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, value };
}

async function join() {
  const response = await raw("/join", "POST", {
    actor: config.actor,
    runtime: "pi",
    profile: config.profile,
    after_seq: state.lastSeq,
  });
  if (!response.ok) throw new Error(`Hub join failed: ${response.status}`);
  state.badge = response.value.badge;
  evidence({ action: "join", actor: config.actor, badge: state.badge });
}

async function request(path: string, method = "GET", body?: unknown) {
  if (!state.badge) await join();
  let response = await raw(path, method, body);
  if (response.status === 401) {
    await join();
    response = await raw(path, method, body);
  }
  if (!response.ok) throw new Error(JSON.stringify(response.value));
  return response.value;
}

function parseTarget(args: string) {
  const match = args.trim().match(/^(\S+)\s+(.+)$/s);
  if (!match) throw new Error("expected: <target> <text>");
  return { target: match[1], text: match[2] };
}

export default function (pi: ExtensionAPI) {
  let context: ExtensionContext | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;

  async function pull() {
    if (state.busy || !context?.isIdle()) return;
    const result = await request(`/events?after_seq=${state.lastSeq}`);
    for (const event of result.events || []) {
      state.lastSeq = event.seq;
      if (["message", "request", "reply", "broadcast"].includes(event.type) && event.actor !== config.actor) {
        pi.sendMessage(
          { customType: "hub-peer", content: JSON.stringify(event), display: true, details: event },
          { deliverAs: "nextTurn" },
        );
        evidence({ action: "receive", event });
      }
    }
    saveState();
  }

  async function submit(type: string, body: Record<string, unknown>) {
    const event = await request("/traffic", "POST", {
      type,
      client_id: `${config.actor}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      ...body,
    });
    evidence({ action: "submit", event });
    return event;
  }

  pi.on("session_start", async (_event, ctx) => {
    context = ctx;
    loadState();
    await join();
    await pull();
    timer = setInterval(() => void pull().catch(error => evidence({ action: "poll-error", error: String(error) })), 150);
  });
  pi.on("agent_start", () => { state.busy = true; });
  pi.on("agent_settled", async (_event, ctx) => {
    context = ctx;
    state.busy = false;
    await pull();
  });
  pi.on("session_before_compact", () => {
    state.busy = true;
    evidence({ action: "compact-freeze" });
  });
  pi.on("session_compact", (_event, ctx) => {
    context = ctx;
    if (ctx.isIdle()) state.busy = false;
  });
  pi.on("session_shutdown", async () => {
    if (timer) clearInterval(timer);
    try { await request("/disconnect", "POST", {}); } catch {}
  });

  pi.registerCommand("hub-peers", {
    description: "List online Hub peers",
    handler: async (_args, ctx) => {
      const peers = await request("/participants");
      ctx.ui.notify(`peers=${peers.filter((peer: any) => peer.connected).map((peer: any) => peer.actor).join(",")}`, "info");
    },
  });
  pi.registerCommand("hub-send", {
    description: "Send a correlated Hub request: /hub-send <target> <text>",
    handler: async (args, ctx) => {
      const { target, text } = parseTarget(args);
      const event = await submit("request", { target, payload: { text } });
      ctx.ui.notify(`request=${event.seq} correlation=${event.correlation_id}`, "info");
    },
  });
  pi.registerCommand("hub-broadcast", {
    description: "Broadcast a Hub message",
    handler: async (args, ctx) => {
      const event = await submit("broadcast", { payload: { text: args } });
      ctx.ui.notify(`broadcast=${event.seq}`, "info");
    },
  });
  pi.registerCommand("hub-inbox", {
    description: "Pull queued Hub traffic at an idle safe point",
    handler: async (_args, ctx) => {
      context = ctx;
      await pull();
      ctx.ui.notify(`last_seq=${state.lastSeq}`, "info");
    },
  });
  pi.registerCommand("hub-reply", {
    description: "Reply: /hub-reply <correlation> <parent-seq> <text>",
    handler: async (args, ctx) => {
      const [correlation_id, parent, ...words] = args.trim().split(/\s+/);
      const event = await submit("reply", {
        correlation_id,
        parent_seq: Number(parent),
        payload: { text: words.join(" ") },
      });
      ctx.ui.notify(`reply=${event.seq}`, "info");
    },
  });
}
