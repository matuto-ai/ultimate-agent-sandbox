const fs = require("node:fs");
const vm = require("node:vm");

const html = fs.readFileSync(new URL("manager-ui-prototype.html", `file://${__dirname}/`), "utf8");
const source = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
if (!source) throw new Error("prototype script not found");

function boot(variant, page, scenario = "attention", project = "", run = "") {
  const elements = new Map();
  const make = id => ({
    id, innerHTML: "", textContent: "", hidden: id === "drawer", open: false,
    value: "", checked: false, disabled: false, className: "",
    classList: { add() {}, remove() {} }, addEventListener() {}, focus() {},
    showModal() { this.open = true; }, close() { this.open = false; },
  });
  const get = id => {
    if (!elements.has(id)) elements.set(id, make(id));
    return elements.get(id);
  };
  const query = new URLSearchParams({ variant, page, scenario });
  if (project) query.set("project", project);
  if (run) query.set("run", run);
  const location = { href: `http://localhost/manager-ui-prototype.html?${query}`, search: `?${query}` };
  const document = {
    body: { className: "", classList: { add() {}, remove() {} } }, title: "", activeElement: null,
    getElementById: get, addEventListener() {}, querySelector() { return null; },
  };
  const context = {
    URL, URLSearchParams, location, document,
    history: { pushState() {}, replaceState() {} }, window: { addEventListener() {} },
    requestAnimationFrame(fn) { fn(); }, setTimeout(fn) { fn(); return 1; }, clearTimeout() {}, Math, Date,
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "manager-ui-prototype.html" });
  return { context, get, markup: get("app").innerHTML, document };
}

let routes = 0;
for (const variant of ["C", "D"]) {
  for (const page of ["projects", "inbox", "health", "project", "run"]) {
    const contextual = page === "project" || page === "run";
    const result = boot(variant, page, "attention", contextual ? "uas" : "", page === "run" ? "run-01J8ZT7G" : "");
    if (!result.markup.includes("<h1") || result.markup.includes("undefined")) throw new Error(`${variant}/${page}: invalid render`);
    if (!result.markup.includes("Project and Run hierarchy")) throw new Error(`${variant}/${page}: Project index missing`);
    if (result.document.body.className !== `v-${variant}`) throw new Error(`${variant}/${page}: theme missing`);
    if (page === "run") {
      if (!result.markup.includes("Run journey") || !result.markup.includes("CHANGES REQUESTED")) throw new Error(`${variant}: journey missing`);
      if ((result.markup.match(/gate-ledger-row/g) || []).length !== 5) throw new Error(`${variant}: gate ledger incomplete`);
    }
    routes++;
  }
  for (const scenario of ["active", "offline"]) {
    const result = boot(variant, "run", scenario, "uas", "run-01J8ZT7G");
    if (!result.markup.includes("<h1") || result.markup.includes("undefined")) throw new Error(`${variant}/${scenario}: invalid render`);
    routes++;
  }
}

const interaction = boot("C", "run", "attention", "uas", "run-01J8ZT7G");
interaction.context.projectDetail("uas");
if (interaction.get("drawer").hidden || !interaction.get("drawer-body").innerHTML.includes("Open Project")) throw new Error("Project drawer failed");
interaction.context.closeDrawer();
interaction.context.gateDetail(3, "uas", "run-01J8ZT7G");
if (!interaction.get("drawer-body").innerHTML.includes("independent check")) throw new Error("gate drawer failed");
interaction.context.closeDrawer();
interaction.context.openAttention("review-cap");
if (!interaction.get("item-dialog").open || !interaction.get("item-actions").innerHTML.includes("Add review rounds")) throw new Error("attention dialog failed");
interaction.context.closeItem();
interaction.context.openAction("extend", "", "uas", "run-01J8ZT7G");
interaction.get("action-reason").value = "One more review cycle is justified";
interaction.context.submitAction({ preventDefault() {} });
if (!interaction.get("action-receipt").innerHTML.includes("Request confirmed")) throw new Error("typed-action receipt failed");

console.log(`manager UI prototype: ${routes} routes and core interactions passed`);
