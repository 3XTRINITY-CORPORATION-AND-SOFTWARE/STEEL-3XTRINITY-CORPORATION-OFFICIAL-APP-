/* eslint-disable @typescript-eslint/ban-ts-comment -- the harness is untyped JS over dynamic target modules; tsconfig.cerberus.json type-checks factory/ with checkJs */
// @ts-nocheck
// PWA/ASSET/INTEGRATION domain (slots 201-250): scripts/grok-pwa-shared.mjs, grok-pwa-plugin.mjs, brand-check.mjs.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const SH = "scripts/grok-pwa-shared.mjs";
const PL = "scripts/grok-pwa-plugin.mjs";
const BR = "scripts/brand-check.mjs";

const tree = (files = {}) => { const r = mkdtempSync(join(tmpdir(), "m-pwa-")); for (const [rel, c] of Object.entries(files)) { mkdirSync(dirname(join(r, rel)), { recursive: true }); writeFileSync(join(r, rel), c); } return r; };
async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) { saved[k] = process.env[k]; if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k]; }
  try { return await fn(); } finally { for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } }
}
const NOENV = { VITE_PUBLIC_HOSTNAME: undefined, VITE_OG_SERVICE_URL: undefined, VITE_PROJECT_ID: undefined, X_CREATOR: undefined, X_CREATOR_ID: undefined };
const E = (fn) => withEnv(NOENV, fn);
const CTX = (over = {}) => ({ host: "", cwd: tree(), site: {}, projectId: "", creator: "", creatorId: "", appName: "Grok App", ...over });
const SCRIPT = '<script src="https://grok.com/grok-app-builder/extensions.js" defer></script>';
const count = (s, needle) => s.split(needle).length - 1;

export const SPECS = [
  { slot: 201, target: SH, fn: "escapeHtml", input: ["<a href=\"x\" b='y'>&</a>"], expected: "&lt;a href=&quot;x&quot; b=&#39;y&#39;&gt;&amp;&lt;/a&gt;", claim: "all five HTML-significant characters are escaped, & exactly once" },
  { slot: 202, target: SH, fn: "appNameFromHost", input: ["wild-race.grok.me"], expected: "Wild Race", claim: "a published grok.me host's first label becomes the Title-Cased display name" },
  { slot: 203, target: SH, fn: "appNameFromHost", input: ["abc-3000-xy.vercel.app"], expected: "Grok App", claim: "preview/system hosts are image origins only and never slugified into a name" },
  { slot: 204, target: PL, expected: { named: true, escapedUrl: true, noPlaceholderLeft: true },
    run: (m) => { const h = m.renderInstallPage("wild-race.grok.me", '/a"b?install=1&platform=ios'); return { named: h.includes("<title>Add Wild Race to your Home Screen</title>"), escapedUrl: h.includes("/a&quot;b") && !h.includes('/a"b'), noPlaceholderLeft: !h.includes("{{") }; },
    claim: "the real install-page.html is rendered with the host-derived name, an escaped install-free app URL and no unreplaced placeholder" },
  { slot: 205, target: SH, fn: "appNameFromHost", input: ["my-app.grok.me:443, other.example.com"], expected: "My App", claim: "only the first entry of a forwarded host list is used and its port is ignored" },
  { slot: 206, target: SH, fn: "publicAppHost", input: ["My-App.grok.me:8080"], expected: "my-app.grok.me", claim: "the public host is lower-cased with the port removed" },
  { slot: 207, target: SH, fn: "publicAppHost", input: ["127.0.0.1:8080"], expected: "", claim: "a bare IPv4 address is never a public og:image origin" },
  { slot: 208, target: SH, fn: "publicAppHost", input: ["shop-abc.vercel.app"], expected: "", claim: "Vercel system hosts (SSO-protected /og.jpg) are rejected as og:image origins" },
  { slot: 209, target: PL, expected: { resolved: "\0virtual:grok-og-identity", other: undefined, source: 'export const grokOgIdentity = {"site":{"title":"Plug"}};' },
    run: (m) => { const p = m.grokPwaPlugin(); p.configResolved({ root: tree({ "src/lib/og/site.json": '{"title":"Plug"}' }) }); return { resolved: p.resolveId("virtual:grok-og-identity"), other: p.resolveId("something-else"), source: p.load("\0virtual:grok-og-identity") }; },
    claim: "the Vite plugin bakes the workspace's og identity into the virtual module and leaves other ids alone" },
  { slot: 210, target: SH, expected: "pub.grok.me", run: (m) => withEnv({ VITE_PUBLIC_HOSTNAME: "pub.grok.me" }, () => m.resolvePublicHost("shop-abc.vercel.app")), claim: "a published app's VITE_PUBLIC_HOSTNAME beats the (Envoy-rewritten) request host" },
  { slot: 211, target: SH, expected: "preview.example.com", run: (m) => withEnv({ VITE_PUBLIC_HOSTNAME: undefined }, () => m.resolvePublicHost("preview.example.com:3000")), claim: "with no published hostname the live preview falls back to the request host" },
  { slot: 212, target: SH, fn: "isInstallQuery", input: ["/?install=1&platform=iOS"], expected: true, claim: "install=1 with platform=ios (case-insensitive) is the install tutorial request" },
  { slot: 213, target: SH, fn: "isInstallQuery", input: ["/?install=1&platform=android"], expected: false, claim: "the install tutorial is iOS-only: android does not trigger it" },
  { slot: 214, target: SH, expected: { root: true, about: true, js: false, grok: false, api: false, vite: false, nm: false },
    run: (m) => ({ root: m.isDocumentPath("/"), about: m.isDocumentPath("/about"), js: m.isDocumentPath("/app.js"), grok: m.isDocumentPath("/__grok/x"), api: m.isDocumentPath("/api/x"), vite: m.isDocumentPath("/@vite/client"), nm: m.isDocumentPath("/node_modules/x") }),
    claim: "only extension-less non-internal paths can carry an app document" },
  { slot: 215, target: SH, expected: { empty: true, html: true, any: true, json: false },
    run: (m) => ({ empty: m.acceptsHtml(""), html: m.acceptsHtml("text/html,application/xhtml+xml"), any: m.acceptsHtml("*/*"), json: m.acceptsHtml("application/json") }), claim: "an empty, html or wildcard Accept header wants a document; application/json does not" },
  { slot: 216, target: SH, fn: "stripInstallParams", input: ["/play?level=2&install=1&platform=ios"], expected: "/play?level=2", claim: "install params are removed from the app link while other query params survive" },
  { slot: 217, target: SH, fn: "renderInstallPageHtml", input: ['<h1>{{APP_NAME}}</h1><a href="{{APP_URL}}">', { host: "cool-game.grok.me", url: '/a"b?install=1&platform=ios' }], expected: '<h1>Cool Game</h1><a href="/a&quot;b">',
    claim: "template placeholders are replaced with the host-derived name and an HTML-escaped, install-param-free URL" },
  { slot: 218, target: SH, expected: { name: "Wild Race", short_name: "Wild Race", display: "standalone", start_url: "/", icon: "/__grok/icon-180.png", bg: "#000000" },
    run: (m) => { const j = JSON.parse(m.renderWebManifest("wild-race.grok.me")); return { name: j.name, short_name: j.short_name, display: j.display, start_url: j.start_url, icon: j.icons[0].src, bg: j.background_color }; },
    claim: "the per-app manifest carries the host-derived name, standalone display and the 180px icon" },
  { slot: 219, target: SH, expected: { keys: ["manifest", "apple-touch-icon", "apple-mobile-web-app-title", "apple-mobile-web-app-status-bar-style", "theme-color"], title: '<meta name="apple-mobile-web-app-title" content="A&amp;B">' },
    run: (m) => { const t = m.grokPwaHeadTags("A&B"); return { keys: t.map((x) => x[0]), title: t[2][1] }; }, claim: "the PWA head set is exactly five keyed tags and the app name in the title tag is escaped" },
  { slot: 220, target: SH, fn: "grokXCreatorHeadTags", input: ["Ann <x>", "123"], expected: ['<meta property="x:creator" content="Ann &lt;x&gt;">', '<meta property="x:creator:id" content="123">'], claim: "x:creator tags are emitted as a pair with the creator name escaped" },
  { slot: 221, target: SH, fn: "grokXCreatorHeadTags", input: ["Ann", ""], expected: [], claim: "a creator name without a creator id emits no tags at all" },
  { slot: 222, target: SH, fn: "grokExtensionsHeadTags", input: [""], expected: [SCRIPT], claim: "without a project id only the deferred extensions script is emitted" },
  { slot: 223, target: SH, fn: "grokExtensionsHeadTags", input: ["proj-1"], expected: ['<meta name="grok-project-id" content="proj-1">', '<script src="https://grok.com/grok-app-builder/extensions.js" data-project-id="proj-1" defer></script>'], claim: "with a project id a grok-project-id meta precedes a script carrying data-project-id" },
  { slot: 224, target: SH, expected: { missing: {}, object: { title: "T" }, array: {}, badJson: {} },
    run: (m) => ({ missing: m.readOgSite(tree()), object: m.readOgSite(tree({ "src/lib/og/site.json": '{"title":"T"}' })), array: m.readOgSite(tree({ "src/lib/og/site.json": "[1]" })), badJson: m.readOgSite(tree({ "src/lib/og/site.json": "{nope" })) }),
    claim: "site.json is read only when it is a JSON object; absent, array and malformed files are {}" },
  { slot: 225, target: SH, expected: { both: "/og.jpg", pngOnly: "/og.png", none: "" },
    run: (m) => ({ both: m.ogCardPublicPath(tree({ "public/og.jpg": "x", "public/og.png": "x" })), pngOnly: m.ogCardPublicPath(tree({ "public/og.png": "x" })), none: m.ogCardPublicPath(tree()) }), claim: "og.jpg wins over og.png, og.png is used alone, and no file gives an empty path" },
  { slot: 226, target: SH, expected: { site: { title: "T", card: "custom", image: "/og.png" } },
    run: (m) => m.snapshotOgIdentity(tree({ "public/og.png": "x", "src/lib/og/site.json": '{"title":"T"}' })), claim: "a card file on disk is baked as card=custom with its public path next to the site.json fields" },
  { slot: 227, target: SH, expected: { site: { banner: "/x-banner.jpg" } },
    run: (m) => m.snapshotOgIdentity(tree({ "public/x-banner.jpg": "x", "src/lib/og/site.json": '{"card":"custom","image":"/og.jpg"}' })), claim: "card=custom without a card file is un-baked (no 404 image) while public/x-banner.jpg stamps a banner" },
  { slot: 228, target: SH, expected: { none: "/og.jpg", png: "/og.png" },
    run: (m) => ({ none: m.customOgAssetPath(tree()), png: m.customOgAssetPath(tree({ "public/og.png": "x" })) }), claim: "the custom card asset path defaults to /og.jpg and follows an existing og.png" },
  { slot: 229, target: SH, expected: { custom: "https://og.example", dflt: "https://og.grok.me" },
    run: async (m) => ({ custom: await withEnv({ VITE_OG_SERVICE_URL: "https://og.example///" }, () => m.ogServiceUrl()), dflt: await withEnv({ VITE_OG_SERVICE_URL: undefined }, () => m.ogServiceUrl()) }),
    claim: "VITE_OG_SERVICE_URL overrides the card service with trailing slashes trimmed; the default is https://og.grok.me" },
  { slot: 230, target: SH, fn: "titleFromDocument", input: ["<html><head><title> A &amp; B </title></head>"], expected: "A & B", claim: "the document <title> is entity-decoded and trimmed" },
  { slot: 231, target: SH, expected: { site: "Site", doc: "Doc", host: "Wild Race", arg: "Arg", fallback: "Grok App" },
    run: (m) => ({ site: m.resolveOgTitle({ title: "Site" }, "App", "x.grok.me", "Doc"), doc: m.resolveOgTitle({}, "App", "x.grok.me", "Doc"), host: m.resolveOgTitle({}, "App", "wild-race.grok.me", ""), arg: m.resolveOgTitle({}, "Arg", "preview.example", ""), fallback: m.resolveOgTitle({}, "", "", "") }),
    claim: "title precedence is site.json, then document <title>, then host-derived name, then the app-name argument, then 'Grok App'" },
  { slot: 232, target: SH, expected: { custom: true, upper: true, empty: false, other: false, none: false },
    run: (m) => ({ custom: m.siteHasCustomCard({ card: "custom" }), upper: m.siteHasCustomCard({ card: "CUSTOM" }), empty: m.siteHasCustomCard({ card: "" }), other: m.siteHasCustomCard({ card: "x" }), none: m.siteHasCustomCard() }), claim: "card=custom is case-insensitive; empty, other values and no site are not custom" },
  { slot: 233, target: SH, expected: { nothing: "", baked: "/baked.jpg", bakedNoImage: "/og.jpg", diskWins: "/og.png" },
    run: (m) => { const empty = tree(); return { nothing: m.resolveOgCardAsset({}, empty), baked: m.resolveOgCardAsset({ card: "custom", image: "/baked.jpg" }, empty), bakedNoImage: m.resolveOgCardAsset({ card: "custom" }, empty), diskWins: m.resolveOgCardAsset({ card: "custom", image: "/baked.jpg" }, tree({ "public/og.png": "x" })) }; },
    claim: "card asset resolution is disk file, then the bake's image (or /og.jpg for card=custom), then empty (placeholder)" },
  { slot: 234, target: SH, expected: ['<meta name="twitter:card" content="summary_large_image">', '<meta property="og:title" content="App">', '<meta property="og:image" content="https://og.grok.me/v1/card.png?host=app.grok.me&amp;title=App&amp;color=FF8800">', '<meta property="og:image:width" content="1200">', '<meta property="og:image:height" content="630">'],
    run: (m) => E(() => m.grokOgHeadTags({ host: "app.grok.me", appName: "X", site: { color: "#FF8800" }, cwd: tree() })), claim: "on a public host with no custom card the placeholder image URL carries host, title and the 6-digit site colour" },
  { slot: 235, target: SH, expected: '<meta property="og:image" content="https://app.grok.me/card.jpg">',
    run: (m) => E(() => m.grokOgHeadTags({ host: "app.grok.me", site: { card: "custom", image: "/card.jpg", color: "#FF8800" }, cwd: tree() }).find((t) => t.includes("og:image\""))), claim: "a baked custom card is served from the app's own host and ignores the placeholder colour" },
  { slot: 236, target: SH, expected: ['<meta property="og:description" content="Fun">', '<meta property="og:type" content="x:game">', '<meta property="x:game:image" content="https://g.grok.me/x-banner.jpg">', '<meta property="x:game:image:width" content="1200">', '<meta property="x:game:image:height" content="264">'],
    run: (m) => E(() => { const t = m.grokOgHeadTags({ host: "g.grok.me", site: { description: "Fun", type: "x:game", banner: "/x-banner.jpg", title: "G" }, cwd: tree() }); return t.filter((x) => /description|og:type|x:game/.test(x)); }), claim: "a game site emits description, og:type=x:game and the 1200x264 banner tags" },
  { slot: 237, target: SH, expected: ['<meta name="twitter:card" content="summary_large_image">', '<meta property="og:title" content="Local">'],
    run: (m) => E(() => m.grokOgHeadTags({ host: "localhost:5173", site: { title: "Local" }, cwd: tree() })), claim: "with no public host (localhost) only twitter:card and og:title are emitted - no image URL that cannot resolve" },
  { slot: 238, target: SH, expected: '<meta property="og:image" content="https://pub.grok.me/og.jpg">',
    run: (m) => withEnv({ ...NOENV, VITE_PUBLIC_HOSTNAME: "pub.grok.me" }, () => m.grokOgHeadTags({ host: "x.vercel.app", site: { card: "custom" }, cwd: tree() }).find((t) => t.includes("og:image\""))), claim: "on a published app the og:image origin is VITE_PUBLIC_HOSTNAME even when the request Host is *.vercel.app" },
  { slot: 239, target: SH, expected: '<meta property="og:title" content="Tom &amp; &quot;Jerry&quot;">',
    run: (m) => E(() => m.grokOgHeadTags({ site: { title: 'Tom & "Jerry"' }, cwd: tree() })[1]), claim: "an og:title containing & and quotes is attribute-escaped" },
  { slot: 240, target: SH, expected: '<meta name="description" content="keep"><meta name="viewport" content="w"><p>x</p>',
    run: (m) => m.stripShareMetaTags('<meta property="og:title" content="a"><meta name="twitter:card" content="s"><meta name="description" content="keep"><meta property=\'og:image\' content="i"><meta name="viewport" content="w"><p>x</p>'), claim: "share-card metas are removed (either quote style) while description and viewport metas stay" },
  { slot: 241, target: SH, expected: { appName: "Baked", projectId: "p", creator: "c", creatorId: "i", host: "x.grok.me", site: { title: "Baked" } },
    run: (m) => { const { cwd, ...rest } = m.normalizeHeadContext({ site: { title: "Baked" }, cwd: tree(), host: "x.grok.me", projectId: "p", creator: "c", creatorId: "i" }); void cwd; return rest; }, claim: "a baked site is kept as-is (no card file on disk) and the app name is its title" },
  { slot: 242, target: SH, expected: `<!doctype html><html><head><meta name="twitter:card" content="summary_large_image"><meta property="og:title" content="My App"><title>My App</title><link rel="manifest" href="/__grok/manifest.webmanifest"><link rel="apple-touch-icon" href="/__grok/icon-180.png"><meta name="apple-mobile-web-app-title" content="My App"><meta name="apple-mobile-web-app-status-bar-style" content="black"><meta name="theme-color" content="#000000">${SCRIPT}</head><body></body></html>`,
    run: (m) => E(() => m.injectGrokPwaHead("<!doctype html><html><head><title>My App</title></head><body></body></html>", CTX())), claim: "the full injection of a minimal document: share metas after <head>, PWA tags and the extensions script before </head>, document title used as the name" },
  { slot: 243, target: SH, expected: { idempotent: true },
    run: (m) => E(() => { const c = CTX({ projectId: "p1", creator: "Ann", creatorId: "7" }); const once = m.injectGrokPwaHead("<html><head><title>T</title></head><body></body></html>", c); return { idempotent: m.injectGrokPwaHead(once, c) === once }; }), claim: "injecting an already-injected document changes nothing (project id and creator tags included)" },
  { slot: 244, target: SH, expected: { extensionsScripts: 1, appIdMetas: 1, projectMetas: 1 },
    run: (m) => E(() => { const html = `<html><head><title>T</title>${SCRIPT}<meta property="grok:app_id" content="p9"></head></html>`; const o = m.injectGrokPwaHead(html, CTX({ projectId: "p9" })); return { extensionsScripts: count(o, "extensions.js"), appIdMetas: count(o, 'property="grok:app_id"'), projectMetas: count(o, 'name="grok-project-id"') }; }), claim: "an existing extensions script and grok:app_id are not duplicated, but the missing grok-project-id meta is added once" },
  { slot: 245, target: SH, expected: { start: "<!doctype html><html><head>", end: "</head><p>hi</p>", pwaOnce: 1 },
    run: (m) => E(() => { const o = m.injectGrokPwaHead("<p>hi</p>", CTX()); return { start: o.slice(0, 27), end: o.slice(-16), pwaOnce: count(o, 'rel="manifest"') }; }), claim: "a fragment with no <head> is wrapped in a document whose head receives the tags exactly once" },
  { slot: 246, target: SH, expected: { both: 2, nameOnly: 0 },
    run: (m) => E(() => { const h = "<html><head><title>T</title></head></html>"; return { both: count(m.injectGrokPwaHead(h, CTX({ creator: "Ann", creatorId: "7" })), 'property="x:creator'), nameOnly: count(m.injectGrokPwaHead(h, CTX({ creator: "Ann" })), 'property="x:creator') }; }), claim: "x:creator metas are injected as a pair only when both creator values are set" },
  { slot: 247, target: SH, expected: { first: 0, secondHasInjection: true, secondTail: "<body>rest</body>", third: "tail" },
    run: (m) => E(() => { const inj = m.createHeadInjector(CTX()); const a = inj.push("<html><head><title>T</title></he"); const b = inj.push("ad><body>rest</body>"); const c = inj.push("tail"); const s = Buffer.concat(b).toString("utf8"); return { first: a.length, secondHasInjection: s.includes('rel="manifest"') && s.indexOf('rel="manifest"') < s.indexOf("</head>"), secondTail: s.slice(s.indexOf("</head>") + 7), third: Buffer.concat(c).toString("utf8") }; }), claim: "the streaming injector buffers until </head> even when split across chunks, injects before it, and passes later chunks through untouched" },

  // ---- brand check (248-250)
  { slot: 248, target: BR, expected: { count: 1, prefix: "BRAND NOTE: no custom public/og.jpg" },
    run: (m) => { const w = m.computeBrandWarnings({ hasCanvas: false, workspaceRoot: tree(), now: Date.now() }); return { count: w.length, prefix: w[0].slice(0, 35) }; }, claim: "a non-canvas app with no card gets exactly one soft BRAND NOTE (plain-utility exception), not a warning" },
  { slot: 249, target: BR, expected: { count: 2, first: "BRAND WARNING: this looks like a game/canvas app but", firstMentions: "public/og.jpg", second: 'is missing "type": "x:game"' },
    run: (m) => { const w = m.computeBrandWarnings({ hasCanvas: true, workspaceRoot: tree(), now: Date.now() }); return { count: w.length, first: w[0].slice(0, 52), firstMentions: w[0].includes("public/og.jpg") ? "public/og.jpg" : "", second: w[1].includes('is missing "type": "x:game"') ? 'is missing "type": "x:game"' : w[1] }; }, claim: "a canvas/game app with no card gets two warnings: missing og.jpg and missing type x:game" },
  { slot: 250, target: BR, expected: { fresh: 0, stale: 1, noMarker: 1 },
    run: (m) => { const root = tree({ ".grok/og-pending": "1" }); const now = Date.now(); const fresh = m.computeBrandWarnings({ hasCanvas: false, workspaceRoot: root, now }).length; const stale = m.computeBrandWarnings({ hasCanvas: false, workspaceRoot: root, now: now + 11 * 60 * 1000 }).length; const noMarker = m.computeBrandWarnings({ hasCanvas: false, workspaceRoot: tree(), now }).length; return { fresh, stale, noMarker }; },
    claim: "an og-pending marker younger than 10 minutes silences brand output; once older than 10 minutes the missing-card note returns" },
];
