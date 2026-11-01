import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../src/index";
import {
	buildMessages,
	extractJson,
	filesFor,
	sourceContext,
} from "../src/agents";
import {
	heuristicScore,
	mergePlans,
	selectUnion,
} from "../src/triage";
import { applyVerdicts, buildReport, checkEvidence } from "../src/analysis";
import {
	buildDependencyFindings,
	parseComposerLock,
	parseGoMod,
	parsePackageLock,
	parseRequirements,
	parseTomlPackages,
	parseYarnLock,
} from "../src/deps";
import { scanSecrets, sensitiveFileFindings } from "../src/scanners";
import { parseSynthesis, parseVerdicts, pickForVerification } from "../src/verify";
import { validateFindings } from "../src/findings";
import { isCandidate } from "../src/github";
import { redactSecrets, safeEqual } from "../src/security";
import { parseSseLine, readChatStream } from "../src/stream";
import type { Env, RepoEntry, RepositorySnapshot } from "../src/env";

const KEY = "k".repeat(40);
const testEnv = (extra: Partial<Env> = {}) =>
	({
		...env,
		ANALYSIS_API_KEY: KEY,
		GITHUB_INSTALLATION_ID: "123",
		ACCESS_TEAM_DOMAIN: "",
		ACCESS_POLICY_AUD: "",
		...extra,
	}) as unknown as Env;

const call = (
	path: string,
	init: RequestInit = {},
	e: Env = testEnv(),
) => worker.fetch(new Request(`https://example.com${path}`, init), e);

const authed = (extra: Record<string, string> = {}) => ({
	Authorization: `Bearer ${KEY}`,
	...extra,
});

beforeAll(async () => {
	await env.DB.batch([
		env.DB.prepare(
			"CREATE TABLE IF NOT EXISTS analysis_runs (id TEXT PRIMARY KEY, owner TEXT NOT NULL, repo TEXT NOT NULL, requested_ref TEXT, commit_sha TEXT, status TEXT NOT NULL, report_json TEXT, error_message TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
		),
		env.DB.prepare(
			"CREATE TABLE IF NOT EXISTS agent_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, agent TEXT NOT NULL, kind TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL)",
		),
		env.DB.prepare(
			"CREATE TABLE IF NOT EXISTS ai_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, agent TEXT NOT NULL, model TEXT NOT NULL, neurons REAL NOT NULL, created_at TEXT NOT NULL)",
		),
	]);
});

describe("authentication", () => {
	it("rejects requests without credentials", async () => {
		const res = await call("/api/runs");
		expect(res.status).toBe(401);
		expect(res.headers.get("content-security-policy")).toContain(
			"default-src 'none'",
		);
	});

	it("rejects a wrong API key", async () => {
		const res = await call("/api/runs", {
			headers: { Authorization: "Bearer nope" },
		});
		expect(res.status).toBe(401);
	});

	it("fails closed when no API key is configured", async () => {
		const res = await call(
			"/api/runs",
			{ headers: { Authorization: "Bearer undefined" } },
			testEnv({ ANALYSIS_API_KEY: undefined }),
		);
		expect(res.status).toBe(401);
	});

	it("rejects a weak API key even when it matches", async () => {
		const res = await call(
			"/api/runs",
			{ headers: { Authorization: "Bearer short" } },
			testEnv({ ANALYSIS_API_KEY: "short" }),
		);
		expect(res.status).toBe(401);
	});

	it("rejects a forged Access JWT", async () => {
		const res = await call(
			"/",
			{ headers: { "cf-access-jwt-assertion": "a.b.c" } },
			testEnv({
				ACCESS_TEAM_DOMAIN: "https://team.cloudflareaccess.com",
				ACCESS_POLICY_AUD: "aud",
			}),
		);
		expect(res.status).toBe(401);
	});

	it("only bypasses Access on localhost when explicitly enabled", async () => {
		const e = testEnv({ DEV_BYPASS_ACCESS: "true" });
		const remote = await worker.fetch(
			new Request("https://example.com/api/runs"),
			e,
		);
		expect(remote.status).toBe(401);
		const local = await worker.fetch(
			new Request("http://localhost/api/runs"),
			e,
		);
		expect(local.status).toBe(200);
	});

	it("compares secrets without length leaks", async () => {
		expect(await safeEqual("abc", "abc")).toBe(true);
		expect(await safeEqual("abc", "abcd")).toBe(false);
	});
});

describe("run API", () => {
	const post = (body: unknown) =>
		call("/api/runs", {
			method: "POST",
			headers: authed({ "Content-Type": "application/json" }),
			body: JSON.stringify(body),
		});

	it("validates owner, repo and ref", async () => {
		expect((await post({ owner: "../x", repo: "y" })).status).toBe(400);
		expect((await post({ owner: "a", repo: "b", ref: "a..b" })).status).toBe(400);
		expect((await post({ owner: "a", repo: "b", ref: "x y" })).status).toBe(400);
	});

	it("requires a JSON content type", async () => {
		const res = await call("/api/runs", {
			method: "POST",
			headers: authed({ "Content-Type": "text/plain" }),
			body: JSON.stringify({ owner: "a", repo: "b" }),
		});
		expect(res.status).toBe(415);
	});

	it("rejects cross-origin posts from browser sessions", async () => {
		const e = testEnv({ DEV_BYPASS_ACCESS: "true" });
		const res = await worker.fetch(
			new Request("http://localhost/api/runs", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Origin: "https://evil.example",
				},
				body: JSON.stringify({ owner: "a", repo: "b" }),
			}),
			e,
		);
		expect(res.status).toBe(403);
	});

	it("refuses to start when the installation is not configured", async () => {
		const res = await worker.fetch(
			new Request("https://example.com/api/runs", {
				method: "POST",
				headers: authed({ "Content-Type": "application/json" }),
				body: JSON.stringify({ owner: "a", repo: "b" }),
			}),
			testEnv({ GITHUB_INSTALLATION_ID: undefined }),
		);
		expect(res.status).toBe(503);
	});

	it("returns events after a cursor", async () => {
		const id = crypto.randomUUID();
		const now = new Date().toISOString();
		await env.DB.batch([
			env.DB.prepare(
				"INSERT INTO analysis_runs (id, owner, repo, status, created_at, updated_at) VALUES (?, 'o', 'r', 'running', ?, ?)",
			).bind(id, now, now),
			env.DB.prepare(
				"INSERT INTO agent_events (run_id, agent, kind, content, created_at) VALUES (?, 'security', 'thinking', 'hmm', ?)",
			).bind(id, now),
		]);

		const res = await call(`/api/runs/${id}/events?after=0`, {
			headers: authed(),
		});
		const body = (await res.json()) as any;
		expect(body.status).toBe("running");
		expect(body.events).toHaveLength(1);

		const next = await call(`/api/runs/${id}/events?after=${body.last}`, {
			headers: authed(),
		});
		expect(((await next.json()) as any).events).toHaveLength(0);
	});
});

describe("usage meter", () => {
	it("sums only today's recorded spend", async () => {
		const day = new Date().toISOString();
		const old = new Date(Date.now() - 3 * 86_400_000).toISOString();
		await env.DB.batch([
			env.DB.prepare("DELETE FROM ai_usage"),
			env.DB.prepare(
				"INSERT INTO ai_usage (run_id, agent, model, neurons, created_at) VALUES ('r', 'a', 'm', 100.5, ?)",
			).bind(day),
			env.DB.prepare(
				"INSERT INTO ai_usage (run_id, agent, model, neurons, created_at) VALUES ('r', 'a', 'm', 999, ?)",
			).bind(old),
		]);

		const res = await call("/api/usage", { headers: authed() });
		const body = (await res.json()) as any;
		expect(body.used).toBeCloseTo(100.5);
		expect(body.limit).toBe(10000);
	});
});

describe("streaming", () => {
	it("parses reasoning and content deltas", () => {
		expect(
			parseSseLine(
				'data: {"choices":[{"delta":{"reasoning_content":"think"}}]}',
			),
		).toEqual({ reasoning: "think" });
		expect(
			parseSseLine('data: {"choices":[{"delta":{"content":"hi"}}]}'),
		).toEqual({ content: "hi" });
		expect(parseSseLine('data: {"response":"legacy"}')).toEqual({
			content: "legacy",
		});
		expect(parseSseLine("data: [DONE]")).toBeNull();
		expect(parseSseLine("data: {not json")).toBeNull();
	});

	it("distinguishes per-chunk and total neuron usage", () => {
		expect(
			parseSseLine(
				'data: {"choices":[{"delta":{"content":"x"}}],"usage":{"neurons":0.5}}',
			),
		).toEqual({ content: "x", neurons: 0.5 });
		expect(
			parseSseLine('data: {"response":"","usage":{"neurons":12.9}}'),
		).toEqual({ totalNeurons: 12.9 });
	});

	it("reassembles lines split across chunks", async () => {
		const line = 'data: {"choices":[{"delta":{"content":"ab"}}]}\n\n';
		const bytes = new TextEncoder().encode(line + "data: [DONE]\n");
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(bytes.slice(0, 20));
				controller.enqueue(bytes.slice(20));
				controller.close();
			},
		});
		const out: string[] = [];
		for await (const d of readChatStream(stream)) out.push(d.content ?? "");
		expect(out).toEqual(["ab"]);
	});
});

describe("analysis pipeline", () => {
	const snapshot: RepositorySnapshot = {
		owner: "o",
		repo: "r",
		commitSha: "abc",
		skippedFiles: 0,
		files: [
			{
				path: "src/a.ts",
				size: 10,
				content: "line1\nconst token = eval(input);\nline3\nline4",
			},
		],
	};
	const finding = (over: object = {}) => ({
		title: "eval",
		category: "security" as const,
		severity: "high" as const,
		confidence: 0.9,
		file: "src/a.ts",
		startLine: 2,
		endLine: 2,
		evidence: "const token = eval(input);",
		explanation: "bad",
		recommendation: "stop",
		...over,
	});

	it("keeps findings whose evidence matches, tolerating near lines", () => {
		const report = buildReport(snapshot, [
			[finding(), finding({ title: "off by one", startLine: 3, endLine: 3 })],
		]);
		expect(report.findings).toHaveLength(2);
	});

	it("accepts evidence that copied line-number prefixes or used ellipses", () => {
		const report = buildReport(snapshot, [
			[
				finding({ evidence: "2:const token = eval(input);" }),
				finding({
					title: "elided",
					evidence: "line1 ... const token = eval(input);",
					startLine: 1,
					endLine: 2,
				}),
			],
		]);
		expect(report.findings).toHaveLength(2);
	});

	it("drops findings with fabricated evidence or paths", () => {
		const report = buildReport(snapshot, [
			[
				finding({ evidence: "something never in the file" }),
				finding({ file: "src/missing.ts" }),
			],
		]);
		expect(report.findings).toHaveLength(0);
	});

	it("notes incomplete agents", () => {
		const report = buildReport(snapshot, [[]], ["testing"]);
		expect(report.incompleteAgents).toEqual(["testing"]);
		expect(report.summary).toContain("testing");
	});

	it("validates model output shape", () => {
		const lines = new Map([["src/a.ts", 4]]);
		expect(validateFindings([finding({ endLine: 99 })], lines)).toHaveLength(0);
		expect(validateFindings([finding()], lines)).toHaveLength(1);
		expect(validateFindings("nope", lines)).toEqual([]);
		const { endLine: _omitted, ...noEnd } = finding();
		expect(validateFindings([noEnd], lines)[0].endLine).toBe(2);
		expect(validateFindings([finding({ confidence: 85 })], lines)[0].confidence).toBe(0.85);
	});

	it("extracts JSON from fenced and thinking-wrapped output", () => {
		expect(
			extractJson('<think>x</think>```json\n{"findings":[]}\n```'),
		).toEqual({ findings: [] });
		expect(extractJson('Sure! {"findings":[]} done')).toEqual({
			findings: [],
		});
		expect(() => extractJson("no json")).toThrow();
	});

	it("skips oversized files without dropping later ones", () => {
		const big = { path: "big.ts", size: 1, content: "x".repeat(300_000) };
		const small = { path: "small.ts", size: 1, content: "ok" };
		const ctx = sourceContext({ ...snapshot, files: [big, small] });
		expect(ctx.included).toBe(1);
		expect(ctx.text).toContain("small.ts");
	});
});

describe("repository filtering and redaction", () => {
	it("excludes secrets, lockfiles and nested vendor dirs", () => {
		expect(isCandidate("src/index.ts")).toBe(true);
		expect(isCandidate("packages/a/node_modules/x/index.js")).toBe(false);
		expect(isCandidate("deploy/key.pem")).toBe(false);
		expect(isCandidate(".dev.vars")).toBe(false);
		expect(isCandidate(".npmrc")).toBe(false);
		expect(isCandidate("package-lock.json")).toBe(false);
		expect(isCandidate("infra/prod.tfstate")).toBe(false);
	});

	it("redacts common secret shapes", () => {
		const out = redactSecrets(
			"ghp_" +
				"a".repeat(36) +
				" AKIAABCDEFGHIJKLMNOP api_key = 'supersecretvalue'",
		);
		expect(out).not.toContain("ghp_a");
		expect(out).not.toContain("AKIAABCD");
		expect(out).not.toContain("supersecretvalue");
		expect(
			redactSecrets(
				"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
			),
		).toBe("[REDACTED PRIVATE KEY]");
	});
});

describe("triage", () => {
	const entry = (path: string, size = 2000): RepoEntry => ({
		path,
		size,
		sha: path,
	});
	const entries = [
		entry("package.json", 500),
		entry("src/auth/session.ts"),
		entry("src/index.ts"),
		entry("src/util.ts"),
		entry("test/session.test.ts"),
		entry("docs/guide.md"),
	];

	it("ranks files differently per specialist", () => {
		const auth = entries[1];
		const test = entries[4];
		expect(heuristicScore(auth, "security")).toBeGreaterThan(
			heuristicScore(entries[3], "security"),
		);
		expect(heuristicScore(test, "testing")).toBeGreaterThan(
			heuristicScore(test, "security"),
		);
	});

	it("ignores invented paths from the model and pads from heuristics", () => {
		const plan = mergePlans(
			{ security: ["src/auth/session.ts", "made/up.ts", 42] },
			entries,
		);
		expect(plan.security[0]).toBe("src/auth/session.ts");
		expect(plan.security).not.toContain("made/up.ts");
		expect(plan.testing.length).toBeGreaterThan(0);
		expect(mergePlans("garbage", entries).security.length).toBeGreaterThan(0);
	});

	it("respects file and byte budgets, interleaving specialists", () => {
		const plan = mergePlans(null, entries);
		const { selected, assigned } = selectUnion(plan, entries, 3, 1_000_000);
		expect(selected).toHaveLength(3);
		for (const paths of Object.values(assigned)) {
			for (const p of paths) {
				expect(selected.map((e) => e.path)).toContain(p);
			}
		}
		const tight = selectUnion(plan, entries, 10, 2500);
		expect(tight.selected.reduce((n, e) => n + e.size, 0)).toBeLessThanOrEqual(2500);
	});

	it("limits each specialist to its assigned files", () => {
		const snapshot: RepositorySnapshot = {
			owner: "o",
			repo: "r",
			commitSha: "abc",
			skippedFiles: 0,
			files: [
				{ path: "a.ts", size: 1, content: "a" },
				{ path: "b.ts", size: 1, content: "b" },
			],
			assigned: { security: ["b.ts"] },
		};
		expect(filesFor(snapshot, "security").map((f) => f.path)).toEqual(["b.ts"]);
		expect(filesFor(snapshot, "testing")).toHaveLength(2);
	});
});

describe("prompt layout", () => {
	it("lists every path and puts the task after the source", () => {
		const snapshot: RepositorySnapshot = {
			owner: "o",
			repo: "r",
			commitSha: "abc",
			skippedFiles: 0,
			files: [{ path: "a.ts", size: 1, content: "x" }],
			paths: ["a.ts", "tests/a.test.ts"],
		};
		const [system, user] = buildMessages(snapshot, "testing", "SOURCE-MARKER");
		expect(user.content).toContain("tests/a.test.ts");
		expect(user.content.indexOf("SOURCE-MARKER")).toBeLessThan(
			user.content.indexOf("TASK (category: testing)"),
		);
		expect(system.content).toContain("WITHOUT the \"N: \" prefix");
	});
});

describe("secrets scanner", () => {
	const snapshot = (path: string, content: string): RepositorySnapshot => ({
		owner: "o",
		repo: "r",
		commitSha: "abc",
		skippedFiles: 0,
		files: [{ path, size: content.length, content }],
	});

	it("flags real-looking tokens without storing the value", () => {
		const token = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jK5";
		const findings = scanSecrets(
			snapshot("src/config.ts", `const t = "${token}";`),
		);
		expect(findings).toHaveLength(1);
		expect(findings[0].category).toBe("secrets");
		expect(JSON.stringify(findings)).not.toContain(token);
	});

	it("ignores placeholders and env lookups", () => {
		const findings = scanSecrets(
			snapshot(
				"src/config.ts",
				[
					'api_key = "your-api-key-here"',
					'password: "process.env.DB_PASSWORD"',
					'token = "aaaaaaaaaaaaaaaaaaaa"',
				].join("\n"),
			),
		);
		expect(findings).toHaveLength(0);
	});

	it("downgrades hits in tests and reports committed key files", () => {
		const token = "AKIA" + "ABCDEFGHIJKLMNOP";
		const [hit] = scanSecrets(snapshot("tests/fixture.ts", `x = "${token}"`));
		expect(hit.severity).toBe("medium");

		const files = sensitiveFileFindings(["id_rsa", ".env", ".env.example"]);
		expect(files.map((f) => f.file)).toEqual(["id_rsa", ".env"]);
	});
});

describe("dependency check", () => {
	it("parses npm lockfiles (v3 and v1)", () => {
		const v3 = JSON.stringify({
			packages: {
				"": { name: "root" },
				"node_modules/lodash": { version: "4.17.15" },
				"node_modules/a/node_modules/@s/b": { version: "1.0.0" },
				"node_modules/linked": { link: true },
			},
		});
		expect(parsePackageLock(v3).map((d) => `${d.name}@${d.version}`)).toEqual([
			"lodash@4.17.15",
			"@s/b@1.0.0",
		]);
		const v1 = JSON.stringify({
			dependencies: { x: { version: "1.0.0", dependencies: { y: { version: "2.0.0" } } } },
		});
		expect(parsePackageLock(v1)).toHaveLength(2);
	});

	it("parses yarn, cargo, poetry, go, pip and composer", () => {
		expect(
			parseYarnLock('"@a/b@^1.0.0", "@a/b@^1.1.0":\n  version "1.2.3"\n\nlodash@^4:\n  version "4.17.15"\n'),
		).toEqual([
			{ ecosystem: "npm", name: "@a/b", version: "1.2.3" },
			{ ecosystem: "npm", name: "lodash", version: "4.17.15" },
		]);

		const cargo = [
			'[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
			'[[package]]\nname = "mine"\nversion = "0.1.0"\n',
		].join("\n");
		expect(parseTomlPackages(cargo, "crates.io", true)).toEqual([
			{ ecosystem: "crates.io", name: "serde", version: "1.0.1" },
		]);

		expect(
			parseGoMod("module x\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\nrequire c/d v0.1.0"),
		).toEqual([
			{ ecosystem: "Go", name: "github.com/a/b", version: "1.2.3" },
			{ ecosystem: "Go", name: "c/d", version: "0.1.0" },
		]);
		expect(parseRequirements("requests==2.19.0  # pin\nflask>=2")).toEqual([
			{ ecosystem: "PyPI", name: "requests", version: "2.19.0" },
		]);
		expect(
			parseComposerLock(JSON.stringify({ packages: [{ name: "a/b", version: "v1.0.0" }] })),
		).toEqual([{ ecosystem: "Packagist", name: "a/b", version: "1.0.0" }]);
	});

	it("turns OSV answers into findings with severity and fixes", () => {
		const deps = [
			{ ecosystem: "npm", name: "lodash", version: "4.17.15" },
			{ ecosystem: "npm", name: "safe", version: "1.0.0" },
		];
		const details = new Map([
			[
				"GHSA-1",
				{
					id: "GHSA-1",
					summary: "Command injection",
					database_specific: { severity: "HIGH" },
					affected: [
						{
							package: { name: "lodash" },
							ranges: [{ events: [{ fixed: "4.17.21" }] }],
						},
					],
				},
			],
		]);
		const findings = buildDependencyFindings(
			deps,
			[["GHSA-1"], []],
			details,
			() => ({ file: "package-lock.json", line: 7 }),
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({
			category: "dependencies",
			severity: "high",
			startLine: 7,
		});
		expect(findings[0].recommendation).toContain("4.17.21");
	});
});

describe("verification and synthesis", () => {
	const mk = (title: string, severity: "high" | "low", confidence = 0.9) => ({
		title,
		category: "security" as const,
		severity,
		confidence,
		file: "src/a.ts",
		startLine: 2,
		endLine: 2,
		evidence: "const token = eval(input);",
		explanation: "x",
		recommendation: "y",
	});

	it("applies verdicts: drops refuted, annotates the rest", () => {
		const list = [mk("a", "high"), mk("b", "high"), mk("c", "high")];
		const { kept, dismissed } = applyVerdicts(list, [
			{ id: 0, verdict: "refuted", reason: "guarded on line 3" },
			{ id: 1, verdict: "uncertain", reason: "depends on caller" },
		]);
		expect(dismissed.map((d) => d.title)).toEqual(["a"]);
		expect(kept.map((f) => f.title)).toEqual(["b", "c"]);
		expect(kept[0].verification).toBe("uncertain");
		expect(kept[0].confidence).toBeCloseTo(0.72);
		expect(kept[1].verification).toBeUndefined();
	});

	it("parses verdicts defensively", () => {
		const verdicts = parseVerdicts(
			JSON.stringify({
				verdicts: [
					{ id: 0, verdict: "confirmed", reason: "ok" },
					{ id: 0, verdict: "refuted", reason: "duplicate id" },
					{ id: 9, verdict: "refuted", reason: "out of range" },
					{ id: 1, verdict: "maybe", reason: "bad verdict" },
				],
			}),
			2,
		);
		expect(verdicts).toEqual([{ id: 0, verdict: "confirmed", reason: "ok" }]);
	});

	it("verifies the most severe findings first", () => {
		const list = [
			...Array.from({ length: 15 }, (_, i) => mk(`low${i}`, "low")),
			mk("important", "high"),
		];
		const picked = pickForVerification(list);
		expect(picked).toHaveLength(12);
		expect(picked[0].title).toBe("important");
	});

	it("validates the summary's finding indexes", () => {
		const out = parseSynthesis(
			JSON.stringify({
				overview: "Mostly fine.",
				priorities: [{ action: "Fix eval", why: "RCE", findings: [0, 7, "x"] }],
			}),
			2,
		);
		expect(out?.priorities[0].findingIndexes).toEqual([0]);
		expect(parseSynthesis('{"priorities":[]}', 1)).toBeNull();
	});
});

describe("trust boundaries", () => {
	const snapshot: RepositorySnapshot = {
		owner: "o",
		repo: "r",
		commitSha: "abc",
		skippedFiles: 0,
		files: [{ path: "src/a.ts", size: 1, content: "hello world" }],
	};
	const base = {
		severity: "high" as const,
		confidence: 0.9,
		file: "package-lock.json",
		startLine: 1,
		endLine: 1,
		evidence: "lodash@4.17.15",
		explanation: "x",
		recommendation: "y",
	};

	it("passes scanner findings through but not model findings", () => {
		const scanner = { ...base, title: "dep", category: "dependencies" as const };
		const model = { ...base, title: "dep", category: "security" as const };
		expect(checkEvidence(snapshot, [[scanner, model]])).toEqual([scanner]);
	});

	it("forces the specialist's own category onto model output", () => {
		const lines = new Map([["src/a.ts", 3]]);
		const [f] = validateFindings(
			[{ ...base, file: "src/a.ts", title: "t", category: "secrets" }],
			lines,
			"security",
		);
		expect(f.category).toBe("security");
	});

	it("keeps infrastructure to genuine CI and deploy files", () => {
		const entries: RepoEntry[] = [
			{ path: ".github/workflows/ci.yml", size: 900, sha: "1" },
			{ path: "Dockerfile", size: 300, sha: "2" },
			{ path: "src/index.ts", size: 5000, sha: "3" },
		];
		const plan = mergePlans(
			{ infrastructure: ["src/index.ts", ".github/workflows/ci.yml"] },
			entries,
		);
		expect(plan.infrastructure).toContain(".github/workflows/ci.yml");
		expect(plan.infrastructure).toContain("Dockerfile");
		expect(plan.infrastructure).not.toContain("src/index.ts");
		expect(mergePlans(null, [entries[2]]).infrastructure).toEqual([]);
	});
});
