import fs from "node:fs";
import path from "node:path";
import semver from "semver";

export type IgnoreRule = {
	package?: string;
	range?: string;
	advisory?: string;
	reason?: string;
	expires?: string;
};

function readJSON<T = unknown>(file: string): T | undefined {
	try {
		return JSON.parse(fs.readFileSync(file, "utf8")) as T;
	} catch {
		return undefined;
	}
}

function normalizeName(s?: string): string | undefined {
	return typeof s === "string" ? s.trim().toLowerCase() : undefined;
}

function isExpired(rule: IgnoreRule, now = new Date()): boolean {
	if (!rule.expires) return false;
	const d = new Date(rule.expires);
	return Number.isFinite(d.getTime()) && d < now;
}

function loadIgnoreFromFile(filePath: string): IgnoreRule[] {
	const json = readJSON<any>(filePath);
	if (!json) return [];
	if (Array.isArray(json)) return json as IgnoreRule[];
	if (Array.isArray(json.ignore)) return json.ignore as IgnoreRule[];
	if (json.packages && typeof json.packages === "object") {
		return Object.entries(json.packages).map(([name, range]) => ({
			package: String(name),
			range: typeof range === "string" ? range : "*",
		}));
	}
	return [];
}

function parseEnvList(name: string): string[] {
	const v = process.env[name];
	if (!v) return [];
	return v
		.split(/[,\s]+/g)
		.map((s) => s.trim())
		.filter(Boolean);
}

function rulesFromEnv(): IgnoreRule[] {
	const pkgTokens = parseEnvList("BUN_OSV_IGNORE_PKG"); // e.g. "ip@*", "lodash@<4.17.21"
	const advTokens = parseEnvList("BUN_OSV_IGNORE_ADVISORY"); // e.g. "CVE-2024-29415"

	const pkgRules = pkgTokens.map((tok) => {
		const at = tok.indexOf("@");
		if (at > 0) return { package: tok.slice(0, at), range: tok.slice(at + 1) };
		return { package: tok, range: "*" };
	});

	const advRules = advTokens.map((id) => ({ advisory: id }));
	return [...pkgRules, ...advRules];
}

export async function loadIgnoreRules(cwd: string): Promise<IgnoreRule[]> {
	const rules: IgnoreRule[] = [];

	rules.push(...loadIgnoreFromFile(path.join(cwd, ".bun-osv.json")));

	const pkg = readJSON<any>(path.join(cwd, "package.json"));
	if (pkg?.bunOsv?.ignore && Array.isArray(pkg.bunOsv.ignore)) {
		rules.push(...(pkg.bunOsv.ignore as IgnoreRule[]));
	}

	const extFile =
		process.env.BUN_OSV_IGNORE_FILE || process.env.OSV_IGNORE_FILE;
	if (extFile) {
		const abs = path.isAbsolute(extFile) ? extFile : path.join(cwd, extFile);
		rules.push(...loadIgnoreFromFile(abs));
	}

	rules.push(...rulesFromEnv());

	// normalize
	return rules
		.filter((r) => r && (r.package || r.advisory))
		.map((r) => ({
			...r,
			package: normalizeName(r.package),
			range: r.range || (r.package ? "*" : undefined),
			advisory: r.advisory?.trim(),
		}));
}

// ----- Robust extraction helpers -----
function collectAdvisoryIds(a: any): string[] {
	const ids: string[] = [];
	const push = (v?: unknown) => {
		if (typeof v === "string" && v.trim()) ids.push(v.trim());
	};
	const pushAll = (arr?: unknown) => {
		if (Array.isArray(arr)) for (const v of arr) push(v);
	};

	push(a?.id);
	push(a?.advisory?.id);
	push(a?.cve);
	push(a?.ghsa);
	push(a?.osvId);
	push(a?.cveId);
	push(a?.vulnerabilityId);
	pushAll(a?.aliases);
	pushAll(a?.ids);
	pushAll(a?.identifiers);

	const urls: string[] = [];
	if (typeof a?.url === "string") urls.push(a.url);
	if (Array.isArray(a?.urls))
		urls.push(...a.urls.filter((u: unknown) => typeof u === "string"));
	if (Array.isArray(a?.references)) {
		for (const r of a.references) {
			if (typeof r === "string") urls.push(r);
			else if (r && typeof r.url === "string") urls.push(r.url);
		}
	}

	for (const u of urls) {
		const cve = u.match(/CVE-\d{4}-\d{4,7}/i);
		if (cve) ids.push(cve[0]);
		const ghsa = u.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
		if (ghsa) ids.push(ghsa[0]);
		const osv = u.match(/OSV-\d{4}-\d+/i);
		if (osv) ids.push(osv[0]);
	}

	// normalize to uppercase for comparison, dedupe
	return Array.from(new Set(ids.map((s) => s.toUpperCase())));
}

function getAdvisoryPkgName(a: any): string | undefined {
	const candidates = [
		typeof a?.package === "string" ? a.package : undefined, // support package as string
		a?.package?.name,
		a?.package_name,
		a?.packageName,
		a?.module_name,
		a?.moduleName,
		a?.module,
		a?.dependency?.name,
		a?.name,
	];
	for (const c of candidates) {
		const n = normalizeName(c);
		if (n) return n;
	}
	return undefined;
}

function getAdvisoryPkgVersion(a: any): string | undefined {
	return (
		a?.package?.version ??
		a?.installed_version ??
		a?.installedVersion ??
		a?.version ??
		a?.dependency?.version
	);
}

function matchesRule(a: any, r: IgnoreRule, now = new Date()): boolean {
	if (isExpired(r, now)) return false;

	// advisory id or alias (CVE/GHSA/OSV) match, including from URLs
	if (r.advisory) {
		const normRuleId = r.advisory.trim().toUpperCase();
		const ids = collectAdvisoryIds(a);
		if (ids.includes(normRuleId)) return true;
	}

	// package match (case-insensitive)
	if (r.package) {
		const name = getAdvisoryPkgName(a);
		if (name && name === r.package) {
			if (!r.range || r.range === "*") return true;

			const v = getAdvisoryPkgVersion(a);
			if (v && semver.valid(v)) {
				try {
					return semver.satisfies(v, r.range, { includePrerelease: true });
				} catch {
					return true; // invalid range -> fall back to name-only
				}
			}
			return true; // missing/non-semver version -> name-only
		}
	}
	return false;
}

export function filterAdvisories<T = any>(
	advisories: T[],
	rules: IgnoreRule[],
	now = new Date(),
): { kept: T[]; ignored: T[] } {
	const kept: T[] = [];
	const ignored: T[] = [];

	for (const a of advisories) {
		let matched = false;
		for (const r of rules) {
			if (matchesRule(a, r, now)) {
				matched = true;
				break;
			}
		}
		if (matched) ignored.push(a);
		else kept.push(a);
	}
	return { kept, ignored };
}
