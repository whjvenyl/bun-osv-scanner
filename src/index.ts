/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

/// <reference types="bun-types" />
import "./types.js";
import { OSVClient } from "./client.js";
import { VulnerabilityProcessor } from "./processor.js";
import { logger } from "./logger.js";
import { loadIgnoreRules, filterAdvisories } from "./ignore.js";

/**
 * Bun Security Scanner for OSV.dev vulnerability detection
 * Integrates with Google's OSV database to detect vulnerabilities in npm packages
 */
export const scanner: Bun.Security.Scanner = {
	version: "1", // This is the version of Bun security scanner implementation. You should keep this set as '1'

	async scan({ packages }) {
		try {
			logger.info(`Starting OSV scan for ${packages.length} packages`);

			// Initialize components
			const client = new OSVClient();
			const processor = new VulnerabilityProcessor();

			// Fetch vulnerabilities from OSV.dev
			const vulnerabilities = await client.queryVulnerabilities(packages);

			// Process vulnerabilities into security advisories
			const advisories = processor.processVulnerabilities(
				vulnerabilities,
				packages,
			);

			// Apply ignore rules before returning results
			const rules = await loadIgnoreRules(process.cwd());
			logger.info(`Loaded ${rules.length} ignore rules`);

			// Filter advisories based on ignore rules
			const { kept, ignored } = filterAdvisories(advisories, rules);

			if (ignored.length > 0) {
				logger.info(
					`Ignored ${ignored.length} advisories via rules (.bun-osv.json, package.json bunOsv.ignore, env)`,
				);
			}

			// If requested, still report ignored advisories but demoted to warnings
			const showIgnored =
				(process.env.BUN_OSV_SHOW_IGNORED ?? "1").toLowerCase() !== "false" &&
				(process.env.BUN_OSV_SHOW_IGNORED ?? "1") !== "0";

			// ANSI style for [ignored]: bold + red, fallback to plain if NO_COLOR
			const supportsColor =
				!!process.stdout?.isTTY &&
				(process.env.NO_COLOR === undefined ||
					process.env.NO_COLOR === "0" ||
					process.env.NO_COLOR === "false");
			const ignoredTag = supportsColor
				? "\x1b[1m\x1b[31m[ignored]\x1b[0m"
				: "[ignored]";

			let output = kept as any[];

			if (showIgnored && ignored.length > 0) {
				const demoted = ignored.map((a: any) => ({
					...a,
					level: "warn", // ensure it won't block install
					description: `${a.description ?? ""} ${ignoredTag}`.trim(),
				}));
				output = [...kept, ...demoted];
			}

			logger.info(
				`OSV scan completed: ${output.length} advisories reported (from ${advisories.length} total) for ${packages.length} packages` +
					(ignored.length && showIgnored
						? ` (${ignored.length} ignored shown as warnings)`
						: ""),
			);

			// Return an empty array if there are no advisories!
			// Only return non-ignored advisories so installs proceed when everything is ignored.
			return output;
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			logger.error("OSV scanner encountered an unexpected error", {
				error: message,
			});

			// Fail-safe: allow installation to proceed on scanner errors
			return [];
		}
	},
};

// CLI entry point
if (import.meta.main) {
	const { runCli } = await import("./cli.js");
	await runCli();
}
