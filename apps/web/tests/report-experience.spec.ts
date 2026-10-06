import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.exposeFunction("recordBrowserErrors", () => errors);
});

test.afterEach(async ({ page }) => {
  const errors = await page.evaluate(() => (window as unknown as { recordBrowserErrors: () => Promise<string[]> }).recordBrowserErrors());
  expect(errors).toEqual([]);
});

test("explains the product and keeps the main action clear on desktop and mobile", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveTitle("Free MCP Report | AgntID Observatory");
  await expect(page.getByRole("link", { name: "Free MCP Report home" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Understand your MCP server before connecting an AI agent.");
  await expect(page.getByText("We inspect advertised metadata. We never execute your tools.")).toBeVisible();
  await expect(page.getByText(/Reports are visible to everyone with access/)).toBeVisible();
  const generate = page.getByRole("button", { name: "Generate your MCP report", exact: true });
  await expect(generate).toBeDisabled();
  await page.getByLabel("MCP Server URL", { exact: true }).fill("https://example.com/mcp");
  await expect(generate).toBeEnabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("landing.png"), fullPage: true });
});

test("navigation supports keyboard dismissal and theme switching", async ({ page }) => {
  await page.goto("/");
  const menu = page.getByRole("button", { name: "Open navigation" });
  await menu.click();
  await expect(page.getByRole("link", { name: "Generate a report", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(menu).toBeFocused();
  await expect(page.getByRole("navigation", { name: "Assessment navigation" })).not.toBeVisible();
  await page.getByRole("button", { name: "Switch to dark theme" }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.screenshot({ path: test.info().outputPath("landing-dark.png"), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("shows a useful error when the assessment cannot be queued", async ({ page }) => {
  await page.route("**/api/v1/assessments", async (route) => {
    if (route.request().method() === "POST") {
      expect(route.request().postDataJSON()).toEqual({
        mode: "live", target: { protocol: "mcp", url: "https://example.com/mcp" },
      });
      await route.fulfill({ status: 422, json: { detail: "Fixture endpoint is unavailable." } });
    } else await route.continue();
  });
  await page.goto("/");
  await page.getByLabel("MCP Server URL", { exact: true }).fill("https://example.com/mcp");
  await page.getByRole("button", { name: "Generate your MCP report", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Fixture endpoint is unavailable." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Try again" })).toBeVisible();
});

test("requests credentials only after anonymous access fails", async ({ page }) => {
  const id = "fixture-authentication";
  let tokenRequested = false;
  await page.route("**/api/v1/assessments", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const body = route.request().postDataJSON();
    if (body.credentialProfiles) {
      tokenRequested = true;
      expect(body.credentialProfiles[0]).toEqual({ label: "Authenticated access", bearerToken: "fixture-token" });
      return route.fulfill({ status: 422, json: { detail: "Fixture credential was rejected." } });
    }
    return route.fulfill({ status: 202, json: { assessmentId: id, status: "queued", eventsUrl: "" } });
  });
  await page.route("**/api/v1/assessments/" + id, (route) => route.fulfill({
    json: { id, status: "partial", mode: "live", connectionStatus: "authentication-required", target: { url: "https://example.com/mcp" } },
  }));
  await page.goto("/");
  await page.getByLabel("MCP Server URL", { exact: true }).fill("https://example.com/mcp");
  await page.getByRole("button", { name: "Generate your MCP report", exact: true }).click();
  await expect(page.getByText("This endpoint requires authentication")).toBeVisible();
  await page.getByLabel("Bearer token", { exact: true }).fill("fixture-token");
  await page.getByRole("button", { name: "Generate your MCP report", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Fixture credential was rejected." })).toBeVisible();
  expect(tokenRequested).toBe(true);
});

test("handles unavailable workspace data without claiming successful results", async ({ page }) => {
  await page.route("**/api/v1/dashboard/summary", (route) => route.fulfill({ status: 503, json: { detail: "Workspace data unavailable" } }));
  await page.route("**/api/v1/assessments?*", (route) => route.fulfill({ status: 503, json: { detail: "Workspace data unavailable" } }));
  await page.goto("/");
  await expect(page.getByText(/Workspace data unavailable.*Confirm that/)).toBeVisible();
  await expect(page.getByText("Average score", { exact: true })).not.toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
});

test("uploads a real snapshot and exports a truthful completed report", async ({ page, request }) => {
  const snapshotFile = path.resolve(process.cwd(), "../../fixtures/offline-snapshot.json");
  await page.goto("/assessments/new");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Generate your MCP report");
  await page.getByRole("button", { name: /Use saved metadata/ }).click();
  await page.locator("#snapshot-file").setInputFiles(snapshotFile);
  await expect(page.getByText("2 tool contracts ready for assessment")).toBeVisible();
  const queued = page.waitForResponse((response) => response.url().endsWith("/api/v1/assessments") && response.request().method() === "POST");
  await page.getByRole("button", { name: "Generate your MCP report", exact: true }).click();
  const created = await (await queued).json();
  let assessment;
  await expect.poll(async () => {
    const response = await request.get("/api/v1/assessments/" + created.assessmentId);
    assessment = await response.json();
    return assessment.status;
  }).toBe("completed");
  const detail = assessment as unknown as { id: string; status: string; progress: number; completedAt: string; engineRuns: { id: string; status: string }[]; artifacts: { id: string; sha256: string }[] };
  for (const id of ["transport", "authentication", "oauth-posture", "authorization", "operational"]) {
    expect(detail.engineRuns.find((run) => run.id === id)?.status).toBe("not-assessed");
  }
  await page.goto("/reports/" + detail.id);
  await expect(page.getByText("Limited evidence", { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/Authentication was not established by this assessment/)).toBeVisible();
  await expect(page.getByText("Anonymous initialization was observed.")).not.toBeVisible();
  const preview = page.locator(".policy-preview-details").first();
  await expect(preview).toBeVisible();
  await expect(preview).not.toHaveAttribute("open", "");
  await preview.getByText("Optional AgntID policy preview", { exact: true }).click();
  await expect(preview).toHaveAttribute("open", "");
  await expect(preview.getByText("Illustrative only. No policy was deployed or enforced.")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("offline-report.png"), fullPage: true });
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("link", { name: "assessment.json", exact: true }).click();
  const download = await downloadEvent;
  const file = await download.path();
  expect(file).not.toBeNull();
  const bytes = await readFile(file!);
  const canonical = JSON.parse(bytes.toString());
  expect(canonical.status).toBe(detail.status);
  expect(canonical.progress).toBe(detail.progress);
  expect(canonical.completedAt).toBe(detail.completedAt);
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(detail.artifacts.find((artifact) => artifact.id === "assessment.json")?.sha256);
  expect(detail.artifacts).toHaveLength(6);
  for (const artifact of detail.artifacts) {
    const response = await request.get("/api/v1/assessments/" + detail.id + "/artifacts/" + artifact.id);
    expect(response.ok()).toBe(true);
    expect(createHash("sha256").update(await response.body()).digest("hex")).toBe(artifact.sha256);
  }
  expect(canonical.executiveSummary).not.toContain("risk is low");
  const markdown = await request.get("/api/v1/assessments/" + detail.id + "/artifacts/technical-report.md");
  expect(await markdown.text()).toContain("OAuth protection was not assessed.");
});
