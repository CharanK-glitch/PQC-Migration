const { test, expect } = require('@playwright/test');
const pageErrors = new WeakMap();

test.beforeEach(async ({ page }) => {
  const errors = [];
  pageErrors.set(page, errors);
  page.on('pageerror', error => errors.push(error.message));
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) || []).toEqual([]);
});

const scoreFixture = {
  project_name: 'Browser test fixture',
  repo_url: 'https://github.com/example/fixture',
  scan_mode: 'github',
  scanner_version: 'test-fixture',
  timestamp: '2026-01-01T00:00:00Z',
  score: 70,
  grade: 'B',
  label: 'Test fixture score',
  total_assets: 1,
  total_occurrences: 1,
  vulnerable_assets: 1,
  safe_assets: 0,
  critical_assets: 1,
  high_risk_assets: 0,
  pqc_assets: 0,
  risk_distribution: { critical: 1, high: 0, safe: 0 },
  primitive_breakdown: { hash: { vulnerable: 1, safe: 0 } },
  family_breakdown: { SHA256: { vulnerable: 1, safe: 0 } },
  scoring_details: {
    base_score: 20,
    pqc_bonus: 0,
    critical_penalty: 5,
    diversity_penalty: 0,
    pg_penalty: 0,
    safe_weight: 0,
    total_weight: 1,
  },
  migration_roadmap: [],
  timeline: { weeks: 4, label: 'Test timeline', description: 'Fixture only' },
  compliance: {},
};

const cbomFixture = {
  components: [{
    name: 'Fixture SHA-256 usage',
    cryptoProperties: {
      algorithmProperties: {
        primitive: 'hash',
        algorithmFamily: 'SHA256',
        risk: 0,
        nistQuantumSecurityLevel: 0,
        classicalSecurityLevel: 128,
        securityProperties: ['fixture-property'],
      },
    },
    properties: [
      { name: 'occurrences', value: JSON.stringify([{ file: 'src/crypto.js', line: 12, snippet: 'createHash("sha256")', language: 'javascript', source: 'generic' }]) },
      { name: 'replacement', value: 'Fixture replacement' },
    ],
  }],
};

const questionFixture = {
  questions: [{
    id: 'data_in_transit',
    category: 'Data Protection',
    question: 'How is data encrypted in transit?',
    weight: 1.3,
    answers: [
      { text: 'TLS 1.3 with PQC hybrid key exchange', score: 10 },
      { text: 'TLS 1.3 with ECDHE', score: 8 },
    ],
  }],
};

async function json(route, body, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installApiMocks(page) {
  const state = {
    scanRequests: [],
    multiRequests: [],
    multiPolls: 0,
    assessmentRequests: [],
    websiteRequests: [],
    history: [{ id: 'history-1', timestamp: '2026-01-01T00:00:00Z', target: 'https://github.com/example/fixture', project_name: 'Fixture repo', mode: 'github', status: 'completed', score: 70, grade: 'B', findings: 1 }],
    deletedIds: [],
    uploadHeaders: [],
  };

  await page.route('https://cdn.jsdelivr.net/**', route => route.fulfill({
    contentType: 'application/javascript',
    body: 'window.Chart = class { constructor() {} destroy() {} };',
  }));
  await page.route('https://fonts.googleapis.com/**', route => route.abort());
  await page.route('https://fonts.gstatic.com/**', route => route.abort());
  await page.route('**/api/**', async route => {
    const request = route.request();
    const { pathname } = new URL(request.url());
    if (pathname === '/api/score') return json(route, scoreFixture);
    if (pathname === '/api/cbom') return json(route, cbomFixture);
    if (pathname === '/api/status') return json(route, { score_file: true, cbom_file: true, scanner_available: true });
    if (pathname === '/api/scan/log') return json(route, { running: false, exit_code: 0, log: ['fixture scan complete'] });
    if (pathname === '/api/scan' && request.method() === 'POST') {
      state.scanRequests.push({ url: request.url(), headers: request.headers() });
      return json(route, { status: 'started', scan_id: 'fixture-scan' });
    }
    if (pathname === '/api/scan/multi/status') {
      if (!state.multiRequests.length) return json(route, { status: 'idle' });
      state.multiPolls += 1;
      if (state.multiPolls === 1) {
        return json(route, {
          scan_id: 'fixture-multi', status: 'running', total: 1, completed: 0,
          urls: state.multiRequests[0].body.urls, current_url: state.multiRequests[0].body.urls[0], results: [],
        });
      }
      return json(route, {
        scan_id: 'fixture-multi', status: 'completed', total: 1, completed: 1,
        urls: state.multiRequests[0].body.urls, current_url: null,
        results: [{ url: state.multiRequests[0].body.urls[0], status: 'completed', score: 70, grade: 'B', total_occurrences: 1 }],
      });
    }
    if (pathname === '/api/scan/multi' && request.method() === 'POST') {
      state.multiRequests.push({ headers: request.headers(), body: request.postDataJSON() });
      return json(route, { status: 'started', scan_id: 'fixture-multi' });
    }
    if (pathname === '/api/assessment/questions') return json(route, questionFixture);
    if (pathname === '/api/assessment/result') return json(route, { detail: 'No prior assessment' }, 404);
    if (pathname === '/api/assessment' && request.method() === 'POST') {
      state.assessmentRequests.push({ headers: request.headers(), body: request.postDataJSON() });
      return json(route, {
        score: 77, partial_score: 77, grade: 'B', label: 'Partially Ready', answered: 1,
        total_questions: 1, categories: { 'Data Protection': { score: 10, max_score: 13, percentage: 77 } },
        timestamp: '2026-01-01T00:00:00Z',
      });
    }
    if (pathname === '/api/scan/web/result') return json(route, { detail: 'No website scan' }, 404);
    if (pathname === '/api/scan/web' && request.method() === 'POST') {
      state.websiteRequests.push({ headers: request.headers(), body: request.postDataJSON() });
      return json(route, {
        url: request.postDataJSON().url, score: 80, grade: 'A', label: 'Fixture website scan',
        timestamp: '2026-01-01T00:00:00Z', tls: { version: 'TLS 1.3' }, headers: {}, crypto_libs: [], recommendations: [],
      });
    }
    if (pathname === '/api/scan/history') return json(route, { scans: state.history });
    if (pathname.startsWith('/api/scan/history/') && request.method() === 'DELETE') {
      const id = pathname.split('/').pop();
      state.deletedIds.push(id);
      state.history = state.history.filter(scan => scan.id !== id);
      return json(route, { deleted: true, id });
    }
    if (pathname === '/api/upload' && request.method() === 'POST') {
      state.uploadHeaders.push(request.headers());
      return json(route, { status: 'started', scan_id: 'fixture-upload' });
    }
    return json(route, { detail: 'Not found in browser test fixture' }, 404);
  });
  return state;
}

async function openDashboard(page) {
  await page.goto('/');
  await expect(page.locator('#overlay')).toBeHidden();
}

test('repository scan uses the session API key and reports completion', async ({ page }) => {
  const state = await installApiMocks(page);
  await openDashboard(page);
  await page.getByRole('button', { name: /API key/ }).click();
  await page.locator('#apiKeyInput').fill('browser-test-secret');
  await page.getByRole('button', { name: 'Save for this session' }).click();
  await expect(page.locator('#apiKeyStatus')).toHaveText('session key set');

  await page.locator('#tab-scan').click();
  await page.locator('#ghUrl').fill('https://github.com/example/fixture');
  await page.locator('#scanBtn').click();
  await expect.poll(() => state.scanRequests.length).toBe(1);
  expect(state.scanRequests[0].headers['x-api-key']).toBe('browser-test-secret');
  expect(state.scanRequests[0].url).not.toContain('browser-test-secret');
  await expect(page.locator('#logBox')).toContainText('Scan complete!');
});

test('upload sends the session key through the multipart request', async ({ page }) => {
  const state = await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#apiKeyButton').click();
  await page.locator('#apiKeyInput').fill('upload-test-secret');
  await page.getByRole('button', { name: 'Save for this session' }).click();
  await page.locator('#tab-upload').click();
  await page.locator('#fileInput').setInputFiles({ name: 'fixture.zip', mimeType: 'application/zip', buffer: Buffer.from('browser fixture') });
  await expect.poll(() => state.uploadHeaders.length).toBe(1);
  expect(state.uploadHeaders[0]['x-api-key']).toBe('upload-test-secret');
  await expect(page.locator('#uploadList')).toContainText('Scan started');
});

test('multi-repo scan rejects invalid URLs and displays per-repository progress', async ({ page }) => {
  const state = await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#tab-multi').click();
  const input = page.locator('#multiRepoList input').first();
  await input.fill('https://example.com/not-github');
  await expect(page.locator('#multiStartBtn')).toBeDisabled();
  await input.fill('https://github.com/example/fixture');
  await expect(page.locator('#multiStartBtn')).toBeEnabled();
  await page.locator('#multiStartBtn').click();

  await expect.poll(() => state.multiRequests.length).toBe(1);
  expect(state.multiRequests[0].body).toEqual({ urls: ['https://github.com/example/fixture'] });
  await expect(page.locator('#multiResults')).toContainText('Scanning');
  await expect(page.getByRole('progressbar', { name: 'Multi-repository scan progress' })).toHaveAttribute('aria-valuenow', '0');
  await expect(page.locator('#multiResults')).toContainText('Complete', { timeout: 7000 });
  await expect(page.locator('#multiProgress')).toHaveAttribute('aria-valuenow', '100');
});

test('assessment tracks a selected answer and submits the existing answer shape', async ({ page }) => {
  const state = await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#tab-assessment').click();
  await page.getByLabel('TLS 1.3 with PQC hybrid key exchange').check();
  await expect(page.locator('#assessmentProgressText')).toHaveText('1 of 1 answered · 0 unanswered');
  await expect(page.locator('#assessmentProgress')).toHaveAttribute('aria-valuenow', '100');
  await page.locator('#assessmentSubmitBtn').click();
  await expect.poll(() => state.assessmentRequests.length).toBe(1);
  expect(state.assessmentRequests[0].body).toEqual({ answers: { data_in_transit: 0 } });
  await expect(page.locator('#assessmentResultCard')).toBeVisible();
  await expect(page.locator('#assessmentResult')).toContainText('Partially Ready');
});

test('website URL scan validates input and sends a normalized URL', async ({ page }) => {
  const state = await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#tab-webscan').click();
  await page.locator('#webScanUrl').fill('ftp://example.com');
  await page.locator('#webScanBtn').click();
  await expect(page.locator('#webScanError')).toContainText('valid public');
  expect(state.websiteRequests).toHaveLength(0);

  await page.locator('#webScanUrl').fill('https://example.com/path#section');
  await page.locator('#webScanBtn').click();
  await expect.poll(() => state.websiteRequests.length).toBe(1);
  expect(state.websiteRequests[0].body).toEqual({ url: 'https://example.com/path' });
  await expect(page.locator('#webScanResult')).toContainText('TLS 1.3');
});

test('history renders a scan and deletes it through the history action', async ({ page }) => {
  const state = await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#tab-history').click();
  await expect(page.locator('#historyList')).toContainText('Fixture repo');
  page.once('dialog', dialog => dialog.accept());
  await page.locator('[data-history-action="delete"]').click();
  await expect.poll(() => state.deletedIds).toEqual(['history-1']);
  await expect(page.locator('#historyList')).toContainText('No scans yet');
});

test('a protected endpoint opens the API-key setup dialog on 401', async ({ page }) => {
  await installApiMocks(page);
  await page.route('**/api/scan/history', route => json(route, { detail: 'Invalid or missing API key' }, 401));
  await openDashboard(page);
  await page.locator('#tab-history').click();
  await expect(page.locator('#apiKeyDialog')).toBeVisible();
  await expect(page.locator('#apiKeyMessage')).toContainText('requires a valid API key');
  await expect(page.locator('#historyList')).toContainText('Invalid or missing API key');
});

test('score provenance and CBOM evidence remain inspectable', async ({ page }) => {
  await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#scoreProvenance > summary').click();
  await expect(page.locator('#scoreProvenanceBody')).toContainText('PQC adoption bonus');
  await expect(page.locator('#scoreProvenanceBody')).toContainText('https://github.com/example/fixture');
  await page.locator('#tab-cbom').click();
  await page.locator('.evidence-details summary').click();
  await expect(page.locator('.evidence-content')).toContainText('src/crypto.js:12');
  await expect(page.locator('.evidence-content pre')).toContainText('createHash');
});

test('empty scan provenance distinguishes no detections from proof of absence', async ({ page }) => {
  await installApiMocks(page);
  await page.route('**/api/score', route => json(route, {
    ...scoreFixture,
    score: 100,
    grade: 'A+',
    label: 'No Crypto Detected',
    total_assets: 0,
    total_occurrences: 0,
    vulnerable_assets: 0,
    safe_assets: 0,
    critical_assets: 0,
    risk_distribution: { critical: 0, high: 0, safe: 0 },
    primitive_breakdown: {},
    family_breakdown: {},
    scoring_details: { base_score: 100, pqc_bonus: 0, critical_penalty: 0, diversity_penalty: 0, pg_penalty: 0, safe_weight: 0, total_weight: 0 },
  }));
  await openDashboard(page);
  await page.locator('#scoreProvenance > summary').click();
  await expect(page.locator('#scoreProvenanceBody')).toContainText('does not prove that cryptography is absent');
});

test('theme, keyboard tabs, API-key dialog, and narrow layout are usable', async ({ page }) => {
  await installApiMocks(page);
  await openDashboard(page);
  await page.locator('#themeToggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');

  await page.locator('#tab-overview').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#tab-cbom')).toBeFocused();
  await expect(page.locator('#tab-cbom')).toHaveAttribute('aria-selected', 'true');
  expect(await page.locator('#tab-cbom').evaluate(tab => parseFloat(getComputedStyle(tab).outlineWidth))).toBeGreaterThanOrEqual(2);

  await page.setViewportSize({ width: 360, height: 780 });
  await page.locator('#tab-multi').click();
  await page.locator('#multiRepoList input').first().fill('https://github.com/example/a-very-long-repository-name-used-to-check-mobile-wrapping');
  const mobileWidth = await page.evaluate(() => ({ viewport: window.innerWidth, document: document.documentElement.scrollWidth }));
  expect(mobileWidth.document).toBeLessThanOrEqual(mobileWidth.viewport + 1);
  await page.locator('#apiKeyButton').click();
  await expect(page.locator('#apiKeyDialog')).toBeVisible();
  const widths = await page.evaluate(() => ({
    viewport: window.innerWidth,
    page: document.documentElement.scrollWidth,
    dialog: Math.ceil(document.querySelector('#apiKeyDialog').getBoundingClientRect().width),
  }));
  expect(widths.page).toBeLessThanOrEqual(widths.viewport + 1);
  expect(widths.dialog).toBeLessThanOrEqual(widths.viewport);
});

test('visible controls have accessible names and interactive tabs preserve panel relationships', async ({ page }) => {
  await installApiMocks(page);
  await openDashboard(page);
  const tabIds = ['overview', 'cbom', 'roadmap', 'compliance', 'scan', 'multi', 'webscan', 'assessment', 'upload', 'history'];
  for (const name of tabIds) {
    await page.locator(`#tab-${name}`).click();
    const audit = await page.evaluate(() => {
      const visible = element => getComputedStyle(element).visibility !== 'hidden' && element.getClientRects().length > 0;
      const unnamedButtons = [...document.querySelectorAll('button')]
        .filter(visible)
        .filter(button => !button.getAttribute('aria-label') && !button.innerText.trim() && !button.title)
        .map(button => button.outerHTML.slice(0, 100));
      const unlabeledInputs = [...document.querySelectorAll('input:not([type="hidden"])')]
        .filter(visible)
        .filter(input => !input.getAttribute('aria-label') && !input.getAttribute('aria-labelledby') && !input.labels?.length)
        .map(input => input.outerHTML.slice(0, 100));
      const tabsWithoutPanel = [...document.querySelectorAll('[role="tab"]')]
        .filter(tab => !document.getElementById(tab.getAttribute('aria-controls'))?.id)
        .map(tab => tab.id);
      return { unnamedButtons, unlabeledInputs, tabsWithoutPanel };
    });
    expect(audit).toEqual({ unnamedButtons: [], unlabeledInputs: [], tabsWithoutPanel: [] });
  }
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const transition = await page.locator('.card').first().evaluate(card => getComputedStyle(card).transitionDuration.split(',')[0].trim());
  expect(parseFloat(transition)).toBeLessThanOrEqual(0.001);
});
