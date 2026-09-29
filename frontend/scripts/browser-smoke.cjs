/* Optional browser E2E. Provide an installed Playwright module with
 * VIBEAUDIT_PLAYWRIGHT_MODULE (default: playwright) and optionally an Edge/
 * Chromium executable via VIBEAUDIT_BROWSER_EXECUTABLE. No downloads occur.
 * VIBEAUDIT_TEST_BASE_URL defaults to http://127.0.0.1:8000.
 * Run after starting the backend. This creates a labeled synthetic demo run.
 */
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require(process.env.VIBEAUDIT_PLAYWRIGHT_MODULE || 'playwright');
const base = new URL(process.env.VIBEAUDIT_TEST_BASE_URL || 'http://127.0.0.1:8000');
assert(base.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(base.hostname) && !base.username && !base.password && base.pathname === '/' && !base.search && !base.hash, 'Only an explicit numeric loopback origin is accepted');
async function main() {
  const options = {headless: true};
  if (process.env.VIBEAUDIT_BROWSER_EXECUTABLE) options.executablePath = process.env.VIBEAUDIT_BROWSER_EXECUTABLE;
  const browser = await chromium.launch(options);
  try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
    page.setDefaultTimeout(45000);
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(base.origin);
    await page.getByRole('button', {name: '新建評估', exact: true}).first().click();
    await page.getByLabel('評估名稱', {exact: true}).fill('瀏覽器完整流程驗收');
    await page.getByLabel('專案識別', {exact: true}).fill('browser-contract-project');
    await page.getByLabel('專案名稱', {exact: true}).fill('瀏覽器保存專案');
    const savedResponse=page.waitForResponse(r=>r.url().endsWith('/api/projects/browser-contract-project')&&r.request().method()==='PUT');
    await page.getByRole('button', {name: '保存目前專案設定', exact: true}).click();
    const saved=await savedResponse;
    assert(saved.ok(),await saved.text());
    await page.getByText('專案設定已保存在本機。', {exact: true}).waitFor();
    const createdResponse = page.waitForResponse(r => r.url().endsWith('/api/runs') && r.request().method() === 'POST');
    await page.getByRole('button', {name: '建立並開始', exact: true}).click();
    const created = await (await createdResponse).json();
    let completed = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      const response = await page.request.get(`${base.origin}/api/runs/${created.id}`);
      const run = await response.json();
      if (run.stage === 'complete') {
        assert.equal(run.status, 'incomplete');
        assert.deepEqual(run.executions.map(e => e.status), ['fail', 'pass', 'inconclusive']);
        assert(run.gaps.some(gap => gap.includes('C-003')));
        completed = true;
        break;
      }
      await page.waitForTimeout(200);
    }
    assert(completed, 'Demo did not finish');
    await page.getByText('未完整完成', {exact: true}).first().waitFor();
    await page.getByRole('tab', {name: '威脅與測試', exact: true}).click();
    await page.getByText('Synthetic vulnerable tenant boundary', {exact: true}).waitFor();
    await page.getByRole('heading', {name: '版本與關聯紀錄', exact: true}).waitFor();
    await page.locator('.trace-record').first().waitFor();
    const docs = path.resolve(__dirname, '../../docs');
    await page.screenshot({path: path.join(docs, 'threat-tests.png'), fullPage: true});
    await page.getByRole('tab', {name: '執行與證據', exact: true}).click();
    await page.getByRole('button', {name: '檢視證據', exact: true}).first().click();
    await page.getByRole('button', {name: '重新核對', exact: true}).first().waitFor();
    await page.locator('summary').filter({hasText: '匯出報告'}).click();
    const links = await page.locator('a[href*="/report"]').evaluateAll(nodes => nodes.map(a => a.getAttribute('href')));
    assert.equal(links.length, 3);
    for (const href of links) assert((await page.request.get(base.origin + href)).ok());
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false);
    await page.screenshot({path: path.join(docs, 'workbench.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false);
    await page.screenshot({path: path.join(docs, 'workbench-mobile.png'), fullPage: true});
    await page.setViewportSize({width: 1440, height: 1000});
    await page.getByRole('button', {name: '建立修補複測', exact: true}).click();
    await page.getByRole('dialog').waitFor();
    await page.getByLabel('修補後部署識別', {exact: true}).fill('synthetic-fixed-v2');
    const retestResponse=page.waitForResponse(r=>r.url().endsWith(`/api/runs/${created.id}/retest`)&&r.request().method()==='POST');
    await page.getByRole('button', {name: '建立複測（暫不啟動）', exact: true}).click();
    const retest=await (await retestResponse).json();
    assert.equal(retest.status,'created');
    assert.equal(retest.manifest.parent_run_id,created.id);
    await page.getByRole('button', {name: '啟動', exact: true}).waitFor();
    assert.deepEqual(errors, []);
    const validation={status: 'passed', mode: 'synthetic', run_id: created.id, exports: 3, saved_project:true,trace_loaded:true,retest_created:true,retest_started:false,page_errors: 0, horizontal_overflow: false};
    require('fs').writeFileSync(path.join(docs,'browser-validation.json'),JSON.stringify(validation,null,2));
    console.log(JSON.stringify(validation));
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
