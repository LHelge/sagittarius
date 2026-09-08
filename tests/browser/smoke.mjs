import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const scratch = await mkdtemp(resolve(tmpdir(), 'sagittarius-browser-'));
const artifacts = resolve(root, 'target/browser-smoke');
await mkdir(artifacts, { recursive: true });

async function freePort() {
    const socket = createServer();
    socket.listen(0, '127.0.0.1');
    await once(socket, 'listening');
    const port = socket.address().port;
    await new Promise((done) => socket.close(done));
    return port;
}

async function until(check, description) {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
        if (await check()) return;
        await delay(100);
    }
    throw new Error(`Timed out: ${description}`);
}

const adminPort = await freePort();
const dnsPort = await freePort();
const url = `http://127.0.0.1:${adminPort}`;
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SAGITTARIUS_')));
const server = spawn(resolve(root, 'target/debug/sagittarius'), [
    '--admin-addr', `127.0.0.1:${adminPort}`,
    '--dns-addr', `127.0.0.1:${dnsPort}`,
    '--db-path', resolve(scratch, 'test.db'),
    '--session-cookie-secure', 'never',
], { env: { ...env, RUST_LOG: 'warn' }, stdio: ['ignore', 'pipe', 'pipe'] });
let serverOutput = '';
server.stdout.on('data', (chunk) => { serverOutput += chunk; });
server.stderr.on('data', (chunk) => { serverOutput += chunk; });
let browser;

async function query(domain = 'stream.test') {
    const packet = Buffer.concat([
        Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        ...domain.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])),
        Buffer.from([0, 0, 1, 0, 1]),
    ]);
    const socket = createSocket('udp4');
    try {
        const response = once(socket, 'message', { signal: AbortSignal.timeout(3000) });
        socket.send(packet, dnsPort, '127.0.0.1');
        const [data] = await response;
        assert.equal(data[3] & 15, 0, 'fixture query should use the default null-IP blocking mode');
        assert.deepEqual([...data.subarray(-4)], [0, 0, 0, 0], 'fixture response is a null IPv4 answer');
    } finally {
        socket.close();
    }
}

try {
    await until(async () => {
        if (server.exitCode !== null) throw new Error(serverOutput);
        return fetch(`${url}/setup`).then((r) => r.ok, () => false);
    }, 'server startup');
    browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome' });
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
        if (message.type() === 'warning' && /Alpine Expression Error/.test(message.text())) errors.push(message.text());
    });
    await page.addInitScript(() => {
        window.streamConnections = 0;
        document.addEventListener('htmx:sse:after:connection', () => window.streamConnections++);
    });
    await page.goto(`${url}/setup`);
    await page.locator('[name=username]').fill('browser-test');
    await page.locator('[name=password]').fill('disposable-test-password');
    await page.locator('[name=confirm]').fill('disposable-test-password');
    await page.locator('button[type=submit]').click();
    await page.waitForURL(`${url}/login`);
    await page.locator('[name=username]').fill('browser-test');
    await page.locator('[name=password]').fill('disposable-test-password');
    await page.locator('button[type=submit]').click();
    await page.waitForURL(`${url}/`);
    await until(() => page.evaluate(() => window.streamConnections === 1), 'initial SSE connection');
    const csrf = await page.locator('meta[name=csrf-token]').getAttribute('content');
    async function post(path, form) {
        const result = await page.request.post(`${url}${path}`, {
            headers: { Origin: url, 'X-CSRF-Token': csrf }, form,
        });
        assert.ok(result.ok(), `${path}: ${result.status()} ${await result.text()}`);
    }
    for (const domain of ['stream.test', 'other.test']) await post('/blacklist/add', { domain });
    for (let i = 0; i < 105; i++) {
        await query();
        await delay(25);
    }
    await until(async () => Number(await page.locator('#live-queries').getAttribute('data-count')) === 105, 'live counters');
    assert.equal(await page.locator('#live-blocked').textContent(), '105');
    assert.equal(await page.locator('#live-ratio').textContent(), '100.0%');
    await until(async () => Number(await page.locator('#live-qps').textContent()) > 0, 'local QPS timer');
    await page.screenshot({ path: resolve(artifacts, 'dashboard.png'), fullPage: true });

    await until(async () => (await (await page.request.get(`${url}/log`)).text()).includes('data-id="105"'), 'history persistence');
    await page.goto(`${url}/log`);
    const rows = page.locator('#log-body > tr');
    await until(async () => await rows.count() === 100, 'initial history page');
    await until(() => page.evaluate(() => window.streamConnections === 1), 'log SSE connection');
    await page.getByLabel('Filter by domain or client').fill('OTHER.TEST');
    await until(async () => await page.locator('#log-body > tr:visible').count() === 0, 'text filter');
    await query('other.test');
    await until(async () => await page.locator('#log-body > tr:visible').count() === 1, 'filtering a streamed row');
    assert.equal(await page.getByLabel('Filter by domain or client').inputValue(), 'OTHER.TEST');
    await page.getByRole('button', { name: 'Load older' }).click();
    await until(async () => await rows.count() === 106, 'history append during live streaming');
    assert.equal(await page.locator('#log-body > tr:visible').count(), 1, 'appended rows inherit filter');
    await page.getByRole('button', { name: 'Load older' }).click();
    await until(async () => await page.getByRole('button', { name: 'Load older' }).count() === 0, 'history exhausted');
    await page.getByLabel('Filter by outcome').selectOption('forwarded');
    await until(async () => await page.locator('#log-body > tr:visible').count() === 0, 'outcome filter');
    await page.getByLabel('Filter by outcome').selectOption('blocked');
    await until(async () => await page.locator('#log-body > tr:visible').count() === 1, 'combined filters');

    const actionRequest = page.waitForRequest((request) => request.url().includes('/log/unblock'));
    await page.locator('#log-body > tr:visible').getByRole('button', { name: 'Unblock' }).click();
    const request = await actionRequest;
    assert.equal(request.headers()['x-csrf-token'], csrf, 'htmx injects the session token');
    await until(async () => (await page.locator('#sgt-toast').textContent()).includes('Unblocked'), 'action toast');
    const blacklist = await (await page.request.get(`${url}/blacklist`)).text();
    assert.ok(!blacklist.includes('other.test'), 'one-click action persisted');
    await page.getByLabel('Filter by domain or client').fill('');
    await until(async () => await page.locator('#log-body > tr:visible').count() === 106, 'clear text filter');
    await page.screenshot({ path: resolve(artifacts, 'log.png'), fullPage: true });

    // A broken response body exercises hx-sse's reconnection path. The next
    // request reaches the real endpoint and receives fresh counter HTML.
    await page.route('**/events', async (route) => {
        await route.fulfill({ status: 200, contentType: 'text/event-stream', body: 'data: \n\n' });
        await page.unroute('**/events');
    });
    await page.reload();
    await until(() => page.evaluate(() => window.streamConnections >= 2), 'SSE reconnect after EOF');
    const before = await rows.count();
    await query();
    await until(async () => await rows.count() === before + 1, 'live row after reconnect');

    await page.goto(`${url}/settings`);
    await page.locator('[name=blocking_mode]').selectOption('custom');
    await page.locator('[name=custom_block_ipv4]').waitFor({ state: 'visible' });
    await page.locator('[name=blocking_mode]').selectOption('nxdomain');
    await page.locator('[name=custom_block_ipv4]').waitFor({ state: 'hidden' });
    await page.locator('[name=upstream_selection_strategy]').selectOption('parallel');
    await page.locator('[name=upstream_parallel_fanout]').waitFor({ state: 'visible' });
    await page.locator('[name=upstream_selection_strategy]').selectOption('random');
    await page.locator('[name=upstream_parallel_fanout]').waitFor({ state: 'hidden' });

    await page.setViewportSize({ width: 390, height: 844 });
    const menu = page.getByRole('button', { name: 'Toggle navigation' });
    await menu.click();
    assert.equal(await menu.getAttribute('aria-expanded'), 'true');
    await page.screenshot({ path: resolve(artifacts, 'mobile-menu.png'), fullPage: true });
    await menu.click();
    assert.equal(await menu.getAttribute('aria-expanded'), 'false');

    await post('/blocking/pause', { minutes: '5' });
    await page.reload();
    const countdown = page.locator('[x-data^="pauseTimer"] strong');
    const initial = await countdown.textContent();
    await until(async () => (await countdown.textContent()) !== initial, 'pause countdown');
    await page.getByRole('button', { name: 'Resume now' }).click();
    await until(async () => await page.locator('[x-data^="pauseTimer"]').count() === 0, 'resume blocking');
    assert.deepEqual(errors, [], 'no browser or Alpine errors');
    console.log('PASS: streamed rows, counters, filtering, pagination, CSRF actions, reconnection, settings, mobile menu, timers');
    console.log(`Screenshots: ${artifacts}`);
} catch (error) {
    console.error(serverOutput);
    throw error;
} finally {
    await browser?.close();
    if (server.exitCode === null) {
        server.kill('SIGTERM');
        await once(server, 'exit');
    }
    await rm(scratch, { recursive: true, force: true });
}
