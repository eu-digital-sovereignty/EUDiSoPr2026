#!/usr/bin/env node
const puppeteer = require('puppeteer');
const PuppeteerHar = require('puppeteer-har');
const colors = require('colors/safe');
const dotenv = require('dotenv');
const fs = require('fs-extra');
const path = require('path');
const dns = require('node:dns').promises;
const crypto = require('crypto');
const { URL } = require('url');
const { DatabaseSync } = require('node:sqlite');
const maxmind = require('maxmind');

dotenv.config({ quiet: true });

const EU_COUNTRY_CODES = new Set([
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
    'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES',
    'SE', 'EU', 'CH',
]);

const DEFAULT_STORAGE_DIR = path.resolve(process.cwd(), 'crawl_blocked_paper');
const DEFAULT_SQLITE_PATH = path.join(DEFAULT_STORAGE_DIR, 'crawler_eu_check.sqlite');
const DEFAULT_SCREENSHOT_DIR = path.join(DEFAULT_STORAGE_DIR, 'screenshots');
const DEFAULT_HAR_DIR = path.join(DEFAULT_STORAGE_DIR, 'har');
const DEFAULT_URLS_FILE = path.join(DEFAULT_STORAGE_DIR, 'urls.txt');
const DEFAULT_USER_AGENT = [
    'Mozilla/5.0 (X11; Linux x86_64)',
    'AppleWebKit/537.36 (KHTML, like Gecko)',
    'Chrome/146.0.0.0 Safari/537.36',
].join(' ');
const DEFAULT_CAIDA_BASE_URL = 'https://api.asrank.caida.org/v2/restful';
const DEFAULT_MMDB_PATH = path.resolve(__dirname, 'metadata/location_extended_latest.mmdb');

function parseArgs(argv) {
    const options = {
        storageDir: DEFAULT_STORAGE_DIR,
        sqlitePath: DEFAULT_SQLITE_PATH,
        screenshotDir: DEFAULT_SCREENSHOT_DIR,
        har: true,
        harDir: DEFAULT_HAR_DIR,
        urlsFile: DEFAULT_URLS_FILE,
        urls: [],
        limit: 25,
        navigationTimeoutMs: 15000,
        networkIdleTimeMs: 1500,
        networkIdleConcurrency: 2,
        browserExecutable: null,
        proxyServer: null,
        proxyUsername: null,
        proxyPassword: null,
        userAgent: DEFAULT_USER_AGENT,
        endpointLabel: 'default',
        mmdbPath: process.env.MMDB_PATH ? path.resolve(process.env.MMDB_PATH) : DEFAULT_MMDB_PATH,
        caidaBaseUrl: process.env.CAIDA_BASE_URL || DEFAULT_CAIDA_BASE_URL,
        caidaTimeoutMs: Number.parseInt(process.env.CAIDA_TIMEOUT_MS || '10000', 10),
        allowCountryCodes: new Set(EU_COUNTRY_CODES),
        allowSameAsMainAsn: true,
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === '--storage-dir') {
            options.storageDir = path.resolve(argv[++i] || options.storageDir);
        } else if (arg.startsWith('--storage-dir=')) {
            options.storageDir = path.resolve(arg.split('=')[1]);
        } else if (arg === '--sqlite-path') {
            options.sqlitePath = path.resolve(argv[++i] || options.sqlitePath);
        } else if (arg.startsWith('--sqlite-path=')) {
            options.sqlitePath = path.resolve(arg.split('=')[1]);
        } else if (arg === '--screenshot-dir') {
            options.screenshotDir = path.resolve(argv[++i] || options.screenshotDir);
        } else if (arg.startsWith('--screenshot-dir=')) {
            options.screenshotDir = path.resolve(arg.split('=')[1]);
        } else if (arg === '--har') {
            options.har = true;
        } else if (arg === '--no-har') {
            options.har = false;
        } else if (arg === '--har-dir') {
            options.harDir = path.resolve(argv[++i] || options.harDir);
        } else if (arg.startsWith('--har-dir=')) {
            options.harDir = path.resolve(arg.split('=')[1]);
        } else if (arg === '--urls-file') {
            options.urlsFile = path.resolve(argv[++i] || options.urlsFile);
        } else if (arg.startsWith('--urls-file=')) {
            options.urlsFile = path.resolve(arg.split('=')[1]);
        } else if (arg === '--limit') {
            options.limit = Number.parseInt(argv[++i], 10) || options.limit;
        } else if (arg.startsWith('--limit=')) {
            options.limit = Number.parseInt(arg.split('=')[1], 10) || options.limit;
        } else if (arg === '--navigation-timeout-ms') {
            options.navigationTimeoutMs = Number.parseInt(argv[++i], 10) || options.navigationTimeoutMs;
        } else if (arg.startsWith('--navigation-timeout-ms=')) {
            options.navigationTimeoutMs = Number.parseInt(arg.split('=')[1], 10) || options.navigationTimeoutMs;
        } else if (arg === '--network-idle-time-ms') {
            options.networkIdleTimeMs = Number.parseInt(argv[++i], 10) || options.networkIdleTimeMs;
        } else if (arg.startsWith('--network-idle-time-ms=')) {
            options.networkIdleTimeMs = Number.parseInt(arg.split('=')[1], 10) || options.networkIdleTimeMs;
        } else if (arg === '--network-idle-concurrency') {
            options.networkIdleConcurrency = Number.parseInt(argv[++i], 10) || options.networkIdleConcurrency;
        } else if (arg.startsWith('--network-idle-concurrency=')) {
            options.networkIdleConcurrency = Number.parseInt(arg.split('=')[1], 10) || options.networkIdleConcurrency;
        } else if (arg === '--browser-executable') {
            options.browserExecutable = path.resolve(argv[++i] || options.browserExecutable);
        } else if (arg.startsWith('--browser-executable=')) {
            options.browserExecutable = path.resolve(arg.split('=')[1]);
        } else if (arg === '--proxy-server') {
            options.proxyServer = argv[++i] || options.proxyServer;
        } else if (arg.startsWith('--proxy-server=')) {
            options.proxyServer = arg.split('=')[1];
        } else if (arg === '--proxy-username') {
            options.proxyUsername = argv[++i] || options.proxyUsername;
        } else if (arg.startsWith('--proxy-username=')) {
            options.proxyUsername = arg.split('=')[1];
        } else if (arg === '--proxy-password') {
            options.proxyPassword = argv[++i] || options.proxyPassword;
        } else if (arg.startsWith('--proxy-password=')) {
            options.proxyPassword = arg.split('=')[1];
        } else if (arg === '--user-agent') {
            options.userAgent = argv[++i] || options.userAgent;
        } else if (arg.startsWith('--user-agent=')) {
            options.userAgent = arg.split('=')[1];
        } else if (arg === '--endpoint-label') {
            options.endpointLabel = argv[++i] || options.endpointLabel;
        } else if (arg.startsWith('--endpoint-label=')) {
            options.endpointLabel = arg.split('=')[1];
        } else if (arg === '--mmdb-path') {
            options.mmdbPath = path.resolve(argv[++i] || options.mmdbPath);
        } else if (arg.startsWith('--mmdb-path=')) {
            options.mmdbPath = path.resolve(arg.split('=')[1]);
        } else if (arg === '--allow-country-codes') {
            options.allowCountryCodes = new Set(String(argv[++i] || '').split(',').map(v => v.trim().toUpperCase()).filter(Boolean));
        } else if (arg.startsWith('--allow-country-codes=')) {
            options.allowCountryCodes = new Set(String(arg.split('=')[1] || '').split(',').map(v => v.trim().toUpperCase()).filter(Boolean));
        } else if (arg === '--allow-same-as-main-asn') {
            options.allowSameAsMainAsn = true;
        } else if (arg === '--no-allow-same-as-main-asn') {
            options.allowSameAsMainAsn = false;
        } else if (arg.startsWith('--')) {
            throw new Error(`Unknown argument: ${arg}`);
        } else {
            options.urls.push(arg);
        }
    }

    options.storageDir = path.resolve(options.storageDir);
    options.sqlitePath = path.resolve(options.sqlitePath);
    options.screenshotDir = path.resolve(options.screenshotDir);
    options.harDir = path.resolve(options.harDir);
    options.urlsFile = path.resolve(options.urlsFile);
    options.mmdbPath = path.resolve(options.mmdbPath);
    options.limit = Math.max(1, options.limit);
    options.networkIdleTimeMs = Math.max(250, options.networkIdleTimeMs);
    options.networkIdleConcurrency = Math.max(0, options.networkIdleConcurrency);
    options.navigationTimeoutMs = Math.max(2000, options.navigationTimeoutMs);

    if (!fs.existsSync(options.mmdbPath)) {
        throw new Error(`Missing MMDB file: ${options.mmdbPath}`);
    }

    for (const code of ['EU', 'CH']) {
        options.allowCountryCodes.add(code);
    }

    return options;
}

function normalizeUrl(value) {
    try {
        const parsed = new URL(value);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return null;
        }
        parsed.hash = '';
        parsed.hostname = parsed.hostname.toLowerCase();
        if (parsed.pathname.length > 1 && parsed.pathname.endsWith('/')) {
            parsed.pathname = parsed.pathname.replace(/\/+$/, '');
        }
        return parsed.toString();
    } catch {
        return null;
    }
}

async function hostResolves(hostname) {
    try {
        const answers = await dns.lookup(hostname, { all: true, verbatim: true });
        return Array.isArray(answers) && answers.length > 0;
    } catch {
        return false;
    }
}

async function resolvePreferredUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) {
        return null;
    }

    const direct = normalizeUrl(raw);
    if (direct) {
        const directHost = new URL(direct).hostname;
        if (await hostResolves(directHost)) {
            return direct;
        }
        if (!directHost.startsWith('www.') && directHost.split('.').length == 2 && await hostResolves(`www.${directHost}`)) {
            const fallback = new URL(direct);
            fallback.hostname = `www.${directHost}`;
            return fallback.toString();
        }
        return direct;
    }

    const bare = raw.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    if (!bare) {
        return null;
    }
    if (await hostResolves(bare)) {
        return `https://${bare}`;
    }
    if (!bare.startsWith('www.') && bare.split('.').length == 2 && await hostResolves(`www.${bare}`)) {
        return `https://www.${bare}`;
    }
    return `https://${bare}`;
}

async function readUrls(options) {
    const rawInputs = options.urls.length > 0
        ? options.urls
        : fs.existsSync(options.urlsFile)
            ? fs.readFileSync(options.urlsFile, 'utf8').split(/\r?\n/).map(line => line.trim()).filter(Boolean)
            : (() => { throw new Error(`Missing urls file: ${options.urlsFile}`); })();

    const resolved = [];
    for (const raw of rawInputs) {
        const preferred = await resolvePreferredUrl(raw);
        if (preferred) {
            resolved.push(preferred);
        }
        if (resolved.length >= options.limit) {
            break;
        }
    }
    return resolved;
}

function pageKey(url) {
    return crypto.createHash('sha256').update(url).digest('hex').slice(0, 16);
}

function isHttpLike(url) {
    return /^https?:/i.test(url);
}

function getNestedValue(record, paths) {
    if (!record || !Array.isArray(paths)) {
        return null;
    }

    for (const candidate of paths) {
        const segments = String(candidate || '').split('.').filter(Boolean);
        let current = record;
        let found = true;

        for (const segment of segments) {
            if (current == null || (typeof current !== 'object' && !Array.isArray(current)) || !(segment in current)) {
                found = false;
                break;
            }
            current = current[segment];
        }

        if (found && current != null && current !== '') {
            return current;
        }
    }

    return null;
}

function extractCaidaAsnFields(record) {
    const payload = record?.data?.asn || record?.asn || record?.data || record || {};
    const org = payload.org || payload.organization || {};
    const country = payload.country || {};
    return {
        asRank: payload.rank ?? null,
        asCountryCode: payload.country_code || country.iso || payload.country || null,
        asOrgName: org.name || payload.organization_name || null,
        asOrgId: org.orgId || org.id || payload.organization_id || null,
    };
}

function extractCaidaOrganizationFields(record) {
    const payload = record?.data?.organization || record?.organization || record?.data || record || {};
    const country = payload.country || {};
    return {
        asOrgName: payload.orgName || payload.name || null,
        asOrgId: payload.orgId || payload.id || null,
        asCountryCode: country.iso || null,
        asRank: payload.rank ?? null,
    };
}

function normalizeAsn(asn) {
    const normalized = String(asn || '').trim().toUpperCase().replace(/^AS/, '');
    return /^\d+$/.test(normalized) ? normalized : null;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const COOKIE_ACCEPT_SELECTORS = [
    '#didomi-notice-agree-button',
    'button#didomi-notice-agree-button',
    '.didomi-notice-agree-button',
    '[data-testid="didomi-notice-agree-button"]',
    '[id^="didomi-notice-agree-button"]',
    '#onetrust-accept-btn-handler',
    '.onetrust-close-btn-handler',
    '#accept-recommended-btn-handler',
    'button[data-testid="uc-accept-all-button"]',
    '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
    '#CybotCookiebotDialogBodyButtonAccept',
    'button[aria-label="Accept cookies"]',
    'button[aria-label="Accept all cookies"]',
    '[data-role="accept-consent"]',
    '[data-action="accept"]',
    '[data-accept-action]',
    '.cc-allow',
    '.cc-btn.cc-allow',
];

const COOKIE_ACCEPT_TEXTS = [
    'accept',
    'accept all',
    'accept all cookies',
    'accept cookies',
    'allow all',
    'allow all cookies',
    'allow cookies',
    'agree',
    'i agree',
    'ok',
    'got it',
    'verstanden',
    'zustimmen',
    'alle akzeptieren',
    'alle cookies akzeptieren',
    'cookies akzeptieren',
    'alle cookies erlauben',
    'cookies erlauben',
    'allen cookies zustimmen',
    'allen cookies und einbindungen zustimmen',
    'acceptar',
    'aceptar',
    'aceptar todo',
    'aceptar todas',
    'tout accepter',
    'accepter',
    'akkoord',
    'alles accepteren',
    'accetta',
    'accetta tutto',
    'hyvaksy',
    'hyvaksy kaikki',
];

const COOKIE_CONTAINER_SELECTORS = [
    '[id*="cookie"]',
    '[class*="cookie"]',
    '[id*="consent"]',
    '[class*="consent"]',
    '[aria-label*="cookie" i]',
    '[aria-label*="consent" i]',
    '[role="dialog"]',
    '[aria-modal="true"]',
];

async function tryAcceptCookieBanner(page) {
    const result = await (async () => {
        const frames = page.frames();
        let bannerDetected = false;

        for (const frame of frames) {
            try {
                const frameResult = await frame.evaluate((cookieAcceptSelectors, cookieAcceptTexts, cookieContainerSelectors) => {
                    const directSelectors = [
                        ...cookieAcceptSelectors,
                        '.didomi-popup-actions button',
                        '.didomi-components-button',
                    ];
                    const acceptTexts = cookieAcceptTexts;
                    const genericSelectors = [
                        'button',
                        'a[role="button"]',
                        'input[type="button"]',
                        'input[type="submit"]',
                        '[role="button"]',
                        '[aria-label]',
                    ];
                    const containerSelectors = cookieContainerSelectors;

                    const isVisible = element => {
                        const rect = element.getBoundingClientRect();
                        const style = window.getComputedStyle(element);
                        return (
                            rect.width > 0
                            && rect.height > 0
                            && style.visibility !== 'hidden'
                            && style.display !== 'none'
                            && style.opacity !== '0'
                        );
                    };

                    const getEffectiveZIndex = element => {
                        let current = element;
                        let best = 0;

                        while (current && current !== document.documentElement) {
                            const value = window.getComputedStyle(current).zIndex;
                            const parsed = Number.parseInt(value, 10);
                            if (!Number.isNaN(parsed)) {
                                best = Math.max(best, parsed);
                            }
                            current = current.parentElement;
                        }

                        return best;
                    };

                    const getViewportCoverageScore = element => {
                        const rect = element.getBoundingClientRect();
                        const viewportArea = Math.max(window.innerWidth * window.innerHeight, 1);
                        const area = Math.max(rect.width * rect.height, 0);
                        return area / viewportArea;
                    };

                    const describe = element => ({
                        tagName: element.tagName,
                        text: (element.innerText || element.textContent || element.getAttribute('aria-label') || '').trim().slice(0, 120),
                    });

                    const normalizeText = value => String(value || '')
                        .toLowerCase()
                        .replace(/\s+/g, ' ')
                        .trim();

                    for (const selector of directSelectors) {
                        const element = document.querySelector(selector);
                        if (element && isVisible(element)) {
                            element.click();
                            return {
                                strategy: 'direct',
                                clicked: true,
                                bannerPresent: true,
                                details: describe(element),
                            };
                        }
                    }

                    const getCandidateText = element => normalizeText([
                        element.innerText,
                        element.textContent,
                        element.getAttribute('aria-label'),
                        element.getAttribute('value'),
                        element.id,
                        element.className,
                    ].filter(Boolean).join(' '));

                    const matchesConsent = element => {
                        const text = getCandidateText(element);
                        return acceptTexts.some(pattern => (
                            text === pattern
                            || text.startsWith(`${pattern} `)
                            || text.includes(` ${pattern} `)
                        ));
                    };

                    const containers = Array.from(document.querySelectorAll(containerSelectors.join(',')))
                        .filter(element => isVisible(element));
                    const bannerPresent = containers.length > 0;
                    const candidateElements = containers.length
                        ? containers.flatMap(container => Array.from(container.querySelectorAll(genericSelectors.join(','))))
                        : Array.from(document.querySelectorAll(genericSelectors.join(',')));

                    const scoredCandidates = candidateElements
                        .filter(element => isVisible(element) && matchesConsent(element))
                        .map(element => {
                            const text = getCandidateText(element);
                            if (text.includes('reject') || text.includes('decline') || text.includes('necessary only')) {
                                return null;
                            }

                            const rect = element.getBoundingClientRect();
                            const container = containers.find(candidate => candidate.contains(element)) || element;

                            return {
                                element,
                                score: (
                                    (getEffectiveZIndex(container) * 1000)
                                    + (getViewportCoverageScore(container) * 100)
                                    + (rect.width * rect.height / 1000)
                                ),
                            };
                        })
                        .filter(Boolean)
                        .sort((left, right) => right.score - left.score);

                    const target = scoredCandidates[0]?.element || null;
                    if (!target) {
                        return {
                            bannerPresent,
                            clicked: false,
                            details: null,
                        };
                    }

                    target.click();
                    return {
                        bannerPresent: true,
                        clicked: true,
                        details: {
                            strategy: 'generic',
                            ...describe(target),
                        },
                    };
                }, COOKIE_ACCEPT_SELECTORS, COOKIE_ACCEPT_TEXTS, COOKIE_CONTAINER_SELECTORS);

                if (frameResult?.bannerPresent) {
                    bannerDetected = true;
                }

                if (frameResult?.clicked) {
                    return {
                        bannerState: 'present',
                        action: 'success',
                        details: frameResult.details,
                    };
                }
            } catch {
            }
        }

        return {
            bannerState: bannerDetected ? 'present' : 'not_present',
            action: bannerDetected ? 'failure' : 'not_present',
            details: null,
        };
    })();

    if (result.action !== 'success') {
        return result;
    }

    await sleep(1500);
    return result;
}

async function suppressConsentOverlays(page) {
    const frames = page.frames();
    let hiddenCount = 0;

    for (const frame of frames) {
        try {
            const result = await frame.evaluate(() => {
                const selectors = [
                    '[id*="cookie" i]',
                    '[class*="cookie" i]',
                    '[id*="consent" i]',
                    '[class*="consent" i]',
                    '[id*="gdpr" i]',
                    '[class*="gdpr" i]',
                    '[id*="privacy" i]',
                    '[class*="privacy" i]',
                    '[role="dialog"]',
                    '[aria-modal="true"]',
                ];

                const isVisible = element => {
                    const rect = element.getBoundingClientRect();
                    const style = window.getComputedStyle(element);
                    return (
                        rect.width > 0
                        && rect.height > 0
                        && style.visibility !== 'hidden'
                        && style.display !== 'none'
                        && style.opacity !== '0'
                    );
                };

                const normalizeText = value => String(value || '')
                    .toLowerCase()
                    .replace(/\s+/g, ' ')
                    .trim();

                const looksConsentLike = element => {
                    const text = normalizeText([
                        element.innerText,
                        element.textContent,
                        element.getAttribute('aria-label'),
                        element.id,
                        element.className,
                    ].filter(Boolean).join(' '));
                    return [
                        'cookie', 'consent', 'gdpr', 'privacy', 'datenschutz', 'zustimmen',
                        'akzeptieren', 'accept', 'agree', 'einwilligung', 'onetrust', 'didomi', 'cookiebot'
                    ].some(token => text.includes(token));
                };

                const getCoverage = element => {
                    const rect = element.getBoundingClientRect();
                    const viewportArea = Math.max(window.innerWidth * window.innerHeight, 1);
                    return Math.max(rect.width * rect.height, 0) / viewportArea;
                };

                const getEffectiveZIndex = element => {
                    let current = element;
                    let best = 0;
                    while (current && current !== document.documentElement) {
                        const value = window.getComputedStyle(current).zIndex;
                        const parsed = Number.parseInt(value, 10);
                        if (!Number.isNaN(parsed)) {
                            best = Math.max(best, parsed);
                        }
                        current = current.parentElement;
                    }
                    return best;
                };

                const candidates = new Set();
                for (const selector of selectors) {
                    for (const element of document.querySelectorAll(selector)) {
                        candidates.add(element);
                    }
                }

                const body = document.body;
                if (body) {
                    for (const element of Array.from(body.querySelectorAll('div, section, aside, form'))) {
                        if (!isVisible(element)) {
                            continue;
                        }
                        const style = window.getComputedStyle(element);
                        const coverage = getCoverage(element);
                        const zIndex = getEffectiveZIndex(element);
                        if ((style.position === 'fixed' || style.position === 'sticky') && zIndex >= 1000 && coverage >= 0.08) {
                            candidates.add(element);
                        }
                    }
                }

                let hidden = 0;
                for (const element of candidates) {
                    if (!isVisible(element)) {
                        continue;
                    }
                    const coverage = getCoverage(element);
                    const zIndex = getEffectiveZIndex(element);
                    if (!looksConsentLike(element) && !(coverage >= 0.12 && zIndex >= 1000)) {
                        continue;
                    }
                    element.setAttribute('data-eu-check-hidden', '1');
                    element.style.setProperty('display', 'none', 'important');
                    element.style.setProperty('visibility', 'hidden', 'important');
                    element.style.setProperty('opacity', '0', 'important');
                    element.style.setProperty('pointer-events', 'none', 'important');
                    hidden += 1;
                }

                document.documentElement.style.removeProperty('overflow');
                if (document.body) {
                    document.body.style.removeProperty('overflow');
                }
                return { hidden };
            });
            hiddenCount += result?.hidden || 0;
        } catch {
        }
    }

    if (hiddenCount > 0) {
        await sleep(300);
    }

    return { hiddenCount };
}

class EuCheckDatabase {
    constructor(sqlitePath) {
        this.db = new DatabaseSync(sqlitePath);
        this.init();
    }

    init() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS eu_check_pages (
                id INTEGER PRIMARY KEY,
                endpoint_label TEXT NOT NULL,
                page_url TEXT NOT NULL,
                page_domain TEXT NOT NULL,
                output_dir TEXT NOT NULL,
                normal_1_screenshot TEXT,
                blocked_screenshot TEXT,
                normal_2_screenshot TEXT,
                normal_1_status INTEGER,
                blocked_status INTEGER,
                normal_2_status INTEGER,
                blocked_request_count INTEGER DEFAULT 0,
                blocked_foreign_ip_count INTEGER DEFAULT 0,
                blocked_foreign_jurisdiction_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(endpoint_label, page_url)
            );
            CREATE TABLE IF NOT EXISTS eu_check_requests (
                id INTEGER PRIMARY KEY,
                page_id INTEGER NOT NULL,
                phase TEXT NOT NULL,
                request_url TEXT NOT NULL,
                request_host TEXT,
                resource_type TEXT,
                decision TEXT NOT NULL,
                block_reason TEXT,
                ip_address TEXT,
                ip_country_code TEXT,
                ip_continent_code TEXT,
                asn TEXT,
                as_name TEXT,
                as_domain TEXT,
                caida_as_country_code TEXT,
                caida_as_org_name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);
        this.upsertPageStmt = this.db.prepare(`
            INSERT INTO eu_check_pages (endpoint_label, page_url, page_domain, output_dir)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(endpoint_label, page_url) DO UPDATE SET
                page_domain = excluded.page_domain,
                output_dir = excluded.output_dir,
                updated_at = CURRENT_TIMESTAMP
            RETURNING id
        `);
        this.updatePageStmt = this.db.prepare(`
            UPDATE eu_check_pages
            SET normal_1_screenshot = ?,
                blocked_screenshot = ?,
                normal_2_screenshot = ?,
                normal_1_status = ?,
                blocked_status = ?,
                normal_2_status = ?,
                blocked_request_count = ?,
                blocked_foreign_ip_count = ?,
                blocked_foreign_jurisdiction_count = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `);
        this.clearRequestsStmt = this.db.prepare('DELETE FROM eu_check_requests WHERE page_id = ?');
        this.insertRequestStmt = this.db.prepare(`
            INSERT INTO eu_check_requests (
                page_id, phase, request_url, request_host, resource_type, decision, block_reason,
                ip_address, ip_country_code, ip_continent_code, asn, as_name, as_domain,
                caida_as_country_code, caida_as_org_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
    }

    upsertPage(endpointLabel, pageUrl, pageDomain, outputDir) {
        return this.upsertPageStmt.get(endpointLabel, pageUrl, pageDomain, outputDir).id;
    }

    replaceRequests(pageId, rows) {
        this.db.exec('BEGIN');
        try {
            this.clearRequestsStmt.run(pageId);
            for (const row of rows) {
                this.insertRequestStmt.run(
                    pageId,
                    row.phase,
                    row.requestUrl,
                    row.requestHost,
                    row.resourceType,
                    row.decision,
                    row.blockReason,
                    row.ipAddress,
                    row.ipCountryCode,
                    row.ipContinentCode,
                    row.asn,
                    row.asName,
                    row.asDomain,
                    row.caidaAsCountryCode,
                    row.caidaAsOrgName,
                );
            }
            this.db.exec('COMMIT');
        } catch (error) {
            this.db.exec('ROLLBACK');
            throw error;
        }
    }

    updatePageResult(pageId, row) {
        this.updatePageStmt.run(
            row.normal1Screenshot,
            row.blockedScreenshot,
            row.normal2Screenshot,
            row.normal1Status,
            row.blockedStatus,
            row.normal2Status,
            row.blockedRequestCount,
            row.blockedForeignIpCount,
            row.blockedForeignJurisdictionCount,
            pageId,
        );
    }
}

class GeoResolver {
    constructor(options) {
        this.options = options;
        this.hostCache = new Map();
        this.ipGeoCache = new Map();
        this.caidaAsnCache = new Map();
        this.caidaOrgCache = new Map();
        this.mmdbReader = null;
    }

    async init() {
        this.mmdbReader = await maxmind.open(this.options.mmdbPath);
    }

    async resolveHost(hostname) {
        if (this.hostCache.has(hostname)) {
            return this.hostCache.get(hostname);
        }
        let entry;
        try {
            const answers = await dns.lookup(hostname, { all: true, verbatim: true });
            const ipAddress = answers[0]?.address || null;
            const ipGeo = ipAddress ? await this.lookupIpGeo(ipAddress) : null;
            const caida = ipGeo?.asn ? await this.lookupCaida(ipGeo.asn) : null;
            entry = {
                hostname,
                ipAddress,
                ipGeo,
                caida,
            };
        } catch (error) {
            entry = {
                hostname,
                ipAddress: null,
                ipGeo: null,
                caida: null,
                error: error.message,
            };
        }
        this.hostCache.set(hostname, entry);
        return entry;
    }

    async lookupIpGeo(ipAddress) {
        if (this.ipGeoCache.has(ipAddress)) {
            return this.ipGeoCache.get(ipAddress);
        }
        if (!this.mmdbReader) {
            throw new Error('MMDB reader not initialized');
        }
        const record = this.mmdbReader.get(ipAddress) || null;
        const data = record ? {
            asn: getNestedValue(record, [
                'asn',
                'autonomous_system_number',
                'traits.autonomous_system_number',
                'as.asn',
            ]),
            as_name: getNestedValue(record, [
                'as_name',
                'autonomous_system_organization',
                'traits.autonomous_system_organization',
                'as.name',
            ]),
            as_domain: getNestedValue(record, [
                'as_domain',
                'as.domain',
                'traits.autonomous_system_domain',
            ]),
            country_code: getNestedValue(record, [
                'country_code',
                'country.iso_code',
                'country.code',
            ]),
            continent_code: getNestedValue(record, [
                'continent_code',
                'continent.code',
                'continent.iso_code',
            ]),
        } : null;
        this.ipGeoCache.set(ipAddress, data);
        return data;
    }

    async lookupCaida(asn) {
        const normalizedAsn = normalizeAsn(asn);
        if (!normalizedAsn) {
            return null;
        }
        if (this.caidaAsnCache.has(normalizedAsn)) {
            return this.caidaAsnCache.get(normalizedAsn);
        }
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.options.caidaTimeoutMs);
        try {
            const response = await fetch(`${String(this.options.caidaBaseUrl).replace(/\/+$/, '')}/asns/${encodeURIComponent(normalizedAsn)}` , {
                signal: controller.signal,
                headers: { accept: 'application/json' },
            });
            if (!response.ok) {
                throw new Error(`CAIDA ASN lookup failed: ${response.status}`);
            }
            let caida = extractCaidaAsnFields(await response.json());
            if (caida.asOrgId) {
                const org = await this.lookupCaidaOrganization(caida.asOrgId);
                caida = {
                    ...caida,
                    asCountryCode: org.asCountryCode || caida.asCountryCode,
                    asOrgName: org.asOrgName || caida.asOrgName,
                };
            }
            this.caidaAsnCache.set(normalizedAsn, caida);
            return caida;
        } finally {
            clearTimeout(timeout);
        }
    }

    async lookupCaidaOrganization(orgId) {
        if (this.caidaOrgCache.has(orgId)) {
            return this.caidaOrgCache.get(orgId);
        }
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.options.caidaTimeoutMs);
        try {
            const response = await fetch(`${String(this.options.caidaBaseUrl).replace(/\/+$/, '')}/organizations/${encodeURIComponent(orgId)}` , {
                signal: controller.signal,
                headers: { accept: 'application/json' },
            });
            if (!response.ok) {
                throw new Error(`CAIDA organization lookup failed: ${response.status}`);
            }
            const payload = extractCaidaOrganizationFields(await response.json());
            this.caidaOrgCache.set(orgId, payload);
            return payload;
        } finally {
            clearTimeout(timeout);
        }
    }

    isAllowedCountry(countryCode) {
        return this.options.allowCountryCodes.has(String(countryCode || '').trim().toUpperCase());
    }

    evaluate(meta) {
        const ipCountryCode = meta?.ipGeo?.country_code || null;
        const ipContinentCode = meta?.ipGeo?.continent_code || null;
        const asn = meta?.ipGeo?.asn || null;
        const asName = meta?.ipGeo?.as_name || null;
        const asDomain = meta?.ipGeo?.as_domain || null;
        const caidaAsCountryCode = meta?.caida?.asCountryCode || null;
        const caidaAsOrgName = meta?.caida?.asOrgName || null;
        const reasons = [];

        if (ipCountryCode && !this.isAllowedCountry(ipCountryCode)) {
            reasons.push('foreign_ip_location');
        }
        if (caidaAsCountryCode && !this.isAllowedCountry(caidaAsCountryCode)) {
            reasons.push('foreign_jurisdiction');
        }

        return {
            ipAddress: meta?.ipAddress || null,
            ipCountryCode,
            ipContinentCode,
            asn,
            asName,
            asDomain,
            caidaAsCountryCode,
            caidaAsOrgName,
            decision: reasons.length > 0 ? 'block' : 'allow',
            blockReason: reasons.join(','),
            foreignIp: reasons.includes('foreign_ip_location') ? 1 : 0,
            foreignJurisdiction: reasons.includes('foreign_jurisdiction') ? 1 : 0,
        };
    }
}

async function withPage(browser, options, task) {
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    try {
        if (options.proxyUsername || options.proxyPassword) {
            await page.authenticate({
                username: options.proxyUsername || '',
                password: options.proxyPassword || '',
            });
        }
        await page.setUserAgent(options.userAgent);
        await page.setCacheEnabled(false);
        return await task(page);
    } finally {
        await page.close().catch(() => {});
        await context.close().catch(() => {});
    }
}

async function capturePhase(browser, options, geoResolver, pageUrl, phase, screenshotPath, harPath = null) {
    const events = [];
    const result = await withPage(browser, options, async (page) => {
        let harRecorder = null;
        if (phase === 'blocked') {
            let mainHost = null;
            let mainHostMetaPromise = null;
            let mainAsn = null;
            try {
                mainHost = new URL(pageUrl).hostname;
                if (mainHost && isHttpLike(pageUrl)) {
                    mainHostMetaPromise = geoResolver.resolveHost(mainHost)
                        .then((meta) => {
                            mainAsn = normalizeAsn(meta?.ipGeo?.asn || null);
                            return meta;
                        })
                        .catch(() => null);
                }
            } catch {
                mainHost = null;
                mainHostMetaPromise = null;
                mainAsn = null;
            }

            await page.setRequestInterception(true);
            page.on('request', async (request) => {
                const requestUrl = request.url();
                const resourceType = request.resourceType();
                const isMainNavigation = request.isNavigationRequest() && request.frame() === page.mainFrame();
                let requestHost = null;
                try {
                    requestHost = isHttpLike(requestUrl) ? new URL(requestUrl).hostname : null;
                } catch {
                    requestHost = null;
                }

                if (isMainNavigation) {
                    events.push({
                        phase,
                        requestUrl,
                        requestHost,
                        resourceType,
                        decision: 'allow',
                        blockReason: 'allow_main_navigation',
                        ipAddress: null,
                        ipCountryCode: null,
                        ipContinentCode: null,
                        asn: null,
                        asName: null,
                        asDomain: null,
                        caidaAsCountryCode: null,
                        caidaAsOrgName: null,
                    });
                    await request.continue();
                    return;
                }

                if (!requestHost || !isHttpLike(requestUrl)) {
                    events.push({
                        phase,
                        requestUrl,
                        requestHost,
                        resourceType,
                        decision: 'allow',
                        blockReason: '',
                        ipAddress: null,
                        ipCountryCode: null,
                        ipContinentCode: null,
                        asn: null,
                        asName: null,
                        asDomain: null,
                        caidaAsCountryCode: null,
                        caidaAsOrgName: null,
                    });
                    await request.continue();
                    return;
                }

                try {
                    if (mainHostMetaPromise) {
                        await mainHostMetaPromise;
                    }
                    const hostMeta = await geoResolver.resolveHost(requestHost);
                    let decision = geoResolver.evaluate(hostMeta);
                    const requestAsn = normalizeAsn(decision.asn);
                    if (options.allowSameAsMainAsn && mainAsn && requestAsn && requestAsn === mainAsn) {
                        decision = {
                            ...decision,
                            decision: 'allow',
                            blockReason: 'allow_same_as_main_asn',
                            foreignIp: 0,
                            foreignJurisdiction: 0,
                        };
                    }
                    events.push({
                        phase,
                        requestUrl,
                        requestHost,
                        resourceType,
                        decision: decision.decision,
                        blockReason: decision.blockReason,
                        ipAddress: decision.ipAddress,
                        ipCountryCode: decision.ipCountryCode,
                        ipContinentCode: decision.ipContinentCode,
                        asn: decision.asn,
                        asName: decision.asName,
                        asDomain: decision.asDomain,
                        caidaAsCountryCode: decision.caidaAsCountryCode,
                        caidaAsOrgName: decision.caidaAsOrgName,
                    });
                    if (decision.decision === 'block') {
                        await request.abort('blockedbyclient');
                    } else {
                        await request.continue();
                    }
                } catch (error) {
                    events.push({
                        phase,
                        requestUrl,
                        requestHost,
                        resourceType,
                        decision: 'allow',
                        blockReason: `lookup_error:${error.message}`,
                        ipAddress: null,
                        ipCountryCode: null,
                        ipContinentCode: null,
                        asn: null,
                        asName: null,
                        asDomain: null,
                        caidaAsCountryCode: null,
                        caidaAsOrgName: null,
                    });
                    await request.continue();
                }
            });
        }

        try {
            if (options.har && harPath) {
                await fs.ensureDir(path.dirname(harPath));
                harRecorder = new PuppeteerHar(page);
                await harRecorder.start({ path: harPath });
            }

            let status = null;
            let error = null;
            try {
                const response = await page.goto(pageUrl, {
                    waitUntil: 'domcontentloaded',
                    timeout: options.navigationTimeoutMs,
                });
                status = response?.status?.() ?? null;
            } catch (err) {
                error = err.message;
            }

            try {
                await page.waitForNetworkIdle({
                    idleTime: options.networkIdleTimeMs,
                    concurrency: options.networkIdleConcurrency,
                    timeout: options.navigationTimeoutMs,
                });
            } catch {
                // Best effort for functionality snapshots.
            }

            let cookieBanner = { bannerState: 'unknown', action: 'skipped', details: null };
            try {
                cookieBanner = await tryAcceptCookieBanner(page);
            } catch {
            }

            let overlaySuppression = { hiddenCount: 0 };
            try {
                overlaySuppression = await suppressConsentOverlays(page);
            } catch {
            }

            try {
                await page.waitForNetworkIdle({
                    idleTime: Math.min(options.networkIdleTimeMs, 1000),
                    concurrency: options.networkIdleConcurrency,
                    timeout: Math.min(options.navigationTimeoutMs, 5000),
                });
            } catch {
            }

            await fs.ensureDir(path.dirname(screenshotPath));
            const htmlPath = screenshotPath.replace(/\.png$/i, '.html');
            const pageHtml = await page.content().catch(() => null);
            if (pageHtml != null) {
                await fs.writeFile(htmlPath, pageHtml, 'utf8');
            }
            await page.screenshot({ path: screenshotPath, fullPage: true });

            return {
                status,
                error,
                finalUrl: page.url(),
                cookieBanner,
                overlaySuppression,
                htmlPath,
                harPath,
            };
        } finally {
            if (harRecorder) {
                try {
                    await harRecorder.stop();
                } catch (error) {
                    console.error(`Error storing HAR for ${pageUrl} (${phase}):`, error.message);
                }
            }
        }
    });

    return {
        ...result,
        screenshotPath,
        harPath,
        events,
    };
}

async function run() {
    const options = parseArgs(process.argv.slice(2));
    const urls = await readUrls(options);
    await fs.ensureDir(options.storageDir);
    await fs.ensureDir(options.screenshotDir);
    if (options.har) {
        await fs.ensureDir(options.harDir);
    }

    const db = new EuCheckDatabase(options.sqlitePath);
    const geoResolver = new GeoResolver(options);
    await geoResolver.init();

    const launchArgs = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
    ];
    if (options.proxyServer) {
        launchArgs.push(`--proxy-server=${options.proxyServer}`);
    }

    const browser = await puppeteer.launch({
        headless: true,
        executablePath: options.browserExecutable || undefined,
        args: launchArgs,
    });

    try {
        for (const url of urls) {
            const normalizedUrl = normalizeUrl(url);
            const domain = new URL(normalizedUrl).hostname;
            const key = pageKey(`${options.endpointLabel}:${normalizedUrl}`);
            const pageOutputDir = path.join(options.screenshotDir, options.endpointLabel, key);
            const pageHarDir = path.join(options.harDir, options.endpointLabel, key);
            await fs.ensureDir(pageOutputDir);
            if (options.har) {
                await fs.ensureDir(pageHarDir);
            }
            const pageId = db.upsertPage(options.endpointLabel, normalizedUrl, domain, pageOutputDir);

            console.log(colors.cyan(`EU check ${options.endpointLabel}: ${normalizedUrl}`));

            const normal1Path = path.join(pageOutputDir, 'normal_1.png');
            const blockedPath = path.join(pageOutputDir, 'blocked_non_eu.png');
            const normal2Path = path.join(pageOutputDir, 'normal_2.png');
            const normal1HarPath = options.har ? path.join(pageHarDir, 'normal_1.har') : null;
            const blockedHarPath = options.har ? path.join(pageHarDir, 'blocked_non_eu.har') : null;
            const normal2HarPath = options.har ? path.join(pageHarDir, 'normal_2.har') : null;

            const normal1 = await capturePhase(browser, options, geoResolver, normalizedUrl, 'normal_1', normal1Path, normal1HarPath);
            const blocked = await capturePhase(browser, options, geoResolver, normalizedUrl, 'blocked', blockedPath, blockedHarPath);
            const normal2 = await capturePhase(browser, options, geoResolver, normalizedUrl, 'normal_2', normal2Path, normal2HarPath);

            const blockedRequestCount = blocked.events.filter(event => event.decision === 'block').length;
            const blockedForeignIpCount = blocked.events.filter(event => event.blockReason.includes('foreign_ip_location')).length;
            const blockedForeignJurisdictionCount = blocked.events.filter(event => event.blockReason.includes('foreign_jurisdiction')).length;

            db.replaceRequests(pageId, blocked.events);
            db.updatePageResult(pageId, {
                normal1Screenshot: normal1.screenshotPath,
                blockedScreenshot: blocked.screenshotPath,
                normal2Screenshot: normal2.screenshotPath,
                normal1Status: normal1.status,
                blockedStatus: blocked.status,
                normal2Status: normal2.status,
                blockedRequestCount,
                blockedForeignIpCount,
                blockedForeignJurisdictionCount,
            });

            await fs.writeJson(path.join(pageOutputDir, 'summary.json'), {
                endpointLabel: options.endpointLabel,
                pageUrl: normalizedUrl,
                pageDomain: domain,
                screenshots: {
                    normal1: normal1.screenshotPath,
                    blocked: blocked.screenshotPath,
                    normal2: normal2.screenshotPath,
                },
                html: {
                    normal1: normal1.htmlPath,
                    blocked: blocked.htmlPath,
                    normal2: normal2.htmlPath,
                },
                har: {
                    normal1: normal1.harPath,
                    blocked: blocked.harPath,
                    normal2: normal2.harPath,
                },
                statuses: {
                    normal1: normal1.status,
                    blocked: blocked.status,
                    normal2: normal2.status,
                },
                blockedStats: {
                    blockedRequestCount,
                    blockedForeignIpCount,
                    blockedForeignJurisdictionCount,
                },
                blockedRequests: blocked.events,
            }, { spaces: 2 });
        }
    } finally {
        await browser.close();
    }

    console.log(colors.green(`EU functionality crawl complete: ${options.sqlitePath}`));
}

run().catch((error) => {
    console.error(colors.red(error.stack || error.message));
    process.exitCode = 1;
});
