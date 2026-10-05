// BOOYAH MARKET backend — Express + Firebase Firestore (Admin SDK)
'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

try { require('dotenv').config(); } catch (e) { /* dotenv optional */ }

// ---------------------------------------------------------------- Firebase
function loadServiceAccount() {
  if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PROJECT_ID)
    return { project_id: process.env.FIREBASE_PROJECT_ID, client_email: process.env.FIREBASE_CLIENT_EMAIL,
             private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') };
  if (process.env.FIREBASE_SERVICE_ACCOUNT) return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  const f = process.env.FIREBASE_SERVICE_ACCOUNT_FILE || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const fp = f && path.resolve(__dirname, f);
  if (fp && fs.existsSync(fp)) return JSON.parse(fs.readFileSync(fp, 'utf8'));
  throw new Error('Firebase credentials missing. Set FIREBASE_SERVICE_ACCOUNT (json) or FIREBASE_SERVICE_ACCOUNT_FILE (path).');
}
admin.initializeApp({ credential: admin.credential.cert(loadServiceAccount()) });
const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });
const C = {
  users: db.collection('users'),
  listings: db.collection('listings'),
  idReq: db.collection('idRequests'),
  planReq: db.collection('planRequests'),
  reports: db.collection('reports'),
  delReq: db.collection('deletionRequests'),
  drafts: db.collection('drafts'),
  images: db.collection('images'),
  purchases: db.collection('purchases'),
  meta: db.collection('meta'),
};

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const DAY = 86400000;
const SERVERS = ['India Server', 'Bangladesh Server', 'Nepal Server'];
const LOGINS = ['Google (Gmail)', 'Facebook', 'VK', 'Twitter / X'];
const TG_RE = /^@[A-Za-z][A-Za-z0-9_]{4,31}$/;
const IMG_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
const MAX_IMAGES = 10;
const MAX_IMAGE_CHARS = 900000; // Firestore doc limit is 1 MiB

// ---------------------------------------------------------------- helpers
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const userKey = v => String(v || '').trim().toLowerCase().replace(/^@/, '');
const clamp = (v, n = 300) => String(v == null ? '' : v).trim().slice(0, n);
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const newId = () => crypto.randomBytes(16).toString('hex');

async function nextId(name) {
  const ref = C.meta.doc('counters');
  return db.runTransaction(async t => {
    const s = await t.get(ref);
    const n = ((s.exists && s.data()[name]) || 0) + 1;
    t.set(ref, { [name]: n }, { merge: true });
    return n;
  });
}

async function deleteSnap(snap) {
  const docs = snap.docs;
  for (let i = 0; i < docs.length; i += 400) {
    const b = db.batch();
    docs.slice(i, i + 400).forEach(d => b.delete(d.ref));
    await b.commit();
  }
}
async function deleteImages(ids) {
  ids = ids || [];
  for (let i = 0; i < ids.length; i += 400) {
    const b = db.batch();
    ids.slice(i, i + 400).forEach(id => b.delete(C.images.doc(id)));
    await b.commit();
  }
}

function effective(u) {
  const exp = u.membershipExpires || 0;
  const left = exp - Date.now();
  if (!u.membershipType || u.membershipType === 'regular' || left <= 0) return { type: 'regular', days: 0 };
  return { type: u.membershipType, days: Math.ceil(left / DAY) };
}

// simple in-memory rate limiter (per IP)
function limiter(max, windowMs) {
  const hits = new Map();
  return (req, res, next) => {
    const k = req.ip, now = Date.now();
    const arr = (hits.get(k) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) return next(new HttpError(429, 'Too many requests. Please wait a bit and try again.'));
    arr.push(now); hits.set(k, arr);
    if (hits.size > 5000) for (const [key, v] of hits) if (!v.some(t => now - t < windowMs)) hits.delete(key);
    next();
  };
}

// ---------------------------------------------------------------- app
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '15mb' }));

let feedCache = null;
const invalidateFeed = () => { feedCache = null; };

// ---- auth middleware
const requireUser = wrap(async (req, res, next) => {
  const name = req.get('X-User'), token = req.get('X-User-Token');
  if (!name || !token) throw new HttpError(401, 'Please login first.');
  const ref = C.users.doc(userKey(name));
  const s = await ref.get();
  if (!s.exists || !s.data().tokenHash || !safeEq(s.data().tokenHash, sha256(token)))
    throw new HttpError(401, 'Session expired. Please login again.');
  req.uref = ref; req.user = s.data();
  next();
});
const adminFails = limiter(10, 15 * 60 * 1000);
const requireAdmin = wrap(async (req, res, next) => {
  if (!ADMIN_PASSWORD) throw new HttpError(503, 'ADMIN_PASSWORD is not set on the server.');
  const p = req.get('X-Admin-Password') || '';
  if (!safeEq(sha256(p), sha256(ADMIN_PASSWORD))) {
    return adminFails(req, res, err => next(err || new HttpError(401, 'Wrong admin password')));
  }
  next();
});

// ---------------------------------------------------------------- public: health + images
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/images/:id', wrap(async (req, res) => {
  const s = await C.images.doc(req.params.id).get();
  if (!s.exists) throw new HttpError(404, 'Not found');
  const m = /^data:(image\/[a-z]+);base64,(.*)$/.exec(s.data().data);
  if (!m) throw new HttpError(404, 'Not found');
  res.set('Content-Type', m[1]);
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.send(Buffer.from(m[2], 'base64'));
}));

const imgUrls = (req, ids) => (ids || []).map(id => `${req.protocol}://${req.get('host')}/api/images/${id}`);

// ---------------------------------------------------------------- accounts
app.post('/api/register', limiter(30, 10 * 60 * 1000), wrap(async (req, res) => {
  const b = req.body || {};
  let username = String(b.username || '').trim().replace(/\s+/g, '');
  if (username && username[0] !== '@') username = '@' + username;
  if (!TG_RE.test(username)) throw new HttpError(400, 'Enter a valid Telegram username, e.g. @username');
  if (b.acceptedTerms !== true) throw new HttpError(400, 'Please accept Terms of Service and Privacy Policy');
  const key = userKey(username), ref = C.users.doc(key);
  const out = await db.runTransaction(async t => {
    const s = await t.get(ref);
    if (!s.exists) {
      const token = crypto.randomBytes(24).toString('hex');
      t.set(ref, {
        username, key, tokenHash: sha256(token), deviceLocked: true,
        membershipType: 'regular', membershipExpires: 0, blocked: false, listingCredits: 0,
        blockedSellers: [], termsVersion: clamp(b.termsVersion, 40), createdAt: Date.now(),
      });
      return { isNew: true, token, username };
    }
    const u = s.data();
    if (b.deviceToken && u.tokenHash && safeEq(u.tokenHash, sha256(b.deviceToken))) {
      t.update(ref, { termsVersion: clamp(b.termsVersion, 40) });
      return { isNew: false, username: u.username };
    }
    if (!u.deviceLocked) { // admin reset the device lock
      const token = crypto.randomBytes(24).toString('hex');
      t.update(ref, { tokenHash: sha256(token), deviceLocked: true, termsVersion: clamp(b.termsVersion, 40) });
      return { isNew: false, token, username: u.username };
    }
    throw new HttpError(403, 'This username is already locked to another mobile. Delete it from Support on that phone, or contact admin on Telegram.');
  });
  res.json(out);
}));

app.get('/api/users/:u', wrap(async (req, res) => {
  const name = req.get('X-User'), token = req.get('X-User-Token');
  const key = userKey(req.params.u);
  if (!name || !token || userKey(name) !== key) return res.json({ exists: false });
  const s = await C.users.doc(key).get();
  if (!s.exists || !s.data().tokenHash || !safeEq(s.data().tokenHash, sha256(token))) return res.json({ exists: false });
  const u = s.data(), e = effective(u);
  res.json({ exists: true, username: u.username, type: e.type, days: e.days, blocked: !!u.blocked, listingCredits: u.listingCredits || 0 });
}));

async function wipeUser(key) {
  const [ls, rs, ps] = await Promise.all([
    C.listings.where('sellerKey', '==', key).get(),
    C.idReq.where('userKey', '==', key).get(),
    C.planReq.where('userKey', '==', key).get(),
  ]);
  for (const d of [...ls.docs, ...rs.docs]) await deleteImages(d.data().imageIds);
  await Promise.all([deleteSnap(ls), deleteSnap(rs), deleteSnap(ps)]);
  await C.drafts.doc(key).delete();
  await C.users.doc(key).delete();
  invalidateFeed();
}

app.delete('/api/account', requireUser, wrap(async (req, res) => {
  await wipeUser(req.user.key);
  res.json({ ok: true });
}));

app.post('/api/account/delete-request', limiter(10, 60 * 60 * 1000), wrap(async (req, res) => {
  const b = req.body || {};
  const u = clamp(b.username, 64);
  if (!u) throw new HttpError(400, 'Username is required');
  const id = await nextId('deletion');
  await C.delReq.doc(String(id)).set({
    id, username: u, contact: clamp(b.contact, 120), reason: clamp(b.reason, 500),
    status: 'pending', created_at: Date.now(),
  });
  res.json({ ok: true, id });
}));

// ---------------------------------------------------------------- drafts
const DRAFT_FIELDS = ['level', 'server', 'login', 'evo', 'skins', 'pass', 'screens', 'price', 'contact', 'utr'];
app.get('/api/drafts/me', requireUser, wrap(async (req, res) => {
  const s = await C.drafts.doc(req.user.key).get();
  res.json(s.exists ? s.data() : {});
}));
app.post('/api/drafts/me', requireUser, wrap(async (req, res) => {
  const d = {};
  DRAFT_FIELDS.forEach(f => { if (req.body && req.body[f]) d[f] = clamp(req.body[f], 400); });
  if (Object.keys(d).length) await C.drafts.doc(req.user.key).set(d); else await C.drafts.doc(req.user.key).delete();
  res.json({ ok: true });
}));

// ---------------------------------------------------------------- listings (public feed)
async function loadFeed() {
  if (feedCache && Date.now() - feedCache.t < 15000) return feedCache.items;
  const snap = await C.listings.orderBy('listingNo', 'desc').get();
  feedCache = { t: Date.now(), items: snap.docs.map(d => d.data()) };
  return feedCache.items;
}

app.get('/api/listings', wrap(async (req, res) => {
  let hidden = new Set();
  const name = req.get('X-User'), token = req.get('X-User-Token');
  if (name && token) {
    const s = await C.users.doc(userKey(name)).get();
    if (s.exists && s.data().tokenHash && safeEq(s.data().tokenHash, sha256(token))) hidden = new Set(s.data().blockedSellers || []);
  }
  const items = await loadFeed();
  res.json(items.filter(l => !hidden.has(l.sellerKey)).map(l => ({
    listingNo: l.listingNo, level: l.level, server: l.server, login: l.login, evo: l.evo,
    skins: l.skins, pass: l.pass, price: l.price, sold: !!l.sold, sellerType: l.sellerType,
    images: imgUrls(req, l.imageIds), createdAt: l.createdAt,
  })));
}));

app.post('/api/listings', requireUser, wrap(async (req, res) => {
  const u = req.user, b = req.body || {};
  if (u.blocked) throw new HttpError(403, 'Your account is blocked. Contact support.');
  const level = clamp(b.level, 120), price = clamp(b.price, 20);
  if (!level || !price || !(Number(price.replace(/[^0-9.]/g, '')) > 0)) throw new HttpError(400, 'Level and a valid price are required');
  const images = Array.isArray(b.images) ? b.images.slice(0, MAX_IMAGES) : [];
  for (const im of images) if (typeof im !== 'string' || im.length > MAX_IMAGE_CHARS || !IMG_RE.test(im)) throw new HttpError(400, 'One of the screenshots is invalid or too large');

  const eff = effective(u);
  const pending = await C.idReq.where('userKey', '==', u.key).where('status', '==', 'pending').count().get();
  if (eff.type !== 'vipro' && pending.data().count >= 10) throw new HttpError(429, 'You already have 10 listings waiting for approval.');

  const payMethod = b.payMethod === 'play' ? 'play' : 'upi';
  const utr = clamp(b.utr, 60);
  if (eff.type !== 'vipro') {
    if (payMethod === 'play') {
      const ok = await db.runTransaction(async t => {
        const s = await t.get(req.uref);
        const c = s.data().listingCredits || 0;
        if (c < 1) return false;
        t.update(req.uref, { listingCredits: c - 1 });
        return true;
      });
      if (!ok) throw new HttpError(402, 'Please pay the ₹25 listing fee first.');
    } else if (!utr) throw new HttpError(400, 'Enter transaction UTR after payment');
  }

  const imageIds = [];
  for (const data of images) { const id = newId(); await C.images.doc(id).set({ data, ownerKey: u.key, createdAt: Date.now() }); imageIds.push(id); }

  const base = {
    level, server: SERVERS.includes(b.server) ? b.server : SERVERS[0],
    login: LOGINS.includes(b.login) ? b.login : LOGINS[0],
    evo: clamp(b.evo, 200), skins: clamp(b.skins, 300), pass: clamp(b.pass, 200),
    contact: clamp(b.contact, 80), price, utr: payMethod === 'play' ? 'GOOGLE PLAY' : utr,
    screens: clamp(b.screens, 500), payMethod, imageIds, createdAt: Date.now(),
  };

  if (eff.type === 'vipro') {
    const listingNo = await nextId('listing');
    await C.listings.doc(String(listingNo)).set({ ...base, listingNo, sellerKey: u.key, seller: u.username, sellerType: 'vipro', sold: false });
    invalidateFeed();
    return res.json({ status: 'approved', id: listingNo, listingNo });
  }
  const id = await nextId('idRequest');
  await C.idReq.doc(String(id)).set({ ...base, id, user: u.username, userKey: u.key, type: eff.type, status: 'pending' });
  res.json({ status: 'pending', id });
}));

// ---------------------------------------------------------------- blocks & reports
app.get('/api/blocks', requireUser, wrap(async (req, res) => res.json({ count: (req.user.blockedSellers || []).length })));
app.post('/api/blocks', requireUser, wrap(async (req, res) => {
  const s = await C.listings.doc(String(Number(req.body.listingNo) || 0)).get();
  if (!s.exists) throw new HttpError(404, 'Listing not found');
  const seller = s.data().sellerKey;
  if (seller === req.user.key) throw new HttpError(400, 'You cannot block yourself');
  await req.uref.update({ blockedSellers: admin.firestore.FieldValue.arrayUnion(seller) });
  res.json({ ok: true });
}));
app.delete('/api/blocks', requireUser, wrap(async (req, res) => {
  await req.uref.update({ blockedSellers: [] });
  res.json({ ok: true });
}));

app.post('/api/reports', requireUser, limiter(30, 60 * 60 * 1000), wrap(async (req, res) => {
  const no = Number(req.body.listingNo) || 0;
  const s = await C.listings.doc(String(no)).get();
  if (!s.exists) throw new HttpError(404, 'Listing not found');
  const l = s.data(), id = await nextId('report');
  await C.reports.doc(String(id)).set({
    id, listingNo: no, sellerKey: l.sellerKey, seller: l.seller, level: l.level, price: l.price,
    reporterKey: req.user.key, reason: clamp(req.body.reason, 100), details: clamp(req.body.details, 800),
    status: 'open', createdAt: Date.now(),
  });
  res.json({ ok: true, id });
}));

// ---------------------------------------------------------------- plan requests (manual UPI)
app.post('/api/plan-requests', requireUser, wrap(async (req, res) => {
  const b = req.body || {};
  const type = ['VIP', 'VIP PRO', 'BUYER'].includes(b.type) ? b.type : null;
  if (!type) throw new HttpError(400, 'Invalid plan');
  const pend = await C.planReq.where('userKey', '==', req.user.key).where('status', '==', 'pending').count().get();
  if (pend.data().count >= 10) throw new HttpError(429, 'You already have pending plan requests.');
  const id = await nextId('planRequest');
  await C.planReq.doc(String(id)).set({
    id, user: req.user.username, userKey: req.user.key, type, name: clamp(b.name, 60),
    price: clamp(b.price, 12), duration: b.duration === 'single' ? 'single' : String(parseInt(b.duration, 10) || 0),
    status: 'pending', createdAt: Date.now(),
  });
  res.json({ id });
}));

// ---------------------------------------------------------------- Google Play billing
const PLAY_PRODUCTS = {
  listing_fee: { kind: 'credit' },
  buyer_escrow: { kind: 'escrow' },
};
[1, 3, 5, 7, 30, 90, 365].forEach(d => PLAY_PRODUCTS['vip_' + d + 'd'] = { kind: 'vip', days: d });
[90, 365].forEach(d => PLAY_PRODUCTS['vippro_' + d + 'd'] = { kind: 'vipro', days: d });

let playClient = null;
async function playGet(productId, token) {
  if (!process.env.GOOGLE_PLAY_PACKAGE_NAME || !process.env.GOOGLE_PLAY_SERVICE_ACCOUNT)
    throw new HttpError(501, 'Google Play billing is not configured on the server.');
  if (!playClient) {
    const { google } = require('googleapis');
    const auth = new google.auth.GoogleAuth({
      credentials: JSON.parse(process.env.GOOGLE_PLAY_SERVICE_ACCOUNT),
      scopes: ['https://www.googleapis.com/auth/androidpublisher'],
    });
    playClient = google.androidpublisher({ version: 'v3', auth });
  }
  const r = await playClient.purchases.products.get({ packageName: process.env.GOOGLE_PLAY_PACKAGE_NAME, productId, token });
  return r.data;
}

async function grantMembership(key, type, days) {
  const ref = C.users.doc(key);
  await db.runTransaction(async t => {
    const s = await t.get(ref);
    if (!s.exists) throw new HttpError(404, 'User not found');
    if (type === 'regular') { t.update(ref, { membershipType: 'regular', membershipExpires: 0 }); return; }
    const u = s.data(), e = effective(u);
    const from = e.type === type ? u.membershipExpires : Date.now(); // same tier extends, new tier replaces
    t.update(ref, { membershipType: type, membershipExpires: from + days * DAY });
  });
}

app.post('/api/billing/verify', requireUser, wrap(async (req, res) => {
  const productId = clamp(req.body.productId, 60), token = clamp(req.body.purchaseToken, 600);
  const prod = PLAY_PRODUCTS[productId];
  if (!prod || !token) throw new HttpError(400, 'Invalid purchase');
  const p = await playGet(productId, token);
  if (p.purchaseState === 2) return res.json({ pending: true });
  if (p.purchaseState !== 0) throw new HttpError(400, 'This purchase was cancelled.');
  if (p.obfuscatedExternalAccountId && p.obfuscatedExternalAccountId !== sha256('booyah:' + req.user.key))
    throw new HttpError(403, 'This purchase belongs to a different account.');

  const pref = C.purchases.doc(sha256(token));
  try { await pref.create({ productId, userKey: req.user.key, orderId: clamp(req.body.orderId, 80), createdAt: Date.now() }); }
  catch (e) { if (e.code === 6) return res.json({ consume: true, duplicate: true }); throw e; }

  try {
    let status = 'ok';
    if (prod.kind === 'credit') await req.uref.update({ listingCredits: admin.firestore.FieldValue.increment(1) });
    else if (prod.kind === 'escrow') {
      const id = await nextId('planRequest');
      await C.planReq.doc(String(id)).set({ id, user: req.user.username, userKey: req.user.key, type: 'BUYER', name: 'Buyer Safety Escrow', price: '99', duration: 'single', status: 'pending', paid: 'play', createdAt: Date.now() });
      status = 'pending_admin';
    } else await grantMembership(req.user.key, prod.kind, prod.days);
    res.json({ consume: true, status });
  } catch (e) { await pref.delete().catch(() => {}); throw e; }
}));

// ---------------------------------------------------------------- admin
app.post('/api/admin/login', requireAdmin, (req, res) => res.json({ ok: true }));

app.get('/api/admin/stats', requireAdmin, wrap(async (req, res) => {
  const n = async q => (await q.count().get()).data().count;
  const [users, live, sold, pendingIds, pendingPlans, openReports, deletionRequests, billing] = await Promise.all([
    n(C.users), n(C.listings.where('sold', '==', false)), n(C.listings.where('sold', '==', true)),
    n(C.idReq.where('status', '==', 'pending')), n(C.planReq.where('status', '==', 'pending')),
    n(C.reports.where('status', '==', 'open')), n(C.delReq.where('status', '==', 'pending')), n(C.purchases),
  ]);
  res.json({ users, liveListings: live, soldListings: sold, pendingIds, pendingPlans, openReports, deletionRequests, billing });
}));

app.get('/api/admin/requests', requireAdmin, wrap(async (req, res) => {
  const [ids, plans] = await Promise.all([
    C.idReq.where('status', '==', 'pending').get(), C.planReq.where('status', '==', 'pending').get(),
  ]);
  res.json({
    idRequests: ids.docs.map(d => { const r = d.data(); return { ...r, images: imgUrls(req, r.imageIds) }; }).sort((a, b) => a.id - b.id),
    planRequests: plans.docs.map(d => d.data()).sort((a, b) => a.id - b.id),
  });
}));

app.post('/api/admin/id-requests/:id/:action(approve|reject)', requireAdmin, wrap(async (req, res) => {
  const ref = C.idReq.doc(req.params.id);
  const approve = req.params.action === 'approve';
  const listingNo = approve ? await nextId('listing') : 0; // gaps are harmless
  const r = await db.runTransaction(async t => {
    const s = await t.get(ref);
    if (!s.exists) throw new HttpError(404, 'Request not found');
    const d = s.data();
    if (d.status !== 'pending') throw new HttpError(409, 'Already handled');
    t.update(ref, { status: approve ? 'approved' : 'rejected', listingNo: approve ? listingNo : null, decidedAt: Date.now() });
    if (approve) t.set(C.listings.doc(String(listingNo)), {
      listingNo, sellerKey: d.userKey, seller: d.user, sellerType: d.type, sold: false,
      level: d.level, server: d.server, login: d.login, evo: d.evo, skins: d.skins, pass: d.pass,
      contact: d.contact, price: d.price, utr: d.utr, screens: d.screens, payMethod: d.payMethod,
      imageIds: d.imageIds, createdAt: Date.now(),
    });
    return d;
  });
  if (!approve) await deleteImages(r.imageIds);
  invalidateFeed();
  res.json({ ok: true, listingNo: approve ? listingNo : undefined });
}));

app.post('/api/admin/plan-requests/:id/:action(approve|reject)', requireAdmin, wrap(async (req, res) => {
  const ref = C.planReq.doc(req.params.id);
  const s = await ref.get();
  if (!s.exists) throw new HttpError(404, 'Request not found');
  const r = s.data();
  if (r.status !== 'pending') throw new HttpError(409, 'Already handled');
  if (req.params.action === 'approve') {
    const days = parseInt(r.duration, 10);
    if (r.type === 'VIP' && days > 0) await grantMembership(r.userKey, 'vip', days);
    else if (r.type === 'VIP PRO' && days > 0) await grantMembership(r.userKey, 'vipro', days);
    // BUYER escrow: nothing to grant, admin handles the deal on Telegram
  }
  await ref.update({ status: req.params.action === 'approve' ? 'approved' : 'rejected', decidedAt: Date.now() });
  res.json({ ok: true, user: r.user });
}));

// ---- admin: users
app.get('/api/admin/users/:u', requireAdmin, wrap(async (req, res) => {
  const s = await C.users.doc(userKey(req.params.u)).get();
  if (!s.exists) return res.json({ exists: false });
  const u = s.data(), e = effective(u);
  res.json({ exists: true, username: u.username, type: e.type, days: e.days, blocked: !!u.blocked, deviceLocked: !!u.deviceLocked, listingCredits: u.listingCredits || 0 });
}));
app.post('/api/admin/users/:u/membership', requireAdmin, wrap(async (req, res) => {
  const type = req.body.type, days = parseInt(req.body.days, 10) || 0;
  if (!['regular', 'vip', 'vipro'].includes(type) || (type !== 'regular' && !(days > 0 && days <= 3650))) throw new HttpError(400, 'Invalid membership');
  await grantMembership(userKey(req.params.u), type, days);
  res.json({ ok: true });
}));
app.post('/api/admin/users/:u/block', requireAdmin, wrap(async (req, res) => {
  const ref = C.users.doc(userKey(req.params.u));
  if (!(await ref.get()).exists) throw new HttpError(404, 'User not found');
  await ref.update({ blocked: !!req.body.blocked });
  res.json({ ok: true, blocked: !!req.body.blocked });
}));
app.post('/api/admin/users/:u/reset-device', requireAdmin, wrap(async (req, res) => {
  const ref = C.users.doc(userKey(req.params.u));
  if (!(await ref.get()).exists) throw new HttpError(404, 'User not found');
  await ref.update({ deviceLocked: false, tokenHash: '' });
  res.json({ ok: true });
}));
app.delete('/api/admin/users/:u', requireAdmin, wrap(async (req, res) => {
  await wipeUser(userKey(req.params.u));
  res.json({ ok: true });
}));

// ---- admin: listings
app.delete('/api/admin/listings/:no', requireAdmin, wrap(async (req, res) => {
  const ref = C.listings.doc(String(Number(req.params.no) || 0));
  const s = await ref.get();
  if (!s.exists) throw new HttpError(404, 'BMW ID not found');
  await deleteImages(s.data().imageIds);
  await ref.delete(); invalidateFeed();
  res.json({ ok: true });
}));
app.post('/api/admin/listings/:no/sold', requireAdmin, wrap(async (req, res) => {
  const ref = C.listings.doc(String(Number(req.params.no) || 0));
  if (!(await ref.get()).exists) throw new HttpError(404, 'BMW ID not found');
  await ref.update({ sold: true, soldAt: Date.now() }); invalidateFeed();
  res.json({ ok: true });
}));

// ---- admin: reports
app.get('/api/admin/reports', requireAdmin, wrap(async (req, res) => {
  const snap = await C.reports.where('status', '==', 'open').get();
  const out = [];
  for (const d of snap.docs) {
    const r = d.data(), l = await C.listings.doc(String(r.listingNo)).get();
    out.push({ id: r.id, listingNo: r.listingNo, reason: r.reason, details: r.details, seller: r.seller, level: r.level, price: r.price,
      listingStatus: !l.exists ? 'deleted' : (l.data().sold ? 'sold' : 'live') });
  }
  res.json(out.sort((a, b) => a.id - b.id));
}));
app.post('/api/admin/reports/:id/:action(dismiss|delete-listing|block-seller)', requireAdmin, wrap(async (req, res) => {
  const ref = C.reports.doc(req.params.id), s = await ref.get();
  if (!s.exists) throw new HttpError(404, 'Report not found');
  const r = s.data(), a = req.params.action;
  if (a === 'delete-listing') {
    const l = await C.listings.doc(String(r.listingNo)).get();
    if (l.exists) { await deleteImages(l.data().imageIds); await l.ref.delete(); }
  } else if (a === 'block-seller') {
    const u = C.users.doc(r.sellerKey);
    if ((await u.get()).exists) await u.update({ blocked: true });
    const ls = await C.listings.where('sellerKey', '==', r.sellerKey).get();
    for (const d of ls.docs) await deleteImages(d.data().imageIds);
    await deleteSnap(ls);
  }
  await ref.update({ status: 'closed', action: a, closedAt: Date.now() });
  invalidateFeed();
  res.json({ ok: true });
}));

// ---- admin: deletion requests
app.get('/api/admin/deletion-requests', requireAdmin, wrap(async (req, res) => {
  const snap = await C.delReq.where('status', '==', 'pending').get();
  res.json(snap.docs.map(d => d.data()).sort((a, b) => a.id - b.id));
}));
app.post('/api/admin/deletion-requests/:id/:action(delete|reject)', requireAdmin, wrap(async (req, res) => {
  const ref = C.delReq.doc(req.params.id), s = await ref.get();
  if (!s.exists) throw new HttpError(404, 'Request not found');
  if (req.params.action === 'delete') await wipeUser(userKey(s.data().username));
  await ref.update({ status: req.params.action === 'delete' ? 'done' : 'rejected', closedAt: Date.now() });
  res.json({ ok: true });
}));

// ---- admin: backup (JSON dump; add ?images=1 to include screenshots)
app.get('/api/admin/backup', requireAdmin, wrap(async (req, res) => {
  const names = ['users', 'listings', 'idRequests', 'planRequests', 'reports', 'deletionRequests', 'purchases', 'drafts', 'meta'];
  if (req.query.images === '1') names.push('images');
  const out = { exportedAt: new Date().toISOString() };
  for (const n of names) out[n] = (await db.collection(n).get()).docs.map(d => ({ _id: d.id, ...d.data() }));
  res.set('Content-Type', 'application/json');
  res.set('Content-Disposition', 'attachment; filename="booyah-backup.json"');
  res.send(JSON.stringify(out));
}));

// ---------------------------------------------------------------- static site + errors
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') err = new HttpError(413, 'Upload too large. Use fewer or smaller screenshots.');
  if (!(err instanceof HttpError)) console.error(err);
  res.status(err.status || 500).json({ error: err instanceof HttpError ? err.message : 'Server error' });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log('BOOYAH MARKET running on :' + PORT));
}
module.exports = app;
