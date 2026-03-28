require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const admin = require('firebase-admin');

const BCRYPT_ROUNDS = 10;
const TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour
const PAYMENT_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const AES_KEY = process.env.AES_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

// ============================================================
// Firebase Firestore
// ============================================================
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

const app = express();
app.set('trust proxy', 1); // Render uses reverse proxy
const PORT = process.env.PORT || 3000;

// Firestore collections
const usersCol = db.collection('users');
const paymentsCol = db.collection('payments');
const tokensCol = db.collection('tokens');

// Seed admin user from env (runs once on startup)
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@admin.com').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

async function seedAdmin() {
  const snapshot = await usersCol.where('email', '==', ADMIN_EMAIL).where('role', '==', 'admin').limit(1).get();
  if (!snapshot.empty) {
    // Re-hash password if stored as plaintext (migration)
    const doc = snapshot.docs[0];
    const data = doc.data();
    if (!data.password.startsWith('$2b$')) {
      const hashed = await bcrypt.hash(ADMIN_PASSWORD, BCRYPT_ROUNDS);
      await usersCol.doc(doc.id).update({ password: hashed });
      console.log('🔒 Admin password migrated to bcrypt');
    }
    return;
  }
  const adminId = 'admin-' + crypto.randomBytes(4).toString('hex');
  const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, BCRYPT_ROUNDS);
  await usersCol.doc(adminId).set({
    id: adminId,
    email: ADMIN_EMAIL,
    password: hashedPassword,
    name: 'المدير',
    role: 'admin',
    createdAt: new Date().toISOString(),
  });
  console.log(`👤 Admin seeded: ${ADMIN_EMAIL}`);
}

// ============================================================
// #19: Reject weak admin password
// ============================================================
if (ADMIN_PASSWORD.length < 8 || ADMIN_PASSWORD === 'admin123') {
  console.warn('⚠️  تحذير: كلمة مرور المدير ضعيفة! غيّرها في متغيرات البيئة');
}

// ============================================================
// Middleware
// ============================================================

// #13: Body size limit (1MB max)
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// Debug: log every incoming request (method + path)
app.use((req, res, next) => {
  console.log(`🚨 [REQ] ${req.method} ${req.path}`);
  next();
});

// ============================================================
// EdfaPay Webhook & 3DS Callback (BEFORE CORS — external origins)
// ============================================================
app.post('/api/edfa/webhook', async (req, res) => {
  console.log('✅ Webhook HIT — body:', JSON.stringify(req.body).slice(0, 200));
  const { order_id, status, trans_id } = req.body;
  if (!order_id) {
    return res.status(400).send('Missing order_id');
  }

  // Verify the webhook comes from EdfaPay by checking hash
  if (req.body.hash && process.env.EDFA_MERCHANT_PASSWORD) {
    const doc = await paymentsCol.doc(order_id).get();
    if (!doc.exists) {
      return res.status(404).send('Not found');
    }
    const payment = doc.data();
    const expectedHash = generateEdfaHash(
      order_id,
      Number(payment.price).toFixed(2),
      process.env.EDFA_CURRENCY || 'SAR',
      payment.productName
    );
    if (req.body.hash !== expectedHash) {
      console.warn(`⚠️ Webhook hash mismatch for ${order_id.slice(0, 8)}...`);
    }
  }

  const doc2 = await paymentsCol.doc(order_id).get();
  if (!doc2.exists) {
    return res.status(404).send('Not found');
  }

  const currentPayment = doc2.data();
  const normalizedStatus = String(status || '').toLowerCase();
  const result = String(req.body.result || '').toUpperCase();

  // Guard: never overwrite a final state (paid/cancelled)
  if (currentPayment.status === 'paid' || currentPayment.status === 'cancelled') {
    console.log(`⚠️ Webhook ignored for ${order_id.slice(0, 8)}... (already ${currentPayment.status})`);
    return res.status(200).send('OK');
  }

  if (normalizedStatus === 'settled' || normalizedStatus === 'success' || normalizedStatus === '3ds_success' || result === 'SUCCESS') {
    await paymentsCol.doc(order_id).update({
      status: 'paid',
      paidAt: new Date().toISOString(),
      edfaTransId: trans_id || null,
    });
    await auditLog('payment_paid', null, { paymentId: order_id.slice(0, 8) });
    console.log(`✅ Payment ${order_id.slice(0, 8)}... paid`);
  } else if (normalizedStatus === 'declined' || normalizedStatus === 'fail' || normalizedStatus === 'error' || result === 'DECLINED') {
    await paymentsCol.doc(order_id).update({
      status: 'failed',
      failReason: req.body.decline_reason || 'unknown',
      edfaTransId: trans_id || null,
    });
    await auditLog('payment_failed', null, { paymentId: order_id.slice(0, 8), reason: req.body.decline_reason });
    console.log(`❌ Payment ${order_id.slice(0, 8)}... failed`);
  }

  res.status(200).send('OK');
});

app.all('/api/edfa/callback-3ds/:id', async (req, res) => {
  const doc = await paymentsCol.doc(req.params.id).get();
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
  if (!doc.exists) {
    return res.redirect(`${baseUrl}/pay/invalid`);
  }
  res.redirect(`${baseUrl}/pay/${doc.data().id}`);
});

// #7: Helmet security headers + #15: CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'", "https://api.edfapay.com"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// #8: CORS restricted to own domain
const allowedOrigins = [
  process.env.BASE_URL,
  process.env.RENDER_EXTERNAL_URL,
  `http://localhost:${PORT}`,
].filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.some(o => origin.startsWith(o))) return cb(null, true);
    cb(new Error('CORS blocked'));
  },
  credentials: true,
}));

// #12: HTTPS redirect in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.hostname}${req.originalUrl}`);
  }
  next();
});

// #3: Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: { error: 'محاولات كثيرة، حاول بعد 15 دقيقة' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: { error: 'طلبات كثيرة، حاول لاحقاً' },
  standardHeaders: true,
  legacyHeaders: false,
});

const paymentSendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10, // 10 payment links per minute
  message: { error: 'إرسال روابط كثيرة، انتظر دقيقة' },
  standardHeaders: true,
  legacyHeaders: false,
});

// #16: Login brute-force blocker (stricter than general rate limit)
const loginFailTracker = new Map(); // IP -> { count, blockedUntil }
function checkLoginBlock(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const tracker = loginFailTracker.get(ip);
  if (tracker && tracker.blockedUntil && Date.now() < tracker.blockedUntil) {
    const mins = Math.ceil((tracker.blockedUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `تم حظرك مؤقتاً، حاول بعد ${mins} دقيقة` });
  }
  req.loginIp = ip;
  next();
}
function recordLoginFail(ip) {
  const tracker = loginFailTracker.get(ip) || { count: 0, blockedUntil: null };
  tracker.count++;
  if (tracker.count >= 5) {
    tracker.blockedUntil = Date.now() + 15 * 60 * 1000; // block 15 min
    tracker.count = 0;
  }
  loginFailTracker.set(ip, tracker);
}
function clearLoginFails(ip) {
  loginFailTracker.delete(ip);
}

// Apply general rate limit to API routes
app.use('/api/', apiLimiter);

// Serve static files but do NOT auto-serve index.html for "/"
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ============================================================
// Auth helpers
// ============================================================
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// #6: Input sanitization
function sanitize(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>]/g, '').trim();
}

// #18: NoSQL injection protection
function isCleanInput(val) {
  if (typeof val === 'object' && val !== null) return false;
  if (typeof val === 'string' && (val.includes('$') || val.includes('{'))) return false;
  return true;
}

// #11: Mask sensitive data in logs
function maskEmail(email) {
  if (!email || typeof email !== 'string') return '***';
  const [user, domain] = email.split('@');
  if (!domain) return '***';
  return user.slice(0, 2) + '***@' + domain;
}

// #14: AES-256 encrypt/decrypt for customer data
function encryptData(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(AES_KEY.slice(0, 64), 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(String(text), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedText) {
  if (!encryptedText || !encryptedText.includes(':')) return encryptedText;
  try {
    const [ivHex, encrypted] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const key = Buffer.from(AES_KEY.slice(0, 64), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return encryptedText;
  }
}

// #17: Audit log
const auditCol = db.collection('audit_logs');
async function auditLog(action, userId, details = {}) {
  try {
    await auditCol.add({
      action,
      userId: userId || 'system',
      details,
      timestamp: new Date().toISOString(),
    });
  } catch (e) { /* silent */ }
}

function requireAuth(role) {
  return async (req, res, next) => {
    // #9: Read token from HttpOnly cookie first, fallback to header
    const token = req.cookies?.auth_token ||
      (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7) : null);
    if (!token) {
      return res.status(401).json({ error: 'غير مصرح' });
    }
    const tokenDoc = await tokensCol.doc(token).get();
    if (!tokenDoc.exists) {
      return res.status(401).json({ error: 'جلسة غير صالحة' });
    }
    const tokenData = tokenDoc.data();
    // Check token expiration
    const tokenAge = Date.now() - new Date(tokenData.createdAt).getTime();
    if (tokenAge > TOKEN_EXPIRY_MS) {
      await tokensCol.doc(token).delete();
      return res.status(401).json({ error: 'انتهت صلاحية الجلسة، سجل دخول مرة أخرى' });
    }
    const userId = tokenData.userId;
    const userDoc = await usersCol.doc(userId).get();
    if (!userDoc.exists) {
      return res.status(401).json({ error: 'مستخدم غير موجود' });
    }
    const user = userDoc.data();
    if (role && user.role !== role) {
      return res.status(403).json({ error: 'ليس لديك صلاحية' });
    }
    req.user = user;
    next();
  };
}

// ============================================================
// Auth routes
// ============================================================

// Clean URL routes
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/merchant', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'merchant.html'));
});

app.post('/api/auth/login', loginLimiter, checkLoginBlock, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'البريد وكلمة المرور مطلوبين' });
  }
  // #18: NoSQL injection check
  if (!isCleanInput(email) || !isCleanInput(password)) {
    return res.status(400).json({ error: 'مدخلات غير صالحة' });
  }
  const normalEmail = sanitize(String(email)).toLowerCase().trim();
  const snapshot = await usersCol.where('email', '==', normalEmail).limit(1).get();
  if (snapshot.empty) {
    recordLoginFail(req.loginIp);
    await auditLog('login_failed', null, { email: maskEmail(normalEmail), reason: 'not_found' });
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  const user = snapshot.docs[0].data();
  // Support both bcrypt and plaintext (auto-migrate old passwords)
  let passwordValid = false;
  if (user.password.startsWith('$2b$')) {
    passwordValid = await bcrypt.compare(password, user.password);
  } else {
    passwordValid = (user.password === password);
    if (passwordValid) {
      const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
      await usersCol.doc(snapshot.docs[0].id).update({ password: hashed });
    }
  }
  if (!passwordValid) {
    recordLoginFail(req.loginIp);
    await auditLog('login_failed', user.id, { reason: 'wrong_password' });
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  clearLoginFails(req.loginIp);
  const token = generateToken();
  await tokensCol.doc(token).set({ userId: user.id, createdAt: new Date().toISOString() });
  await auditLog('login_success', user.id, { role: user.role });

  // #9: Set HttpOnly cookie
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: TOKEN_EXPIRY_MS,
    path: '/',
  });

  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies?.auth_token ||
    (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7) : null);
  if (token) {
    await tokensCol.doc(token).delete();
  }
  res.clearCookie('auth_token', { path: '/' });
  res.json({ success: true });
});

// ============================================================
// SMTP / Email
// ============================================================
function createTransporter() {
  const port = parseInt(process.env.SMTP_PORT || '465');
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'mail.privateemail.com',
    port,
    secure: port === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: true },
  });
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return text.replace(/[&<>"']/g, (c) => map[c]);
}

// ============================================================
// EdfaPay helpers
// ============================================================
function generateEdfaHash(orderId, orderAmount, orderCurrency, orderDescription) {
  const merchantPass = process.env.EDFA_MERCHANT_PASSWORD;
  const raw = (orderId + orderAmount + orderCurrency + orderDescription + merchantPass).toUpperCase();
  const md5 = crypto.createHash('md5').update(raw).digest('hex');
  const sha1 = crypto.createHash('sha1').update(md5).digest('hex');
  return sha1;
}

async function initiateEdfaPayment(payment, payerIp) {
  const merchantId = process.env.EDFA_MERCHANT_ID;
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  const orderId = payment.id;
  const orderAmount = Number(payment.price).toFixed(2);
  const orderCurrency = process.env.EDFA_CURRENCY || 'SAR';
  const orderDescription = payment.productName;

  const hash = generateEdfaHash(orderId, orderAmount, orderCurrency, orderDescription);

  const nameParts = payment.customerName.trim().split(/\s+/);
  const firstName = nameParts[0] || 'Customer';
  const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'N/A';

  const formData = new URLSearchParams();
  formData.append('action', 'SALE');
  formData.append('edfa_merchant_id', merchantId);
  formData.append('order_id', orderId);
  formData.append('order_amount', orderAmount);
  formData.append('order_currency', orderCurrency);
  formData.append('order_description', orderDescription);
  formData.append('req_token', 'N');
  formData.append('payer_first_name', firstName);
  formData.append('payer_last_name', lastName);
  formData.append('payer_address', payment.customerEmail);
  formData.append('payer_country', process.env.EDFA_COUNTRY || 'SA');
  formData.append('payer_city', process.env.EDFA_CITY || 'Riyadh');
  formData.append('payer_zip', process.env.EDFA_ZIP || '12221');
  formData.append('payer_email', payment.customerEmail);
  formData.append('payer_phone', payment.customerPhone || '966500000000');
  formData.append('payer_ip', payerIp || '127.0.0.1');
  formData.append('term_url_3ds', `${baseUrl}/api/edfa/callback-3ds/${orderId}`);
  formData.append('auth', 'N');
  formData.append('recurring_init', 'N');
  formData.append('hash', hash);

  const res = await fetch('https://api.edfapay.com/payment/initiate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formData.toString(),
  });

  const data = await res.json();
  return data;
}

// Build payment email HTML
function buildPaymentEmailHtml(customerName, customerEmail, productName, price, paymentLink, merchantName) {
  const safeName = escapeHtml(String(customerName));
  const safeEmail = escapeHtml(String(customerEmail));
  const safeProduct = escapeHtml(String(productName));
  const safeMerchant = escapeHtml(String(merchantName || ''));
  const formattedPrice = Number(price).toFixed(2);

  return `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>طلب دفع</title>
</head>
<body style="margin:0; padding:0; background-color:#f0f2f5; font-family:'Segoe UI',Tahoma,Arial,sans-serif; direction:rtl; -webkit-text-size-adjust:100%;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5; padding:20px 8px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:440px; background-color:#ffffff; border-radius:20px; overflow:hidden; box-shadow:0 8px 30px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#6c5ce7,#a855f7); padding:30px 20px; text-align:center;">
              <div style="font-size:36px; margin-bottom:10px;">💳</div>
              <h1 style="margin:0; color:#ffffff; font-size:20px; font-weight:700; letter-spacing:-0.3px;">طلب دفع جديد</h1>
              <p style="margin:8px 0 0; color:rgba(255,255,255,0.85); font-size:13px;">تم إنشاء طلب دفع خاص بك</p>
            </td>
          </tr>

          <!-- Greeting -->
          <tr>
            <td style="padding:24px 20px 8px;">
              <p style="margin:0; font-size:16px; color:#1a1a2e; font-weight:600;">مرحباً ${safeName} 👋</p>
              <p style="margin:8px 0 0; font-size:13px; color:#64748b; line-height:1.7;">لديك طلب دفع جديد، راجع التفاصيل أدناه ثم اضغط على الزر لإتمام الدفع.</p>
            </td>
          </tr>

          <!-- Amount Card -->
          <tr>
            <td style="padding:16px 20px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#6c5ce7,#a855f7); border-radius:14px; overflow:hidden;">
                <tr>
                  <td style="padding:22px; text-align:center;">
                    <p style="margin:0 0 4px; color:rgba(255,255,255,0.8); font-size:12px;">المبلغ المطلوب</p>
                    <p style="margin:0; color:#ffffff; font-size:30px; font-weight:800; letter-spacing:-1px;">${formattedPrice} <span style="font-size:16px; font-weight:600;">ر.س</span></p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Details -->
          <tr>
            <td style="padding:0 20px 10px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8f9fc; border-radius:14px; border:1px solid #e8eaf0;">
                <tr>
                  <td style="padding:20px 22px 8px;">
                    <p style="margin:0 0 14px; font-size:14px; color:#6c5ce7; font-weight:700;">📋 تفاصيل الطلب</p>
                  </td>
                </tr>
                <tr>
                  <td style="padding:0 22px;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                      ${safeMerchant ? `<tr>
                        <td style="padding:12px 0; border-bottom:1px solid #e8eaf0; width:35%;">
                          <span style="color:#94a3b8; font-size:13px;">🏪 التاجر</span>
                        </td>
                        <td style="padding:12px 0; border-bottom:1px solid #e8eaf0; text-align:left;">
                          <span style="color:#1e293b; font-size:14px; font-weight:600;">${safeMerchant}</span>
                        </td>
                      </tr>` : ''}
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #e8eaf0; width:35%;">
                          <span style="color:#94a3b8; font-size:13px;">👤 العميل</span>
                        </td>
                        <td style="padding:12px 0; border-bottom:1px solid #e8eaf0; text-align:left;">
                          <span style="color:#1e293b; font-size:14px; font-weight:600;">${safeName}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #e8eaf0;">
                          <span style="color:#94a3b8; font-size:13px;">📧 البريد</span>
                        </td>
                        <td style="padding:12px 0; border-bottom:1px solid #e8eaf0; text-align:left;" dir="ltr">
                          <span style="color:#1e293b; font-size:14px;">${safeEmail}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0;">
                          <span style="color:#94a3b8; font-size:13px;">🛍️ المنتج</span>
                        </td>
                        <td style="padding:12px 0; text-align:left;">
                          <span style="color:#1e293b; font-size:14px; font-weight:600;">${safeProduct}</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr><td style="padding:0 0 16px;"></td></tr>
              </table>
            </td>
          </tr>

          <!-- CTA Button -->
          <tr>
            <td style="padding:14px 20px 6px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center">
                    <a href="${paymentLink}" target="_blank" style="display:inline-block; width:100%; max-width:380px; background:linear-gradient(135deg,#6c5ce7,#a855f7); color:#ffffff; padding:16px 24px; border-radius:12px; text-decoration:none; font-size:16px; font-weight:700; text-align:center; box-sizing:border-box;">
                      ادفع الآن ←
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Link fallback -->
          <tr>
            <td style="padding:6px 20px 20px; text-align:center;">
              <p style="margin:0; font-size:12px; color:#94a3b8;">أو انسخ الرابط:</p>
              <a href="${paymentLink}" dir="ltr" style="font-size:12px; color:#6c5ce7; word-break:break-all; text-decoration:underline;">${paymentLink}</a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8f9fc; padding:16px 20px; text-align:center; border-top:1px solid #e8eaf0;">
              <p style="margin:0; font-size:12px; color:#94a3b8;">🔒 ستتم عملية الدفع عبر بوابة دفع آمنة ومشفرة</p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ============================================================
// Send payment link (shared logic)
// ============================================================
async function sendPaymentLink(req, merchantId) {
  const { customerName, customerEmail, productName, price, customerPhone } = req.body;

  if (!customerName || !customerEmail || !productName || !price) {
    return { status: 400, body: { error: 'جميع الحقول مطلوبة' } };
  }
  // #18: NoSQL injection check
  if (!isCleanInput(customerName) || !isCleanInput(customerEmail) || !isCleanInput(productName)) {
    return { status: 400, body: { error: 'مدخلات غير صالحة' } };
  }
  if (typeof price !== 'number' || price <= 0 || price > 1000000) {
    return { status: 400, body: { error: 'السعر غير صالح' } };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(customerEmail)) {
    return { status: 400, body: { error: 'البريد الإلكتروني غير صالح' } };
  }

  // #6: Sanitize inputs
  const cleanName = sanitize(String(customerName)).slice(0, 200);
  const cleanEmail = sanitize(String(customerEmail)).slice(0, 200);
  const cleanPhone = sanitize(String(customerPhone || '')).slice(0, 20);
  const cleanProduct = sanitize(String(productName)).slice(0, 200);

  const paymentId = uuidv4();
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  // Fetch merchant name to store with payment
  const merchantDoc = await usersCol.doc(merchantId).get();
  const merchantName = merchantDoc.exists ? merchantDoc.data().name : '';

  // #14: Encrypt sensitive customer data
  const payment = {
    id: paymentId,
    merchantId,
    merchantName,
    customerName: cleanName,
    customerEmail: cleanEmail,
    customerNameEnc: encryptData(cleanName),
    customerEmailEnc: encryptData(cleanEmail),
    customerPhone: cleanPhone,
    productName: cleanProduct,
    price: Number(price),
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  await paymentsCol.doc(paymentId).set(payment);

  // #17: Audit log
  await auditLog('payment_created', merchantId, { paymentId, product: cleanProduct, price: Number(price) });

  // Always link to intermediate page, not directly to EdfaPay
  const paymentLink = `${baseUrl}/pay/${paymentId}`;

  // Initiate EdfaPay if configured (store redirect URL for the intermediate page)
  if (process.env.EDFA_MERCHANT_ID && process.env.EDFA_MERCHANT_PASSWORD) {
    try {
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1';
      const edfaResult = await initiateEdfaPayment(payment, clientIp);
      if (edfaResult.redirect_url) {
        payment.edfaRedirectUrl = edfaResult.redirect_url;
        await paymentsCol.doc(paymentId).update({ edfaRedirectUrl: edfaResult.redirect_url });
        console.log(`✅ EdfaPay: payment ${paymentId.slice(0, 8)}...`);
      } else {
        console.error('EdfaPay error:', JSON.stringify(edfaResult));
        payment.edfaError = JSON.stringify(edfaResult);
        await paymentsCol.doc(paymentId).update({ edfaError: payment.edfaError });
      }
    } catch (err) {
      console.error('EdfaPay request failed:', err.message);
    }
  }

  // Send email
  try {
    const transporter = createTransporter();
    const htmlEmail = buildPaymentEmailHtml(customerName, customerEmail, productName, price, paymentLink, merchantName);
    const fromName = process.env.SMTP_FROM_NAME || '';
    const fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER;
    const fromAddress = fromName ? `"${fromName}" <${fromEmail}>` : fromEmail;

    await transporter.sendMail({
      from: fromAddress,
      to: customerEmail,
      subject: `رابط دفع: ${String(productName).slice(0, 100)}`,
      html: htmlEmail,
    });

    return { status: 200, body: { success: true, paymentId, paymentLink } };
  } catch (error) {
    console.error('Email error:', error.message);
    return {
      status: 200,
      body: {
        success: true,
        paymentId,
        paymentLink,
        emailWarning: 'تم إنشاء الرابط ولكن فشل إرسال البريد الإلكتروني.',
      },
    };
  }
}

// ============================================================
// ADMIN routes
// ============================================================

// Admin dashboard data
app.get('/api/admin/dashboard', requireAuth('admin'), async (req, res) => {
  const paymentsSnap = await paymentsCol.get();
  const allPayments = paymentsSnap.docs.map(d => d.data()).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  const totalRevenue = allPayments.filter(p => p.status === 'paid').reduce((sum, p) => sum + p.price, 0);
  const merchantsSnap = await usersCol.where('role', '==', 'merchant').get();
  res.json({
    totalRevenue,
    totalCount: allPayments.length,
    paidCount: allPayments.filter(p => p.status === 'paid').length,
    pendingCount: allPayments.filter(p => p.status === 'pending').length,
    failedCount: allPayments.filter(p => p.status === 'failed').length,
    merchantsCount: merchantsSnap.size,
    payments: allPayments,
  });
});

// Admin: list payments
app.get('/api/admin/payments', requireAuth('admin'), async (req, res) => {
  const paymentsSnap = await paymentsCol.get();
  const allPayments = paymentsSnap.docs.map(d => d.data()).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  // Attach merchant name
  const enriched = [];
  for (const p of allPayments) {
    const merchantDoc = await usersCol.doc(p.merchantId).get();
    enriched.push({ ...p, merchantName: merchantDoc.exists ? merchantDoc.data().name : '—' });
  }
  res.json(enriched);
});

// Admin: list merchants
app.get('/api/admin/merchants', requireAuth('admin'), async (req, res) => {
  const merchantsSnap = await usersCol.where('role', '==', 'merchant').get();
  const merchantsList = [];
  for (const doc of merchantsSnap.docs) {
    const u = doc.data();
    const mpSnap = await paymentsCol.where('merchantId', '==', u.id).get();
    const merchantPayments = mpSnap.docs.map(d => d.data());
    const walletBalance = merchantPayments.filter(p => p.status === 'paid').reduce((sum, p) => sum + p.price, 0);
    merchantsList.push({
      id: u.id,
      email: u.email,
      name: u.name,
      createdAt: u.createdAt,
      paymentsCount: merchantPayments.length,
      walletBalance,
    });
  }
  res.json(merchantsList);
});

// Admin: add merchant
app.post('/api/admin/merchants', requireAuth('admin'), async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  const normalEmail = sanitize(String(email)).toLowerCase().trim();
  // #18: NoSQL injection check
  if (!isCleanInput(email) || !isCleanInput(name)) {
    return res.status(400).json({ error: 'مدخلات غير صالحة' });
  }
  const existsSnap = await usersCol.where('email', '==', normalEmail).limit(1).get();
  if (!existsSnap.empty) {
    return res.status(400).json({ error: 'البريد مسجل مسبقاً' });
  }
  const id = 'merchant-' + crypto.randomBytes(4).toString('hex');
  const hashedPass = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
  const merchant = {
    id,
    email: normalEmail,
    password: hashedPass,
    name: sanitize(String(name)).slice(0, 200),
    role: 'merchant',
    createdAt: new Date().toISOString(),
  };
  await usersCol.doc(id).set(merchant);
  await auditLog('merchant_created', req.user.id, { merchantId: id, email: maskEmail(normalEmail) });
  console.log(`✅ Merchant added: ${maskEmail(normalEmail)}`);
  res.json({ success: true, merchant: { id, email: merchant.email, name: merchant.name } });
});

// Admin: delete merchant
app.delete('/api/admin/merchants/:id', requireAuth('admin'), async (req, res) => {
  const userDoc = await usersCol.doc(req.params.id).get();
  if (!userDoc.exists || userDoc.data().role !== 'merchant') {
    return res.status(404).json({ error: 'التاجر غير موجود' });
  }
  await usersCol.doc(req.params.id).delete();
  // Remove merchant's tokens
  const tokSnap = await tokensCol.where('userId', '==', req.params.id).get();
  const batch = db.batch();
  tokSnap.docs.forEach(d => batch.delete(d.ref));
  await batch.commit();
  await auditLog('merchant_deleted', req.user.id, { merchantId: req.params.id, email: maskEmail(userDoc.data().email) });
  console.log(`🗑️ Merchant deleted: ${maskEmail(userDoc.data().email)}`);
  res.json({ success: true });
});

// Admin: send payment link
app.post('/api/admin/send-payment-link', requireAuth('admin'), paymentSendLimiter, async (req, res) => {
  const result = await sendPaymentLink(req, req.user.id);
  res.status(result.status).json(result.body);
});

// ============================================================
// MERCHANT routes
// ============================================================

// Merchant dashboard data
app.get('/api/merchant/dashboard', requireAuth('merchant'), async (req, res) => {
  try {
    const myPaymentsSnap = await paymentsCol.where('merchantId', '==', req.user.id).get();
    const myPayments = myPaymentsSnap.docs.map(d => d.data()).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));

    const walletBalance = myPayments.filter(p => p.status === 'paid').reduce((sum, p) => sum + p.price, 0);

    res.json({
      walletBalance,
      totalCount: myPayments.length,
      paidCount: myPayments.filter(p => p.status === 'paid').length,
      pendingCount: myPayments.filter(p => p.status === 'pending').length,
      failedCount: myPayments.filter(p => p.status === 'failed').length,
      payments: myPayments,
    });
  } catch (e) {
    console.error('Merchant dashboard error:', e.message);
    res.status(500).json({ error: 'خطأ في تحميل البيانات' });
  }
});

// Merchant: send payment link
app.post('/api/merchant/send-payment-link', requireAuth('merchant'), paymentSendLimiter, async (req, res) => {
  const result = await sendPaymentLink(req, req.user.id);
  res.status(result.status).json(result.body);
});

// ============================================================
// Public payment routes (no auth needed)
// ============================================================

// Auto-expire pending payments after 5 minutes
async function autoExpireIfNeeded(docRef, payment) {
  if (payment.status === 'pending' && payment.createdAt) {
    const elapsed = Date.now() - new Date(payment.createdAt).getTime();
    if (elapsed >= PAYMENT_EXPIRY_MS) {
      await docRef.update({ status: 'cancelled', cancelledAt: new Date().toISOString(), cancelledBy: 'auto-expiry' });
      payment.status = 'cancelled';
    }
  }
}

// Get payment details (#5: limit exposed data — only show to payment link holder)
app.get('/api/payment/:id', async (req, res) => {
  const doc = await paymentsCol.doc(req.params.id).get();
  if (!doc.exists) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  const payment = doc.data();
  await autoExpireIfNeeded(paymentsCol.doc(req.params.id), payment);
  // Only expose what's needed for the payment page — mask email partially
  const emailParts = payment.customerEmail.split('@');
  const maskedEmail = emailParts[0].slice(0, 3) + '***@' + (emailParts[1] || '');
  res.json({
    productName: payment.productName,
    customerName: payment.customerName,
    customerEmail: maskedEmail,
    merchantName: payment.merchantName || '',
    price: payment.price,
    status: payment.status,
    edfaRedirectUrl: payment.edfaRedirectUrl || null,
    failReason: payment.failReason || null,
  });
});

// Confirm payment (local fallback)
app.post('/api/payment/:id/pay', async (req, res) => {
  const doc = await paymentsCol.doc(req.params.id).get();
  if (!doc.exists) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  const payment = doc.data();
  if (payment.status === 'paid') {
    return res.status(400).json({ error: 'تم الدفع مسبقاً' });
  }
  if (payment.edfaRedirectUrl) {
    return res.json({ redirect: payment.edfaRedirectUrl });
  }
  await paymentsCol.doc(req.params.id).update({
    status: 'paid',
    paidAt: new Date().toISOString(),
  });
  res.json({ success: true });
});

// Serve payment page (always show intermediate page, no auto-redirect)
app.get('/pay/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay.html'));
});

// Serve tracking page (for merchant/admin after creating payment)
app.get('/track/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'track.html'));
});

// Track API — full details for authorized merchant/admin
app.get('/api/track/:id', requireAuth(), async (req, res) => {
  const doc = await paymentsCol.doc(req.params.id).get();
  if (!doc.exists) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  const payment = doc.data();
  // Only the owning merchant or admin can see full details
  if (req.user.role !== 'admin' && payment.merchantId !== req.user.id) {
    return res.status(403).json({ error: 'ليس لديك صلاحية' });
  }
  await autoExpireIfNeeded(paymentsCol.doc(req.params.id), payment);
  res.json({
    id: payment.id,
    customerName: payment.customerName,
    customerEmail: payment.customerEmail,
    customerPhone: payment.customerPhone || '',
    productName: payment.productName,
    price: payment.price,
    status: payment.status,
    createdAt: payment.createdAt,
    paidAt: payment.paidAt || null,
    expiresAt: new Date(new Date(payment.createdAt).getTime() + PAYMENT_EXPIRY_MS).toISOString(),
  });
});

// Cancel endpoint removed — payments auto-expire after 5 minutes

// ============================================================
// Start server
// ============================================================
seedAdmin().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    const url = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
    console.log(`\n🚀 الخادم يعمل على: ${url}`);
    console.log(`� Firebase Firestore متصل\n`);
  });
}).catch(err => {
  console.error('❌ خطأ في التشغيل:', err.message);
  process.exit(1);
});
