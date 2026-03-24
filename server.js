require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');

const BCRYPT_ROUNDS = 10;
const TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

// ============================================================
// Firebase Firestore
// ============================================================
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

const app = express();
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
// Middleware
// ============================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Serve static files but do NOT auto-serve index.html for "/"
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ============================================================
// Auth helpers
// ============================================================
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function requireAuth(role) {
  return async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'غير مصرح' });
    }
    const token = authHeader.slice(7);
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

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'البريد وكلمة المرور مطلوبين' });
  }
  const normalEmail = String(email).toLowerCase().trim();
  const snapshot = await usersCol.where('email', '==', normalEmail).limit(1).get();
  if (snapshot.empty) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  const user = snapshot.docs[0].data();
  // Support both bcrypt and plaintext (auto-migrate old passwords)
  let passwordValid = false;
  if (user.password.startsWith('$2b$')) {
    passwordValid = await bcrypt.compare(password, user.password);
  } else {
    // Legacy plaintext — migrate to bcrypt
    passwordValid = (user.password === password);
    if (passwordValid) {
      const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
      await usersCol.doc(snapshot.docs[0].id).update({ password: hashed });
    }
  }
  if (!passwordValid) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  const token = generateToken();
  await tokensCol.doc(token).set({ userId: user.id, createdAt: new Date().toISOString() });
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

app.post('/api/auth/logout', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    await tokensCol.doc(authHeader.slice(7)).delete();
  }
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
function buildPaymentEmailHtml(customerName, customerEmail, productName, price, paymentLink) {
  const safeName = escapeHtml(String(customerName));
  const safeEmail = escapeHtml(String(customerEmail));
  const safeProduct = escapeHtml(String(productName));
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
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5; padding:30px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:500px; background-color:#ffffff; border-radius:20px; overflow:hidden; box-shadow:0 8px 30px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#6c5ce7,#a855f7); padding:40px 30px; text-align:center;">
              <div style="font-size:40px; margin-bottom:12px;">💳</div>
              <h1 style="margin:0; color:#ffffff; font-size:24px; font-weight:700; letter-spacing:-0.3px;">طلب دفع جديد</h1>
              <p style="margin:10px 0 0; color:rgba(255,255,255,0.85); font-size:14px;">تم إنشاء طلب دفع خاص بك</p>
            </td>
          </tr>

          <!-- Greeting -->
          <tr>
            <td style="padding:30px 30px 10px;">
              <p style="margin:0; font-size:18px; color:#1a1a2e; font-weight:600;">مرحباً ${safeName} 👋</p>
              <p style="margin:10px 0 0; font-size:14px; color:#64748b; line-height:1.7;">لديك طلب دفع جديد، راجع التفاصيل أدناه ثم اضغط على الزر لإتمام الدفع.</p>
            </td>
          </tr>

          <!-- Amount Card -->
          <tr>
            <td style="padding:20px 30px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#6c5ce7,#a855f7); border-radius:16px; overflow:hidden;">
                <tr>
                  <td style="padding:28px; text-align:center;">
                    <p style="margin:0 0 6px; color:rgba(255,255,255,0.8); font-size:13px;">المبلغ المطلوب</p>
                    <p style="margin:0; color:#ffffff; font-size:36px; font-weight:800; letter-spacing:-1px;">${formattedPrice} <span style="font-size:18px; font-weight:600;">ر.س</span></p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Details -->
          <tr>
            <td style="padding:0 30px 10px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8f9fc; border-radius:14px; border:1px solid #e8eaf0;">
                <tr>
                  <td style="padding:20px 22px 8px;">
                    <p style="margin:0 0 14px; font-size:14px; color:#6c5ce7; font-weight:700;">📋 تفاصيل الطلب</p>
                  </td>
                </tr>
                <tr>
                  <td style="padding:0 22px;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
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
            <td style="padding:16px 30px 8px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center">
                    <a href="${paymentLink}" target="_blank" style="display:inline-block; width:100%; max-width:400px; background:linear-gradient(135deg,#6c5ce7,#a855f7); color:#ffffff; padding:18px 30px; border-radius:14px; text-decoration:none; font-size:17px; font-weight:700; text-align:center; box-sizing:border-box;">
                      ادفع الآن ←
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Link fallback -->
          <tr>
            <td style="padding:8px 30px 24px; text-align:center;">
              <p style="margin:0; font-size:12px; color:#94a3b8;">أو انسخ الرابط:</p>
              <a href="${paymentLink}" dir="ltr" style="font-size:12px; color:#6c5ce7; word-break:break-all; text-decoration:underline;">${paymentLink}</a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8f9fc; padding:20px 30px; text-align:center; border-top:1px solid #e8eaf0;">
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
  if (typeof price !== 'number' || price <= 0 || price > 1000000) {
    return { status: 400, body: { error: 'السعر غير صالح' } };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(customerEmail)) {
    return { status: 400, body: { error: 'البريد الإلكتروني غير صالح' } };
  }

  const paymentId = uuidv4();
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  const payment = {
    id: paymentId,
    merchantId,
    customerName: String(customerName).slice(0, 200),
    customerEmail: String(customerEmail).slice(0, 200),
    customerPhone: String(customerPhone || '').slice(0, 20),
    productName: String(productName).slice(0, 200),
    price: Number(price),
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  await paymentsCol.doc(paymentId).set(payment);

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
        console.log(`✅ EdfaPay: رابط دفع لطلب ${paymentId}`);
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
    const htmlEmail = buildPaymentEmailHtml(customerName, customerEmail, productName, price, paymentLink);
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
  const paymentsSnap = await paymentsCol.orderBy('createdAt', 'desc').get();
  const allPayments = paymentsSnap.docs.map(d => d.data());
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
  const paymentsSnap = await paymentsCol.orderBy('createdAt', 'desc').get();
  const allPayments = paymentsSnap.docs.map(d => d.data());
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
  const normalEmail = String(email).toLowerCase().trim();
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
    name: String(name).slice(0, 200),
    role: 'merchant',
    createdAt: new Date().toISOString(),
  };
  await usersCol.doc(id).set(merchant);
  console.log(`✅ Merchant added: ${normalEmail}`);
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
  console.log(`🗑️ Merchant deleted: ${userDoc.data().email}`);
  res.json({ success: true });
});

// Admin: send payment link
app.post('/api/admin/send-payment-link', requireAuth('admin'), async (req, res) => {
  const result = await sendPaymentLink(req, req.user.id);
  res.status(result.status).json(result.body);
});

// ============================================================
// MERCHANT routes
// ============================================================

// Merchant dashboard data
app.get('/api/merchant/dashboard', requireAuth('merchant'), async (req, res) => {
  const myPaymentsSnap = await paymentsCol.where('merchantId', '==', req.user.id).orderBy('createdAt', 'desc').get();
  const myPayments = myPaymentsSnap.docs.map(d => d.data());

  const walletBalance = myPayments.filter(p => p.status === 'paid').reduce((sum, p) => sum + p.price, 0);

  res.json({
    walletBalance,
    totalCount: myPayments.length,
    paidCount: myPayments.filter(p => p.status === 'paid').length,
    pendingCount: myPayments.filter(p => p.status === 'pending').length,
    failedCount: myPayments.filter(p => p.status === 'failed').length,
    payments: myPayments,
  });
});

// Merchant: send payment link
app.post('/api/merchant/send-payment-link', requireAuth('merchant'), async (req, res) => {
  const result = await sendPaymentLink(req, req.user.id);
  res.status(result.status).json(result.body);
});

// ============================================================
// Public payment routes (no auth needed)
// ============================================================

// Get payment details
app.get('/api/payment/:id', async (req, res) => {
  const doc = await paymentsCol.doc(req.params.id).get();
  if (!doc.exists) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  const payment = doc.data();
  res.json({
    productName: payment.productName,
    customerName: payment.customerName,
    customerEmail: payment.customerEmail,
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

// ============================================================
// EdfaPay Webhook
// ============================================================
app.post('/api/edfa/webhook', async (req, res) => {
  console.log('📩 EdfaPay Webhook received:', JSON.stringify(req.body));

  const { order_id, status, trans_id } = req.body;
  if (!order_id) {
    return res.status(400).send('Missing order_id');
  }

  const doc = await paymentsCol.doc(order_id).get();
  if (!doc.exists) {
    console.error('Webhook: payment not found for order_id:', order_id);
    return res.status(404).send('Not found');
  }

  const normalizedStatus = String(status || '').toLowerCase();
  const result = String(req.body.result || '').toUpperCase();

  if (normalizedStatus === 'settled' || normalizedStatus === 'success' || normalizedStatus === '3ds_success' || result === 'SUCCESS') {
    await paymentsCol.doc(order_id).update({
      status: 'paid',
      paidAt: new Date().toISOString(),
      edfaTransId: trans_id || null,
    });
    console.log(`✅ Payment ${order_id} marked as paid via webhook`);
  } else if (normalizedStatus === 'declined' || normalizedStatus === 'fail' || normalizedStatus === 'error' || result === 'DECLINED') {
    await paymentsCol.doc(order_id).update({
      status: 'failed',
      failReason: req.body.decline_reason || 'unknown',
      edfaTransId: trans_id || null,
    });
    console.log(`❌ Payment ${order_id} failed: ${req.body.decline_reason || 'unknown'}`);
  }

  res.status(200).send('OK');
});

// EdfaPay 3DS Callback
app.all('/api/edfa/callback-3ds/:id', async (req, res) => {
  const doc = await paymentsCol.doc(req.params.id).get();
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  if (!doc.exists) {
    return res.redirect(`${baseUrl}/pay/invalid`);
  }
  res.redirect(`${baseUrl}/pay/${doc.data().id}`);
});

// Serve payment page (always show intermediate page, no auto-redirect)
app.get('/pay/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay.html'));
});

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
