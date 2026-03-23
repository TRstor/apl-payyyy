require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// In-memory stores
// ============================================================
const payments = new Map();
const users = new Map();      // id -> user
const tokens = new Map();     // token -> userId

// Seed admin user from env
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@admin.com').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const adminId = 'admin-' + crypto.randomBytes(4).toString('hex');
users.set(adminId, {
  id: adminId,
  email: ADMIN_EMAIL,
  password: ADMIN_PASSWORD,
  name: 'المدير',
  role: 'admin',
  createdAt: new Date().toISOString(),
});
console.log(`👤 Admin seeded: ${ADMIN_EMAIL}`);

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
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'غير مصرح' });
    }
    const token = authHeader.slice(7);
    const userId = tokens.get(token);
    if (!userId) {
      return res.status(401).json({ error: 'جلسة غير صالحة' });
    }
    const user = users.get(userId);
    if (!user) {
      return res.status(401).json({ error: 'مستخدم غير موجود' });
    }
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

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'البريد وكلمة المرور مطلوبين' });
  }
  const normalEmail = String(email).toLowerCase().trim();
  const user = Array.from(users.values()).find(u => u.email === normalEmail);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  const token = generateToken();
  tokens.set(token, user.id);
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    tokens.delete(authHeader.slice(7));
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
  return `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; direction: rtl;">
      <div style="max-width: 520px; margin: 0 auto; background: #fff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
        <div style="background: linear-gradient(135deg, #667eea, #764ba2); padding: 32px; text-align: center; color: #fff;">
          <h1 style="margin: 0; font-size: 22px;">💳 تفاصيل طلب الدفع</h1>
          <p style="margin: 8px 0 0; font-size: 13px; opacity: 0.8;">تم إنشاء طلب دفع خاص بك</p>
        </div>
        <div style="padding: 32px;">
          <p style="font-size: 16px; color: #333; margin-bottom: 20px;">مرحباً <strong>${escapeHtml(String(customerName))}</strong>,</p>
          <p style="color: #666; line-height: 1.6; margin-bottom: 24px;">لديك طلب دفع جديد، يرجى مراجعة التفاصيل أدناه ثم الضغط على الزر لإتمام عملية الدفع.</p>
          
          <div style="background: #f8f9fa; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #eee;">
            <h3 style="margin: 0 0 16px; font-size: 15px; color: #555;">📋 تفاصيل الطلب</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 10px 0; color: #888; font-size: 14px;">العميل:</td>
                <td style="padding: 10px 0; color: #333; font-weight: 600; text-align: left; font-size: 14px;">${escapeHtml(String(customerName))}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; color: #888; font-size: 14px; border-top: 1px solid #eee;">البريد:</td>
                <td style="padding: 10px 0; color: #555; text-align: left; font-size: 14px; border-top: 1px solid #eee;" dir="ltr">${escapeHtml(String(customerEmail))}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; color: #888; font-size: 14px; border-top: 1px solid #eee;">المنتج:</td>
                <td style="padding: 10px 0; color: #333; font-weight: 600; text-align: left; font-size: 14px; border-top: 1px solid #eee;">${escapeHtml(String(productName))}</td>
              </tr>
              <tr>
                <td style="padding: 12px 0; color: #888; font-size: 14px; border-top: 2px solid #667eea;">المبلغ المطلوب:</td>
                <td style="padding: 12px 0; color: #667eea; font-weight: 700; font-size: 22px; text-align: left; border-top: 2px solid #667eea;">
                  ${Number(price).toFixed(2)} ر.س
                </td>
              </tr>
            </table>
          </div>

          <a href="${paymentLink}" style="display: block; text-align: center; background: linear-gradient(135deg, #667eea, #764ba2); color: #fff; padding: 16px; border-radius: 12px; text-decoration: none; font-size: 17px; font-weight: 700; margin-bottom: 16px;">
            عرض التفاصيل وإتمام الدفع →
          </a>
          <p style="font-size: 12px; color: #999; text-align: center; margin-bottom: 0;">
            أو انسخ الرابط:<br>
            <a href="${paymentLink}" style="color: #667eea; word-break: break-all;">${paymentLink}</a>
          </p>
        </div>
        <div style="background: #f8f9fa; padding: 16px; text-align: center; font-size: 12px; color: #999;">
          🔒 سيتم تحويلك لصفحة آمنة لمراجعة الطلب قبل الدفع
        </div>
      </div>
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
  payments.set(paymentId, payment);

  // Always link to intermediate page, not directly to EdfaPay
  const paymentLink = `${baseUrl}/pay/${paymentId}`;

  // Initiate EdfaPay if configured (store redirect URL for the intermediate page)
  if (process.env.EDFA_MERCHANT_ID && process.env.EDFA_MERCHANT_PASSWORD) {
    try {
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1';
      const edfaResult = await initiateEdfaPayment(payment, clientIp);
      if (edfaResult.redirect_url) {
        payment.edfaRedirectUrl = edfaResult.redirect_url;
        console.log(`✅ EdfaPay: رابط دفع لطلب ${paymentId}`);
      } else {
        console.error('EdfaPay error:', JSON.stringify(edfaResult));
        payment.edfaError = JSON.stringify(edfaResult);
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
app.get('/api/admin/dashboard', requireAuth('admin'), (req, res) => {
  const allPayments = Array.from(payments.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const totalRevenue = allPayments.filter(p => p.status === 'paid').reduce((sum, p) => sum + p.price, 0);
  const merchantsList = Array.from(users.values()).filter(u => u.role === 'merchant');
  res.json({
    totalRevenue,
    totalCount: allPayments.length,
    paidCount: allPayments.filter(p => p.status === 'paid').length,
    pendingCount: allPayments.filter(p => p.status === 'pending').length,
    failedCount: allPayments.filter(p => p.status === 'failed').length,
    merchantsCount: merchantsList.length,
    payments: allPayments,
  });
});

// Admin: list payments
app.get('/api/admin/payments', requireAuth('admin'), (req, res) => {
  const allPayments = Array.from(payments.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  // Attach merchant name
  const enriched = allPayments.map(p => {
    const merchant = users.get(p.merchantId);
    return { ...p, merchantName: merchant ? merchant.name : '—' };
  });
  res.json(enriched);
});

// Admin: list merchants
app.get('/api/admin/merchants', requireAuth('admin'), (req, res) => {
  const merchantsList = Array.from(users.values())
    .filter(u => u.role === 'merchant')
    .map(u => {
      const merchantPayments = Array.from(payments.values()).filter(p => p.merchantId === u.id);
      const walletBalance = merchantPayments.filter(p => p.status === 'paid').reduce((sum, p) => sum + p.price, 0);
      return {
        id: u.id,
        email: u.email,
        name: u.name,
        createdAt: u.createdAt,
        paymentsCount: merchantPayments.length,
        walletBalance,
      };
    });
  res.json(merchantsList);
});

// Admin: add merchant
app.post('/api/admin/merchants', requireAuth('admin'), (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  const normalEmail = String(email).toLowerCase().trim();
  const exists = Array.from(users.values()).find(u => u.email === normalEmail);
  if (exists) {
    return res.status(400).json({ error: 'البريد مسجل مسبقاً' });
  }
  const id = 'merchant-' + crypto.randomBytes(4).toString('hex');
  const merchant = {
    id,
    email: normalEmail,
    password: String(password),
    name: String(name).slice(0, 200),
    role: 'merchant',
    createdAt: new Date().toISOString(),
  };
  users.set(id, merchant);
  console.log(`✅ Merchant added: ${normalEmail}`);
  res.json({ success: true, merchant: { id, email: merchant.email, name: merchant.name } });
});

// Admin: delete merchant
app.delete('/api/admin/merchants/:id', requireAuth('admin'), (req, res) => {
  const user = users.get(req.params.id);
  if (!user || user.role !== 'merchant') {
    return res.status(404).json({ error: 'التاجر غير موجود' });
  }
  users.delete(req.params.id);
  // Remove merchant's tokens
  for (const [tok, uid] of tokens.entries()) {
    if (uid === req.params.id) tokens.delete(tok);
  }
  console.log(`🗑️ Merchant deleted: ${user.email}`);
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
app.get('/api/merchant/dashboard', requireAuth('merchant'), (req, res) => {
  const myPayments = Array.from(payments.values())
    .filter(p => p.merchantId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

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
app.get('/api/payment/:id', (req, res) => {
  const payment = payments.get(req.params.id);
  if (!payment) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  res.json({
    productName: payment.productName,
    customerName: payment.customerName,
    customerEmail: payment.customerEmail,
    price: payment.price,
    status: payment.status,
    edfaRedirectUrl: payment.edfaRedirectUrl || null,
  });
});

// Confirm payment (local fallback)
app.post('/api/payment/:id/pay', (req, res) => {
  const payment = payments.get(req.params.id);
  if (!payment) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  if (payment.status === 'paid') {
    return res.status(400).json({ error: 'تم الدفع مسبقاً' });
  }
  if (payment.edfaRedirectUrl) {
    return res.json({ redirect: payment.edfaRedirectUrl });
  }
  payment.status = 'paid';
  payment.paidAt = new Date().toISOString();
  res.json({ success: true });
});

// ============================================================
// EdfaPay Webhook
// ============================================================
app.post('/api/edfa/webhook', (req, res) => {
  console.log('📩 EdfaPay Webhook received:', JSON.stringify(req.body));

  const { order_id, status, trans_id } = req.body;
  if (!order_id) {
    return res.status(400).send('Missing order_id');
  }

  const payment = payments.get(order_id);
  if (!payment) {
    console.error('Webhook: payment not found for order_id:', order_id);
    return res.status(404).send('Not found');
  }

  const normalizedStatus = String(status || '').toLowerCase();
  const result = String(req.body.result || '').toUpperCase();

  if (normalizedStatus === 'settled' || normalizedStatus === 'success' || normalizedStatus === '3ds_success' || result === 'SUCCESS') {
    payment.status = 'paid';
    payment.paidAt = new Date().toISOString();
    payment.edfaTransId = trans_id;
    console.log(`✅ Payment ${order_id} marked as paid via webhook (merchant: ${payment.merchantId})`);
  } else if (normalizedStatus === 'declined' || normalizedStatus === 'fail' || normalizedStatus === 'error' || result === 'DECLINED') {
    payment.status = 'failed';
    payment.failReason = req.body.decline_reason || 'unknown';
    payment.edfaTransId = trans_id;
    console.log(`❌ Payment ${order_id} failed: ${payment.failReason}`);
  }

  res.status(200).send('OK');
});

// EdfaPay 3DS Callback
app.all('/api/edfa/callback-3ds/:id', (req, res) => {
  const payment = payments.get(req.params.id);
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  if (!payment) {
    return res.redirect(`${baseUrl}/pay/invalid`);
  }
  res.redirect(`${baseUrl}/pay/${payment.id}`);
});

// Serve payment page (always show intermediate page, no auto-redirect)
app.get('/pay/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay.html'));
});

// ============================================================
// Start server
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  const url = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
  console.log(`\n🚀 الخادم يعمل على: ${url}`);
  console.log(`🔐 تسجيل الدخول: ${url}/login`);
  console.log(`👤 المدير: ${ADMIN_EMAIL}`);
  console.log(`\n⚙️  تأكد من ضبط إعدادات SMTP في ملف .env\n`);
});
