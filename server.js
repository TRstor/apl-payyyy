require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory store (replace with a database in production)
const payments = new Map();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Email transporter
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

// --- EdfaPay Hash Generation ---
function generateEdfaHash(orderId, orderAmount, orderCurrency, orderDescription) {
  const merchantPass = process.env.EDFA_MERCHANT_PASSWORD;
  const raw = (orderId + orderAmount + orderCurrency + orderDescription + merchantPass).toUpperCase();
  const md5 = crypto.createHash('md5').update(raw).digest('hex');
  const sha1 = crypto.createHash('sha1').update(md5).digest('hex');
  return sha1;
}

// --- EdfaPay: Initiate Payment ---
async function initiateEdfaPayment(payment, payerIp) {
  const merchantId = process.env.EDFA_MERCHANT_ID;
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  const orderId = payment.id;
  const orderAmount = Number(payment.price).toFixed(2);
  const orderCurrency = process.env.EDFA_CURRENCY || 'SAR';
  const orderDescription = payment.productName;

  const hash = generateEdfaHash(orderId, orderAmount, orderCurrency, orderDescription);

  // Split customer name into first/last
  const nameParts = payment.customerName.trim().split(/\s+/);
  const firstName = nameParts[0] || 'Customer';
  const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'N/A';

  // Build form data
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

// --- API Routes ---

// Send payment link
app.post('/api/send-payment-link', async (req, res) => {
  const { customerName, customerEmail, productName, price, customerPhone } = req.body;

  // Validation
  if (!customerName || !customerEmail || !productName || !price) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }

  if (typeof price !== 'number' || price <= 0 || price > 1000000) {
    return res.status(400).json({ error: 'السعر غير صالح' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(customerEmail)) {
    return res.status(400).json({ error: 'البريد الإلكتروني غير صالح' });
  }

  const paymentId = uuidv4();
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  // Store payment
  const payment = {
    id: paymentId,
    customerName: String(customerName).slice(0, 200),
    customerEmail: String(customerEmail).slice(0, 200),
    customerPhone: String(customerPhone || '').slice(0, 20),
    productName: String(productName).slice(0, 200),
    price: Number(price),
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  payments.set(paymentId, payment);

  // Determine payment link
  let paymentLink;
  let edfaRedirectUrl = null;

  // Try EdfaPay if configured
  if (process.env.EDFA_MERCHANT_ID && process.env.EDFA_MERCHANT_PASSWORD) {
    try {
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1';
      const edfaResult = await initiateEdfaPayment(payment, clientIp);

      if (edfaResult.redirect_url) {
        edfaRedirectUrl = edfaResult.redirect_url;
        payment.edfaRedirectUrl = edfaRedirectUrl;
        paymentLink = edfaRedirectUrl;
        console.log(`✅ EdfaPay: رابط دفع لطلب ${paymentId}`);
      } else {
        console.error('EdfaPay error:', JSON.stringify(edfaResult));
        // Fallback to local payment page
        paymentLink = `${baseUrl}/pay/${paymentId}`;
        payment.edfaError = JSON.stringify(edfaResult);
      }
    } catch (err) {
      console.error('EdfaPay request failed:', err.message);
      paymentLink = `${baseUrl}/pay/${paymentId}`;
    }
  } else {
    // No EdfaPay credentials — use local payment page
    paymentLink = `${baseUrl}/pay/${paymentId}`;
  }

  // Send email
  try {
    const transporter = createTransporter();

    const htmlEmail = `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; direction: rtl;">
      <div style="max-width: 500px; margin: 0 auto; background: #fff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
        <div style="background: linear-gradient(135deg, #667eea, #764ba2); padding: 32px; text-align: center; color: #fff;">
          <h1 style="margin: 0; font-size: 24px;">💳 رابط الدفع</h1>
        </div>
        <div style="padding: 32px;">
          <p style="font-size: 16px; color: #333;">مرحباً <strong>${escapeHtml(String(customerName))}</strong>,</p>
          <p style="color: #666; line-height: 1.6;">تم إنشاء رابط دفع خاص بك للمنتج التالي:</p>
          
          <div style="background: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 8px 0; color: #888;">المنتج:</td>
                <td style="padding: 8px 0; color: #333; font-weight: 600; text-align: left;">${escapeHtml(String(productName))}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; color: #888; border-top: 1px solid #eee;">المبلغ:</td>
                <td style="padding: 8px 0; color: #667eea; font-weight: 700; font-size: 20px; text-align: left; border-top: 1px solid #eee;">
                  ${Number(price).toFixed(2)} ر.س
                </td>
              </tr>
            </table>
          </div>

          <a href="${paymentLink}" style="display: block; text-align: center; background: linear-gradient(135deg, #2ecc71, #27ae60); color: #fff; padding: 16px; border-radius: 12px; text-decoration: none; font-size: 18px; font-weight: 700; margin: 24px 0;">
            ادفع الآن ✓
          </a>
          
          <p style="font-size: 12px; color: #999; text-align: center;">
            أو انسخ الرابط التالي:<br>
            <a href="${paymentLink}" style="color: #667eea; word-break: break-all;">${paymentLink}</a>
          </p>
        </div>
        <div style="background: #f8f9fa; padding: 16px; text-align: center; font-size: 12px; color: #999;">
          🔒 هذا الرابط آمن ومخصص لك فقط
        </div>
      </div>
    </body>
    </html>
    `;

    const fromName = process.env.SMTP_FROM_NAME || '';
    const fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER;
    const fromAddress = fromName ? `"${fromName}" <${fromEmail}>` : fromEmail;

    await transporter.sendMail({
      from: fromAddress,
      to: customerEmail,
      subject: `رابط دفع: ${String(productName).slice(0, 100)}`,
      html: htmlEmail,
    });

    res.json({ success: true, paymentId, paymentLink });
  } catch (error) {
    console.error('Email error:', error.message);
    // Still return the link even if email fails
    res.json({
      success: true,
      paymentId,
      paymentLink,
      emailWarning: 'تم إنشاء الرابط ولكن فشل إرسال البريد الإلكتروني. تأكد من إعدادات SMTP.',
    });
  }
});

// Get payment details
app.get('/api/payment/:id', (req, res) => {
  const payment = payments.get(req.params.id);
  if (!payment) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  // Return only safe fields
  res.json({
    productName: payment.productName,
    customerName: payment.customerName,
    price: payment.price,
    status: payment.status,
  });
});

// Confirm payment (local fallback only)
app.post('/api/payment/:id/pay', (req, res) => {
  const payment = payments.get(req.params.id);
  if (!payment) {
    return res.status(404).json({ error: 'الدفعة غير موجودة' });
  }
  if (payment.status === 'paid') {
    return res.status(400).json({ error: 'تم الدفع مسبقاً' });
  }

  // If EdfaPay is configured, redirect to EdfaPay instead
  if (payment.edfaRedirectUrl) {
    return res.json({ redirect: payment.edfaRedirectUrl });
  }

  payment.status = 'paid';
  payment.paidAt = new Date().toISOString();
  res.json({ success: true });
});

// --- EdfaPay Webhook (Callback) ---
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

  // Update payment status based on EdfaPay response
  const normalizedStatus = String(status).toLowerCase();
  if (normalizedStatus === 'settled' || normalizedStatus === 'success' || normalizedStatus === '3ds_success') {
    payment.status = 'paid';
    payment.paidAt = new Date().toISOString();
    payment.edfaTransId = trans_id;
    console.log(`✅ Payment ${order_id} marked as paid via webhook`);
  } else if (normalizedStatus === 'declined' || normalizedStatus === 'fail') {
    payment.status = 'failed';
    payment.edfaTransId = trans_id;
    console.log(`❌ Payment ${order_id} failed via webhook`);
  }

  // Respond 200 to acknowledge
  res.status(200).send('OK');
});

// --- EdfaPay 3DS Callback (term_url_3ds) ---
app.all('/api/edfa/callback-3ds/:id', (req, res) => {
  const payment = payments.get(req.params.id);
  const baseUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  if (!payment) {
    return res.redirect(`${baseUrl}/pay/invalid`);
  }

  // Redirect to our payment status page
  res.redirect(`${baseUrl}/pay/${payment.id}`);
});

// List all payments (for dashboard)
app.get('/api/payments', (req, res) => {
  const list = Array.from(payments.values())
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// Serve payment page
app.get('/pay/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay.html'));
});

// Escape HTML to prevent XSS in emails
function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return text.replace(/[&<>"']/g, (c) => map[c]);
}

app.listen(PORT, '0.0.0.0', () => {
  const url = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
  console.log(`\n🚀 الخادم يعمل على: ${url}`);
  console.log(`📧 لوحة التحكم: ${url}`);
  console.log(`\n⚙️  تأكد من ضبط إعدادات SMTP في ملف .env\n`);
});
