/**
 * POLARIS — Stripe Webhook ハンドラー
 * Vercel Serverless Function
 */
 
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
 
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const gasUrl        = process.env.GAS_URL;
 
  // rawボディを取得
  const rawBody = await getRawBody(req);
  const sig     = req.headers['stripe-signature'];
 
  // Stripeの署名を検証
  let event;
  try {
    event = verifyStripeSignature(rawBody, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook署名エラー:', err.message);
    return res.status(400).json({ error: err.message });
  }
 
  // 決済完了イベントを処理
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.customer_details?.email || session.customer_email;
 
    console.log('決済完了:', email, session.id);
 
    if (email && gasUrl) {
      try {
        const response = await fetch(gasUrl, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({
            action:          'payment_complete',
            email:           email,
            stripeSessionId: session.id,
          })
        });
        console.log('GAS送信完了:', response.status);
      } catch (err) {
        console.error('GAS送信エラー:', err.message);
      }
    }
  }
 
  return res.status(200).json({ received: true });
}
 
// rawボディ取得
async function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
 
// Stripe署名検証（stripe パッケージ不要・自前実装）
function verifyStripeSignature(payload, header, secret) {
  if (!header) throw new Error('stripe-signatureヘッダーがありません');
 
  const parts  = header.split(',');
  const tPart  = parts.find(p => p.startsWith('t='));
  const v1Part = parts.find(p => p.startsWith('v1='));
  if (!tPart || !v1Part) throw new Error('不正なsignatureヘッダー');
 
  const timestamp     = tPart.slice(2);
  const signature     = v1Part.slice(3);
  const signedPayload = `${timestamp}.${payload}`;
 
  const crypto   = require('crypto');
  const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
 
  if (expected !== signature) throw new Error('署名が一致しません');
 
  const tolerance = 300;
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > tolerance) {
    throw new Error('リクエストが古すぎます');
  }
 
  return JSON.parse(payload);
}
 
export const config = {
  api: { bodyParser: false }
};
 
