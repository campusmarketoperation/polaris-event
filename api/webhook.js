/**
 * POLARIS — Stripe Webhook ハンドラー
 * =====================================
 * Vercelのサーバーレス関数として動作します。
 * ファイルは /api/webhook.js に配置してください。
 *
 * 【設定手順】
 * 1. このファイルを GitHub の polaris-event/api/webhook.js としてアップロード
 * 2. Vercel の Environment Variables に以下を追加：
 *    - STRIPE_WEBHOOK_SECRET : Stripeダッシュボードで発行されるWebhookシークレット
 *    - GAS_URL               : Google Apps ScriptのデプロイURL
 * 3. Stripeダッシュボード → Webhooks → エンドポイントを追加：
 *    URL: https://polaris-event.vercel.app/api/webhook
 *    イベント: checkout.session.completed
 */
 
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
 
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const gasUrl = process.env.GAS_URL;
 
  let event;
 
  try {
    // Stripeの署名を検証（なりすまし防止）
    const sig = req.headers['stripe-signature'];
    const rawBody = await getRawBody(req);
    event = stripe.webhooks.constructEvent(rawBody, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook署名エラー:', err.message);
    return res.status(400).json({ error: `Webhook Error: ${err.message}` });
  }
 
  // 決済完了イベントを処理
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.customer_details?.email || session.customer_email;
 
    if (!email) {
      return res.status(200).json({ received: true, note: 'メールアドレスなし' });
    }
 
    // GASにメールアドレスを送って支払いステータスを更新
    try {
      await fetch(gasUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'payment_complete',
          email:  email,
          stripeSessionId: session.id,
        })
      });
      console.log('支払い済み更新完了:', email);
    } catch (err) {
      console.error('GAS送信エラー:', err);
    }
  }
 
  return res.status(200).json({ received: true });
}
 
// Stripeの署名検証のためにrawボディが必要
async function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
 
// Next.jsのbodyParserを無効化（rawボディを取得するために必要）
export const config = {
  api: { bodyParser: false }
};
 
