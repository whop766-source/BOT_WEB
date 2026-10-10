
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const providerApi = require('./provider');

const app = express();

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({ windowMs: 900000, limit: 300 }));

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const token = (user) =>
  jwt.sign({ sub: String(user.id) }, process.env.JWT_SECRET, {
    expiresIn: '7d'
  });

const auth = asyncRoute(async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Bearer token required' });
    }

    const payload = jwt.verify(
      header.slice(7),
      process.env.JWT_SECRET
    );

    const result = await db.query(
      `SELECT id, name, email, role, balance, status
       FROM users WHERE id = $1`,
      [payload.sub]
    );

    if (!result.rowCount || result.rows[0].status !== 'active') {
      return res.status(401).json({ error: 'Account unavailable' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid/expired token' });
  }
});

const admin = (req, res, next) =>
  req.user.role === 'admin'
    ? next()
    : res.status(403).json({ error: 'Admin only' });

const safe = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  role: user.role,
  balance: user.balance,
  status: user.status
});

app.get('/', (req, res) => {
  res.json({
    name: 'Suru Traffic API',
    health: '/health',
    api: '/api'
  });
});

app.get('/health', asyncRoute(async (req, res) => {
  await db.query('SELECT 1');
  res.json({ status: 'ok', database: 'connected' });
}));

app.get('/api', (req, res) => {
  res.json({
    auth: [
      'POST /api/auth/register',
      'POST /api/auth/login',
      'GET /api/me'
    ],
    user: [
      'GET /api/services',
      'POST /api/orders',
      'GET /api/orders',
      'GET /api/transactions',
      'POST /api/deposits'
    ],
    admin: [
      'POST /api/admin/providers',
      'GET /api/admin/providers',
      'POST /api/admin/providers/:id/import-services',
      'POST /api/admin/services',
      'GET /api/admin/services',
      'GET /api/admin/users',
      'POST /api/admin/wallet-adjust',
      'GET /api/admin/deposits',
      'POST /api/admin/deposits/:id/decision'
    ],
    cron: 'POST /api/cron/sync'
  });
});

// REGISTER
app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (
    name.length < 2 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    password.length < 8
  ) {
    return res.status(400).json({
      error: 'Valid name/email and password (8+ chars) required'
    });
  }

  if ((await db.query(
    'SELECT id FROM users WHERE email = $1',
    [email]
  )).rowCount) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  try {
    const result = await db.query(
      `INSERT INTO users(name, email, password_hash, role)
       VALUES($1, $2, $3, 'user') RETURNING *`,
      [name, email, await bcrypt.hash(password, 12)]
    );

    res.status(201).json({
      user: safe(result.rows[0]),
      token: token(result.rows[0])
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    throw error;
  }
}));

// LOGIN
app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const result = await db.query(
    'SELECT * FROM users WHERE email = $1',
    [email]
  );

  const user = result.rows[0];

  if (
    !user ||
    user.status !== 'active' ||
    !(await bcrypt.compare(password, user.password_hash))
  ) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  res.json({
    user: safe(user),
    token: token(user)
  });
}));

app.get('/api/me', auth, (req, res) => {
  res.json({ user: safe(req.user) });
});

// CUSTOMER SERVICES
app.get('/api/services', auth, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT s.id, s.category, s.name, s.description,
            s.price_per_1000, s.min_qty, s.max_qty
     FROM services s
     JOIN providers p ON p.id = s.provider_id
     WHERE s.active = TRUE AND p.active = TRUE
     ORDER BY s.category, s.id`
  );

  res.json({ services: result.rows });
}));

// PLACE ORDER
app.post('/api/orders', auth, asyncRoute(async (req, res) => {
  const serviceId = Number(req.body.service_id);
  const quantity = Number(req.body.quantity);
  const link = String(req.body.link || '').trim();

  let parsedUrl;
  try {
    parsedUrl = new URL(link);
  } catch (_) {}

  if (
    !Number.isSafeInteger(serviceId) ||
    serviceId < 1 ||
    !Number.isSafeInteger(quantity) ||
    quantity < 1 ||
    !parsedUrl ||
    !['http:', 'https:'].includes(parsedUrl.protocol)
  ) {
    return res.status(400).json({
      error: 'Valid service_id, URL and quantity required'
    });
  }

  const client = await db.client();
  let order;
  let service;
  let provider;

  try {
    await client.query('BEGIN');

    const result = await client.query(
      `SELECT s.*, p.api_url, p.api_key, p.active AS provider_active
       FROM services s
       JOIN providers p ON p.id = s.provider_id
       WHERE s.id = $1
       FOR UPDATE OF s`,
      [serviceId]
    );

    service = result.rows[0];

    if (!service || !service.provider_active || !service.active) {
      throw Object.assign(new Error('Service unavailable'), { status: 400 });
    }

    if (quantity < service.min_qty || quantity > service.max_qty) {
      throw Object.assign(
        new Error(`Quantity must be ${service.min_qty}-${service.max_qty}`),
        { status: 400 }
      );
    }

    const charge = (
      quantity * Number(service.price_per_1000) / 1000
    ).toFixed(4);

    const balanceResult = await client.query(
      'SELECT balance FROM users WHERE id = $1 FOR UPDATE',
      [req.user.id]
    );

    if (
      !balanceResult.rowCount ||
      Number(balanceResult.rows[0].balance) < Number(charge)
    ) {
      throw Object.assign(new Error('Insufficient wallet balance'), {
        status: 400
      });
    }

    await client.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [charge, req.user.id]
    );

    order = (await client.query(
      `INSERT INTO orders
       (user_id, service_id, target_url, quantity, charge, status)
       VALUES($1, $2, $3, $4, $5, 'pending')
       RETURNING *`,
      [req.user.id, serviceId, link, quantity, charge]
    )).rows[0];

    await client.query(
      `INSERT INTO transactions
       (user_id, kind, amount, reference, note)
       VALUES($1, 'order', $2, $3, 'Order charge')`,
      [req.user.id, -Number(charge), `ORDER-${order.id}`]
    );

    await client.query('COMMIT');

    provider = {
      api_url: service.api_url,
      api_key: service.api_key
    };
  } catch (error) {
    await client.query('ROLLBACK');

    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }

    throw error;
  } finally {
    client.release();
  }

  try {
    const result = await providerApi.add(
      provider,
      service.provider_service_id,
      link,
      quantity
    );

    if (!result.order) {
      throw new Error('Provider did not return order ID');
    }

    const updated = await db.query(
      `UPDATE orders
       SET provider_order_id = $1,
           status = 'processing',
           provider_status = 'processing',
           updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [String(result.order), order.id]
    );

    return res.status(201).json({ order: updated.rows[0] });
  } catch (error) {
    const refundClient = await db.client();

    try {
      await refundClient.query('BEGIN');

      const result = await refundClient.query(
        'SELECT * FROM orders WHERE id = $1 FOR UPDATE',
        [order.id]
      );

      const current = result.rows[0];

      if (
        current &&
        !current.provider_order_id &&
        Number(current.refunded) === 0
      ) {
        await refundClient.query(
          'UPDATE users SET balance = balance + $1 WHERE id = $2',
          [current.charge, current.user_id]
        );

        await refundClient.query(
          `UPDATE orders
           SET status = 'failed', refunded = charge,
               provider_status = 'dispatch_failed'
           WHERE id = $1`,
          [order.id]
        );

        await refundClient.query(
          `INSERT INTO transactions
           (user_id, kind, amount, reference, note)
           VALUES($1, 'refund', $2, $3, 'Provider dispatch failed')`,
          [current.user_id, current.charge, `ORDER-${order.id}`]
        );
      }

      await refundClient.query('COMMIT');
    } catch (refundError) {
      await refundClient.query('ROLLBACK');
      console.error('Refund error:', refundError.message);
    } finally {
      refundClient.release();
    }

    res.status(502).json({
      error: 'Provider dispatch failed; refund attempted',
      order_id: order.id
    });
  }
}));

// CUSTOMER ORDER HISTORY
app.get('/api/orders', auth, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT o.*, s.name AS service_name
     FROM orders o
     JOIN services s ON s.id = o.service_id
     WHERE o.user_id = $1
     ORDER BY o.id DESC LIMIT 200`,
    [req.user.id]
  );

  res.json({ orders: result.rows });
}));

app.get('/api/transactions', auth, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT * FROM transactions
     WHERE user_id = $1
     ORDER BY id DESC LIMIT 200`,
    [req.user.id]
  );

  res.json({ transactions: result.rows });
}));

// MANUAL DEPOSIT REQUEST
app.post('/api/deposits', auth, asyncRoute(async (req, res) => {
  const amount = Number(req.body.amount);
  const reference = String(req.body.reference || '').trim();

  if (!Number.isFinite(amount) || amount <= 0 || !reference) {
    return res.status(400).json({
      error: 'Positive amount and payment reference required'
    });
  }

  const result = await db.query(
    `INSERT INTO deposits(user_id, amount, reference)
     VALUES($1, $2, $3) RETURNING *`,
    [req.user.id, amount, reference]
  );

  res.status(201).json({ deposit: result.rows[0] });
}));

// ADMIN: ADD PROVIDER
app.post('/api/admin/providers', auth, admin, asyncRoute(async (req, res) => {
  const { name, api_url, api_key } = req.body;

  let parsedUrl;
  try {
    parsedUrl = new URL(api_url);
  } catch (_) {}

  if (
    !name ||
    !api_key ||
    !parsedUrl ||
    !['https:', 'http:'].includes(parsedUrl.protocol)
  ) {
    return res.status(400).json({
      error: 'name, valid API URL and API key required'
    });
  }

  const result = await db.query(
    `INSERT INTO providers(name, api_url, api_key)
     VALUES($1, $2, $3)
     RETURNING id, name, api_url, active`,
    [name, api_url, api_key]
  );

  res.status(201).json({ provider: result.rows[0] });
}));

// ADMIN: LIST PROVIDERS
app.get('/api/admin/providers', auth, admin, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT id, name, api_url, active, created_at
     FROM providers ORDER BY id DESC`
  );

  res.json({ providers: result.rows });
}));

// ADMIN: IMPORT OR UPDATE SERVICES FROM PROVIDER
app.post(
  '/api/admin/providers/:id/import-services',
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const providerId = Number(req.params.id);

    if (!Number.isSafeInteger(providerId) || providerId < 1) {
      return res.status(400).json({ error: 'Invalid provider ID' });
    }

    const providerResult = await db.query(
      `SELECT id, api_url, api_key
       FROM providers
       WHERE id = $1 AND active = TRUE`,
      [providerId]
    );

    if (!providerResult.rowCount) {
      return res.status(404).json({ error: 'Active provider not found' });
    }

    const provider = providerResult.rows[0];
    const list = await providerApi.services(provider);

    if (!Array.isArray(list)) {
      return res.status(502).json({
        error: 'Provider services response was not an array'
      });
    }

    let inserted = 0;
    let updated = 0;
    let skipped = 0;

    for (const item of list) {
      // YoYo examples may use "service" or "services" for the service ID.
      const providerServiceId = String(
        item.service ?? item.services ?? ''
      ).trim();

      const name = String(item.name ?? '').trim();
      const category = String(
        item.Category ?? item.category ?? 'Other'
      ).trim();

      const rate = Number(item.rate);
      const min = Number(item.min);
      const max = Number(item.max);

      if (
        !providerServiceId ||
        !name ||
        !Number.isFinite(rate) ||
        rate < 0 ||
        !Number.isSafeInteger(min) ||
        min < 1 ||
        !Number.isSafeInteger(max) ||
        max < min
      ) {
        skipped++;
        continue;
      }

      // 30% markup: adjust if you want a different margin.
      const customerPrice = Number((rate * 1.30).toFixed(4));

      const existing = await db.query(
        `SELECT id FROM services
         WHERE provider_id = $1 AND provider_service_id = $2
         LIMIT 1`,
        [providerId, providerServiceId]
      );

      if (existing.rowCount) {
        await db.query(
          `UPDATE services
           SET category = $1,
               name = $2,
               description = $3,
               cost_per_1000 = $4,
               price_per_1000 = $5,
               min_qty = $6,
               max_qty = $7,
               active = TRUE
           WHERE id = $8`,
          [
            category,
            name,
            String(item.type ?? ''),
            rate,
            customerPrice,
            min,
            max,
            existing.rows[0].id
          ]
        );

        updated++;
      } else {
        await db.query(
          `INSERT INTO services
           (provider_id, provider_service_id, category, name,
            description, cost_per_1000, price_per_1000,
            min_qty, max_qty)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            providerId,
            providerServiceId,
            category,
            name,
            String(item.type ?? ''),
            rate,
            customerPrice,
            min,
            max
          ]
        );

        inserted++;
      }
    }

    res.json({
      provider_id: providerId,
      received: list.length,
      inserted,
      updated,
      skipped
    });
  })
);

// ADMIN: ADD A SINGLE SERVICE MANUALLY
app.post('/api/admin/services', auth, admin, asyncRoute(async (req, res) => {
  const body = req.body;

  if (
    !body.provider_id ||
    !body.provider_service_id ||
    !body.category ||
    !body.name ||
    !Number.isFinite(Number(body.price_per_1000))
  ) {
    return res.status(400).json({
      error: 'provider_id, provider_service_id, category, name, price_per_1000 required'
    });
  }

  const result = await db.query(
    `INSERT INTO services
     (provider_id, provider_service_id, category, name, description,
      cost_per_1000, price_per_1000, min_qty, max_qty)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING *`,
    [
      body.provider_id,
      body.provider_service_id,
      body.category,
      body.name,
      body.description || null,
      body.cost_per_1000 || 0,
      body.price_per_1000,
      body.min_qty || 1,
      body.max_qty || 1000000
    ]
  );

  res.status(201).json({ service: result.rows[0] });
}));

// ADMIN: LIST SERVICES
app.get('/api/admin/services', auth, admin, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT s.*, p.name AS provider_name
     FROM services s
     JOIN providers p ON p.id = s.provider_id
     ORDER BY s.id DESC`
  );

  res.json({ services: result.rows });
}));

// ADMIN: LIST USERS
app.get('/api/admin/users', auth, admin, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT id, name, email, role, balance, status, created_at
     FROM users ORDER BY id DESC LIMIT 500`
  );

  res.json({ users: result.rows });
}));

// ADMIN: ADJUST USER WALLET
app.post(
  '/api/admin/wallet-adjust',
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const userId = Number(req.body.user_id);
    const amount = Number(req.body.amount);

    if (!userId || !Number.isFinite(amount) || amount === 0) {
      return res.status(400).json({
        error: 'user_id and non-zero amount required'
      });
    }

    const client = await db.client();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        'SELECT balance FROM users WHERE id = $1 FOR UPDATE',
        [userId]
      );

      if (!result.rowCount) {
        throw Object.assign(new Error('User not found'), { status: 404 });
      }

      if (Number(result.rows[0].balance) + amount < 0) {
        throw Object.assign(new Error('Balance cannot be negative'), {
          status: 400
        });
      }

      await client.query(
        'UPDATE users SET balance = balance + $1 WHERE id = $2',
        [amount, userId]
      );

      await client.query(
        `INSERT INTO transactions
         (user_id, kind, amount, reference, note)
         VALUES($1, 'adjustment', $2, 'ADMIN', 'Admin adjustment')`,
        [userId, amount]
      );

      await client.query('COMMIT');
      res.json({ message: 'Wallet updated' });
    } catch (error) {
      await client.query('ROLLBACK');

      if (error.status) {
        return res.status(error.status).json({ error: error.message });
      }

      throw error;
    } finally {
      client.release();
    }
  })
);

// ADMIN: LIST DEPOSITS
app.get('/api/admin/deposits', auth, admin, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT d.*, u.email
     FROM deposits d
     JOIN users u ON u.id = d.user_id
     ORDER BY d.id DESC`
  );

  res.json({ deposits: result.rows });
}));

// ADMIN: APPROVE OR REJECT DEPOSIT
app.post(
  '/api/admin/deposits/:id/decision',
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const client = await db.client();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        'SELECT * FROM deposits WHERE id = $1 FOR UPDATE',
        [req.params.id]
      );

      const deposit = result.rows[0];

      if (!deposit) {
        throw Object.assign(new Error('Deposit not found'), { status: 404 });
      }

      if (deposit.status !== 'pending') {
        throw Object.assign(new Error('Already reviewed'), { status: 409 });
      }

      if (req.body.decision === 'approve') {
        await client.query(
          'UPDATE users SET balance = balance + $1 WHERE id = $2',
          [deposit.amount, deposit.user_id]
        );

        await client.query(
          `INSERT INTO transactions
           (user_id, kind, amount, reference, note)
           VALUES($1, 'deposit', $2, $3, 'Deposit approved')`,
          [
            deposit.user_id,
            deposit.amount,
            `DEPOSIT-${deposit.id}`
          ]
        );
      } else if (req.body.decision !== 'reject') {
        throw Object.assign(
          new Error('decision must be approve/reject'),
          { status: 400 }
        );
      }

      await client.query(
        'UPDATE deposits SET status = $1 WHERE id = $2',
        [
          req.body.decision === 'approve' ? 'approved' : 'rejected',
          deposit.id
        ]
      );

      await client.query('COMMIT');
      res.json({ message: 'Deposit reviewed' });
    } catch (error) {
      await client.query('ROLLBACK');

      if (error.status) {
        return res.status(error.status).json({ error: error.message });
      }

      throw error;
    } finally {
      client.release();
    }
  })
);

// CRON: SYNC ORDER STATUSES
app.post('/api/cron/sync', asyncRoute(async (req, res) => {
  if (
    !process.env.CRON_SECRET ||
    req.headers['x-cron-secret'] !== process.env.CRON_SECRET
  ) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const result = await db.query(
    `SELECT o.*, s.provider_service_id, p.api_url, p.api_key
     FROM orders o
     JOIN services s ON s.id = o.service_id
     JOIN providers p ON p.id = s.provider_id
     WHERE o.provider_order_id IS NOT NULL
       AND o.status IN ('pending', 'processing')
     ORDER BY o.id
     LIMIT 100`
  );

  const counts = {
    checked: 0,
    updated: 0,
    refunded: 0,
    errors: 0
  };

  for (const order of result.rows) {
    counts.checked++;

    try {
      const data = await providerApi.status(
        {
          api_url: order.api_url,
          api_key: order.api_key
        },
        order.provider_order_id
      );

      const raw = String(data.status || '').toLowerCase();

      const statusMap = {
        completed: 'completed',
        partial: 'partial',
        canceled: 'cancelled',
        cancelled: 'cancelled',
        processing: 'processing',
        'in progress': 'processing',
        pending: 'pending'
      };

      const status = statusMap[raw] || 'processing';

      const remains = Number.isFinite(Number(data.remains))
        ? Math.max(
            0,
            Math.min(Number(order.quantity), Number(data.remains))
          )
        : null;

      const client = await db.client();

      try {
        await client.query('BEGIN');

        const currentResult = await client.query(
          'SELECT * FROM orders WHERE id = $1 FOR UPDATE',
          [order.id]
        );

        const current = currentResult.rows[0];

        await client.query(
          `UPDATE orders
           SET status = $1,
               provider_status = $2,
               remains = $3,
               last_sync_at = NOW(),
               updated_at = NOW()
           WHERE id = $4`,
          [status, raw, remains, order.id]
        );

        if (
          current &&
          ['partial', 'cancelled'].includes(status) &&
          Number(current.refunded) === 0
        ) {
          const undelivered = status === 'cancelled'
            ? Number(current.quantity)
            : (remains === null ? 0 : remains);

          const refund = Number(
            (
              undelivered *
              Number(current.charge) /
              Math.max(1, Number(current.quantity))
            ).toFixed(4)
          );

          if (refund > 0) {
            await client.query(
              'UPDATE users SET balance = balance + $1 WHERE id = $2',
              [refund, current.user_id]
            );

            await client.query(
              'UPDATE orders SET refunded = $1 WHERE id = $2',
              [refund, order.id]
            );

            await client.query(
              `INSERT INTO transactions
               (user_id, kind, amount, reference, note)
               VALUES($1, 'refund', $2, $3,
                      'Automatic undelivered quantity refund')`,
              [
                current.user_id,
                refund,
                `ORDER-${order.id}`
              ]
            );

            counts.refunded++;
          }
        }

        await client.query('COMMIT');
        counts.updated++;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      counts.errors++;
      console.error('Sync order', order.id, error.message);
    }
  }

  res.json(counts);
}));

// ERROR HANDLER
app.use((error, req, res, next) => {
  console.error(error.stack || error.message);

  res.status(500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Server error; check host logs'
      : error.message
  });
});

const server = app.listen(
  Number(process.env.PORT || 3000),
  () => console.log('Suru Traffic API listening')
);

process.on('SIGTERM', () => {
  server.close(() => db.pool.end());
});
