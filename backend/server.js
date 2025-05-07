// backend/server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-and-secret-key-for-jwt-yuma-v3'; // Змініть це!
if (JWT_SECRET === 'your-very-strong-and-secret-key-for-jwt-yuma-v3' && process.env.NODE_ENV === 'production') {
    console.warn('WARNING: JWT_SECRET is using a default insecure value in production!');
}

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    process.exit(1);
}
const pool = new Pool({
    connectionString: connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});
pool.on('connect', () => console.log('PostgreSQL pool connected to the database.'));
pool.on('error', (err) => {
    console.error('Unexpected error on idle PostgreSQL client', err);
    process.exit(-1);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..');
app.use('/frontend', express.static(frontendPath));

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Token missing.' });
    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) return res.status(403).json({ success: false, message: 'Token invalid or expired.' });
        req.user = userPayload;
        next();
    });
};

const INITIAL_ASSETS = ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'XRP', 'ADA', 'DOGE', 'YMC'];

// --- API Ендпоінти ---
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!email || !password || password.length < 6) return res.status(400).json({ success: false, message: 'Valid email and password (min 6 chars) are required.' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const hashedPassword = await bcrypt.hash(password, 10);
        const userUid = crypto.randomBytes(8).toString('hex').toUpperCase();
        const username = name || email.split('@')[0];

        const userSql = `INSERT INTO users (email, username, uid, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, email, username, uid`;
        const userResult = await client.query(userSql, [email, username, userUid, hashedPassword]);
        const newUser = userResult.rows[0];

        const assetPromises = INITIAL_ASSETS.map(assetSymbol => {
            const assetSql = `INSERT INTO assets (user_id, coin_symbol) VALUES ($1, $2) ON CONFLICT (user_id, coin_symbol) DO NOTHING`;
            return client.query(assetSql, [newUser.id, assetSymbol]);
        });
        await Promise.all(assetPromises);

        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'User registered successfully!', user: newUser });
    } catch (error) {
        await client.query('ROLLBACK');
        if (error.code === '23505') return res.status(409).json({ success: false, message: 'Email or username already exists.' });
        console.error("[Register] Error:", error);
        res.status(500).json({ success: false, message: 'Failed to register user.' });
    } finally {
        client.release();
    }
});

app.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ success: false, message: 'Identifier and password are required.' });

    const sql = `SELECT id, email, username, uid, password_hash FROM users WHERE email = $1 OR username = $1`;
    try {
        const result = await pool.query(sql, [identifier]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            const accessToken = jwt.sign(
                { userId: user.id, email: user.email, username: user.username, uid: user.uid },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            res.status(200).json({
                success: true, message: 'Login successful!', token: accessToken,
                user: { id: user.id, email: user.email, username: user.username, uid: user.uid }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error("[Login] Error:", error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

app.post('/auth/logout', (req, res) => {
    res.status(200).json({ success: true, message: 'Logged out (client should clear token).' });
});

// ПРОФІЛЬ
app.get('/api/profile', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, email, username, uid, created_at FROM users WHERE id = $1`;
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'User profile not found.' });
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("[API /profile] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching profile.' });
    }
});

// БАЛАНС (зараз повертає 0, потрібна логіка розрахунку на основі активів та цін)
app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    // TODO: Розрахувати реальний сумарний баланс.
    // Для MVP можна повернути суму всіх total_balance * 1 (якщо це USDT) або фейкові ціни.
    // Зараз повернемо просто 0 або суму USDT, якщо є.
    let totalUSDEquivalent = 0;
    try {
        const assetsSql = `SELECT coin_symbol, total_balance FROM assets WHERE user_id = $1`;
        const assetsResult = await pool.query(assetsSql, [userId]);
        for (const asset of assetsResult.rows) {
            if (asset.coin_symbol === 'USDT') { // Припускаємо, що USDT = 1 USD
                totalUSDEquivalent += parseFloat(asset.total_balance);
            }
            // Для інших криптовалют потрібні їх ціни в USD
        }
        res.json({ success: true, balance: totalUSDEquivalent.toFixed(2) });
    } catch (error) {
         console.error("[API /balance] Error:", error);
        res.status(500).json({ success: false, message: 'Server error calculating balance.' });
    }
});

// АКТИВИ
app.get('/api/assets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, coin_symbol, total_balance, available_balance, in_order_balance FROM assets WHERE user_id = $1 ORDER BY coin_symbol`;
        const result = await pool.query(sql, [userId]);
        const assetsWithUSDValue = result.rows.map(asset => ({
            ...asset,
            total_balance: parseFloat(asset.total_balance).toFixed(8),
            available_balance: parseFloat(asset.available_balance).toFixed(8),
            in_order_balance: parseFloat(asset.in_order_balance).toFixed(8),
            value_usd: (asset.coin_symbol === 'USDT' ? parseFloat(asset.total_balance) : 0).toFixed(2) // Дуже спрощено, тільки для USDT
        }));
        res.json({ success: true, assets: assetsWithUSDValue });
    } catch (error) {
        console.error("[API /assets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching assets.' });
    }
});

// РИНКИ
app.get('/api/markets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name,
                   EXISTS (SELECT 1 FROM user_favourite_markets ufm WHERE ufm.user_id = $1 AND ufm.market_pair_id = mp.id) as "isFavourite"
            FROM market_pairs mp WHERE mp.is_active = TRUE ORDER BY mp.symbol;
        `;
        const result = await pool.query(sql, [userId]);
        // Для MVP поки без real-time цін
        const markets = result.rows.map(pair => ({
            ...pair,
            currentPrice: null, // Заповнити з real-time даних пізніше
            change24hPercent: null,
            volume24h: null
        }));
        res.json({ success: true, markets: markets });
    } catch (error) {
        console.error("[API /markets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching markets.' });
    }
});

// УЛЮБЛЕНІ РИНКИ
app.get('/api/markets/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name
            FROM market_pairs mp
            JOIN user_favourite_markets ufm ON mp.id = ufm.market_pair_id
            WHERE ufm.user_id = $1 AND mp.is_active = TRUE ORDER BY mp.symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const markets = result.rows.map(pair => ({
            ...pair,
            currentPrice: null, // Заповнити з real-time даних пізніше
            change24hPercent: null,
        }));
        res.json({ success: true, markets: markets });
    } catch (error) {
        console.error("[API /markets/favourites] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching favourite markets.' });
    }
});

app.post('/api/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { marketPairId } = req.body;
    if (!marketPairId) return res.status(400).json({ success: false, message: 'Market Pair ID is required.' });
    try {
        const pairCheckSql = `SELECT id FROM market_pairs WHERE id = $1`;
        const pairCheckResult = await pool.query(pairCheckSql, [marketPairId]);
        if (pairCheckResult.rows.length === 0) return res.status(404).json({ success: false, message: 'Market pair not found.' });

        const sql = `INSERT INTO user_favourite_markets (user_id, market_pair_id) VALUES ($1, $2) ON CONFLICT (user_id, market_pair_id) DO NOTHING RETURNING *`;
        const result = await pool.query(sql, [userId, marketPairId]);
        if (result.rows.length > 0) {
            res.status(201).json({ success: true, message: 'Market pair added to favourites.', favourite: result.rows[0] });
        } else {
            res.status(200).json({ success: true, message: 'Market pair was already in favourites.' });
        }
    } catch (error) {
        console.error("[API /favourites POST] Error:", error);
        res.status(500).json({ success: false, message: 'Server error adding to favourites.' });
    }
});

app.delete('/api/favourites/:marketPairId', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const marketPairId = parseInt(req.params.marketPairId, 10);
    if (isNaN(marketPairId)) return res.status(400).json({ success: false, message: 'Invalid Market Pair ID.' });
    try {
        const sql = `DELETE FROM user_favourite_markets WHERE user_id = $1 AND market_pair_id = $2 RETURNING *`;
        const result = await pool.query(sql, [userId, marketPairId]);
        if (result.rowCount > 0) {
            res.status(200).json({ success: true, message: 'Market pair removed from favourites.' });
        } else {
            res.status(404).json({ success: false, message: 'Favourite market pair not found or already removed.' });
        }
    } catch (error) {
        console.error("[API /favourites DELETE] Error:", error);
        res.status(500).json({ success: false, message: 'Server error removing from favourites.' });
    }
});

// ОРДЕРИ (повертають дані з БД, поки без real-time оновлень)
app.get('/api/orders/open', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, pair, type, side, price, amount, filled_amount_base, created_at, status FROM orders WHERE user_id = $1 AND status = 'open' ORDER BY created_at DESC`;
        const result = await pool.query(sql, [userId]);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("[API /orders/open] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching open orders.' });
    }
});

app.get('/api/orders/history', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, pair, type, side, avg_fill_price, filled_amount_base, amount, status, created_at FROM orders WHERE user_id = $1 AND status IN ('filled', 'canceled', 'partially_filled') ORDER BY created_at DESC`;
        const result = await pool.query(sql, [userId]);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("[API /orders/history] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching order history.' });
    }
});


// --- Обслуговування HTML сторінок ---
app.get('/', (req, res) => res.sendFile(path.join(projectRootPath, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(projectRootPath, 'index.html')));

const htmlPages = [
    'login-page.html', 'sign_up-page.html', 'profile.html',
    'assets.html', 'order.html', 'account.html', 'settings.html',
    'markets.html', 'trading-page.html', 'buy_crypto-page.html',
    'futures-page.html', 'spot-page.html'
];
htmlPages.forEach(page => {
    app.get(`/${page}`, (req, res) => {
        res.sendFile(path.join(frontendPath, 'html', page));
    });
});

// --- Запуск сервера ---
app.listen(port, () => {
    console.log(`YuMa Backend Server is running on http://localhost:${port}`);
});

// --- Обробка закриття сервера ---
async function gracefulShutdown() {
    console.log('Received signal to terminate, shutting down gracefully.');
    try {
        if (pool) await pool.end();
        console.log('PostgreSQL pool has ended.');
        process.exit(0);
    } catch (e) {
        console.error('Error during shutdown:', e.stack);
        process.exit(1);
    }
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);