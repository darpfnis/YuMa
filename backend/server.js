// backend/server.js
const express = require('express');
const { Pool } = require('pg'); // Драйвер для PostgreSQL
const bcrypt = require('bcryptjs');
const path = require('path');   // Вбудований модуль Node.js для роботи зі шляхами
const jwt = require('jsonwebtoken'); // Для JWT

const app = express();
const port = process.env.PORT || 3000;

// Секретний ключ для JWT. У реальному проекті зберігайте його в змінних середовища!
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-and-secret-key-for-jwt-yuma'; // Змініть це!
if (JWT_SECRET === 'your-very-strong-and-secret-key-for-jwt-yuma' && process.env.NODE_ENV === 'production') {
    console.warn('WARNING: JWT_SECRET is using the default insecure value in production! Please set a strong JWT_SECRET environment variable.');
}

// --- Налаштування Бази Даних PostgreSQL ---
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    process.exit(1);
}
const pool = new Pool({
    connectionString: connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client for PostgreSQL on startup:', err.stack);
    } else {
        console.log('Successfully connected to the PostgreSQL database via pool on startup.');
        if (client) client.release();
    }
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..');
app.use('/frontend', express.static(frontendPath)); // Обслуговує /frontend/css, /frontend/js тощо

// --- Middleware для перевірки JWT ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.status(401).json({ success: false, message: 'Access token is missing.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err.message);
            return res.status(403).json({ success: false, message: 'Invalid or expired token.' }); // Forbidden
        }
        req.user = user; // Додаємо інформацію про користувача (payload з токена) до об'єкту запиту
        next();
    });
};

// --- Глобальна змінна для ринкових даних (оновлюється через WebSocket) ---
// Це приклад, реальне оновлення має бути через WebSocket клієнт до Binance
let currentMarketData = {}; // Наприклад: { "BTCUSDT": { price: 50000, change24hPercent: 2.5, ... }, ... }

// (Тут має бути ваш код для підключення до WebSocket Binance та оновлення currentMarketData)
// const WebSocket = require('ws');
// function connectToBinanceMarketStreams() { ... }
// connectToBinanceMarketStreams();


// --- API Ендпоінти ---

// АУТЕНТИФІКАЦІЯ
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body; // Припускаємо, що може приходити і 'name' (username)
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userUid = require('crypto').randomBytes(8).toString('hex'); // Простий UID
        const username = name || email.split('@')[0];

        const sql = `INSERT INTO users (email, username, uid, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, email, username, uid`;
        const result = await pool.query(sql, [email, username, userUid, hashedPassword]);
        res.status(201).json({
            success: true,
            message: 'User registered successfully!',
            user: result.rows[0]
        });
    } catch (error) {
        if (error.code === '23505') { // Unique violation (наприклад, для email або username, якщо вони UNIQUE)
            return res.status(409).json({ success: false, message: 'Email or username already exists.' });
        }
        console.error("Error during user registration (PostgreSQL):", error);
        res.status(500).json({ success: false, message: 'Failed to register user.' });
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
                { expiresIn: '1h' } // Токен дійсний 1 годину
            );
            res.status(200).json({
                success: true,
                message: 'Login successful!',
                token: accessToken,
                user: { id: user.id, email: user.email, username: user.username, uid: user.uid }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error("Error during login (PostgreSQL):", error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

app.post('/auth/logout', (req, res) => {
    // Для JWT на стороні сервера зазвичай нічого не робиться для виходу,
    // клієнт просто видаляє токен. Можна додати логування.
    console.log('User logout request received (token should be invalidated client-side).');
    res.status(200).json({ success: true, message: 'Logged out successfully (client should clear token).' });
});


// ПРОФІЛЬ КОРИСТУВАЧА
app.get('/api/profile', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, email, username, uid, created_at FROM users WHERE id = $1`;
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User profile not found.' });
        }
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("Error fetching user profile:", error);
        res.status(500).json({ success: false, message: 'Server error fetching profile.' });
    }
});

// БАЛАНС (приклад, можна об'єднати з /api/profile або /api/assets)
app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    // TODO: Реалізувати запит до БД для отримання реального сумарного балансу користувача
    // на основі його активів та їх поточної вартості.
    const fakeBalance = (Math.random() * 15000).toFixed(2); // Фейковий баланс
    res.json({ success: true, balance: parseFloat(fakeBalance) });
});


// РИНКИ ТА УЛЮБЛЕНІ
app.get('/api/markets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `
            SELECT
                mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name,
                EXISTS (
                    SELECT 1 FROM user_favourite_markets ufm
                    WHERE ufm.user_id = $1 AND ufm.market_pair_id = mp.id
                ) as "isFavourite"
            FROM market_pairs mp
            WHERE mp.is_active = TRUE
            ORDER BY mp.symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const marketsWithLiveData = result.rows.map(pair => {
            const liveData = currentMarketData[pair.symbol] || {};
            return { ...pair, ...liveData };
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("Error fetching markets:", error);
        res.status(500).json({ success: false, message: 'Server error fetching markets.' });
    }
});

app.get('/api/markets/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name
            FROM market_pairs mp
            JOIN user_favourite_markets ufm ON mp.id = ufm.market_pair_id
            WHERE ufm.user_id = $1 AND mp.is_active = TRUE
            ORDER BY mp.symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const marketsWithLiveData = result.rows.map(pair => {
            const liveData = currentMarketData[pair.symbol] || {};
            return { ...pair, ...liveData }; // Додаємо 'живі' дані, якщо є
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("Error fetching user's favourite markets:", error);
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
        console.error("Error adding to favourites:", error);
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
        console.error("Error removing from favourites:", error);
        res.status(500).json({ success: false, message: 'Server error removing from favourites.' });
    }
});


// АКТИВИ (плейсхолдер, реалізуйте запити до таблиці assets)
app.get('/api/assets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT coin_symbol, total_balance, available_balance, in_order_balance FROM assets WHERE user_id = $1 ORDER BY coin_symbol`;
        const result = await pool.query(sql, [userId]);
        // Додайте логіку для отримання поточної вартості в USD
        const assetsWithUSDValue = result.rows.map(asset => ({
            ...asset,
            value_usd: (parseFloat(asset.total_balance) * (currentMarketData[`${asset.coin_symbol}USDT`]?.price || (asset.coin_symbol === 'USDT' ? 1 : 0) )).toFixed(2) || 'N/A'
        }));
        res.json({ success: true, assets: assetsWithUSDValue });
    } catch (error) {
        console.error("Error fetching user assets:", error);
        res.status(500).json({ success: false, message: 'Server error fetching assets.' });
    }
});

// ОРДЕРИ (плейсхолдери, реалізуйте запити до таблиці orders)
app.get('/api/orders/open', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, pair, type, side, price, amount, filled_amount_base, created_at FROM orders WHERE user_id = $1 AND status = 'open' ORDER BY created_at DESC`;
        const result = await pool.query(sql, [userId]);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("Error fetching open orders:", error);
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
        console.error("Error fetching order history:", error);
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
        if (pool) {
            await pool.end();
            console.log('PostgreSQL pool has ended.');
        }
        process.exit(0);
    } catch (e) {
        console.error('Error during shutdown:', e.stack);
        process.exit(1);
    }
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);