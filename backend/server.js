// backend/server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-and-secret-key-for-jwt-yuma-v3-final-final-final'; // ЗМІНІТЬ ЦЕ В ЗМІННИХ СЕРЕДОВИЩА!
if (JWT_SECRET === 'your-very-strong-and-secret-key-for-jwt-yuma-v3-final-final-final' && process.env.NODE_ENV === 'production') {
    console.warn('WARNING: JWT_SECRET is using a default insecure value in production! Please set a strong JWT_SECRET environment variable on Render.');
}

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    // Для локальної розробки, якщо DATABASE_URL не встановлено, можна тут тимчасово задати:
    // const localDevConnectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_database_name";
    // if (process.env.NODE_ENV !== 'production' && localDevConnectionString) {
    //     console.warn("DATABASE_URL not set, using local development connection string.");
    //     // connectionString = localDevConnectionString; // НЕ РОЗКОМЕНТОВУЙТЕ ДЛЯ RENDER
    // } else {
        process.exit(1); // Критично для Render
    // }
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('connect', (client) => {
    console.log('PostgreSQL pool: New client connected to the database.');
    client.on('error', err => { // Додаємо обробник помилок для окремого клієнта з пулу
        console.error('PostgreSQL client error within pool:', err);
    });
});
pool.on('error', (err, client) => { // Загальний обробник помилок пулу
    console.error('Unexpected error on idle PostgreSQL client in pool', err);
    // process.exit(-1); // Можливо, не варто зупиняти сервер на кожну помилку пулу
});


// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..');
app.use('/frontend', express.static(frontendPath));


// --- Middleware для перевірки JWT (обов'язковий для захищених маршрутів) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    // console.log('[AuthMiddleware] Path:', req.path, 'Auth Header:', authHeader);

    if (token == null) {
        // console.log('[AuthMiddleware] Token missing for path:', req.path);
        return res.status(401).json({ success: false, message: 'Access token is missing.' });
    }

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.error('[AuthMiddleware] JWT verification error for path:', req.path, err.name, '-', err.message);
            return res.status(403).json({ success: false, message: 'Token invalid or expired.', errorType: err.name });
        }
        req.user = userPayload; // payload з токена
        // console.log('[AuthMiddleware] Token verified. User:', req.user, 'for path:', req.path);
        next();
    });
};

// --- Middleware для опціональної автентифікації ---
const tryAuthenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    // console.log('[TryAuthMiddleware] Path:', req.path, 'Auth Header:', authHeader);

    if (token == null) {
        req.user = null; // Користувача немає
        // console.log('[TryAuthMiddleware] No token, proceeding as anonymous for path:', req.path);
        return next();
    }

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            // console.warn('[TryAuthMiddleware] Invalid token received, proceeding as anonymous for path:', req.path, err.message);
            req.user = null;
        } else {
            req.user = userPayload;
            // console.log('[TryAuthMiddleware] Token verified. User:', req.user, 'for path:', req.path);
        }
        next();
    });
};


const INITIAL_ASSETS = ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'XRP', 'ADA', 'DOGE', 'YMC']; // YMC - ваша монета
let currentMarketData = {}; // Це має оновлюватися з WebSocket Binance

// (ТУТ МАЄ БУТИ ВАШ КОД ДЛЯ ПІДКЛЮЧЕННЯ ДО WEBSOCKET BINANCE ТА ОНОВЛЕННЯ currentMarketData)
// const WebSocket = require('ws');
// function connectToBinanceMarketStreams() { /* ... */ }
// connectToBinanceMarketStreams(); // Викликати при старті


// --- API Ендпоінти ---

// АУТЕНТИФІКАЦІЯ
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!email || !password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Valid email and password (min 6 chars) are required.' });
    }

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
            const assetSql = `INSERT INTO assets (user_id, coin_symbol, total_balance, available_balance, in_order_balance) VALUES ($1, $2, 0, 0, 0) ON CONFLICT (user_id, coin_symbol) DO NOTHING`;
            return client.query(assetSql, [newUser.id, assetSymbol]);
        });
        await Promise.all(assetPromises);

        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'User registered successfully! Initial assets created.', user: newUser });
    } catch (error) {
        await client.query('ROLLBACK');
        if (error.code === '23505') {
            return res.status(409).json({ success: false, message: 'Email or username already exists.' });
        }
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

app.post('/auth/logout', (req, res) => { // Можна додати authenticateToken, якщо логіка вимагає знати, хто виходить
    // console.log('[Logout] User logout request. User from token (if provided):', req.user);
    res.status(200).json({ success: true, message: 'Logged out (client should clear token).' });
});


// ПРОФІЛЬ, АКТИВИ, РИНКИ, ОРДЕРИ
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

app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    let totalUSDEquivalent = 0;
    try {
        const assetsSql = `SELECT coin_symbol, total_balance FROM assets WHERE user_id = $1`;
        const assetsResult = await pool.query(assetsSql, [userId]);
        for (const asset of assetsResult.rows) {
            let priceInUSD = 0;
            const assetSymbolUpper = asset.coin_symbol.toUpperCase();
            if (['USDT', 'USDC', 'BUSD'].includes(assetSymbolUpper)) {
                priceInUSD = 1;
            } else {
                const pairSymbolUSDT = `${assetSymbolUpper}USDT`;
                priceInUSD = currentMarketData[pairSymbolUSDT]?.price || 0;
            }
            totalUSDEquivalent += parseFloat(asset.total_balance) * priceInUSD;
        }
        res.json({ success: true, balance: totalUSDEquivalent.toFixed(2) });
    } catch (error) {
         console.error("[API /balance] Error:", error);
        res.status(500).json({ success: false, message: 'Server error calculating balance.' });
    }
});

app.get('/api/assets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `
            SELECT a.id, a.coin_symbol, COALESCE(mp.name, a.coin_symbol) as coin_name,
                   a.total_balance, a.available_balance, a.in_order_balance
            FROM assets a
            LEFT JOIN market_pairs mp ON UPPER(a.coin_symbol) = UPPER(mp.base_asset) OR UPPER(a.coin_symbol) = UPPER(mp.symbol) -- Адаптуйте JOIN
            WHERE a.user_id = $1 ORDER BY a.coin_symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const assetsWithDetails = result.rows.map(asset => {
            let valueInUSD = 0;
            const assetSymbolUpper = asset.coin_symbol.toUpperCase();
             if (['USDT', 'USDC', 'BUSD'].includes(assetSymbolUpper)) {
                valueInUSD = parseFloat(asset.total_balance);
            } else {
                const pairSymbolUSDT = `${assetSymbolUpper}USDT`;
                const livePrice = currentMarketData[pairSymbolUSDT]?.price;
                if (livePrice) valueInUSD = parseFloat(asset.total_balance) * livePrice;
            }
            return {
                ...asset,
                total_balance: parseFloat(asset.total_balance).toFixed(8),
                available_balance: parseFloat(asset.available_balance).toFixed(8),
                in_order_balance: parseFloat(asset.in_order_balance).toFixed(8),
                value_usd: valueInUSD.toFixed(2)
            };
        });
        res.json({ success: true, assets: assetsWithDetails });
    } catch (error) {
        console.error("[API /assets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching assets.' });
    }
});

app.get('/api/assets/base', tryAuthenticateToken, async (req, res) => {
    try {
        const sql = `SELECT DISTINCT mp.base_asset FROM market_pairs mp WHERE mp.is_active = TRUE ORDER BY mp.base_asset;`;
        const result = await pool.query(sql);
        res.json({ success: true, baseAssets: result.rows.map(r => r.base_asset) });
    } catch (error) {
        console.error("[API /api/assets/base] Error fetching base assets:", error);
        res.status(500).json({ success: false, message: 'Server error fetching base assets.' });
    }
});

app.get('/api/markets', tryAuthenticateToken, async (req, res) => {
    const userId = req.user ? req.user.userId : null;
    const { baseAsset, popularOnly } = req.query;
    try {
        let queryParams = [];
        let paramIndex = 1;
        let selectIsFavourite = `FALSE as "isFavourite"`;
        if (userId) {
            selectIsFavourite = `EXISTS (SELECT 1 FROM user_favourite_markets ufm WHERE ufm.user_id = $${paramIndex++} AND ufm.market_pair_id = mp.id) as "isFavourite"`;
            queryParams.push(userId);
        }
        const baseSelect = `SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name, mp.is_popular, ${selectIsFavourite} FROM market_pairs mp`;
        let conditions = ["mp.is_active = TRUE"];
        if (popularOnly === 'true') conditions.push("mp.is_popular = TRUE");
        else if (baseAsset) {
            conditions.push(`mp.base_asset = $${paramIndex++}`);
            queryParams.push(baseAsset);
        }
        const sql = `${baseSelect} WHERE ${conditions.join(' AND ')} ORDER BY mp.symbol;`;
        const result = await pool.query(sql, queryParams);
        const marketsWithLiveData = result.rows.map(pair => {
            const liveData = currentMarketData[pair.symbol] || currentMarketData[pair.binance_symbol] || {};
            return { ...pair, currentPrice: liveData.price, change24hPercent: liveData.priceChangePercent, volume24h: liveData.quoteVolume };
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("[API /markets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching markets.' });
    }
});

app.get('/api/markets/favourites', authenticateToken, async (req, res) => { /* ... код з попередніх відповідей, адаптований ... */ });
app.post('/api/favourites', authenticateToken, async (req, res) => { /* ... код ... */ });
app.delete('/api/favourites/:marketPairId', authenticateToken, async (req, res) => { /* ... код ... */ });
app.get('/api/orders/open', authenticateToken, async (req, res) => { /* ... код ... */ });
app.get('/api/orders/history', authenticateToken, async (req, res) => { /* ... код ... */ });


// --- Обслуговування HTML сторінок ---
app.get('/', (req, res) => res.sendFile(path.join(projectRootPath, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(projectRootPath, 'index.html')));
const htmlPages = [
    'login-page.html', 'sign_up-page.html', 'profile.html', 'assets.html', 'order.html',
    'account.html', 'settings.html', 'markets.html', 'trading-page.html',
    'buy_crypto-page.html', 'futures-page.html', 'spot-page.html'
];
htmlPages.forEach(page => {
    app.get(`/${page}`, (req, res) => res.sendFile(path.join(frontendPath, 'html', page)));
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