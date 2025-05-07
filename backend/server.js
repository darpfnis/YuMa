// backend/server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Для UID

const app = express();
const port = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-and-secret-key-for-jwt-yuma-v2'; // Змініть це в змінних середовища!
if (JWT_SECRET === 'your-very-strong-and-secret-key-for-jwt-yuma-v2' && process.env.NODE_ENV === 'production') {
    console.warn('WARNING: JWT_SECRET is using a default insecure value in production!');
}

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    // Для локальної розробки, якщо DATABASE_URL не встановлено:
    // const localDevConnectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_db_name";
    // if (process.env.NODE_ENV !== 'production' && localDevConnectionString) {
    //     console.warn("DATABASE_URL not set, using local development connection string.");
    //     // connectionString = localDevConnectionString; // НЕ РОЗКОМЕНТОВУЙТЕ ДЛЯ RENDER
    // } else {
    //    process.exit(1);
    // }
     process.exit(1);
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('connect', () => {
    console.log('PostgreSQL pool connected to the database.');
});
pool.on('error', (err) => {
    console.error('Unexpected error on idle PostgreSQL client', err);
    process.exit(-1);
});


// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..');
app.use('/frontend', express.static(frontendPath));


// --- Middleware для перевірки JWT ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    console.log('[AuthMiddleware] Auth Header:', authHeader);
    console.log('[AuthMiddleware] Token Extracted:', token);

    if (token == null) {
        console.log('[AuthMiddleware] Token missing.');
        return res.status(401).json({ success: false, message: 'Access token is missing.' });
    }

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.error('[AuthMiddleware] JWT verification error:', err.message); // ДУЖЕ ВАЖЛИВИЙ ЛОГ
            return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
        }
        req.user = userPayload;
        console.log('[AuthMiddleware] Token verified. User:', req.user);
        next();
    });
};

// --- Список основних криптовалют для початкового створення активів ---
const INITIAL_ASSETS = ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'XRP', 'ADA', 'DOGE', 'YMC']; // Додайте YMC або інші потрібні

// --- API Ендпоінти ---
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    console.log('[Register] Request body:', req.body);

    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });

    const client = await pool.connect(); // Отримуємо клієнта з пулу для транзакції
    try {
        await client.query('BEGIN'); // Починаємо транзакцію

        const hashedPassword = await bcrypt.hash(password, 10);
        const userUid = crypto.randomBytes(8).toString('hex').toUpperCase();
        const username = name || email.split('@')[0];

        const userSql = `INSERT INTO users (email, username, uid, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, email, username, uid`;
        const userResult = await client.query(userSql, [email, username, userUid, hashedPassword]);
        const newUser = userResult.rows[0];
        console.log('[Register] User created:', newUser);

        // Створюємо початкові записи в таблиці assets для нового користувача
        const assetPromises = INITIAL_ASSETS.map(assetSymbol => {
            const assetSql = `INSERT INTO assets (user_id, coin_symbol, total_balance, available_balance, in_order_balance) VALUES ($1, $2, 0, 0, 0)`;
            return client.query(assetSql, [newUser.id, assetSymbol]);
        });
        await Promise.all(assetPromises);
        console.log(`[Register] Initial assets created for user ID: ${newUser.id}`);

        await client.query('COMMIT'); // Завершуємо транзакцію

        res.status(201).json({
            success: true,
            message: 'User registered successfully! Initial assets created.',
            user: newUser
        });
    } catch (error) {
        await client.query('ROLLBACK'); // Відкочуємо транзакцію у випадку помилки
        if (error.code === '23505') { // Unique violation
            return res.status(409).json({ success: false, message: 'Email or username already exists.' });
        }
        console.error("[Register] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Failed to register user.' });
    } finally {
        client.release(); // Повертаємо клієнта до пулу
    }
});

app.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    console.log('[Login] Request body:', req.body);
    if (!identifier || !password) return res.status(400).json({ success: false, message: 'Identifier and password are required.' });

    const sql = `SELECT id, email, username, uid, password_hash FROM users WHERE email = $1 OR username = $1`;
    try {
        const result = await pool.query(sql, [identifier]);
        const user = result.rows[0];

        if (!user) {
            console.log('[Login] User not found for identifier:', identifier);
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            const accessToken = jwt.sign(
                { userId: user.id, email: user.email, username: user.username, uid: user.uid },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            console.log('[Login] Login successful for user:', user.email);
            res.status(200).json({
                success: true,
                message: 'Login successful!',
                token: accessToken,
                user: { id: user.id, email: user.email, username: user.username, uid: user.uid }
            });
        } else {
            console.log('[Login] Password incorrect for user:', user.email);
            res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error("[Login] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

app.post('/auth/logout', (req, res) => {
    console.log('[Logout] User logout request.');
    res.status(200).json({ success: true, message: 'Logged out successfully (client should clear token).' });
});

// ПРОФІЛЬ, АКТИВИ, ОРДЕРИ, РИНКИ (захищені ендпоінти)
app.get('/api/profile', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    console.log(`[API /profile] Request for user ID: ${userId}`);
    try {
        const sql = `SELECT id, email, username, uid, created_at FROM users WHERE id = $1`;
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User profile not found.' });
        }
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("[API /profile] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching profile.' });
    }
});

app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    console.log(`[API /balance] Request for user ID: ${userId}`);
    // TODO: Реальна логіка розрахунку сумарного балансу з таблиці assets та поточних цін
    const fakeBalance = (Math.random() * 10000).toFixed(2);
    res.json({ success: true, balance: parseFloat(fakeBalance) });
});

app.get('/api/assets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    console.log(`[API /assets] Request for user ID: ${userId}`);
    try {
        const sql = `SELECT id, coin_symbol, total_balance, available_balance, in_order_balance FROM assets WHERE user_id = $1 ORDER BY coin_symbol`;
        const result = await pool.query(sql, [userId]);
        const assetsWithUSDValue = result.rows.map(asset => {
            const livePrice = currentMarketData[`${asset.coin_symbol}USDT`]?.price || (asset.coin_symbol === 'USDT' ? 1 : 0);
            return {
                ...asset,
                value_usd: (parseFloat(asset.total_balance) * livePrice).toFixed(2)
            };
        });
        res.json({ success: true, assets: assetsWithUSDValue });
    } catch (error) {
        console.error("[API /assets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching assets.' });
    }
});

// ... (ендпоінти для /api/markets, /api/markets/favourites, /api/favourites (POST, DELETE), /api/orders/* залишаються схожими,
// але переконайтеся, що вони використовують async/await та try/catch для pool.query) ...
// ПРИКЛАД для /api/markets
app.get('/api/markets', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    console.log(`[API /markets] Request for user ID: ${userId}`);
    try {
        const sql = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name,
                   EXISTS (SELECT 1 FROM user_favourite_markets ufm WHERE ufm.user_id = $1 AND ufm.market_pair_id = mp.id) as "isFavourite"
            FROM market_pairs mp WHERE mp.is_active = TRUE ORDER BY mp.symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const marketsWithLiveData = result.rows.map(pair => {
            const liveData = currentMarketData[pair.symbol] || currentMarketData[pair.binance_symbol] || {};
            return {
                ...pair,
                currentPrice: liveData.price,
                change24hPercent: liveData.priceChangePercent,
                volume24h: liveData.quoteVolume
            };
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("[API /markets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching markets.' });
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
