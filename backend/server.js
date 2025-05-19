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


const DEV_MODE_SKIP_AUTH = false; // Встановіть в true для вимкнення автентифікації, false для увімкнення
const DEV_MODE_TEST_USER = { // Тестовий користувач, якщо автентифікація вимкнена
    userId: 1, // ID існуючого тестового користувача у вашій БД
    email: 'testuser@example.com',
    username: 'testuser',
    uid: 'TESTUID123'
};

const authenticateToken = (req, res, next) => {
    if (DEV_MODE_SKIP_AUTH) {
        console.warn('[AuthMiddleware - DEV MODE] Authentication SKIPPED. Using test user.');
        req.user = DEV_MODE_TEST_USER; 
        return next();
    }

    // Ваша існуюча логіка перевірки токена
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Token missing.' });
    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) return res.status(403).json({ success: false, message: 'Token invalid or expired.', errorType: err.name });
        req.user = userPayload;
        next();
    });
};

const tryAuthenticateToken = (req, res, next) => {
    if (DEV_MODE_SKIP_AUTH) {
        console.warn('[TryAuthMiddleware - DEV MODE] Authentication SKIPPED. Using test user if no real token, else anonymous.');
        // Якщо ви хочете, щоб tryAuth завжди встановлював тестового користувача в DEV_MODE,
        // навіть якщо токена немає (для тестів, де req.user очікується):
        // req.user = DEV_MODE_TEST_USER;
        // Або, якщо ви хочете імітувати ситуацію, коли користувач може бути анонімним:
        const authHeader = req.headers['authorization']; // Перевіряємо, чи клієнт все ж надіслав токен
        const token = authHeader && authHeader.split(' ')[1];
        if (token) { // Якщо токен є, спробуємо його верифікувати
            jwt.verify(token, JWT_SECRET, (err, userPayload) => {
                req.user = err ? null : userPayload; // Якщо токен невалідний, то req.user = null
                if(req.user) console.log('[TryAuthMiddleware - DEV MODE] Dev token verified (or real token passed). User:', req.user);
                else console.log('[TryAuthMiddleware - DEV MODE] Dev token invalid or no token, proceeding as anonymous.');
                next();
            });
        } else { // Якщо токена взагалі немає
            req.user = null; // Або req.user = DEV_MODE_TEST_USER; залежно від потреби
            console.log('[TryAuthMiddleware - DEV MODE] No token, proceeding as anonymous (or test user).');
            next();
        }
        return; // Виходимо, щоб не виконувалася стандартна логіка
    }

    // Ваша існуюча логіка tryAuthenticateToken
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        req.user = null; return next();
    }
    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        req.user = err ? null : userPayload;
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
            console.log('[Login] Generated Access Token:', accessToken);
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
    console.log(`[API GET /api/profile] Request for user ID: ${userId}`);
    try {
        const sql = `SELECT id, email, username, uid, created_at, avatar_url FROM users WHERE id = $1`; // Додали avatar_url
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User profile not found.' });
        }
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("[API GET /api/profile] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error fetching profile.' });
    }
});

// НОВИЙ ЕНДПОІНТ: Оновлення нікнейму
app.put('/api/profile/username', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { newUsername } = req.body;
    console.log(`[API PUT /api/profile/username] User ID: ${userId}, New Username: ${newUsername}`);

    if (!newUsername || newUsername.trim().length < 3) { // Проста валідація
        return res.status(400).json({ success: false, message: 'Username must be at least 3 characters long.' });
    }

    try {
        // Перевірка, чи нікнейм вже не зайнятий іншим користувачем (якщо username UNIQUE)
        const checkSql = `SELECT id FROM users WHERE username = $1 AND id != $2`;
        const checkResult = await pool.query(checkSql, [newUsername, userId]);
        if (checkResult.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'Username already taken.' }); // 409 Conflict
        }

        const updateSql = `UPDATE users SET username = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, username, email, uid, avatar_url`;
        const result = await pool.query(updateSql, [newUsername.trim(), userId]);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found to update username.' });
        }
        // Повертаємо оновлений профіль (або тільки оновлене поле)
        // Також потрібно оновити токен, якщо username є частиною payload токена!
        const updatedUser = result.rows[0];
        const newToken = jwt.sign(
            { userId: updatedUser.id, email: updatedUser.email, username: updatedUser.username, uid: updatedUser.uid },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ success: true, message: 'Username updated successfully.', user: updatedUser, token: newToken });
    } catch (error) {
        console.error("[API PUT /api/profile/username] Error:", error);
        // Перевірка на унікальність, якщо вона не була зроблена вище
        if (error.code === '23505' && error.constraint && error.constraint.includes('username')) {
             return res.status(409).json({ success: false, message: 'Username already taken (DB constraint).' });
        }
        res.status(500).json({ success: false, message: 'Server error updating username.' });
    }
});

// НОВИЙ ЕНДПОІНТ: Оновлення URL аватара
app.put('/api/profile/avatar', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { avatarUrl } = req.body; // Очікуємо URL аватара
    console.log(`[API PUT /api/profile/avatar] User ID: ${userId}, Avatar URL: ${avatarUrl}`);

    if (avatarUrl === undefined) { // Дозволяємо порожній рядок для видалення аватара, але не undefined
        return res.status(400).json({ success: false, message: 'Avatar URL is required (can be an empty string to remove).' });
    }

    // Проста валідація URL (дуже базова)
    if (avatarUrl !== '' && !avatarUrl.startsWith('http://') && !avatarUrl.startsWith('https://')) {
        return res.status(400).json({ success: false, message: 'Invalid avatar URL format.' });
    }
    
    try {
        // Переконайтеся, що avatar_url є у SELECT
        const sql = `SELECT id, email, username, uid, created_at, avatar_url FROM users WHERE id = $1`;
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User profile not found.' });
        }
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("[API GET /api/profile] Error:", error.message, error.stack);
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

    // Переконуємося, що кеш актуальний перед тим, як його використовувати
    // Це може затримати перший запит, якщо кеш оновлюється, але забезпечить свіжі дані
    // Для кращої продуктивності, ensureMarketDataCache може працювати у фоні,
    // а тут ми просто читаємо поточний стан кешу.
    // Поки що зробимо так для простоти.
    await ensureMarketDataCache(); // Чекаємо, якщо кеш оновлюється

    try {
        let queryParams = [];
        let paramIndex = 1;
        let selectIsFavourite = `FALSE as "isFavourite"`;
        if (userId) {
            selectIsFavourite = `EXISTS (SELECT 1 FROM user_favourite_markets ufm WHERE ufm.user_id = $${paramIndex++} AND ufm.market_pair_id = mp.id) as "isFavourite"`;
            queryParams.push(userId);
        }
        // Додаємо binance_symbol, якщо він у вас є і використовується для currentMarketData з Binance WS
        const baseSelect = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name, 
                   mp.is_popular, ${selectIsFavourite}, 
                   COALESCE(mp.binance_symbol, mp.symbol) as effective_symbol_for_live_data
            FROM market_pairs mp
        `;
        let conditions = ["mp.is_active = TRUE"];
        if (popularOnly === 'true') conditions.push("mp.is_popular = TRUE");
        else if (baseAsset) {
            conditions.push(`mp.base_asset = $${paramIndex++}`);
            queryParams.push(baseAsset);
        }
        const sql = `${baseSelect} WHERE ${conditions.join(' AND ')} ORDER BY mp.display_order, mp.symbol;`; // Додав display_order для сортування
        
        const client = await pool.connect();
        let result;
        try {
            result = await client.query(sql, queryParams);
        } finally {
            client.release();
        }
        
        const marketsWithLiveData = result.rows.map(pair => {
            // Спочатку спробуємо дані з вашого `currentMarketData` (якщо це WebSocket від Binance)
            // Потім з нашого нового `marketDataCache` (який отримує дані, наприклад, з CoinGecko)
            const binanceLiveData = currentMarketData[pair.effective_symbol_for_live_data];
            const cachedExternalData = marketDataCache.data[pair.symbol]; // Ключ в кеші - це ваш mp.symbol

            let livePrice, liveChange, liveVolume;

            if (binanceLiveData && binanceLiveData.price !== undefined) {
                livePrice = binanceLiveData.price;
                liveChange = binanceLiveData.priceChangePercent;
                liveVolume = binanceLiveData.quoteVolume;
            } else if (cachedExternalData && cachedExternalData.price !== undefined) {
                livePrice = cachedExternalData.price;
                liveChange = cachedExternalData.priceChangePercent;
                // Об'єм може бути недоступний або мати іншу назву в CoinGecko
            }

            return { 
                ...pair, 
                currentPrice: livePrice !== undefined ? parseFloat(livePrice).toFixed(pair.price_precision || 2) : null, // Додав price_precision
                change24hPercent: liveChange !== undefined ? parseFloat(liveChange).toFixed(2) : null,
                volume24h: liveVolume !== undefined ? parseFloat(liveVolume).toFixed(2) : null
            };
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("[API /markets] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching markets.' });
    }
});

// --- Ендпоінти для Улюблених Ринкових Пар ---

app.get('/api/markets/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    console.log(`[API GET /api/markets/favourites] Request for user ID: ${userId}`);
    
    await ensureMarketDataCache(); // Переконуємося, що кеш актуальний

    try {
        const sql = `
            SELECT 
                mp.id, 
                mp.symbol, 
                mp.base_asset, 
                mp.quote_asset, 
                mp.name,
                COALESCE(mp.binance_symbol, mp.symbol) as effective_symbol_for_live_data,
                mp.price_precision -- Додаємо точність ціни
                -- Можна додати інші поля з market_pairs, якщо потрібно
            FROM market_pairs mp
            JOIN user_favourite_markets ufm ON mp.id = ufm.market_pair_id
            WHERE ufm.user_id = $1 AND mp.is_active = TRUE
            ORDER BY mp.symbol;
        `;
        
        const client = await pool.connect();
        let result;
        try {
            result = await client.query(sql, [userId]);
        } finally {
            client.release();
        }

        const marketsWithLiveData = result.rows.map(pair => {
            const binanceLiveData = currentMarketData[pair.effective_symbol_for_live_data];
            const cachedExternalData = marketDataCache.data[pair.symbol];
            let livePrice, liveChange;

            if (binanceLiveData && binanceLiveData.price !== undefined) {
                livePrice = binanceLiveData.price;
                liveChange = binanceLiveData.priceChangePercent;
            } else if (cachedExternalData && cachedExternalData.price !== undefined) {
                livePrice = cachedExternalData.price;
                liveChange = cachedExternalData.priceChangePercent;
            }

            return {
                ...pair,
                isFavourite: true, // Всі пари тут є улюбленими
                currentPrice: livePrice !== undefined ? parseFloat(livePrice).toFixed(pair.price_precision || 2) : null,
                change24hPercent: liveChange !== undefined ? parseFloat(liveChange).toFixed(2) : null,
            };
        });

        console.log(`[API GET /api/markets/favourites] Found ${marketsWithLiveData.length} favourite markets for user ID: ${userId}`);
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("[API GET /api/markets/favourites] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error fetching favourite markets.' });
    }
});

// ДОДАВАННЯ ПАРИ ДО УЛЮБЛЕНИХ
app.post('/api/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { marketPairId } = req.body; // Очікуємо ID пари з market_pairs
    console.log(`[API POST /api/favourites] User ID: ${userId}, Attempting to add MarketPairID: ${marketPairId}`);

    if (!marketPairId || isNaN(parseInt(marketPairId))) {
        return res.status(400).json({ success: false, message: 'Valid Market Pair ID is required.' });
    }
    const parsedMarketPairId = parseInt(marketPairId, 10);

    try {
        // Перевіряємо, чи існує така пара в market_pairs
        const pairCheckSql = `SELECT id FROM market_pairs WHERE id = $1 AND is_active = TRUE`;
        const pairCheckResult = await pool.query(pairCheckSql, [parsedMarketPairId]);
        if (pairCheckResult.rows.length === 0) {
            console.log(`[API POST /api/favourites] Active market pair with ID ${parsedMarketPairId} not found.`);
            return res.status(404).json({ success: false, message: 'Active market pair not found.' });
        }

        // Додаємо до улюблених, ON CONFLICT нічого не робить, якщо вже існує
        const sql = `
            INSERT INTO user_favourite_markets (user_id, market_pair_id) 
            VALUES ($1, $2) 
            ON CONFLICT (user_id, market_pair_id) DO NOTHING 
            RETURNING *; 
        `;
        // Використовуємо RETURNING * щоб перевірити, чи був вставлений новий запис
        const result = await pool.query(sql, [userId, parsedMarketPairId]);

        if (result.rows.length > 0) {
            console.log(`[API POST /api/favourites] Market pair ${parsedMarketPairId} added to favourites for user ${userId}`);
            res.status(201).json({ success: true, message: 'Market pair added to favourites.', favourite: result.rows[0] });
        } else {
            console.log(`[API POST /api/favourites] Market pair ${parsedMarketPairId} was already in favourites for user ${userId}`);
            res.status(200).json({ success: true, message: 'Market pair was already in favourites.' });
        }
    } catch (error) {
        console.error("[API POST /api/favourites] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error adding to favourites.' });
    }
});

// ВИДАЛЕННЯ ПАРИ З УЛЮБЛЕНИХ
app.delete('/api/favourites/:marketPairId', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const marketPairId = parseInt(req.params.marketPairId, 10);
    console.log(`[API DELETE /api/favourites] User ID: ${userId}, Attempting to remove MarketPairID: ${marketPairId}`);

    if (isNaN(marketPairId)) {
        return res.status(400).json({ success: false, message: 'Invalid Market Pair ID.' });
    }

    try {
        const sql = `DELETE FROM user_favourite_markets WHERE user_id = $1 AND market_pair_id = $2 RETURNING *`;
        const result = await pool.query(sql, [userId, marketPairId]);

        if (result.rowCount > 0) { // rowCount показує кількість видалених рядків
            console.log(`[API DELETE /api/favourites] Market pair ${marketPairId} removed from favourites for user ${userId}`);
            res.status(200).json({ success: true, message: 'Market pair removed from favourites.' });
        } else {
            console.log(`[API DELETE /api/favourites] Favourite market pair ${marketPairId} not found for user ${userId} or already removed`);
            res.status(404).json({ success: false, message: 'Favourite market pair not found or already removed.' });
        }
    } catch (error) {
        console.error("[API DELETE /api/favourites] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error removing from favourites.' });
    }
});


// --- Ендпоінти для Ордерів ---

// ОТРИМАННЯ ВІДКРИТИХ ОРДЕРІВ КОРИСТУВАЧА
app.get('/api/orders/open', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    console.log(`[API GET /api/orders/open] Request for user ID: ${userId}`);
    try {
        const sql = `
            SELECT 
                id, 
                pair, 
                type, 
                side, 
                price, 
                amount, 
                filled_amount_base, 
                (price * amount) as total_value, -- Загальна вартість ордера (якщо ціна є)
                created_at, 
                status 
            FROM orders 
            WHERE user_id = $1 AND status = 'open' -- Можна додати 'partially_filled', якщо це вважається відкритим
            ORDER BY created_at DESC;
        `;
        const result = await pool.query(sql, [userId]);
        console.log(`[API GET /api/orders/open] Found ${result.rows.length} open orders for user ID: ${userId}`);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("[API GET /api/orders/open] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error fetching open orders.' });
    }
});

// ОТРИМАННЯ ІСТОРІЇ ОРДЕРІВ КОРИСТУВАЧА (з фільтрацією)
app.get('/api/orders/history', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { dateFrom, dateTo, pair, type, side } = req.query; // Отримуємо параметри фільтра
    console.log(`[API GET /api/orders/history] Request for user ID: ${userId}, Filters:`, req.query);

    let queryParams = [userId];
    // Статуси, які вважаються історією
    let conditions = ["o.user_id = $1", "o.status IN ('filled', 'canceled', 'partially_filled')"]; 
    let paramIndex = 2; // Починаємо індексацію параметрів з $2 ($1 - це userId)

    if (dateFrom) {
        conditions.push(`o.created_at >= $${paramIndex++}`);
        queryParams.push(dateFrom); // Формат 'YYYY-MM-DD'
    }
    if (dateTo) {
        // Щоб включити весь день dateTo, ми беремо початок наступного дня
        const nextDay = new Date(dateTo);
        nextDay.setDate(nextDay.getDate() + 1);
        conditions.push(`o.created_at < $${paramIndex++}`);
        queryParams.push(nextDay.toISOString().split('T')[0]); // 'YYYY-MM-DD'
    }
    if (pair) {
        conditions.push(`o.pair ILIKE $${paramIndex++}`); // ILIKE для пошуку без урахування регістру
        queryParams.push(`%${pair}%`); // Шукаємо входження
    }
    if (type && ['limit', 'market'].includes(type.toLowerCase())) { // Валідація типу
        conditions.push(`o.type = $${paramIndex++}`);
        queryParams.push(type.toLowerCase());
    }
    if (side && ['buy', 'sell'].includes(side.toLowerCase())) { // Валідація сторони
        conditions.push(`o.side = $${paramIndex++}`);
        queryParams.push(side.toLowerCase());
    }
    
    const conditionsStr = conditions.join(' AND ');

    try {
        const sql = `
            SELECT 
                o.id, 
                o.pair, 
                o.type, 
                o.side, 
                o.avg_fill_price, 
                o.filled_amount_base, 
                o.amount, 
                (o.avg_fill_price * o.filled_amount_base) as total_executed_value, -- Загальна вартість виконаної частини
                o.status, 
                o.created_at 
            FROM orders o
            WHERE ${conditionsStr}
            ORDER BY o.created_at DESC;
        `;
        console.log(`[API GET /api/orders/history] SQL: ${sql} PARAMS: ${JSON.stringify(queryParams)}`);
        const result = await pool.query(sql, queryParams);
        console.log(`[API GET /api/orders/history] Found ${result.rows.length} orders in history for user ID: ${userId} with current filters.`);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("[API GET /api/orders/history] Error:", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error fetching order history.' });
    }
});

const axios = require('axios'); // Популярна бібліотека для HTTP запитів

// --- Глобальні змінні та кеш ---
let marketDataCache = { // Простий in-memory кеш
    data: {},           // Тут будуть дані { 'BTC/USDT': { price: ..., change24h: ... }, ... }
    lastUpdated: 0,
    cacheDuration: 5 * 60 * 1000 // 5 хвилин в мілісекундах
};

const COINGECKO_IDS_MAP = { // Мапінг ваших символів на CoinGecko IDs
    'BTC': 'bitcoin',
    'ETH': 'ethereum',
    'USDT': 'tether', // Потрібен, якщо ви десь використовуєте USDT як базовий актив для запиту
    'BNB': 'binancecoin',
    'SOL': 'solana',
    'XRP': 'ripple',
    'ADA': 'cardano',
    'DOGE': 'dogecoin',
    'AVAX': 'avalanche-2',
    'DOT': 'polkadot',
    'TRX': 'tron',
    'SHIB': 'shiba-inu',
    'MATIC': 'matic-network', // або 'polygon-pos' - перевірте актуальний ID на CoinGecko
    'LTC': 'litecoin',
    'LINK': 'chainlink',
    'UNI': 'uniswap',
    'ATOM': 'cosmos',
    'NEAR': 'near',
    'FTM': 'fantom',
    'ICP': 'internet-computer',
    'ETC': 'ethereum-classic',
    'XLM': 'stellar',
    'ALGO': 'algorand',
    'VET': 'vechain',
    'FIL': 'filecoin',
    'HBAR': 'hedera-hashgraph', // Або 'hedera'
    'EOS': 'eos',
    'AAVE': 'aave',
    'XTZ': 'tezos',
    'SAND': 'the-sandbox',
    'MANA': 'decentraland',
    'AXS': 'axie-infinity',
    'THETA': 'theta-token',
    'GRT': 'the-graph',
    'EGLD': 'elrond-erd-2', // Або 'multiversx'
    'MKR': 'maker',
    'KSM': 'kusama',
    'WAVES': 'waves',
    'ZEC': 'zcash',
    'DASH': 'dash',
    'NEO': 'neo',
    'CHZ': 'chiliz',
    'ENJ': 'enjincoin',
    'COMP': 'compound-governance-token',
    'SNX': 'havven', // Або 'synthetix-network-token'
    'SUSHI': 'sushi',
    'YFI': 'yearn-finance',
    'APT': 'aptos',
    'ARB': 'arbitrum',
    'OP': 'optimism',
    'SUI': 'sui',
    'PEPE': 'pepe',
    'FET': 'fetch-ai',
    'RNDR': 'render-token',
    'INJ': 'injective-protocol', // Або 'injective'
    'TIA': 'celestia',
    'IMX': 'immutable-x',
    'GALA': 'gala',
    'MINA': 'mina-protocol',
    'FLOW': 'flow',
    'CRV': 'curve-dao-token',
    'LDO': 'lido-dao',
    'RUNE': 'thorchain',
    'CAKE': 'pancakeswap-token',
    'DYDX': 'dydx',
    '1INCH': '1inch',
    'APE': 'apecoin',
    'STX': 'stacks', // Раніше був 'blockstack'
    'SEI': 'sei-network', // Або 'sei'
    'FLOKI': 'floki',
    'BONK': 'bonk',
    'TWT': 'trust-wallet-token',
    'QNT': 'quant-network',
    'KAS': 'kaspa',
    'ORDI': 'ordinals',
    'WLD': 'worldcoin-wld',
    'PYTH': 'pyth-network',
    'ROSE': 'oasis-network',
    'ONE': 'harmony',
    'CELO': 'celo',
    'KAVA': 'kava',
    'ZIL': 'zilliqa',
    'GMT': 'stepn',
    'JASMY': 'jasmycoin', // Або 'jasmy'
    'WOO': 'woo-network',
};

// Функція для отримання даних з CoinGecko для списку пар
async function fetchExternalMarketData(baseAssetsToFetch) { // baseAssetsToFetch - це масив типу ['BTC', 'ETH', ...]
    console.log(`[ExternalData] Attempting to fetch market data for ${baseAssetsToFetch.length} key base assets: ${baseAssetsToFetch.join(', ')}`);
    const idsToFetch = new Set();
    const cgIdToSymbolMap = {}; // Ключ - coingecko_id ('bitcoin'), значення - наш символ ('BTC')

    baseAssetsToFetch.forEach(baseAssetSymbol => {
        const baseAssetUpper = baseAssetSymbol.toUpperCase();
        const cgId = COINGECKO_IDS_MAP[baseAssetUpper];
        if (cgId) {
            idsToFetch.add(cgId);
            cgIdToSymbolMap[cgId] = baseAssetUpper; // Наприклад, cgIdToSymbolMap['bitcoin'] = 'BTC'
        } else {
            console.warn(`[ExternalData] No CoinGecko ID found for key base asset: ${baseAssetUpper} in COINGECKO_IDS_MAP.`);
        }
    });

    if (idsToFetch.size === 0) {
        console.log('[ExternalData] No valid CoinGecko IDs to fetch from key base assets list.');
        return {};
    }

    const idsQueryParam = Array.from(idsToFetch).join(',');
    const vsCurrency = 'usd'; // Завжди запитуємо ціни відносно USD
    const coingeckoUrl = `https://api.coingecko.com/api/v3/simple/price?ids=${idsQueryParam}&vs_currencies=${vsCurrency}&include_24hr_change=true`;
    console.log(`[ExternalData] CoinGecko request URL: ${coingeckoUrl}`);

    try {
        const response = await axios.get(coingeckoUrl);
        const coingeckoData = response.data;
        const processedData = {}; // Ключ - символ базового активу ('BTC', 'ETH'), значення - { price, change }

        for (const cgId in coingeckoData) {
            if (coingeckoData.hasOwnProperty(cgId) && cgIdToSymbolMap[cgId]) {
                const baseAssetSymbol = cgIdToSymbolMap[cgId]; // Отримуємо наш символ, наприклад 'BTC'
                const dataForCgId = coingeckoData[cgId];

                if (dataForCgId && dataForCgId[vsCurrency] !== undefined) {
                    // Тепер ми записуємо дані для базового активу (наприклад, 'BTC')
                    // в processedData. Ключем буде сам символ базового активу.
                    processedData[baseAssetSymbol] = {
                        price: dataForCgId[vsCurrency],
                        priceChangePercent: dataForCgId[`${vsCurrency}_24h_change`]
                        // Можна додати інші поля, якщо API їх повертає і вони потрібні
                    };
                } else {
                    console.warn(`[ExternalData] No price data for ${vsCurrency} found for cgId: ${cgId} (mapped to ${baseAssetSymbol})`);
                }
            }
        }
        console.log(`[ExternalData] Successfully fetched and processed data for ${Object.keys(processedData).length} key base assets. Sample:`, JSON.stringify(Object.entries(processedData).slice(0,2), null, 2));
        return processedData;
    } catch (error) {
        // Лог помилки тепер тут, щоб бачити, що саме викликало проблему
        console.error('[ExternalData] Error during fetching from CoinGecko:', error.message);
        if (error.response) {
            console.error('[ExternalData] CoinGecko Response Status:', error.response.status);
            console.error('[ExternalData] CoinGecko Response Data:', JSON.stringify(error.response.data, null, 2));
            if (error.response.status === 429) {
                console.warn('[ExternalData] CoinGecko API rate limit hit. Request was for: ' + idsQueryParam);
            }
        } else if (error.request) {
            console.error('[ExternalData] No response received from CoinGecko. Request was for: ' + idsQueryParam);
        } else {
            console.error('[ExternalData] Error setting up CoinGecko request:', error.message);
        }
        return {}; // Повертаємо порожній об'єкт у разі помилки
    }
}


async function ensureMarketDataCache(forceUpdate = false) {
    const now = Date.now();
    if (forceUpdate || !marketDataCache.lastUpdated || (now - marketDataCache.lastUpdated > marketDataCache.cacheDuration)) {
        console.log('[Cache] Market data cache is stale or missing. Updating...');
        try {
            // Отримуємо всі активні пари з БД для формування запиту до CoinGecko
            const client = await pool.connect();
            let activePairs = [];
            try {
                const result = await client.query("SELECT symbol, base_asset, quote_asset FROM market_pairs WHERE is_active = TRUE");
                activePairs = result.rows;
            } finally {
                client.release();
            }

            if (activePairs.length > 0) {
                const externalData = await fetchExternalMarketData(activePairs);
                if (Object.keys(externalData).length > 0) {
                    marketDataCache.data = externalData;
                    marketDataCache.lastUpdated = now;
                    console.log('[Cache] Market data cache updated successfully.');
                } else {
                    console.warn('[Cache] Failed to update market data cache from external source. Old data might be used.');
                    // Не оновлюємо lastUpdated, щоб спробувати ще раз при наступному запиті
                }
            } else {
                console.log('[Cache] No active market pairs found to update cache.');
                marketDataCache.data = {}; // Очищаємо, якщо немає активних пар
                marketDataCache.lastUpdated = now;
            }
        } catch (error) {
            console.error('[Cache] Error during market data cache update process:', error);
            // Також не оновлюємо lastUpdated
        }
    } else {
        console.log('[Cache] Market data cache is fresh.');
    }
}

// Викликаємо оновлення кешу при старті сервера і періодично
ensureMarketDataCache(true); // Примусове оновлення при старті
setInterval(() => ensureMarketDataCache(), marketDataCache.cacheDuration); // Періодичне оновлення



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
