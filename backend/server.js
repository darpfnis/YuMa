const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios'); 
const cron = require('node-cron');


const app = express();
const port = process.env.PORT || 3000;

// --- Конфігурація та змінні середовища ---
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-and-secret-key-for-jwt-yuma-v3-final-final-final-please-change';
if (JWT_SECRET === 'your-very-strong-and-secret-key-for-jwt-yuma-v3-final-final-final-please-change' && process.env.NODE_ENV === 'production') {
    console.warn('\x1b[31m%s\x1b[0m', 'WARNING: JWT_SECRET is using a default insecure value in production! Please set a strong JWT_SECRET environment variable.');
}

const connectionString = process.env.DATABASE_URL;
if (!connectionString && process.env.NODE_ENV === 'production') { // Лише критично для продакшена
    console.error('\x1b[31m%s\x1b[0m', 'FATAL ERROR: DATABASE_URL environment variable is not set in production.');
    process.exit(1);
} else if (!connectionString) {
    // Для локальної розробки, якщо DATABASE_URL не встановлено, можна тут тимчасово задати:
    // connectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_database_name";
    console.warn('\x1b[33m%s\x1b[0m', "DATABASE_URL not set. Ensure it's configured for production or local development if needed.");
    // Можливо, не варто виходити, якщо це локальна розробка без потреби в БД на старті
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('connect', (client) => {
    console.log('PostgreSQL pool: New client connected to the database.');
    client.on('error', err => {
        console.error('PostgreSQL client error within pool:', err);
    });
});
pool.on('error', (err, client) => {
    console.error('Unexpected error on idle PostgreSQL client in pool', err);
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..'); // Для index.html в корені
app.use('/frontend', express.static(frontendPath));


// --- Режим розробки (вимкнення автентифікації) ---
const DEV_MODE_SKIP_AUTH = process.env.NODE_ENV !== 'production' && false; // Встановіть в true для вимкнення, false для увімкнення
const DEV_MODE_TEST_USER = { // Тестовий користувач, якщо автентифікація вимкнена
    userId: 1, // ID існуючого тестового користувача у вашій БД (важливо!)
    email: 'devtest@example.com',
    username: 'dev_tester',
    uid: 'DEVUID123'
};

if (DEV_MODE_SKIP_AUTH) {
    console.warn('\x1b[33m%s\x1b[0m', '[DEV MODE] Authentication is SKIPPED. All authenticated routes will use DEV_MODE_TEST_USER.');
}

// --- Middleware автентифікації ---
const authenticateToken = (req, res, next) => {
    if (DEV_MODE_SKIP_AUTH) {
        req.user = DEV_MODE_TEST_USER;
        return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Token missing.' });

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.warn(`[Auth] Token verification failed: ${err.name} - ${err.message}`);
            return res.status(403).json({ success: false, message: 'Token invalid or expired.', errorType: err.name });
        }
        req.user = userPayload;
        next();
    });
};

const tryAuthenticateToken = (req, res, next) => {
    if (DEV_MODE_SKIP_AUTH) {
        // У режимі розробки, tryAuthenticate може або завжди встановлювати тестового користувача,
        // або імітувати анонімного користувача, якщо токен не передано.
        // Для простоти, якщо DEV_MODE_SKIP_AUTH=true, зробимо його схожим на authenticateToken.
        // req.user = DEV_MODE_TEST_USER; 
        // Або, щоб tryAuthenticate працював більш реалістично:
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token) {
             jwt.verify(token, JWT_SECRET, (err, userPayload) => {
                req.user = err ? null : userPayload;
                if(req.user) console.log('[TryAuth - DEV MODE] Token (dev or real) verified. User:', req.user.username);
                else console.log('[TryAuth - DEV MODE] Token (dev or real) invalid, proceeding as anonymous.');
                next();
            });
        } else {
            req.user = null; // Якщо токен не передано, користувач анонімний
            console.log('[TryAuth - DEV MODE] No token, proceeding as anonymous.');
            next();
        }
        return;
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        req.user = null;
        return next();
    }
    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        req.user = err ? null : userPayload;
        next();
    });
};

// --- Дані ринків та WebSocket (Заглушка, реалізуйте підключення) ---
const INITIAL_ASSETS = ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'XRP', 'ADA', 'DOGE']; // YMC - ваша монета
let currentMarketData = {}; // Оновлюється з WebSocket Binance

// TODO: Реалізувати підключення до Binance WebSocket
const WebSocket = require('ws');
function connectToBinanceMarketStreams() {
console.log("Attempting to connect to Binance WebSocket streams...");
const ws = new WebSocket('wss://stream.binance.com:9443/ws/btcusdt@ticker/ethusdt@ticker');
ws.on('message', (data) => {
const ticker = JSON.parse(data);
currentMarketData[ticker.s] = { // s - symbol, c - last price, P - price change percent, q - quote volume
price: ticker.c,
priceChangePercent: ticker.P,
quoteVolume: ticker.q,
};
});
ws.on('error', (error) => console.error('Binance WebSocket error:', error));
ws.on('close', () => console.log('Binance WebSocket connection closed. Reconnecting...')); // Додати логіку перепідключення
}
if (process.env.NODE_ENV !== 'test') { // Не запускати WS під час тестів, якщо вони є
connectToBinanceMarketStreams();
 console.warn("\x1b[33m%s\x1b[0m", "Binance WebSocket connection is currently commented out. `currentMarketData` will be empty.");
}


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
        const username = name || email.split('@')[0]; // Використовуємо name, якщо є, інакше частина email

        const userSql = `INSERT INTO users (email, username, uid, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, email, username, uid`;
        const userResult = await client.query(userSql, [email.toLowerCase(), username, userUid, hashedPassword]);
        const newUser = userResult.rows[0];

        const assetPromises = INITIAL_ASSETS.map(assetSymbol => {
            const assetSql = `INSERT INTO assets (user_id, coin_symbol, total_balance, available_balance, in_order_balance) VALUES ($1, $2, 0, 0, 0) ON CONFLICT (user_id, coin_symbol) DO NOTHING`;
            return client.query(assetSql, [newUser.id, assetSymbol]);
        });
        await Promise.all(assetPromises);

        await client.query('COMMIT');
        console.log(`[Register] User ${newUser.username} (ID: ${newUser.id}) registered successfully.`);
        res.status(201).json({ success: true, message: 'User registered successfully! Initial assets created.', user: { id: newUser.id, email: newUser.email, username: newUser.username, uid: newUser.uid } });
    } catch (error) {
        await client.query('ROLLBACK');
        if (error.code === '23505') { // Код помилки для порушення унікальності
            const field = error.constraint.includes('email') ? 'Email' : error.constraint.includes('username') ? 'Username' : 'Field';
            console.warn(`[Register] Attempt to register with existing ${field.toLowerCase()}: ${email}/${name}`);
            return res.status(409).json({ success: false, message: `${field} already exists.` });
        }
        console.error("[Register] Error:", error);
        res.status(500).json({ success: false, message: 'Failed to register user.' });
    } finally {
        client.release();
    }
});

app.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body; // identifier може бути email або username
    if (!identifier || !password) return res.status(400).json({ success: false, message: 'Identifier and password are required.' });

    const sql = `SELECT id, email, username, uid, password_hash FROM users WHERE email = $1 OR username = $1`;
    try {
        const result = await pool.query(sql, [identifier.toLowerCase()]); // Шукаємо по email в нижньому регістрі
        const user = result.rows[0];
        if (!user) {
            console.warn(`[Login] User not found for identifier: ${identifier}`);
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            const accessToken = jwt.sign(
                { userId: user.id, email: user.email, username: user.username, uid: user.uid },
                JWT_SECRET,
                { expiresIn: '1h' } // Тривалість життя токена
            );
            console.log(`[Login] User ${user.username} (ID: ${user.id}) logged in successfully.`);
            res.status(200).json({
                success: true, message: 'Login successful!', token: accessToken,
                user: { id: user.id, email: user.email, username: user.username, uid: user.uid }
            });
        } else {
            console.warn(`[Login] Invalid password attempt for user: ${user.username} (ID: ${user.id})`);
            res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error("[Login] Error:", error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

app.post('/auth/logout', (req, res) => {
    // Тут немає потреби в authenticateToken, оскільки логаут - це дія клієнта
    console.log('[Logout] User logout request received.');
    res.status(200).json({ success: true, message: 'Logged out (client should clear token).' });
});


// ПРОФІЛЬ, АКТИВИ, РИНКИ, ОРДЕРИ
app.get('/api/profile', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, email, username, uid, created_at, avatar_url FROM users WHERE id = $1`;
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) {
            console.warn(`[API GET /api/profile] Profile not found for user ID: ${userId}`);
            return res.status(404).json({ success: false, message: 'User profile not found.' });
        }
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("[API GET /api/profile] Error:", error.message);
        res.status(500).json({ success: false, message: 'Server error fetching profile.' });
    }
});

app.put('/api/profile/username', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { newUsername } = req.body;

    if (!newUsername || newUsername.trim().length < 3 || newUsername.trim().length > 30) {
        return res.status(400).json({ success: false, message: 'Username must be between 3 and 30 characters long.' });
    }
    const trimmedUsername = newUsername.trim();

    try {
        const checkSql = `SELECT id FROM users WHERE username = $1 AND id != $2`;
        const checkResult = await pool.query(checkSql, [trimmedUsername, userId]);
        if (checkResult.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'Username already taken.' });
        }

        const updateSql = `UPDATE users SET username = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, username, email, uid, avatar_url`;
        const result = await pool.query(updateSql, [trimmedUsername, userId]);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found to update username.' });
        }
        const updatedUser = result.rows[0];
        const newToken = jwt.sign( // Перегенерувати токен з новим username
            { userId: updatedUser.id, email: updatedUser.email, username: updatedUser.username, uid: updatedUser.uid },
            JWT_SECRET, { expiresIn: '1h' }
        );
        console.log(`[API PUT /api/profile/username] Username for user ID ${userId} updated to ${trimmedUsername}`);
        res.json({ success: true, message: 'Username updated successfully.', user: updatedUser, token: newToken });
    } catch (error)

    {
        console.error("[API PUT /api/profile/username] Error:", error);
        if (error.code === '23505' && error.constraint && error.constraint.includes('username')) {
             return res.status(409).json({ success: false, message: 'Username already taken (DB constraint).' });
        }
        res.status(500).json({ success: false, message: 'Server error updating username.' });
    }
});

app.put('/api/profile/avatar', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { avatarUrl } = req.body;

    if (avatarUrl === undefined) {
        return res.status(400).json({ success: false, message: 'Avatar URL is required (can be an empty string to remove).' });
    }

    if (avatarUrl !== '' && !(avatarUrl.startsWith('http://') || avatarUrl.startsWith('https://'))) {
        // Можна додати більш строгу валідацію URL
        return res.status(400).json({ success: false, message: 'Invalid avatar URL format.' });
    }
    
    try {
        const sql = `UPDATE users SET avatar_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, username, email, uid, avatar_url`;
        const result = await pool.query(sql, [avatarUrl, userId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found to update avatar.' });
        }
        console.log(`[API PUT /api/profile/avatar] Avatar for user ID ${userId} updated.`);
        res.json({ success: true, message: 'Avatar updated successfully.', user: result.rows[0] });
    } catch (error) {
        console.error("[API PUT /api/profile/avatar] Error:", error);
        res.status(500).json({ success: false, message: 'Server error updating avatar.' });
    }
});

app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    let totalUSDEquivalent = 0;
    try {
        await ensureMarketDataCache(); // Переконуємось, що кеш цін актуальний
        const assetsSql = `SELECT coin_symbol, total_balance FROM assets WHERE user_id = $1`;
        const assetsResult = await pool.query(assetsSql, [userId]);

        for (const asset of assetsResult.rows) {
            let priceInUSD = 0;
            const assetSymbolUpper = asset.coin_symbol.toUpperCase();

            if (['USDT', 'USDC', 'BUSD', 'USD'].includes(assetSymbolUpper)) { // Додав USD для гнучкості
                priceInUSD = 1;
            } else {
                // Спочатку шукаємо в `currentMarketData` (Binance WS)
                const binancePairSymbolUSDT = `${assetSymbolUpper}USDT`; // Припускаємо, що Binance має пару до USDT
                if (currentMarketData[binancePairSymbolUSDT] && currentMarketData[binancePairSymbolUSDT].price) {
                    priceInUSD = parseFloat(currentMarketData[binancePairSymbolUSDT].price);
                } else {
                    // Якщо немає в Binance, шукаємо в кеші CoinGecko
                    // Ключ в marketDataCache.data - це символ пари, наприклад 'BTCUSDT'
                    // Нам потрібна ціна базового активу (assetSymbolUpper) відносно USDT
                    const coingeckoPairSymbol = `${assetSymbolUpper}USDT`; // Припускаємо, що нам потрібна ця пара
                    if (marketDataCache.data[coingeckoPairSymbol] && marketDataCache.data[coingeckoPairSymbol].price) {
                        priceInUSD = parseFloat(marketDataCache.data[coingeckoPairSymbol].price);
                    } else if (COINGECKO_IDS_MAP[assetSymbolUpper] && marketDataCache.data[COINGECKO_IDS_MAP[assetSymbolUpper]] && marketDataCache.data[COINGECKO_IDS_MAP[assetSymbolUpper]].price){
                        // Якщо в кеші ціни зберігаються за cgID, а не за символом пари
                        // І ціна там відносно USD
                        priceInUSD = parseFloat(marketDataCache.data[COINGECKO_IDS_MAP[assetSymbolUpper]].price);
                    }
                }
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
        await ensureMarketDataCache();
        // LEFT JOIN для отримання name, якщо це base_asset в якійсь парі, або сам символ (для USDT, YMC)
        const sql = `
            SELECT 
                a.id, 
                a.coin_symbol, 
                COALESCE(mp_direct.name, mp_base.name, a.coin_symbol) as coin_name,
                a.total_balance, 
                a.available_balance, 
                a.in_order_balance
            FROM assets a
            LEFT JOIN market_pairs mp_direct ON UPPER(a.coin_symbol) = UPPER(mp_direct.symbol) AND mp_direct.is_active = TRUE
            LEFT JOIN market_pairs mp_base ON UPPER(a.coin_symbol) = UPPER(mp_base.base_asset) AND mp_base.is_active = TRUE AND mp_base.quote_asset = 'USDT' -- Пріоритет для пари до USDT
            WHERE a.user_id = $1
            GROUP BY a.id, a.coin_symbol, coin_name, a.total_balance, a.available_balance, a.in_order_balance -- Додав GROUP BY
            ORDER BY a.coin_symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const assetsWithDetails = result.rows.map(asset => {
            let valueInUSD = 0;
            const assetSymbolUpper = asset.coin_symbol.toUpperCase();
             if (['USDT', 'USDC', 'BUSD', 'USD'].includes(assetSymbolUpper)) {
                valueInUSD = parseFloat(asset.total_balance);
            } else {
                const binancePairSymbolUSDT = `${assetSymbolUpper}USDT`;
                if (currentMarketData[binancePairSymbolUSDT] && currentMarketData[binancePairSymbolUSDT].price) {
                    valueInUSD = parseFloat(asset.total_balance) * parseFloat(currentMarketData[binancePairSymbolUSDT].price);
                } else {
                    const coingeckoPairSymbol = `${assetSymbolUpper}USDT`;
                    if (marketDataCache.data[coingeckoPairSymbol] && marketDataCache.data[coingeckoPairSymbol].price) {
                        valueInUSD = parseFloat(asset.total_balance) * parseFloat(marketDataCache.data[coingeckoPairSymbol].price);
                    } else if (COINGECKO_IDS_MAP[assetSymbolUpper] && marketDataCache.data[COINGECKO_IDS_MAP[assetSymbolUpper]] && marketDataCache.data[COINGECKO_IDS_MAP[assetSymbolUpper]].price){
                        valueInUSD = parseFloat(asset.total_balance) * parseFloat(marketDataCache.data[COINGECKO_IDS_MAP[assetSymbolUpper]].price);
                    }
                }
            }
            return {
                ...asset,
                total_balance: parseFloat(asset.total_balance).toFixed(8), // Можливо, потрібна різна точність для різних монет
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

    await ensureMarketDataCache(); 

    try {
        let queryParams = [];
        let paramIndex = 1;
        let selectIsFavourite = `FALSE as "isFavourite"`;
        if (userId) {
            selectIsFavourite = `EXISTS (SELECT 1 FROM user_favourite_markets ufm WHERE ufm.user_id = $${paramIndex++} AND ufm.market_pair_id = mp.id) as "isFavourite"`;
            queryParams.push(userId);
        }
        
        const baseSelect = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name, 
                   mp.is_popular, ${selectIsFavourite}, 
                   COALESCE(mp.binance_symbol, mp.symbol) as effective_symbol_for_live_data,
                   mp.price_precision, mp.quantity_precision
            FROM market_pairs mp
        `;
        let conditions = ["mp.is_active = TRUE"];
        if (popularOnly === 'true') {
            conditions.push("mp.is_popular = TRUE");
        } else if (baseAsset) { // baseAsset використовується тільки якщо popularOnly не 'true'
            conditions.push(`mp.base_asset = $${paramIndex++}`);
            queryParams.push(baseAsset);
        }
        const sql = `${baseSelect} WHERE ${conditions.join(' AND ')} ORDER BY mp.display_order, mp.symbol;`;
        
        const result = await pool.query(sql, queryParams);
        
        const marketsWithLiveData = result.rows.map(pair => {
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
                // Поки що не беремо об'єм з CoinGecko тут, щоб не ускладнювати
            }
            console.log(`Pair: ${pair.symbol}, BinancePrice: ${binanceLiveData?.price}, CachedPrice: ${cachedExternalData?.price}, FinalPrice: ${livePrice}`);

            return { 
                ...pair, 
                currentPrice: livePrice !== undefined ? parseFloat(livePrice).toFixed(pair.price_precision || 2) : null,
                change24hPercent: liveChange !== undefined ? parseFloat(liveChange).toFixed(2) : null,
                volume24h: liveVolume !== undefined ? parseFloat(liveVolume).toFixed(2) : null // Тільки з Binance WS
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
    await ensureMarketDataCache();
    try {
        const sql = `
            SELECT 
                mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name,
                COALESCE(mp.binance_symbol, mp.symbol) as effective_symbol_for_live_data,
                mp.price_precision, mp.quantity_precision
            FROM market_pairs mp
            JOIN user_favourite_markets ufm ON mp.id = ufm.market_pair_id
            WHERE ufm.user_id = $1 AND mp.is_active = TRUE
            ORDER BY mp.symbol;
        `;
        const result = await pool.query(sql, [userId]);
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
                isFavourite: true,
                currentPrice: livePrice !== undefined ? parseFloat(livePrice).toFixed(pair.price_precision || 2) : null,
                change24hPercent: liveChange !== undefined ? parseFloat(liveChange).toFixed(2) : null,
            };
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("[API GET /api/markets/favourites] Error:", error.message);
        res.status(500).json({ success: false, message: 'Server error fetching favourite markets.' });
    }
});

app.post('/api/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { marketPairId } = req.body;
    if (!marketPairId || isNaN(parseInt(marketPairId))) {
        return res.status(400).json({ success: false, message: 'Valid Market Pair ID is required.' });
    }
    const parsedMarketPairId = parseInt(marketPairId, 10);
    try {
        const pairCheckSql = `SELECT id FROM market_pairs WHERE id = $1 AND is_active = TRUE`;
        const pairCheckResult = await pool.query(pairCheckSql, [parsedMarketPairId]);
        if (pairCheckResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Active market pair not found.' });
        }
        const sql = `INSERT INTO user_favourite_markets (user_id, market_pair_id) VALUES ($1, $2) ON CONFLICT (user_id, market_pair_id) DO NOTHING RETURNING *;`;
        const result = await pool.query(sql, [userId, parsedMarketPairId]);
        if (result.rows.length > 0) {
            res.status(201).json({ success: true, message: 'Market pair added to favourites.', favourite: result.rows[0] });
        } else {
            res.status(200).json({ success: true, message: 'Market pair was already in favourites.' });
        }
    } catch (error) {
        console.error("[API POST /api/favourites] Error:", error.message);
        res.status(500).json({ success: false, message: 'Server error adding to favourites.' });
    }
});

app.delete('/api/favourites/:marketPairId', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const marketPairId = parseInt(req.params.marketPairId, 10);
    if (isNaN(marketPairId)) {
        return res.status(400).json({ success: false, message: 'Invalid Market Pair ID.' });
    }
    try {
        const sql = `DELETE FROM user_favourite_markets WHERE user_id = $1 AND market_pair_id = $2 RETURNING *`;
        const result = await pool.query(sql, [userId, marketPairId]);
        if (result.rowCount > 0) {
            res.status(200).json({ success: true, message: 'Market pair removed from favourites.' });
        } else {
            res.status(404).json({ success: false, message: 'Favourite market pair not found or already removed.' });
        }
    } catch (error) {
        console.error("[API DELETE /api/favourites] Error:", error.message);
        res.status(500).json({ success: false, message: 'Server error removing from favourites.' });
    }
});

// --- Ендпоінти для Ордерів (приклад, розширте за потребою) ---
app.get('/api/orders/open', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, pair, type, side, price, amount, filled_amount_base, (price * amount) as total_value, created_at, status FROM orders WHERE user_id = $1 AND status IN ('open', 'partially_filled') ORDER BY created_at DESC;`;
        const result = await pool.query(sql, [userId]);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("[API GET /api/orders/open] Error:", error.message);
        res.status(500).json({ success: false, message: 'Server error fetching open orders.' });
    }
});

app.get('/api/orders/history', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { dateFrom, dateTo, pair, type, side } = req.query;
    let queryParams = [userId];
    let conditions = ["o.user_id = $1", "o.status IN ('filled', 'canceled', 'partially_filled_and_canceled')"]; // Розширте статуси за потребою
    let paramIndex = 2;

    if (dateFrom) { conditions.push(`o.created_at >= $${paramIndex++}`); queryParams.push(dateFrom); }
    if (dateTo) { const nextDay = new Date(dateTo); nextDay.setDate(nextDay.getDate() + 1); conditions.push(`o.created_at < $${paramIndex++}`); queryParams.push(nextDay.toISOString().split('T')[0]); }
    if (pair) { conditions.push(`o.pair ILIKE $${paramIndex++}`); queryParams.push(`%${pair}%`); }
    if (type && ['limit', 'market'].includes(type.toLowerCase())) { conditions.push(`o.type = $${paramIndex++}`); queryParams.push(type.toLowerCase()); }
    if (side && ['buy', 'sell'].includes(side.toLowerCase())) { conditions.push(`o.side = $${paramIndex++}`); queryParams.push(side.toLowerCase()); }
    
    const conditionsStr = conditions.join(' AND ');
    try {
        const sql = `SELECT o.id, o.pair, o.type, o.side, o.avg_fill_price, o.filled_amount_base, o.amount, (o.avg_fill_price * o.filled_amount_base) as total_executed_value, o.status, o.created_at FROM orders o WHERE ${conditionsStr} ORDER BY o.created_at DESC;`;
        const result = await pool.query(sql, queryParams);
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        console.error("[API GET /api/orders/history] Error:", error.message);
        res.status(500).json({ success: false, message: 'Server error fetching order history.' });
    }
});
app.get('/api/portfolio/history', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    // Параметр для визначення періоду: '7d', '30d', '90d', '1y', 'all'
    // За замовчуванням, наприклад, '30d'
    const period = req.query.period || '30d'; 

    let dateCondition = "";
    const queryParams = [userId]; // Перший параметр завжди userId

    // Формуємо умову для дати на основі періоду
    switch (period) {
        case '7d':
            dateCondition = `AND snapshot_date >= CURRENT_DATE - INTERVAL '7 days'`;
            break;
        case '30d':
            dateCondition = `AND snapshot_date >= CURRENT_DATE - INTERVAL '30 days'`;
            break;
        case '90d':
            dateCondition = `AND snapshot_date >= CURRENT_DATE - INTERVAL '90 days'`;
            break;
        case '1y':
            dateCondition = `AND snapshot_date >= CURRENT_DATE - INTERVAL '1 year'`;
            break;
        case 'all':
            // Немає додаткової умови по даті, беремо всі записи
            break;
        default:
            // Якщо передано невідомий період, можна повернути помилку або використати значення за замовчуванням
            console.warn(`[API /portfolio/history] Unknown period: ${period}. Defaulting to 30d.`);
            dateCondition = `AND snapshot_date >= CURRENT_DATE - INTERVAL '30 days'`;
    }

    try {
        const sql = `
            SELECT 
                TO_CHAR(snapshot_date, 'YYYY-MM-DD') as date, 
                total_value_usd as value
            FROM portfolio_history
            WHERE user_id = $1 ${dateCondition}
            ORDER BY snapshot_date ASC;
        `;
        
        const result = await pool.query(sql, queryParams);
        
        res.json({ success: true, history: result.rows }); // Стало

    } catch (error) {
        console.error(`[API GET /api/portfolio/history] Error for user ${userId}, period ${period}:`, error.message);
        res.status(500).json({ success: false, message: 'Server error fetching portfolio history.' });
    }
});

app.get('/api/user/balances', authenticateToken, async (req, res) => {
    // req.user тепер містить дані з JWT, включаючи ID користувача
    // У тебе в authenticateToken використовується `userId` (з токена { userId: user.id, ... })
    const userId = req.user.userId;

    if (!userId) {
        // Ця перевірка, ймовірно, зайва, якщо authenticateToken завжди встановлює req.user або повертає помилку
        return res.status(400).json({ success: false, message: "User ID not found in token." });
    }

    try {
        // Запит до БД для отримання балансів користувача
        // Важливо: повертаємо числові значення як TEXT, щоб уникнути проблем з точністю
        const query = `
            SELECT
                a.coin_symbol,
                a.total_balance::TEXT AS total_balance,
                a.available_balance::TEXT AS available_balance,
                a.in_order_balance::TEXT AS in_order_balance,
                COALESCE(
                    cry.quantity_precision, -- Беремо точність з таблиці cryptocurrencies
                    CASE -- Якщо в cryptocurrencies немає, використовуємо дефолтні значення
                        WHEN a.coin_symbol IN ('BTC', 'ETH') THEN 8
                        WHEN a.coin_symbol IN ('USDT', 'USDC', 'BUSD', 'FDUSD', 'DAI', 'TUSD') THEN 2
                        ELSE 6 -- Дефолтна точність для інших
                    END
                ) AS quantity_precision
            FROM assets a
            LEFT JOIN cryptocurrencies cry ON a.coin_symbol = cry.symbol
            WHERE a.user_id = $1;
        `;
        const { rows } = await pool.query(query, [userId]);

        // Трансформація результату у зручний для фронтенда формат
        // Об'єкт, де ключ - це символ монети
        const balances = rows.reduce((acc, row) => {
            acc[row.coin_symbol] = {
                total: row.total_balance,
                available: row.available_balance, // Це значення нам потрібне для форм
                inOrder: row.in_order_balance,
                precision: parseInt(row.quantity_precision) // Переконуємось, що precision - це число
            };
            return acc;
        }, {});
        
        res.json({ success: true, balances: balances });

    } catch (error) {
        console.error('[API GET /api/user/balances] Error fetching user balances:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch user balances' });
    }
});

// --- Зовнішні дані та кешування (CoinGecko) ---
let marketDataCache = {
    data: {}, // { 'BTCUSDT': { price: ..., priceChangePercent: ... }, 'ETHUSDT': { ... } }
    lastUpdated: 0,
    cacheDuration: 5 * 60 * 1000, // 5 хвилин
    isUpdating: false // Флаг для запобігання одночасним оновленням
};

const COINGECKO_IDS_MAP = {
    'BTC': 'bitcoin', 'ETH': 'ethereum', 'USDT': 'tether', 'BNB': 'binancecoin', 
    'SOL': 'solana', 'XRP': 'ripple', 'ADA': 'cardano', 'DOGE': 'dogecoin', 
    'AVAX': 'avalanche-2', 'DOT': 'polkadot', 'TRX': 'tron', 'SHIB': 'shiba-inu', 
    'MATIC': 'matic-network', 'LTC': 'litecoin', 'LINK': 'chainlink', 'UNI': 'uniswap', 
    'ATOM': 'cosmos', 'NEAR': 'near', 'FTM': 'fantom', 'ICP': 'internet-computer', 
    'ETC': 'ethereum-classic', 'XLM': 'stellar', 'ALGO': 'algorand', 'VET': 'vechain', 
    'FIL': 'filecoin', 'HBAR': 'hedera-hashgraph', 'EOS': 'eos', 'AAVE': 'aave', 
    'XTZ': 'tezos', 'SAND': 'the-sandbox', 'MANA': 'decentraland', 'AXS': 'axie-infinity', 
    'THETA': 'theta-token', 'GRT': 'the-graph', 'EGLD': 'elrond-erd-2', 'MKR': 'maker', 
    'KSM': 'kusama', 'WAVES': 'waves', 'ZEC': 'zcash', 'DASH': 'dash', 'NEO': 'neo', 
    'CHZ': 'chiliz', 'ENJ': 'enjincoin', 'COMP': 'compound-governance-token', 'SNX': 'havven', 
    'SUSHI': 'sushi', 'YFI': 'yearn-finance', 'APT': 'aptos', 'ARB': 'arbitrum', 
    'OP': 'optimism', 'SUI': 'sui', 'PEPE': 'pepe', 'FET': 'fetch-ai', 
    'RNDR': 'render-token', 'INJ': 'injective-protocol', 'TIA': 'celestia', 
    'IMX': 'immutable-x', 'GALA': 'gala', 'MINA': 'mina-protocol', 'FLOW': 'flow', 
    'CRV': 'curve-dao-token', 'LDO': 'lido-dao', 'RUNE': 'thorchain', 'CAKE': 'pancakeswap-token', 
    'DYDX': 'dydx', '1INCH': '1inch', 'APE': 'apecoin', 'STX': 'stacks', 
    'SEI': 'sei-network', 'FLOKI': 'floki', 'BONK': 'bonk', 'TWT': 'trust-wallet-token', 
    'QNT': 'quant-network', 'KAS': 'kaspa', 'ORDI': 'ordinals', 'WLD': 'worldcoin-wld', 
    'PYTH': 'pyth-network', 'ROSE': 'oasis-network', 'ONE': 'harmony', 'CELO': 'celo', 
    'KAVA': 'kava', 'ZIL': 'zilliqa', 'GMT': 'stepn', 'JASMY': 'jasmycoin', 
    'WOO': 'woo-network',
    'YMC': 'your-custom-coin-id-on-coingecko' // Замініть, якщо є
};

async function fetchExternalMarketDataForPairs(activeMarketPairs) {
    console.log(`[ExternalData] Attempting to fetch for ${activeMarketPairs.length} active pairs.`);
    const cgBaseIdsToFetch = new Set();
    // Нам потрібні унікальні ID базових активів, для яких ми хочемо отримати ціну відносно USD(T)
    activeMarketPairs.forEach(pair => {
        // Ми хочемо ціну для КОЖНОЇ пари. CoinGecko /coins/markets дозволяє це краще, ніж /simple/price
        // для отримання цін для конкретних пар. АЛЕ /simple/price простіше для цін BASE/USD.
        // Поточна логіка працює так: отримуємо ціну BASE/USD, а потім застосовуємо до пари BASE/USDT.
        const baseId = COINGECKO_IDS_MAP[pair.base_asset.toUpperCase()];
        if (baseId) {
            cgBaseIdsToFetch.add(baseId);
        }
    });

    if (cgBaseIdsToFetch.size === 0) {
        console.log('[ExternalData] No valid CoinGecko base asset IDs to fetch.');
        return {};
    }

    const idsQueryParam = Array.from(cgBaseIdsToFetch).join(',');
    const vsCurrency = 'usd'; // Отримуємо ціни відносно USD
    const coingeckoUrl = `https://api.coingecko.com/api/v3/simple/price?ids=${idsQueryParam}&vs_currencies=${vsCurrency}&include_24hr_change=true`;
    console.log(`[ExternalData] CoinGecko URL: ${coingeckoUrl}`);

    try {
        const response = await axios.get(coingeckoUrl, { timeout: 10000 }); // Таймаут 10 секунд
        const coingeckoResponseData = response.data;
        const processedDataForCache = {};

        // Тепер проходимо по всіх активних парах з БД і намагаємося знайти для них ціну
        activeMarketPairs.forEach(pairFromDb => {
            const baseAssetUpper = pairFromDb.base_asset.toUpperCase();
            const quoteAssetUpper = pairFromDb.quote_asset.toUpperCase();
            const coingeckoBaseId = COINGECKO_IDS_MAP[baseAssetUpper];

            if (coingeckoBaseId && coingeckoResponseData[coingeckoBaseId]) {
                const baseAssetData = coingeckoResponseData[coingeckoBaseId];
                const priceBaseVsUsd = baseAssetData[vsCurrency];
                const changeBaseVsUsd = baseAssetData[`${vsCurrency}_24h_change`];

                if (priceBaseVsUsd === undefined) return; // Немає ціни для базового активу

                if (quoteAssetUpper === 'USDT' || quoteAssetUpper === 'USD') {
                    // Це пряма пара до USD/USDT
                    processedDataForCache[pairFromDb.symbol] = {
                        price: priceBaseVsUsd,
                        priceChangePercent: changeBaseVsUsd
                    };
                } else {
                    // Логіка для крос-курсів, наприклад, ETH/BTC
                    // Потрібна ціна quote_asset/USD
                    const coingeckoQuoteId = COINGECKO_IDS_MAP[quoteAssetUpper];
                    if (coingeckoQuoteId && coingeckoResponseData[coingeckoQuoteId]) {
                        const quoteAssetData = coingeckoResponseData[coingeckoQuoteId];
                        const priceQuoteVsUsd = quoteAssetData[vsCurrency];

                        if (priceQuoteVsUsd && priceQuoteVsUsd > 0) {
                            const crossPrice = priceBaseVsUsd / priceQuoteVsUsd;
                            // Зміну для крос-курсів розрахувати складніше, поки що пропустимо
                            processedDataForCache[pairFromDb.symbol] = {
                                price: crossPrice,
                                priceChangePercent: null // TODO: Розрахувати зміну для крос-курсів
                            };
                        }
                    }
                }
            }
        });
        console.log(`[ExternalData] Successfully fetched and processed data for ${Object.keys(processedDataForCache).length} pairs.`);
        // console.log('[ExternalData] Processed Cache Data:', JSON.stringify(processedDataForCache, null, 2));
        return processedDataForCache;

    } catch (error) {
        if (error.response) {
            console.error(`[ExternalData] CoinGecko API Error: Status ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            if (error.response.status === 429) console.warn('\x1b[31m%s\x1b[0m', '[ExternalData] CoinGecko API rate limit likely hit.');
        } else if (error.request) {
            console.error('[ExternalData] CoinGecko API No Response:', error.message);
        } else {
            console.error('[ExternalData] Error setting up CoinGecko request:', error.message);
        }
        return {};
    }
}


async function ensureMarketDataCache(forceUpdate = false) {
    const now = Date.now();
    if (marketDataCache.isUpdating && !forceUpdate) {
        console.log('[Cache] Update already in progress. Skipping.');
        return;
    }
    if (forceUpdate || !marketDataCache.lastUpdated || (now - marketDataCache.lastUpdated > marketDataCache.cacheDuration)) {
        marketDataCache.isUpdating = true;
        console.log(`[Cache] Market data cache is stale or needs update (force: ${forceUpdate}). Updating...`);
        try {
            const client = await pool.connect();
            let activePairsFromDb = [];
            try {
                const result = await client.query("SELECT symbol, base_asset, quote_asset, price_precision, quantity_precision FROM market_pairs WHERE is_active = TRUE");
                activePairsFromDb = result.rows;
            } finally {
                client.release();
            }

            if (activePairsFromDb.length > 0) {
                const externalData = await fetchExternalMarketDataForPairs(activePairsFromDb);
                if (Object.keys(externalData).length > 0) {
                    marketDataCache.data = externalData;
                    marketDataCache.lastUpdated = now;
                    console.log(`[Cache] Market data cache updated successfully with ${Object.keys(externalData).length} entries.`);
                } else {
                    console.warn('[Cache] Failed to update market data cache from external source (empty data returned). Old data might be used if available.');
                    // Не оновлюємо lastUpdated, щоб спробувати ще раз швидше, якщо це тимчасова помилка
                }
            } else {
                console.log('[Cache] No active market pairs found in DB to update cache.');
                marketDataCache.data = {}; // Очищаємо, якщо немає активних пар
                marketDataCache.lastUpdated = now; // Вважаємо, що "порожній" кеш актуальний
            }
        } catch (error) {
            console.error('[Cache] Critical error during market data cache update process:', error);
        } finally {
            marketDataCache.isUpdating = false;
        }
    } else {
        console.log('[Cache] Market data cache is fresh.');
    }
}
async function updateAllUsersPortfolioHistoryUsingBinanceWS() {
    console.log('[CronTask] Starting portfolio history update using Binance WS data...');
    const client = await pool.connect(); // Використовуємо існуючий пул

    try {
        // 1. Використовуємо currentMarketData, який оновлюється вашим WebSocket клієнтом
        //    currentMarketData виглядає приблизно так:
        //    { 'BTCUSDT': { price: '...', priceChangePercent: '...', quoteVolume: '...' }, ... }

        if (Object.keys(currentMarketData).length === 0) {
            console.warn("[CronTask] currentMarketData is empty. Binance WebSocket might not be connected or providing data. Skipping portfolio update.");
            // Можна додати логіку спроби перепідключення WS або очікування
            client.release();
            return;
        }

        // 2. Отримуємо всіх користувачів
        const usersResult = await client.query('SELECT id FROM users');
        const users = usersResult.rows;

        console.log(`[CronTask] Found ${users.length} users to update portfolio history.`);

        // 3. Для кожного користувача розраховуємо вартість портфеля та вставляємо запис
        for (const user of users) {
            let totalPortfolioValueUSD = 0;
            const assetsResult = await client.query('SELECT coin_symbol, total_balance FROM assets WHERE user_id = $1', [user.id]);
            const userAssets = assetsResult.rows;

            for (const asset of userAssets) {
                const balance = parseFloat(asset.total_balance);
                if (balance === 0) continue;

                let priceInUSD = 0;
                const assetSymbolUpper = asset.coin_symbol.toUpperCase();

                if (['USDT', 'USDC', 'BUSD', 'USD'].includes(assetSymbolUpper)) {
                    priceInUSD = 1;
                } else {
                    // Шукаємо ціну в currentMarketData для пари <ASSET>USDT
                    // Binance WebSocket зазвичай надає символи без слеша, наприклад "BTCUSDT"
                    const binancePairSymbol = `${assetSymbolUpper}USDT`;

                    if (currentMarketData[binancePairSymbol] && currentMarketData[binancePairSymbol].price) {
                        priceInUSD = parseFloat(currentMarketData[binancePairSymbol].price);
                    } else {
                        // ЯКЩО НЕМАЄ В BINANCE WS:
                        // Тут можна додати резервну логіку, наприклад, спробувати взяти ціну
                        // з вашого marketDataCache (який оновлюється з CoinGecko), ЯКЩО ВІН Є І АКТУАЛЬНИЙ.
                        // Або просто пропустити/залогувати.
                        // Для чистоти прикладу з Binance WS, поки що залишимо так:
                        console.warn(`[CronTask] Price not found in currentMarketData (Binance WS) for ${binancePairSymbol} for user ${user.id}. Asset value will be 0.`);
                    }
                }
                totalPortfolioValueUSD += balance * priceInUSD;
            }

            // Визначаємо дату для запису
            // Якщо скрипт запускається на початку дня (напр. 00:05), то фіксуємо за попередній день
            const snapshotDateSQL = "CURRENT_DATE - INTERVAL '1 day'";
            // Якщо хочете фіксувати на поточний момент запуску:
            // const snapshotDateSQL = "CURRENT_DATE";

            const insertSql = `
                INSERT INTO portfolio_history (user_id, snapshot_date, total_value_usd)
                VALUES ($1, ${snapshotDateSQL}, $2)
                ON CONFLICT (user_id, snapshot_date) 
                DO UPDATE SET total_value_usd = EXCLUDED.total_value_usd;
            `;
            await client.query(insertSql, [user.id, totalPortfolioValueUSD.toFixed(2)]);
            // console.log(`[CronTask] Portfolio history for user ${user.id} updated. Total value: ${totalPortfolioValueUSD.toFixed(2)} USD.`);
        }
        console.log('[CronTask] Portfolio history update finished successfully.');

    } catch (error) {
        console.error('[CronTask] Error during portfolio history update:', error);
    } finally {
        client.release(); // Повертаємо клієнта в пул
        // НЕ викликайте pool.end() тут, оскільки сервер продовжує працювати!
    }
}

// --- Налаштування Cron Job ---
// Запускати щодня о 00:05 UTC (або інший час/часовий пояс)
// 'TZ' змінна середовища на вашому сервері впливатиме на те, як інтерпретується час cron
if (process.env.NODE_ENV !== 'test') { // Не запускати cron під час тестів
    cron.schedule('5 0 * * *', async () => { // "At 00:05."
        console.log('[CronJob] Running scheduled task: updateAllUsersPortfolioHistoryUsingBinanceWS');
        await updateAllUsersPortfolioHistoryUsingBinanceWS();
    }, {
        scheduled: true,
        timezone: "Etc/UTC" // Рекомендується вказувати часовий пояс явно
    });
    console.log('[CronJob] Portfolio history update task scheduled for 00:05 UTC daily.');
}


// Перший запуск та періодичне оновлення
if (process.env.NODE_ENV !== 'test') {
    ensureMarketDataCache(true).then(() => {
        console.log("[Cache] Initial market data cache population attempt finished.");
    });
    setInterval(() => ensureMarketDataCache(), marketDataCache.cacheDuration / 2); // Оновлюємо частіше, ніж тривалість кешу
}


// --- Обслуговування HTML сторінок ---
app.get('/', (req, res) => res.sendFile(path.join(projectRootPath, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(projectRootPath, 'index.html')));

const htmlPages = [
    'login-page.html', 'sign_up-page.html', 'profile.html', 'assets.html', 
    'order.html', // Якщо є така сторінка
    'account.html', 'settings.html', 'markets.html', 
    'trading-page.html', // Якщо є
    'buy_crypto-page.html', 'futures-page.html', 'spot-page.html'
];
htmlPages.forEach(page => {
    app.get(`/${page}`, (req, res) => {
        const filePath = path.join(frontendPath, 'html', page);
        // console.log(`Serving HTML page: ${page} from ${filePath}`); // Для дебагу шляхів
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error(`Error sending file ${filePath}: ${err.message}`);
                if (!res.headersSent) { // Перевіряємо, чи не були вже надіслані заголовки
                    res.status(err.status || 500).end();
                }
            }
        });
    });
});

// --- Запуск сервера ---
if (connectionString || process.env.NODE_ENV !== 'production') { // Не запускати сервер без БД в продакшені
    app.listen(port, () => {
        console.log(`\x1b[32m%s\x1b[0m`,`YuMa Backend Server is running on http://localhost:${port}`);
        if (process.env.NODE_ENV !== 'production') {
             console.log(`Current NODE_ENV: ${process.env.NODE_ENV || 'development (default)'}`);
        }
    });
} else {
    console.error("\x1b[31m%s\x1b[0m", "Server not started due to missing DATABASE_URL in production.");
}


// --- Обробка закриття сервера ---
async function gracefulShutdown() {
    console.log('Received signal to terminate, shutting down gracefully...');
    try {
        // Тут можна закрити інші ресурси, якщо є (наприклад, WebSocket з'єднання)
        if (pool) {
            await pool.end();
            console.log('PostgreSQL pool has been closed.');
        }
        process.exit(0);
    } catch (e) {
        console.error('Error during shutdown:', e.stack);
        process.exit(1);
    }
}
process.on('SIGINT', gracefulShutdown); // Ctrl+C
process.on('SIGTERM', gracefulShutdown); // Сигнал завершення від ОС (наприклад, від Render)
