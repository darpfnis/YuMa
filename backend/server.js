// backend/server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios'); 
const WebSocket = require('ws');


const app = express();
const port = process.env.PORT || 3000; // Render надає PORT

// --- Налаштування JWT ---
const JWT_SECRET = process.env.JWT_SECRET || 'a3b8c1d7e5f2a1b6c0d4e9f7a2b5c8d1e6f0a0b3c6d0e4f1a7b2c5d8e3f6a4b9c2d5e8f3a6b1c4d7e0f9';
if (JWT_SECRET === 'a3b8c1d7e5f2a1b6c0d4e9f7a2b5c8d1e6f0a0b3c6d0e4f1a7b2c5d8e3f6a4b9c2d5e8f3a6b1c4d7e0f9' && process.env.NODE_ENV === 'production') {
    console.warn('CRITICAL WARNING: JWT_SECRET is using a default insecure value in production! Please set a strong JWT_SECRET environment variable on Render.');
}

// --- Налаштування Бази Даних ---
const connectionString = process.env.DATABASE_URL;
if (!connectionString && process.env.NODE_ENV === 'production') { // Критично тільки для production на Render
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set in production.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: connectionString || "postgres://postgres:your_local_password@localhost:5432/yuma_db", // Локальний fallback
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('connect', (client) => {
    console.log('PostgreSQL pool: New client connected to the database.');
    client.on('error', err => {
        console.error('PostgreSQL client error within pool:', err);
    });
});
pool.on('error', (err, client) => {
    console.error('Unexpected error on idle PostgreSQL client in pool:', err);
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..');
app.use('/frontend', express.static(frontendPath));

// --- Налаштування режиму розробки (DEV_MODE) ---
const DEV_MODE_SKIP_AUTH = process.env.NODE_ENV !== 'production' && (process.env.DEV_MODE_SKIP_AUTH === 'true'); // true/false
const DEV_MODE_TEST_USER = {
    userId: 1,
    email: 'devuser@example.com',
    username: 'devuser',
    uid: 'DEVUID123'
};
if (DEV_MODE_SKIP_AUTH) {
    console.warn("*****************************************************************");
    console.warn("* WARNING: DEV_MODE_SKIP_AUTH is ENABLED. Authentication is OFF *");
    console.warn("*****************************************************************");
}


// --- Middleware Автентифікації ---
const authenticateToken = (req, res, next) => {
    if (DEV_MODE_SKIP_AUTH) {
        req.user = DEV_MODE_TEST_USER;
        return next();
    }
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
        req.user = DEV_MODE_TEST_USER; // В DEV_MODE завжди встановлюємо тестового користувача для tryAuth
        return next();
    }
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

// --- Дані Ринку (Binance WebSocket та CoinGecko Cache) ---
const INITIAL_ASSETS = ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'XRP', 'ADA', 'DOGE', 'YMC'];
let currentMarketData = {}; // Має оновлюватися з WebSocket Binance

const BINANCE_WS_BASE_URL = 'wss://stream.binance.com:9443/ws';
let binanceWs = null; // Зберігатиме екземпляр WebSocket
let subscribedStreams = new Set(); // Для відстеження поточних підписок
const RECONNECT_INTERVAL = 5000; // 5 секунд
const MAX_STREAMS_PER_CONNECTION = 100; // Binance обмежує кількість стрімів на одне з'єднання

// Функція для оновлення currentMarketData на основі повідомлень з WebSocket
function handleBinanceMessage(data) {
    try {
        const message = JSON.parse(data);

        // Приклад для стріму тикера (!ticker@arr не завжди дає ціну напряму, краще @ticker або @miniTicker)
        // Використаємо @miniTicker для простоти (ціна, об'єм)
        if (message.e === '24hrMiniTicker') {
            const symbol = message.s; // Наприклад, "BTCUSDT"
            currentMarketData[symbol] = {
                price: parseFloat(message.c), // Остання ціна
                priceChangePercent: null, // MiniTicker не дає % зміни, потрібен @ticker або розрахунок
                quoteVolume: parseFloat(message.q), // Об'єм в котирувальній валюті за 24 години
                openPrice: parseFloat(message.o),
                highPrice: parseFloat(message.h),
                lowPrice: parseFloat(message.l),
                volume: parseFloat(message.v), // Об'єм в базовій валюті
                lastUpdatedAt: Date.now(),
                source: 'BinanceWS'
            };
            // console.log(`[BinanceWS] Updated ${symbol}: Price ${currentMarketData[symbol].price}`);
        }
        // Якщо ви підписуєтесь на інші типи стрімів (наприклад, книга ордерів, угоди),
        // додайте відповідну логіку обробки тут.

    } catch (error) {
        console.error('[BinanceWS] Error parsing message:', error, 'Data:', data.substring(0, 200));
    }
}

// Функція для отримання списку символів для підписки з БД
async function getBinanceSymbolsToSubscribe() {
    let client;
    try {
        client = await pool.connect();
        // Вибираємо binance_symbol, якщо є, інакше symbol. Лише активні пари.
        const result = await client.query(
            `SELECT DISTINCT COALESCE(NULLIF(TRIM(binance_symbol), ''), symbol) as stream_symbol 
             FROM market_pairs 
             WHERE is_active = TRUE AND NULLIF(TRIM(COALESCE(NULLIF(TRIM(binance_symbol), ''), symbol)), '') IS NOT NULL`
        );
        return result.rows.map(row => `${row.stream_symbol.toLowerCase()}@miniTicker`); // наприклад, btcusdt@miniTicker
    } catch (error) {
        console.error('[BinanceWS][DB] Error fetching symbols for WebSocket subscription:', error);
        return []; // Повертаємо порожній масив у разі помилки
    } finally {
        if (client) client.release();
    }
}


function connectToBinanceStreams(streamsToSubscribe) {
    if (binanceWs && (binanceWs.readyState === WebSocket.OPEN || binanceWs.readyState === WebSocket.CONNECTING)) {
        console.log('[BinanceWS] WebSocket already open or connecting. Attempting to update subscriptions.');
        // Логіка для додавання/видалення стрімів з існуючого з'єднання (якщо потрібно)
        // Зараз ми просто перепідписуємося на новий набір при перепідключенні
        // Для простоти, якщо список стрімів змінився, ми закриємо старе з'єднання і відкриємо нове
        // Нижче при закритті буде спроба перепідключення, яка візьме новий список стрімів.
        if (streamsToSubscribe.length > 0) { // Якщо є на що підписуватись
            const currentStreamsKey = Array.from(subscribedStreams).sort().join(',');
            const newStreamsKey = streamsToSubscribe.sort().join(',');
            if (currentStreamsKey !== newStreamsKey) {
                console.log('[BinanceWS] Stream list changed. Reconnecting.');
                if (binanceWs) binanceWs.close(1000, "Reconnecting due to stream list change"); // 1000 - Normal Closure
                return; // connectToBinanceMarketStreams буде викликано знову через on 'close'
            } else {
                 console.log('[BinanceWS] Stream list has not changed. No action needed on existing connection.');
                 return;
            }
        } else { // Якщо немає на що підписуватись, а з'єднання є - закриваємо.
            console.log('[BinanceWS] No streams to subscribe to, closing existing connection if open.');
            if (binanceWs) binanceWs.close(1000, "No streams to subscribe to");
            return;
        }
    }
    
    if (streamsToSubscribe.length === 0) {
        console.log('[BinanceWS] No symbols to subscribe to from database. Skipping WebSocket connection.');
        subscribedStreams.clear();
        currentMarketData = {}; // Очищаємо дані, якщо немає підписок
        return;
    }

    // Розділяємо стріми на чанки, якщо їх більше MAX_STREAMS_PER_CONNECTION
    // Для цього прикладу ми не будемо робити кілька з'єднань, а просто обмежимо.
    // У реальному продакшені може знадобитися кілька WebSocket з'єднань.
    if (streamsToSubscribe.length > MAX_STREAMS_PER_CONNECTION) {
        console.warn(`[BinanceWS] Warning: Number of streams (${streamsToSubscribe.length}) exceeds max per connection (${MAX_STREAMS_PER_CONNECTION}). Subscribing to the first ${MAX_STREAMS_PER_CONNECTION}.`);
        streamsToSubscribe = streamsToSubscribe.slice(0, MAX_STREAMS_PER_CONNECTION);
    }


    const streamPath = streamsToSubscribe.join('/');
    const fullUrl = `${BINANCE_WS_BASE_URL}/${streamPath}`;
    console.log(`[BinanceWS] Connecting to: ${streamsToSubscribe.length} streams. (URL might be long, showing first few: ${streamsToSubscribe.slice(0,3).join('/')}...)`);

    binanceWs = new WebSocket(fullUrl);
    subscribedStreams = new Set(streamsToSubscribe); // Оновлюємо список активних підписок

    binanceWs.on('open', () => {
        console.log('[BinanceWS] Connected to Binance Market Streams successfully!');
        // Підписка відбувається через URL, додаткове повідомлення не потрібне для комбінованих стрімів
    });

    binanceWs.on('message', (data) => {
        // Binance може надсилати дані як Buffer, перетворюємо на рядок
        handleBinanceMessage(data.toString());
    });

    binanceWs.on('error', (error) => {
        console.error('[BinanceWS] WebSocket Error:', error.message);
        // Спроба перепідключення не відбувається тут, а в 'close'
    });

    binanceWs.on('close', (code, reason) => {
        console.log(`[BinanceWS] WebSocket connection closed. Code: ${code}, Reason: ${reason ? reason.toString() : 'No reason'}`);
        binanceWs = null; // Очищаємо екземпляр
        subscribedStreams.clear();
        // Очистити currentMarketData для символів, що були підписані, або всі, якщо це бажано
        // currentMarketData = {}; // Або більш вибіркова очистка

        // Спроба перепідключення, якщо закриття не було навмисним (код не 1000)
        // або якщо причина вказує на необхідність перепідключення
        if (code !== 1000) { // 1000 - нормальне закриття
            console.log(`[BinanceWS] Attempting to reconnect in ${RECONNECT_INTERVAL / 1000} seconds...`);
            setTimeout(connectToBinanceMarketStreams, RECONNECT_INTERVAL); // Викликаємо головну функцію для перепідключення
        }
    });

    binanceWs.on('ping', () => {
        // Binance надсилає ping, ws автоматично відповідає pong
        // console.log('[BinanceWS] Received ping, pong sent.');
        if (binanceWs) binanceWs.pong();
    });
}

// Головна функція для запуску та управління підключенням
async function connectToBinanceMarketStreams() {
    console.log('[BinanceWS] Preparing to connect/reconnect to Binance WebSocket...');
    const streams = await getBinanceSymbolsToSubscribe();
    if (streams.length > 0) {
        connectToBinanceStreams(streams);
    } else {
        console.log('[BinanceWS] No active symbols found in DB to subscribe for Binance WebSocket.');
        // Якщо WebSocket був активний і тепер немає символів, його потрібно закрити
        if (binanceWs && binanceWs.readyState === WebSocket.OPEN) {
            console.log('[BinanceWS] Closing existing WebSocket connection as there are no symbols to subscribe to.');
            binanceWs.close(1000, "No symbols to subscribe to."); // 1000 - Normal closure
        }
        subscribedStreams.clear();
    }
}


// --- РОЗДІЛ ДЛЯ РИНКОВИХ ДАНИХ CoinGecko (інтегровано) ---
let marketDataCache = { // Кеш для даних, розрахованих з CoinGecko
    data: {},
    lastUpdated: 0,
    cacheDuration: 5 * 60 * 1000 // 5 хвилин
};

async function fetchIndividualAssetDataFromCoinGecko(coinGeckoIdsToFetch, cgIdToAssetSymbolMap) {
    if (!Array.isArray(coinGeckoIdsToFetch) || coinGeckoIdsToFetch.length === 0) {
        console.log('[ExternalDataCG] No CoinGecko IDs provided to fetch.');
        return {};
    }
    if (typeof cgIdToAssetSymbolMap !== 'object' || cgIdToAssetSymbolMap === null) {
        console.error('[ExternalDataCG] FATAL: cgIdToAssetSymbolMap is not a valid object!');
        return {};
    }

    console.log(`[ExternalDataCG] Attempting to fetch market data for ${coinGeckoIdsToFetch.length} unique CoinGecko IDs: ${coinGeckoIdsToFetch.join(',')}`);
    const idsQueryParam = coinGeckoIdsToFetch.join(',');
    const vsCurrency = 'usd';
    const coingeckoUrl = `https://api.coingecko.com/api/v3/simple/price?ids=${idsQueryParam}&vs_currencies=${vsCurrency}&include_24hr_change=true`;

    try {
        const response = await axios.get(coingeckoUrl, { timeout: 15000 });
        const coingeckoData = response.data;
        const processedData = {};

        for (const cgId in coingeckoData) {
            if (coingeckoData.hasOwnProperty(cgId) && cgIdToAssetSymbolMap[cgId]) {
                const assetSymbol = cgIdToAssetSymbolMap[cgId];
                const dataForCgId = coingeckoData[cgId];
                if (dataForCgId && dataForCgId[vsCurrency] !== undefined) {
                    processedData[assetSymbol] = {
                        price: dataForCgId[vsCurrency],
                        priceChangePercent: dataForCgId[`${vsCurrency}_24h_change`]
                    };
                } else {
                    console.warn(`[ExternalDataCG] No price data for ${vsCurrency} found for cgId: ${cgId} (mapped to ${assetSymbol})`);
                }
            } else {
                 console.warn(`[ExternalDataCG] Received data for unknown cgId: ${cgId} or cgId not in cgIdToAssetSymbolMap.`);
            }
        }
        return processedData;
    } catch (error) {
        console.error('[ExternalDataCG] Error fetching from CoinGecko:', error.message);
        if (error.response) {
            console.error('[ExternalDataCG] CoinGecko Response Status:', error.response.status);
            if (error.response.data && error.response.data.error) {
                 console.error('[ExternalDataCG] CoinGecko Error Message:', error.response.data.error);
            }
            if (error.response.status === 429) {
                console.warn('[ExternalDataCG] CoinGecko API rate limit. IDs: ' + idsQueryParam.substring(0,100) + '...');
            }
        } else if (error.request) {
            console.error('[ExternalDataCG] No response from CoinGecko. IDs: ' + idsQueryParam.substring(0,100) + '...');
        } else {
            console.error('[ExternalDataCG] Error setting up CoinGecko request:', error.message);
        }
        return {};
    }
}

async function ensureMarketDataCache(forceUpdate = false) {
    const now = Date.now();
    if (forceUpdate || !marketDataCache.lastUpdated || (now - marketDataCache.lastUpdated > marketDataCache.cacheDuration)) {
        console.log('[CacheCG] Market data cache (CoinGecko) is stale or missing. Updating...');
        let client;
        try {
            client = await pool.connect();
            let activePairsDbRows = [];
            try {
                const result = await client.query(
                    `SELECT symbol, base_asset, quote_asset, 
                            coingecko_base_id, coingecko_quote_id, 
                            price_precision, quantity_precision 
                     FROM market_pairs 
                     WHERE is_active = TRUE`
                );
                activePairsDbRows = result.rows;
            } catch (dbError) {
                console.error('[CacheCG][DB] Error fetching active pairs for CoinGecko data:', dbError);
                if (client) client.release();
                return;
            }

            if (activePairsDbRows.length > 0) {
                const uniqueCoinGeckoIds = new Set();
                const cgIdToAssetSymbolMap = {};
                activePairsDbRows.forEach(pair => {
                    if (pair.coingecko_base_id && typeof pair.coingecko_base_id === 'string') {
                        uniqueCoinGeckoIds.add(pair.coingecko_base_id.trim());
                        cgIdToAssetSymbolMap[pair.coingecko_base_id.trim()] = pair.base_asset.toUpperCase();
                    }
                    if (pair.coingecko_quote_id && typeof pair.coingecko_quote_id === 'string') {
                        uniqueCoinGeckoIds.add(pair.coingecko_quote_id.trim());
                        cgIdToAssetSymbolMap[pair.coingecko_quote_id.trim()] = pair.quote_asset.toUpperCase();
                    }
                });

                const coinGeckoIdsToFetchArray = Array.from(uniqueCoinGeckoIds);
                if (coinGeckoIdsToFetchArray.length === 0) {
                    console.log('[CacheCG] No valid CoinGecko IDs from DB. Clearing CoinGecko cache.');
                    marketDataCache.data = {};
                    marketDataCache.lastUpdated = now;
                    if (client) client.release();
                    return;
                }

                const individualAssetUsdData = await fetchIndividualAssetDataFromCoinGecko(coinGeckoIdsToFetchArray, cgIdToAssetSymbolMap);
                if (Object.keys(individualAssetUsdData).length > 0) {
                    const newPairDataCache = {};
                    let processedPairsCount = 0;
                    activePairsDbRows.forEach(pair => {
                        const baseAssetSymbol = pair.base_asset.toUpperCase();
                        const quoteAssetSymbol = pair.quote_asset.toUpperCase();
                        const baseAssetData = individualAssetUsdData[baseAssetSymbol];
                        const quoteAssetData = individualAssetUsdData[quoteAssetSymbol];

                        if (baseAssetData && baseAssetData.price !== undefined &&
                            quoteAssetData && quoteAssetData.price !== undefined && quoteAssetData.price !== 0) {
                            const pairPrice = baseAssetData.price / quoteAssetData.price;
                            let pairPriceChangePercent = null;
                            if (baseAssetData.priceChangePercent !== undefined && baseAssetData.priceChangePercent !== null &&
                                quoteAssetData.priceChangePercent !== undefined && quoteAssetData.priceChangePercent !== null) {
                                const changeBaseFraction = baseAssetData.priceChangePercent / 100;
                                const changeQuoteFraction = quoteAssetData.priceChangePercent / 100;
                                if ((1 + changeQuoteFraction) !== 0) {
                                    pairPriceChangePercent = (((1 + changeBaseFraction) / (1 + changeQuoteFraction)) - 1) * 100;
                                }
                            }
                            newPairDataCache[pair.symbol] = {
                                price: parseFloat(pairPrice.toFixed(pair.price_precision || 8)),
                                priceChangePercent: pairPriceChangePercent !== null ? parseFloat(pairPriceChangePercent.toFixed(2)) : null,
                                pricePrecision: pair.price_precision,
                                quantityPrecision: pair.quantity_precision,
                                source: 'CoinGeckoCalculated'
                            };
                            processedPairsCount++;
                        }
                    });
                    marketDataCache.data = newPairDataCache;
                    marketDataCache.lastUpdated = now;
                    console.log(`[CacheCG] CoinGecko market data cache updated. Processed ${processedPairsCount} pair prices.`);
                    if (processedPairsCount < activePairsDbRows.length) {
                         console.warn(`[CacheCG] Could not process ${activePairsDbRows.length - processedPairsCount} pairs for CoinGecko data.`);
                    }
                } else {
                    console.warn('[CacheCG] Failed to fetch any individual asset USD data from CoinGecko. CoinGecko cache may be empty or outdated.');
                }
            } else {
                console.log('[CacheCG] No active market pairs in DB for CoinGecko cache.');
                marketDataCache.data = {};
                marketDataCache.lastUpdated = now;
            }
        } catch (error) {
            console.error('[CacheCG] Critical error during CoinGecko market data cache update:', error);
        } finally {
            if (client) client.release();
        }
    } else {
        console.log('[CacheCG] CoinGecko market data cache is fresh.');
    }
}
// --- КІНЕЦЬ РОЗДІЛУ ДЛЯ РИНКОВИХ ДАНИХ CoinGecko ---


// --- API Ендпоінти (ваші існуючі ендпоінти) ---

// АУТЕНТИФІКАЦІЯ
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!email || !password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Valid email and password (min 6 chars) are required.' });
    }
    let client;
    try {
        client = await pool.connect();
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
        if (client) await client.query('ROLLBACK');
        if (error.code === '23505') { // Unique violation
            const field = error.constraint && error.constraint.includes('email') ? 'Email' : 'Username';
            return res.status(409).json({ success: false, message: `${field} already exists.` });
        }
        console.error("[Register] Error:", error);
        res.status(500).json({ success: false, message: 'Failed to register user.' });
    } finally {
        if (client) client.release();
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
                { expiresIn: '1h' } // Рекомендується '1h' або '1d', не більше
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


// ПРОФІЛЬ, АКТИВИ, РИНКИ, ОРДЕРИ
app.get('/api/profile', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const sql = `SELECT id, email, username, uid, created_at, avatar_url FROM users WHERE id = $1`;
        const result = await pool.query(sql, [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User profile not found.' });
        }
        res.json({ success: true, profile: result.rows[0] });
    } catch (error) {
        console.error("[API GET /api/profile] Error:", error);
        res.status(500).json({ success: false, message: 'Server error fetching profile.' });
    }
});

app.put('/api/profile/username', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { newUsername } = req.body;
    if (!newUsername || newUsername.trim().length < 3) {
        return res.status(400).json({ success: false, message: 'Username must be at least 3 characters long.' });
    }
    try {
        const checkSql = `SELECT id FROM users WHERE username = $1 AND id != $2`;
        const checkResult = await pool.query(checkSql, [newUsername, userId]);
        if (checkResult.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'Username already taken.' });
        }
        const updateSql = `UPDATE users SET username = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, username, email, uid, avatar_url`;
        const result = await pool.query(updateSql, [newUsername.trim(), userId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        const updatedUser = result.rows[0];
        const newToken = jwt.sign(
            { userId: updatedUser.id, email: updatedUser.email, username: updatedUser.username, uid: updatedUser.uid },
            JWT_SECRET, { expiresIn: '1h' }
        );
        res.json({ success: true, message: 'Username updated.', user: updatedUser, token: newToken });
    } catch (error) {
        console.error("[API PUT /api/profile/username] Error:", error);
        if (error.code === '23505' && error.constraint && error.constraint.includes('username')) {
             return res.status(409).json({ success: false, message: 'Username already taken (DB constraint).' });
        }
        res.status(500).json({ success: false, message: 'Server error updating username.' });
    }
});

// Цей ендпоінт у вас був дубльований з /api/profile, виправляю на оновлення аватара
app.put('/api/profile/avatar', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { avatarUrl } = req.body;

    if (avatarUrl === undefined) {
        return res.status(400).json({ success: false, message: 'Avatar URL is required (can be empty string to remove).' });
    }
    if (avatarUrl !== '' && (!avatarUrl.startsWith('http://') && !avatarUrl.startsWith('https://'))) {
         // Дуже базова валідація, можна покращити
        return res.status(400).json({ success: false, message: 'Invalid avatar URL format.' });
    }

    try {
        const updateSql = `UPDATE users SET avatar_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING avatar_url`;
        const result = await pool.query(updateSql, [avatarUrl, userId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.json({ success: true, message: 'Avatar updated successfully.', avatarUrl: result.rows[0].avatar_url });
    } catch (error) {
        console.error("[API PUT /api/profile/avatar] Error:", error);
        res.status(500).json({ success: false, message: 'Server error updating avatar.' });
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

            if (['USDT', 'USDC', 'BUSD'].includes(assetSymbolUpper)) { // Стейблкоіни
                priceInUSD = 1;
            } else {
                // Спочатку шукаємо ціну в currentMarketData (Binance WS)
                const pairSymbolUSDT_Binance = `${assetSymbolUpper}USDT`;
                const binanceData = currentMarketData[pairSymbolUSDT_Binance];

                if (binanceData && binanceData.price !== undefined) {
                    priceInUSD = parseFloat(binanceData.price);
                } else {
                    // Якщо немає в Binance, шукаємо в CoinGecko кеші (ціна пари відносно USDT)
                    const pairSymbolUSDT_CoinGecko = `${assetSymbolUpper}USDT`; // Наприклад, BTCUSDT
                    const coingeckoPairData = marketDataCache.data[pairSymbolUSDT_CoinGecko];
                    if (coingeckoPairData && coingeckoPairData.price !== undefined) {
                        priceInUSD = parseFloat(coingeckoPairData.price);
                    } else {
                        // Якщо немає пари до USDT, але є пряма ціна активу в USD з CoinGecko
                        // (це менш ймовірно, оскільки ми розраховуємо пари)
                        // Цю логіку можна розширити, якщо fetchIndividualAssetDataFromCoinGecko
                        // буде зберігати і прямі ціни активів у якомусь окремому кеші.
                        // Наразі marketDataCache.data зберігає ціни ПАР.
                        console.warn(`[API /balance] Price not found for ${assetSymbolUpper} in Binance WS or CoinGecko USDT pair cache.`);
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
        const sql = `
            SELECT a.id, a.coin_symbol, COALESCE(mp.name, a.coin_symbol) as coin_name,
                   a.total_balance, a.available_balance, a.in_order_balance, mp.price_precision as asset_price_precision
            FROM assets a
            LEFT JOIN market_pairs mp ON UPPER(a.coin_symbol) = UPPER(mp.base_asset) AND UPPER(mp.quote_asset) = 'USDT' -- Припускаємо, що ціна в USD через USDT пару
            WHERE a.user_id = $1 ORDER BY a.coin_symbol;
        `;
        const result = await pool.query(sql, [userId]);
        const assetsWithDetails = result.rows.map(asset => {
            let valueInUSD = 0;
            const assetSymbolUpper = asset.coin_symbol.toUpperCase();

             if (['USDT', 'USDC', 'BUSD'].includes(assetSymbolUpper)) {
                valueInUSD = parseFloat(asset.total_balance);
            } else {
                const pairSymbolUSDT_Binance = `${assetSymbolUpper}USDT`;
                const binanceData = currentMarketData[pairSymbolUSDT_Binance];
                let livePrice;

                if (binanceData && binanceData.price !== undefined) {
                    livePrice = parseFloat(binanceData.price);
                } else {
                    const pairSymbolUSDT_CoinGecko = `${assetSymbolUpper}USDT`;
                    const coingeckoPairData = marketDataCache.data[pairSymbolUSDT_CoinGecko];
                    if (coingeckoPairData && coingeckoPairData.price !== undefined) {
                        livePrice = parseFloat(coingeckoPairData.price);
                    }
                }
                if (livePrice) valueInUSD = parseFloat(asset.total_balance) * livePrice;
            }
            return {
                ...asset,
                total_balance: parseFloat(asset.total_balance).toFixed(8), // Точність для балансів
                available_balance: parseFloat(asset.available_balance).toFixed(8),
                in_order_balance: parseFloat(asset.in_order_balance).toFixed(8),
                value_usd: valueInUSD.toFixed(2) // USD зазвичай 2 знаки
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
        // Вибираємо унікальні базові активи з активних пар
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

    // НЕ викликаємо await ensureMarketDataCache() тут, щоб не блокувати запит.
    // Кеш оновлюється у фоні через setInterval.

    try {
        let queryParams = [];
        let paramIndex = 1;
        let selectIsFavourite = `FALSE as "isFavourite"`; // За замовчуванням не улюблена
        if (userId) {
            // Якщо користувач авторизований, перевіряємо, чи пара в його улюблених
            selectIsFavourite = `EXISTS (SELECT 1 FROM user_favourite_markets ufm WHERE ufm.user_id = $${paramIndex} AND ufm.market_pair_id = mp.id) as "isFavourite"`;
            queryParams.push(userId);
            paramIndex++;
        }
        
        const baseSelect = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name, 
                   mp.is_popular, ${selectIsFavourite}, mp.price_precision, mp.quantity_precision,
                   COALESCE(mp.binance_symbol, mp.symbol) as effective_symbol_for_live_data 
            FROM market_pairs mp
        `;
        let conditions = ["mp.is_active = TRUE"];
        if (popularOnly === 'true') conditions.push("mp.is_popular = TRUE");
        else if (baseAsset && typeof baseAsset === 'string' && baseAsset.trim() !== '') {
            conditions.push(`mp.base_asset = $${paramIndex++}`);
            queryParams.push(baseAsset.toUpperCase()); // Приводимо до верхнього регістру для порівняння
        }
        const sql = `${baseSelect} WHERE ${conditions.join(' AND ')} ORDER BY mp.display_order, mp.symbol;`;
        
        const result = await pool.query(sql, queryParams);
        
        const marketsWithLiveData = result.rows.map(pair => {
            const binanceLiveData = currentMarketData[pair.effective_symbol_for_live_data]; // Дані з Binance WS
            const cachedExternalData = marketDataCache.data[pair.symbol]; // Дані з CoinGecko кешу

            let livePrice, liveChangePercent, liveVolume;

            if (binanceLiveData && binanceLiveData.price !== undefined) {
                livePrice = parseFloat(binanceLiveData.price);
                liveChangePercent = parseFloat(binanceLiveData.priceChangePercent); // Або інше поле, якщо назва інша
                liveVolume = parseFloat(binanceLiveData.quoteVolume); // Або інше поле
            } else if (cachedExternalData && cachedExternalData.price !== undefined) {
                livePrice = cachedExternalData.price; // Вже parseFloat при збереженні
                liveChangePercent = cachedExternalData.priceChangePercent; // Вже parseFloat
                // Об'єм з CoinGecko може бути недоступний або мати іншу структуру
            }

            return { 
                ...pair, 
                currentPrice: livePrice !== undefined ? livePrice.toFixed(pair.price_precision || 2) : null,
                change24hPercent: liveChangePercent !== undefined ? liveChangePercent.toFixed(2) : null,
                volume24h: liveVolume !== undefined ? liveVolume.toFixed(2) : null // Припускаємо, що об'єм в quote валюті
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
    try {
        const sql = `
            SELECT mp.id, mp.symbol, mp.base_asset, mp.quote_asset, mp.name, mp.price_precision, mp.quantity_precision,
                   COALESCE(mp.binance_symbol, mp.symbol) as effective_symbol_for_live_data
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
                livePrice = parseFloat(binanceLiveData.price);
                liveChange = parseFloat(binanceLiveData.priceChangePercent);
            } else if (cachedExternalData && cachedExternalData.price !== undefined) {
                livePrice = cachedExternalData.price;
                liveChange = cachedExternalData.priceChangePercent;
            }
            return {
                ...pair,
                isFavourite: true,
                currentPrice: livePrice !== undefined ? livePrice.toFixed(pair.price_precision || 2) : null,
                change24hPercent: liveChange !== undefined ? liveChange.toFixed(2) : null,
            };
        });
        res.json({ success: true, markets: marketsWithLiveData });
    } catch (error) {
        console.error("[API GET /api/markets/favourites] Error:", error);
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
        console.error("[API POST /api/favourites] Error:", error);
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
        console.error("[API DELETE /api/favourites] Error:", error);
        res.status(500).json({ success: false, message: 'Server error removing from favourites.' });
    }
});

// --- Ендпоінти для Ордерів (скорочено, залиште вашу повну реалізацію) ---
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

// --- Ініціалізація та періодичне оновлення кешу ринкових даних CoinGecko ---
(async () => {
    // 1. CoinGecko Cache
    try {
        console.log('[Startup] Performing initial CoinGecko market data cache update...');
        await ensureMarketDataCache(true);
    } catch (initialCacheError) {
        console.error("[Startup] Error during initial CoinGecko market data cache update:", initialCacheError);
    }

    setInterval(async () => {
        try {
            await ensureMarketDataCache();
        } catch (intervalError) {
             console.error("[IntervalCacheUpdateCG] Error during scheduled CoinGecko market data cache update:", intervalError);
        }
    }, marketDataCache.cacheDuration); // Для CoinGecko

    // 2. Binance WebSocket (якщо увімкнено)
    if (process.env.ENABLE_BINANCE_WS === 'true') {
        console.log('[Startup] ENABLE_BINANCE_WS is true. Initializing Binance WebSocket connection...');
        try {
            await connectToBinanceMarketStreams(); // Перший запуск
            // Можна додати періодичну перевірку/оновлення списку підписок, якщо пари в БД часто змінюються
            // setInterval(connectToBinanceMarketStreams, 60 * 60 * 1000); // Наприклад, кожну годину
        } catch (wsError) {
            console.error('[Startup] Error initializing Binance WebSocket:', wsError);
        }
    } else {
        console.log('[Startup] ENABLE_BINANCE_WS is not set to true. Binance WebSocket will not be started.');
    }
})();


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
app.listen(port, '0.0.0.0', () => { // Слухаємо на 0.0.0.0 для Render
    console.log(`YuMa Backend Server is running on http://localhost:${port} (externally via Render)`);
});

// --- Обробка закриття сервера ---
async function gracefulShutdown() {
    console.log('Received signal to terminate, shutting down gracefully.');
    // Тут можна додати закриття WebSocket з'єднань, якщо вони є
    try {
        if (pool) {
            console.log('Attempting to end PostgreSQL pool...');
            await pool.end();
            console.log('PostgreSQL pool has ended.');
        }
        process.exit(0);
    } catch (e) {
        console.error('Error during shutdown:', e.stack);
        process.exit(1);
    }
}
process.on('SIGINT', gracefulShutdown); // Ctrl+C
process.on('SIGTERM', gracefulShutdown); // Сигнал від Render для зупинки

module.exports = app; // Для можливих тестів
