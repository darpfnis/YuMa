// backend/server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken'); // Додано jsonwebtoken

const app = express();
const port = process.env.PORT || 3000;

// Секретний ключ для JWT. У реальному проекті зберігайте його в змінних середовища!
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-and-secret-key-for-jwt';
if (JWT_SECRET === 'your-very-strong-and-secret-key-for-jwt' && process.env.NODE_ENV === 'production') {
    console.warn('WARNING: JWT_SECRET is using the default insecure value in production!');
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
        console.error('Error acquiring client for PostgreSQL:', err.stack);
        // process.exit(1); // Можна не виходити, щоб побачити інші помилки, але БД не працюватиме
    } else {
        console.log('Successfully connected to the PostgreSQL database via pool.');
        if (client) client.release();
    }
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const frontendPath = path.join(__dirname, '..', 'frontend');
const projectRootPath = path.join(__dirname, '..');
app.use('/frontend', express.static(frontendPath));

// --- Middleware для перевірки JWT (дуже базовий приклад) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // Немає токена

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err.message);
            return res.sendStatus(403); // Недійсний токен
        }
        req.user = user; // Додаємо інформацію про користувача до об'єкту запиту
        next(); // Переходимо до наступного обробника
    });
};


// --- API Ендпоінти ---
// 1. Реєстрація
app.post('/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`;
        const result = await pool.query(sql, [email, hashedPassword]);
        res.status(201).json({ success: true, message: 'User registered successfully!', userId: result.rows[0].id });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ success: false, message: 'Email already exists.' });
        }
        console.error("Error during user registration (PostgreSQL):", error.message);
        res.status(500).json({ success: false, message: 'Failed to register user due to a server error.' });
    }
});

// 2. Вхід
app.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ success: false, message: 'Identifier (email) and password are required.' });

    const sql = `SELECT id, email, password_hash FROM users WHERE email = $1`; // Вибираємо id та email
    try {
        const result = await pool.query(sql, [identifier]);
        const user = result.rows[0];

        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials. User not found.' });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            // Створюємо JWT токен
            const accessToken = jwt.sign(
                { userId: user.id, email: user.email }, // Дані, які будуть в токені
                JWT_SECRET,
                { expiresIn: '1h' } // Токен дійсний 1 годину (можна налаштувати)
            );
            res.status(200).json({
                success: true,
                message: 'Login successful!',
                token: accessToken, // Відправляємо токен клієнту
                user: { id: user.id, email: user.email } // Можна також повернути базову інфо
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials. Password incorrect.' });
        }
    } catch (error) {
        console.error("Error during login (PostgreSQL):", error.message);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

// 3. Вихід (плейсхолдер, для JWT на стороні клієнта це просто видалення токена)
app.post('/auth/logout', (req, res) => {
    // Для JWT-аутентифікації на стороні сервера зазвичай нічого не робиться,
    // клієнт просто видаляє токен.
    // Можна додати логування або інвалідцію токена, якщо використовується blacklist.
    res.status(200).json({ success: true, message: 'Logged out successfully (client-side action required).' });
});


// --- Захищені API Ендпоінти для профілю (потрібна аутентифікація) ---

// Отримання даних профілю
app.get('/api/profile', authenticateToken, async (req, res) => {
    // req.user тепер містить { userId: ..., email: ... } з токена
    const userId = req.user.userId;
    // Тут ви б зробили запит до БД, щоб отримати повніші дані профілю за userId, якщо потрібно
    // Наприклад, ім'я, UID (якщо він зберігається окремо), статус KYC тощо.

    // Для MVP повернемо дані з токена та фейковий UID
    const fakeUID = `UID-${userId}-${Math.random().toString(16).slice(2, 8).toUpperCase()}`;
    res.json({
        success: true,
        profile: {
            email: req.user.email,
            username: req.user.email.split('@')[0], // Як приклад
            uid: fakeUID,
            // ... інші дані профілю ...
        }
    });
});

// Отримання балансу (приклад, можна об'єднати з /api/profile)
app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    // Тут запит до БД для отримання реального балансу користувача userId
    // Зараз повернемо фейковий
    const fakeBalance = (Math.random() * 15000).toFixed(2);
    res.json({ success: true, balance: parseFloat(fakeBalance) });
});

// Отримання улюблених ринків (приклад)
app.get('/api/markets/favourites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    // Тут запит до БД для отримання улюблених ринків для userId
    // Зараз повернемо фейкові
    const fakeFavouriteMarkets = [
        { pair: 'BTC/USDT', lastPrice: (Math.random() * 5000 + 38000).toFixed(2), change24h: (Math.random() * 5 - 2.5).toFixed(2) },
        { pair: 'ETH/USDT', lastPrice: (Math.random() * 500 + 2200).toFixed(2), change24h: (Math.random() * 6 - 3).toFixed(2) },
        { pair: 'YMC/USDT', lastPrice: (Math.random() * 2 + 0.5).toFixed(2), change24h: (Math.random() * 20 - 10).toFixed(2) }
    ];
    res.json({ success: true, markets: fakeFavouriteMarkets });
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
async function gracefulShutdown() { /* ... ваш код для закриття пулу ... */ }
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);