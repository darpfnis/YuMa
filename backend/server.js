// server.js
const express = require('express');
const { Pool } = require('pg'); // Замінюємо sqlite3 на pg
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000; // Render може надати свій PORT через змінну середовища

// --- Налаштування Бази Даних PostgreSQL ---
// Render надасть DATABASE_URL. Якщо її немає (наприклад, для локальної розробки),
// можна використовувати окремі змінні або локальні налаштування.
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
    connectionString: connectionString,
    // Якщо DATABASE_URL не встановлено, і ви хочете мати локальні налаштування за замовчуванням:
    // user: process.env.PGUSER || 'локальний_юзер',
    // host: process.env.PGHOST || 'localhost',
    // database: process.env.PGDATABASE || 'yuma_db_local',
    // password: process.env.PGPASSWORD || 'локальний_пароль',
    // port: process.env.PGPORT || 5432,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, // Потрібно для Heroku/Render, якщо вони використовують SSL
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client for PostgreSQL:', err.stack);
        process.exit(1); // Завершуємо процес, якщо БД недоступна
    }
    console.log('Successfully connected to the PostgreSQL database.');
    if (client) client.release(); // Важливо звільнити клієнта після перевірки підключення
});


// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '')));

// --- API Ендпоінти ---

// 1. Реєстрація нового користувача
app.post('/auth/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // SQL для PostgreSQL - значення автоінкременту id повертається через RETURNING id
        const sql = `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`;
        const values = [email, hashedPassword];

        const result = await pool.query(sql, values);
        res.status(201).json({ success: true, message: 'User registered successfully!', userId: result.rows[0].id });

    } catch (error) {
        // Код помилки PostgreSQL для UNIQUE constraint (потрібно перевірити точний код або повідомлення)
        if (error.code === '23505') { // 23505 - це типовий код для unique_violation в PostgreSQL
            return res.status(409).json({ success: false, message: 'Email already exists.' });
        }
        console.error("Error during user registration (PostgreSQL):", error);
        res.status(500).json({ success: false, message: 'Failed to register user due to a server error.' });
    }
});

// 2. Вхід існуючого користувача
app.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ success: false, message: 'Identifier (email) and password are required.' });
    }

    const sql = `SELECT * FROM users WHERE email = $1`;
    try {
        const result = await pool.query(sql, [identifier]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials. User not found.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            res.status(200).json({
                success: true,
                message: 'Login successful!',
                user: {
                    id: user.id,
                    email: user.email
                }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials. Password incorrect.' });
        }
    } catch (error) {
        console.error("Error during login (PostgreSQL):", error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

// --- Обслуговування HTML сторінок ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login-page.html', (req, res) => res.sendFile(path.join(__dirname, 'login-page.html')));
app.get('/sign_up-page.html', (req, res) => res.sendFile(path.join(__dirname, 'sign_up-page.html')));
app.get('/profile.html', (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));
app.get('/assets.html', (req, res) => res.sendFile(path.join(__dirname, 'assets.html')));
app.get('/order.html', (req, res) => res.sendFile(path.join(__dirname, 'order.html')));
app.get('/account.html', (req, res) => res.sendFile(path.join(__dirname, 'account.html')));
app.get('/settings.html', (req, res) => res.sendFile(path.join(__dirname, 'settings.html')));
app.get('/markets.html', (req, res) => res.sendFile(path.join(__dirname, 'markets.html')));
app.get('/trading-page.html', (req, res) => res.sendFile(path.join(__dirname, 'trading-page.html')));

// --- Запуск сервера ---
app.listen(port, () => {
    console.log(`YuMa MVP Server is running on http://localhost:${port}`);
});

// --- Обробка закриття сервера ---
// Для PostgreSQL пул з'єднань зазвичай керує закриттям сам,
// але можна додати явне закриття пулу при завершенні роботи сервера.
async function gracefulShutdown() {
    console.log('Received kill signal, shutting down gracefully.');
    try {
        await pool.end();
        console.log('PostgreSQL pool has ended.');
        process.exit(0);
    } catch (e) {
        console.error('Error during shutdown:', e.stack);
        process.exit(1);
    }
}

process.on('SIGINT', gracefulShutdown); // Обробка Ctrl+C
process.on('SIGTERM', gracefulShutdown); // Обробка сигналу завершення