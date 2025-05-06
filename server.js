// server.js
const express = require('express');
const { Pool } = require('pg'); // Драйвер для PostgreSQL
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
// Render надасть PORT через змінну середовища, або використовуємо 3000 локально
const port = process.env.PORT || 3000;

// --- Налаштування Бази Даних PostgreSQL ---
const connectionString = process.env.DATABASE_URL; // Цю змінну надасть Render

if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    // Для локальної розробки, якщо DATABASE_URL не встановлено, можна тут задати
    // локальний рядок підключення або вийти з помилкою, як зараз.
    // Наприклад:
    // console.log("Attempting to use local DB connection as DATABASE_URL is not set.");
    // connectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_database_name";
    // if (!connectionString) process.exit(1); // Якщо і локального немає, то виходимо
    process.exit(1); // Якщо на Render немає DATABASE_URL, це проблема
}

const pool = new Pool({
    connectionString: connectionString,
    // SSL потрібен для підключення до баз даних на Render (та багатьох інших хмарних провайдерах)
    // process.env.NODE_ENV автоматично встановлюється в 'production' на Render
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client for PostgreSQL:', err.stack);
        process.exit(1);
    }
    console.log('Successfully connected to the PostgreSQL database via pool.');
    if (client) client.release();
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, ''))); // Обслуговування статичних файлів

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
        if (error.code === '23505') { // Unique violation в PostgreSQL
            return res.status(409).json({ success: false, message: 'Email already exists.' });
        }
        console.error("Error during user registration (PostgreSQL):", error);
        res.status(500).json({ success: false, message: 'Failed to register user due to a server error.' });
    }
});

// 2. Вхід
app.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ success: false, message: 'Identifier (email) and password are required.' });

    const sql = `SELECT * FROM users WHERE email = $1`;
    try {
        const result = await pool.query(sql, [identifier]);
        const user = result.rows[0];

        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials. User not found.' });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            res.status(200).json({
                success: true,
                message: 'Login successful!',
                user: { id: user.id, email: user.email }
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
// Повний список ваших сторінок, які обслуговуються статично
['index.html', 'login-page.html', 'sign_up-page.html', 'profile.html', 'assets.html', 'order.html', 'account.html', 'settings.html', 'markets.html', 'trading-page.html']
    .forEach(page => {
        app.get(`/${page}`, (req, res) => res.sendFile(path.join(__dirname, page)));
        if (page === 'index.html') { // Для кореневого шляху
            app.get('/', (req, res) => res.sendFile(path.join(__dirname, page)));
        }
    });

// --- Запуск сервера ---
app.listen(port, () => {
    console.log(`YuMa MVP Server is running on http://localhost:${port}`);
});

// --- Обробка закриття сервера ---
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
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);і