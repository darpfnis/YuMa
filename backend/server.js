// backend/server.js
const express = require('express');
const { Pool } = require('pg'); // Драйвер для PostgreSQL
const bcrypt = require('bcryptjs');
const path = require('path');   // Вбудований модуль Node.js для роботи зі шляхами

const app = express();
// Render надасть PORT через змінну середовища, або використовуємо 3000 локально
const port = process.env.PORT || 3000;

// --- Налаштування Бази Даних PostgreSQL ---
const connectionString = process.env.DATABASE_URL; // Цю змінну надасть Render

if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    // Для локальної розробки, якщо DATABASE_URL не встановлено:
    // Замініть на ваш реальний рядок підключення до локального PostgreSQL, якщо тестуєте локально з PG
    // const localConnectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_database_name";
    // if (localConnectionString && process.env.NODE_ENV !== 'production') {
    //     console.log("Using local PostgreSQL connection string as DATABASE_URL is not set.");
    //     // connectionString = localConnectionString; // НЕ РОЗКОМЕНТОВУЙТЕ ЦЕ ДЛЯ RENDER
    // } else {
    //     process.exit(1); // Якщо на Render немає DATABASE_URL, це проблема
    // }
    process.exit(1); // Для Render DATABASE_URL має бути встановлено
}

const pool = new Pool({
    connectionString: connectionString,
    // SSL потрібен для підключення до баз даних на Render
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client for PostgreSQL:', err.stack);
        process.exit(1);
    }
    console.log('Successfully connected to the PostgreSQL database via pool.');
    if (client) client.release(); // Важливо звільнити клієнта після перевірки
});

// --- Middleware ---
app.use(express.json()); // Для парсингу JSON тіла запитів
app.use(express.urlencoded({ extended: true })); // Для парсингу URL-encoded тіла запитів

// --- Обслуговування статичних файлів ---
// __dirname тут буде .../gdc/backend/
// Вказуємо шлях до папки frontend, яка знаходиться на один рівень вище
const frontendPath = path.join(__dirname, '..', 'frontend');
// Вказуємо шлях до кореневої папки проекту (де лежить index.html)
const projectRootPath = path.join(__dirname, '..');

// Обслуговуємо вміст папки /frontend (наприклад, /css, /js)
// Запит /frontend/css/styles.css буде шукати .../gdc/frontend/css/styles.css
// Це важливо, оскільки ваші HTML-файли посилаються на CSS через /frontend/css/...
app.use('/frontend', express.static(frontendPath));


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

// Маршрут для головної сторінки (index.html знаходиться в корені проекту)
app.get('/', (req, res) => {
    // __dirname = .../gdc/backend/
    // path.join(__dirname, '..', 'index.html') = .../gdc/index.html
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Інші HTML сторінки (знаходяться в frontend/html/)
// Ці маршрути дозволять звертатися до сторінок за URL типу /login-page.html
const htmlPages = [
    'login-page.html', 'sign_up-page.html', 'profile.html',
    'assets.html', 'order.html', 'account.html', 'settings.html',
    'markets.html', 'trading-page.html', 'buy_crypto-page.html',
    'futures-page.html', 'spot-page.html'
    // Додайте сюди всі ваші HTML сторінки з папки frontend/html/
];

htmlPages.forEach(page => {
    app.get(`/${page}`, (req, res) => {
        // __dirname = .../gdc/backend/
        // path.join(__dirname, '..', 'frontend', 'html', page) = .../gdc/frontend/html/page_name.html
        res.sendFile(path.join(__dirname, '..', 'frontend', 'html', page));
    });
});


// --- Запуск сервера ---
app.listen(port, () => {
    console.log(`YuMa Backend Server is running on http://localhost:${port}`);
});

// --- Обробка закриття сервера (для коректного закриття пулу БД) ---
async function gracefulShutdown() {
    console.log('Received kill signal, shutting down gracefully.');
    try {
        if (pool) { // Перевіряємо, чи пул взагалі був ініціалізований
            await pool.end();
            console.log('PostgreSQL pool has ended.');
        }
        process.exit(0);
    } catch (e) {
        console.error('Error during shutdown:', e.stack);
        process.exit(1);
    }
}
process.on('SIGINT', gracefulShutdown); // Обробка Ctrl+C
process.on('SIGTERM', gracefulShutdown); // Обробка сигналу завершення