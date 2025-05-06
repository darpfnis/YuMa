// backend/server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    // Для локальної розробки можна тут тимчасово задати:
    // connectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_database_name_for_pg";
    if (!connectionString) process.exit(1);
}
const pool = new Pool({
    connectionString: connectionString,
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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Обслуговування статичних файлів з папки frontend ---
// __dirname тут буде .../gdc/backend/
// Нам потрібно вказати шлях до .../gdc/frontend/
const frontendPath = path.join(__dirname, '..', 'frontend');
// Всі запити, що починаються з / (крім API та спеціальних HTML маршрутів),
// будуть шукати файли в папці frontendPath
// Наприклад, /css/styles.css -> .../gdc/frontend/css/styles.css
// Або /js/script.js -> .../gdc/frontend/js/script.js
app.use(express.static(frontendPath));


// --- API Ендпоінти (/auth/register, /auth/login) ---
// Ваш код для API залишається тут (як для PostgreSQL)
app.post('/auth/register', async (req, res) => { /* ... ваш код ... */ });
app.post('/auth/login', async (req, res) => { /* ... ваш код ... */ });


// --- Обслуговування HTML сторінок ---
// Головна сторінка (index.html тепер в frontend/html/)
app.get('/', (req, res) => {
    res.sendFile(path.join(frontendPath, 'html', 'index.html'));
});

// Інші HTML сторінки (всі з папки frontend/html/)
const htmlPages = [
    'login-page.html', 'sign_up-page.html', 'profile.html',
    'assets.html', 'order.html', 'account.html', 'settings.html',
    'markets.html', 'trading-page.html', 'buy_crypto-page.html',
    'futures-page.html', 'spot-page.html'
    // Додайте сюди ВСІ ваші HTML сторінки з папки frontend/html/
];

htmlPages.forEach(page => {
    // Щоб URL в браузері був http://your-app.onrender.com/login-page.html
    app.get(`/${page}`, (req, res) => {
        res.sendFile(path.join(frontendPath, 'html', page));
    });
});

app.listen(port, () => {
    console.log(`YuMa Backend Server is running on http://localhost:${port}`);
});

async function gracefulShutdown() { /* ... ваш код для закриття пулу ... */ }
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);