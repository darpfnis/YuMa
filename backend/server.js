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
    // Для локальної розробки, якщо DATABASE_URL не встановлено, можна тут тимчасово задати рядок підключення
    // до вашого локального PostgreSQL, якщо ви його використовуєте для тестів.
    // Наприклад:
    // const localDevConnectionString = "postgres://your_local_user:your_local_password@localhost:5432/your_local_db_name";
    // if (process.env.NODE_ENV !== 'production' && localDevConnectionString) {
    //     console.warn("DATABASE_URL not set, using local development connection string.");
    //     // connectionString = localDevConnectionString; // НЕ РОЗКОМЕНТОВУЙТЕ ДЛЯ RENDER
    // } else {
    //    process.exit(1); // Якщо на Render немає DATABASE_URL, це критична помилка
    // }
    process.exit(1); // На Render DATABASE_URL має бути завжди встановлено
}

const pool = new Pool({
    connectionString: connectionString,
    // SSL потрібен для підключення до баз даних на Render та багатьох інших хмарних провайдерах
    // process.env.NODE_ENV автоматично встановлюється в 'production' на Render
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client for PostgreSQL on startup:', err.stack);
        // Не завершуємо процес тут, щоб дати можливість побачити інші логи,
        // але запити до БД не працюватимуть.
        // В ідеалі, додаток не має стартувати без успішного підключення до БД.
    } else {
        console.log('Successfully connected to the PostgreSQL database via pool on startup.');
        if (client) client.release(); // Важливо звільнити клієнта після перевірки
    }
});

// --- Middleware ---
app.use(express.json()); // Для парсингу JSON тіла запитів
app.use(express.urlencoded({ extended: true })); // Для парсингу URL-encoded тіла запитів

// --- Обслуговування статичних файлів ---
// __dirname тут буде .../gdc/backend/
// Шлях до папки frontend, яка знаходиться на один рівень вище
const frontendPath = path.join(__dirname, '..', 'frontend');
// Шлях до кореневої папки проекту (де лежить index.html)
const projectRootPath = path.join(__dirname, '..');

// 1. Обслуговуємо вміст папки /frontend (наприклад, /css, /js, /html)
// Запит /frontend/css/styles.css буде шукати .../gdc/frontend/css/styles.css
// Це потрібно, оскільки ваші HTML-файли посилаються на CSS через /frontend/css/...
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
        console.error("Error during user registration (PostgreSQL):", error.message, error.stack);
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
        console.error("Error during login (PostgreSQL):", error.message, error.stack);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});


// --- Обслуговування HTML сторінок ---

// Маршрут для головної сторінки (index.html знаходиться в корені проекту)
app.get('/', (req, res) => {
    const indexPath = path.join(projectRootPath, 'index.html');
    console.log(`[ROUTE /] Attempting to serve index.html from: ${indexPath}`);
    res.sendFile(indexPath, (err) => {
        if (err) {
            console.error(`[ROUTE /] Error sending index.html: ${err.message}`, err.stack);
            if (!res.headersSent) { // Перевіряємо, чи не були вже відправлені заголовки
                res.status(500).send("Error serving the main page.");
            }
        }
    });
});

// Якщо користувач явно запитує /index.html
app.get('/index.html', (req, res) => {
    const indexPath = path.join(projectRootPath, 'index.html');
    console.log(`[ROUTE /index.html] Attempting to serve index.html from: ${indexPath}`);
    res.sendFile(indexPath, (err) => {
        if (err) {
            console.error(`[ROUTE /index.html] Error sending index.html: ${err.message}`, err.stack);
            if (!res.headersSent) {
                res.status(500).send("Error serving the main page.");
            }
        }
    });
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
        const pagePath = path.join(frontendPath, 'html', page);
        console.log(`[ROUTE /${page}] Attempting to serve ${page} from: ${pagePath}`);
        res.sendFile(pagePath, (err) => {
            if (err) {
                console.error(`[ROUTE /${page}] Error sending ${page} (${pagePath}): ${err.message}`, err.stack);
                if (!res.headersSent) {
                    if (err.code === 'ENOENT') { // ENOENT = No such file or directory
                        res.status(404).send(`Cannot GET /${page}`);
                    } else {
                        res.status(500).send(`Error serving ${page}.`);
                    }
                }
            }
        });
    });
});


// --- Запуск сервера ---
app.listen(port, () => {
    console.log(`YuMa Backend Server is running on http://localhost:${port}`);
});

// --- Обробка закриття сервера (для коректного закриття пулу БД) ---
async function gracefulShutdown() {
    console.log('Received signal to terminate, shutting down gracefully.');
    try {
        if (pool) {
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
process.on('SIGTERM', gracefulShutdown); // Обробка сигналу завершення (наприклад, від Render)