/**
 * AuthShield 360 - Server entry point
 * Boots the Express application, initialises SQLite, serves the static
 * dashboard and mounts the /api router.
 */
import express from 'express';
import path from 'node:path';
import { initDb } from './db.js';
import { FRONTEND_DIR } from './config.js';
import apiRouter from './routes.js';
import { log } from './console.js';

const PORT = process.env.PORT || 4000;
const app = express();

app.locals.sidSet = new Map();

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Tiny request logger for the SOC banner (avoids noisy console)
app.use((req, _res, next) => {
    if (req.path.startsWith('/api/stream')) return next();
    log.http(`${req.method} ${req.originalUrl}`);
    next();
});

// API + health
app.use('/api', apiRouter);

// Static SPA (frontend/ — decoupled from the API)
app.use(express.static(FRONTEND_DIR, { extensions: ['html'] }));
app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
});

// Boot
try {
    initDb(false);
    log.banner();
    const server = app.listen(PORT, () => log.start(PORT));
    server.on('error', (err) => { log.error(err.message); process.exit(1); });
} catch (err) {
    log.error(String(err && err.stack || err));
    process.exit(1);
}

export { app };