import { app } from './app.js';
import { CONFIG } from './config.js';
import { runMigrations } from './database/migrations.js';

runMigrations();

app.listen(CONFIG.PORT, '0.0.0.0', () => {
  console.log(`[PS5 Backend API] Running on http://0.0.0.0:${CONFIG.PORT} in ${CONFIG.NODE_ENV} mode`);
});
