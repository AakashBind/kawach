import { app } from './app.js';
import { CONFIG } from './config.js';
import { runMigrations } from './database/migrations.js';

runMigrations();

app.listen(CONFIG.PORT, () => {
  console.log(`[PS5 Backend API] Running on http://127.0.0.1:${CONFIG.PORT} in ${CONFIG.NODE_ENV} mode`);
});
