import { app } from './app.js';
import { CONFIG } from './config.js';
import { runMigrations } from './database/migrations.js';

try {
  runMigrations();
} catch (e) {
  console.warn('[Kawach DB Migration Notice]:', e);
}

const primaryPort = CONFIG.PORT || 8080;

app.listen(primaryPort, '0.0.0.0', () => {
  console.log(`[Kawach API] Running on http://0.0.0.0:${primaryPort} in ${CONFIG.NODE_ENV} mode`);
});

// Also bind secondary port if different (e.g. if primary is 8080, also open 5000)
const fallbackPort = primaryPort === 8080 ? 5000 : 8080;
try {
  const fallbackServer = app.listen(fallbackPort, '0.0.0.0', () => {
    console.log(`[Kawach API] Also running on fallback port http://0.0.0.0:${fallbackPort}`);
  });
  fallbackServer.on('error', (err: any) => {
    // Port might be in use or unavailable, log and continue
    console.log(`[Kawach API] Fallback port ${fallbackPort} notice: ${err.message}`);
  });
} catch {
  // Ignore fallback port errors
}
