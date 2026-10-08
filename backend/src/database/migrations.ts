import { db, initDatabase } from './db.js';
import fs from 'fs';
import path from 'path';

export function runMigrations() {
  initDatabase();

  // Clean up any stale/legacy model rows from early development iterations
  db.prepare(`
    DELETE FROM model_metadata
    WHERE model_id = 'message-scam-intent'
       OR id IN ('mdl_url-phishing_1.0.0', 'mdl_text-scam_1.0.0', 'mdl_text-scam_2.0.0', 'mdl_message-scam-intent_1.0.0')
  `).run();

  // Seed authoritative model metadata
  const mlModelsDir = path.resolve(__dirname, '../../../ml/models');
  if (fs.existsSync(mlModelsDir)) {
    // 1. URL Phishing v2.0.0 (Active)
    const urlMetaPath = path.join(mlModelsDir, 'url_phishing/metadata.json');
    if (fs.existsSync(urlMetaPath)) {
      const meta = JSON.parse(fs.readFileSync(urlMetaPath, 'utf-8'));
      db.prepare(`
        INSERT OR REPLACE INTO model_metadata (id, model_id, version, dataset_version, artifact_hash, metrics, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `).run(
        'mdl_url_phishing_2.0.0',
        meta.model_id || 'url-phishing-2.0.0',
        '2.0.0',
        meta.dataset_version || 'url_phishing_curated_v2',
        meta.artifact_hash || 'b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156',
        JSON.stringify(meta)
      );
    }

    // 2. URL Phishing v1.0.0 (Archived Baseline)
    db.prepare(`
      INSERT OR REPLACE INTO model_metadata (id, model_id, version, dataset_version, artifact_hash, metrics, is_active)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(
      'mdl_url_phishing_1.0.0',
      'url-phishing-1.0.0',
      '1.0.0',
      'url_phishing_baseline_v1',
      '3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49',
      JSON.stringify({
        status: 'archived_baseline',
        superseded_by: 'url-phishing-2.0.0',
        description: 'Historical baseline model; superseded by v2.0.0 with 31-feature schema.'
      })
    );

    // 3. Text Scam v2.0.0 (Active)
    const textMetaPath = path.join(mlModelsDir, 'text_scam/metadata.json');
    if (fs.existsSync(textMetaPath)) {
      const meta = JSON.parse(fs.readFileSync(textMetaPath, 'utf-8'));
      db.prepare(`
        INSERT OR REPLACE INTO model_metadata (id, model_id, version, dataset_version, artifact_hash, metrics, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `).run(
        'mdl_text_scam_2.0.0',
        meta.model_id || 'text-scam-2.0.0',
        '2.0.0',
        meta.dataset_version || 'email_message_scam_curated_v3',
        meta.artifact_hash || '3dd3b1713b667c64d3acb190be6673ea284efb88a9f69d4434dc1ed07e9c952c',
        JSON.stringify(meta)
      );
    }

    // 4. Text Scam v1.0.0 (Archived / Superseded)
    db.prepare(`
      INSERT OR REPLACE INTO model_metadata (id, model_id, version, dataset_version, artifact_hash, metrics, is_active)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(
      'mdl_text_scam_1.0.0',
      'text-scam-1.0.0',
      '1.0.0',
      'email_message_scam_curated_v1',
      'fc533b14161475482661f73cb34e400991586a327cff47c34e246379a69b1ab5',
      JSON.stringify({
        status: 'archived_superseded',
        superseded_by: 'text-scam-2.0.0',
        vectorizer_hash: '82dec31d11037ea219d430027341f3988792c55c4c97b93a9328a858962bd95e',
        description: 'Superseded by text-scam-2.0.0 after OOD generalization audit revealed high false-positive rates on conversational OOD data.'
      })
    );
  }
}
