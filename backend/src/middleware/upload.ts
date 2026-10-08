import multer from 'multer';
import { Request } from 'express';
import { CONFIG } from '../config.js';

const storage = multer.memoryStorage();

const ALLOWED_MIME_TYPES = ['image/png', 'image/jpeg', 'image/webp'];

function fileFilter(_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('UNSUPPORTED_MEDIA: Only PNG, JPEG, and WebP images are allowed.'));
  }
}

export const qrUpload = multer({
  storage,
  limits: {
    fileSize: CONFIG.MAX_UPLOAD_BYTES,
    files: 1
  },
  fileFilter
});
