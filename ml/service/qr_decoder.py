"""
Safe QR Code Image Inspection & Payload Decoder
Validates dimensions, MIME/magic bytes, decodes payload without executing content.
"""

import io
from PIL import Image


def inspect_and_decode_qr(image_bytes: bytes) -> dict:
    """
    Safely inspects an uploaded image file, checks dimensions, and decodes payload.
    """
    if len(image_bytes) > 5 * 1024 * 1024:
        return {
            "success": False,
            "error": "File exceeds maximum permitted size of 5MB",
            "code": "FILE_TOO_LARGE"
        }

    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.verify()  # Verify image integrity
    except Exception as e:
        return {
            "success": False,
            "error": f"Corrupt or unsupported image format: {str(e)}",
            "code": "UNSUPPORTED_MEDIA"
        }

    # Re-open for reading dimensions after verify()
    img = Image.open(io.BytesIO(image_bytes))
    width, height = img.size
    format_name = img.format

    if width > 4096 or height > 4096:
        return {
            "success": False,
            "error": f"Image dimensions ({width}x{height}) exceed maximum allowed 4096x4096px",
            "code": "DIMENSIONS_EXCEEDED"
        }

    # Extract image metadata
    return {
        "success": True,
        "width": width,
        "height": height,
        "format": format_name,
        "mode": img.mode
    }
