"""Signature image intake.

The drawn-signature PNG is the only raw binary the browser ever sends, so it is treated as
hostile. Three separate things are being defended against:

1. **Resource exhaustion.** The declared dimensions are read from the header and checked *before a
   single pixel is decoded*, so a 4 KB file that claims to be 50000x50000 costs nothing.
2. **Smuggling.** Only PNG is accepted, and the output is re-encoded from raw pixel data into a
   brand-new image, so text chunks, ICC profiles, EXIF, private chunks and anything appended after
   ``IEND`` do not survive.
3. **Empty evidence.** A blank canvas is not a signature. An image with too little ink, or ink in
   too few places to be a stroke, is rejected rather than stamped onto a legal document.

The image is also trimmed to its ink so it fills the field rectangle instead of floating in
whatever margin the browser's canvas happened to have.
"""

from __future__ import annotations

import io
import threading
from typing import Final

from PIL import Image, ImageChops, UnidentifiedImageError

from esign.config import Settings
from esign.contracts import ValidationFailed

__all__ = [
    "MAX_SIGNATURE_PNG_DIMENSION",
    "MIN_SIGNATURE_PNG_DIMENSION",
    "sanitize_signature_png",
]

_PNG_MAGIC: Final[bytes] = b"\x89PNG\r\n\x1a\n"

#: Widest or tallest a signature canvas may be. Not in ``Settings`` -- see the module docstring in
#: ``__init__`` and the contract note in the report.
MAX_SIGNATURE_PNG_DIMENSION: Final[int] = 4000
MIN_SIGNATURE_PNG_DIMENSION: Final[int] = 8

#: Alpha at or below this counts as background.
_ALPHA_FLOOR: Final[int] = 32
#: Luminance at or above this counts as background for an opaque image.
_LUMA_CEILING: Final[int] = 220
#: A stroke has to cover at least this fraction of the trimmed box, and this many pixels.
_MIN_INK_FRACTION: Final[float] = 0.0015
_MIN_INK_PIXELS: Final[int] = 48

#: Serialises the one process-wide Pillow global this module has to touch. See below.
_decode_lock = threading.Lock()


def _extrema(band: Image.Image) -> tuple[float, float]:
    """``getextrema`` is typed for multi-band images; every call here is single-band."""
    low, high = band.getextrema()[:2]
    return float(low), float(high)  # type: ignore[arg-type]


def _ink_mask(image: Image.Image) -> Image.Image:
    """A 1-bit mask of everything that is not background.

    Handles both shapes a signature pad produces: strokes on transparency, and dark strokes on an
    opaque white background.
    """
    rgba = image.convert("RGBA")
    alpha = rgba.getchannel("A")
    opaque = alpha.point(lambda value: 255 if value > _ALPHA_FLOOR else 0)
    luma = rgba.convert("L")
    dark = luma.point(lambda value: 255 if value < _LUMA_CEILING else 0)
    alpha_min, _alpha_max = _extrema(alpha)
    if alpha_min < 255:
        # There is real transparency: the alpha channel is the authority, but a fully opaque white
        # region inside it is still background.
        return ImageChops.multiply(opaque, dark) if _extrema(dark)[1] else opaque
    return dark


def sanitize_signature_png(data: bytes, settings: Settings) -> bytes:
    """Implements ``DocumentService.sanitize_signature_png``."""
    if not data:
        raise ValidationFailed("signature image is empty", code="signature_image_empty")
    if len(data) > settings.max_signature_png_bytes:
        raise ValidationFailed("signature image exceeds the maximum size", code="signature_image_too_large")
    if not data.startswith(_PNG_MAGIC):
        raise ValidationFailed("signature image is not a PNG", code="signature_image_not_png")

    # Pillow's bomb guard is a process-wide global, so tightening it for this decode has to be
    # serialised or a concurrent request would run under -- or restore -- the wrong limit. The
    # explicit dimension and pixel checks below are the real defence; this only narrows Pillow's
    # own. Signature images are small and bounded, so the lock costs nothing that matters.
    with _decode_lock:
        return _decode_and_clean(data, settings)


def _decode_and_clean(data: bytes, settings: Settings) -> bytes:
    previous_limit = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = settings.max_signature_png_pixels
    try:
        try:
            image = Image.open(io.BytesIO(data))
        except Image.DecompressionBombError as exc:
            # Pillow reads the header, sees the declared size, and refuses before allocating.
            raise ValidationFailed(
                "signature image exceeds the maximum pixel count", code="signature_image_too_large"
            ) from exc
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            raise ValidationFailed("signature image could not be decoded", code="signature_image_undecodable") from exc

        if image.format != "PNG":
            raise ValidationFailed("signature image is not a PNG", code="signature_image_not_png")

        width, height = image.size
        if width < MIN_SIGNATURE_PNG_DIMENSION or height < MIN_SIGNATURE_PNG_DIMENSION:
            raise ValidationFailed("signature image is too small", code="signature_image_too_small")
        if width > MAX_SIGNATURE_PNG_DIMENSION or height > MAX_SIGNATURE_PNG_DIMENSION:
            raise ValidationFailed("signature image exceeds the maximum dimensions", code="signature_image_too_large")
        if width * height > settings.max_signature_png_pixels:
            raise ValidationFailed("signature image exceeds the maximum pixel count", code="signature_image_too_large")

        try:
            image.seek(0)  # an animated PNG contributes its first frame and nothing else
            image.load()
        except (Image.DecompressionBombError, OSError, ValueError, EOFError) as exc:
            raise ValidationFailed("signature image could not be decoded", code="signature_image_undecodable") from exc
    finally:
        Image.MAX_IMAGE_PIXELS = previous_limit

    mask = _ink_mask(image)
    box = mask.getbbox()
    if box is None:
        raise ValidationFailed("signature image is blank", code="signature_image_blank")

    # ``histogram`` rather than iterating pixels: the mask is single-band, so bucket 255 is the
    # ink count, and nothing materialises a list of a few million integers.
    ink_pixels = mask.histogram()[255]
    box_area = max(1, (box[2] - box[0]) * (box[3] - box[1]))
    if ink_pixels < _MIN_INK_PIXELS or ink_pixels / box_area < _MIN_INK_FRACTION:
        raise ValidationFailed("signature image is blank or nearly blank", code="signature_image_blank")

    rgba = image.convert("RGBA").crop(box)
    # Rebuild from raw pixels so nothing from the original file -- chunks, profiles, palettes,
    # comments, anything appended after IEND -- can ride along into the stored evidence.
    clean = Image.frombytes("RGBA", rgba.size, rgba.tobytes())

    out = io.BytesIO()
    clean.save(out, format="PNG", optimize=True)
    encoded = out.getvalue()
    if len(encoded) > settings.max_signature_png_bytes:
        raise ValidationFailed("signature image exceeds the maximum size", code="signature_image_too_large")
    return encoded
