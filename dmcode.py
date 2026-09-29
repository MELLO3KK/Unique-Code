"""dmcode - a scannable 2D barcode that looks like a QR code but is NOT one.

It generates a Data Matrix (ECC200) symbol, styled with rounded modules and
QR-like colors so it visually resembles a QR code at a glance. Any modern
phone scanner (Google Lens, iOS Camera, ZXing-based apps) can scan it.

Pure-Python generation via zxing-cpp; rendering & self-verification via Pillow.
"""

import io

import numpy as np
import zxingcpp
from PIL import Image, ImageDraw

MAX_TEXT_BYTES = 800  # keep symbols comfortably sized for phone cameras


class DMCodeError(ValueError):
    """Raised when the requested content/style cannot produce a valid code."""


def _text_to_matrix(text: str) -> np.ndarray:
    """Encode text into a Data Matrix module grid (bool array, True = dark)."""
    data = text.encode("utf-8")
    if not data:
        raise DMCodeError("The message is empty.")
    if len(data) > MAX_TEXT_BYTES:
        raise DMCodeError(
            f"Message too long ({len(data)} bytes); the limit is {MAX_TEXT_BYTES}."
        )

    bc = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.DataMatrix)
    if not bc.valid:
        raise DMCodeError(f"Could not encode the message: {bc.error}")

    img = bc.to_image(1)  # 1 pixel per module
    arr = np.asarray(img)
    # zxing-cpp's to_image() adds a one-module white margin around the symbol;
    # crop back to the actual module grid via the bounding box of dark pixels.
    matrix = arr == 0  # zxing renders dark modules as 0
    rows = np.where(matrix.any(axis=1))[0]
    cols = np.where(matrix.any(axis=0))[0]
    if len(rows) == 0 or len(cols) == 0:
        raise DMCodeError("Could not extract the module grid from the encoding.")
    return matrix[rows.min():rows.max() + 1, cols.min():cols.max() + 1]


def render(
    matrix: np.ndarray,
    scale: int = 10,
    quiet_zone: int = 4,
    fg: tuple = (26, 35, 126),
    bg: tuple = (255, 255, 255),
    rounded: bool = True,
) -> Image.Image:
    """Draw the module matrix as a QR-styled RGB image (rounded modules)."""
    rows, cols = matrix.shape
    pad = quiet_zone * scale
    if rounded:
        # Rounded dots break Data Matrix edge-detection on rectangular
        # symbols, so keep the QR-like look only for square symbols.
        rounded = rows == cols
    width = cols * scale + 2 * pad
    height = rows * scale + 2 * pad

    img = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(img)

    inset = 1 if rounded else 0
    radius = max(1, (scale - 2 * inset) // 3) if rounded else 0

    for r in range(rows):
        for c in range(cols):
            if not matrix[r, c]:
                continue
            x0 = pad + c * scale + inset
            y0 = pad + r * scale + inset
            x1 = pad + (c + 1) * scale - inset
            y1 = pad + (r + 1) * scale - inset
            if rounded and radius > 0:
                draw.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=fg)
            else:
                # Fill exactly the module cell (inclusive end coords) so
                # neighbouring dark modules merge into solid bars.
                draw.rectangle([pad + c * scale, pad + r * scale,
                                pad + (c + 1) * scale - 1,
                                pad + (r + 1) * scale - 1], fill=fg)
    return img


def verify(image: Image.Image, expected_text: str) -> bool:
    """Decode our own rendered image to prove it is actually scannable."""
    results = zxingcpp.read_barcodes(
        image, formats=zxingcpp.BarcodeFormat.DataMatrix
    )
    return any(r.text == expected_text for r in results)


# Color presets exposed to the UI: name -> (label, fg, bg)
STYLES = {
    "classic": ("Classic (indigo on white)", (26, 35, 126), (255, 255, 255)),
    "qrblack": ("QR look-alike (black on white)", (17, 17, 17), (255, 255, 255)),
    "ocean": ("Ocean (teal on ice)", (8, 94, 104), (236, 250, 250)),
    "sunset": ("Sunset (dark red on cream)", (122, 22, 22), (255, 244, 229)),
    "forest": ("Forest (green on mint)", (16, 78, 40), (235, 250, 238)),
    "midnight": ("Midnight (white on navy)", (240, 244, 255), (15, 23, 42)),
}


def generate(text: str, style: str = "classic", scale: int = 10,
             rounded: bool = True) -> Image.Image:
    """Full pipeline: text -> Data Matrix modules -> styled image -> verified."""
    label_fg, label_bg = STYLES.get(style, STYLES["classic"])[1:]
    matrix = _text_to_matrix(text)
    image = render(matrix, scale=scale, fg=label_fg, bg=label_bg, rounded=rounded)

    if not verify(image, text):
        # Extremely unlikely; retry once without rounding as a safety net.
        image = render(matrix, scale=scale, fg=label_fg, bg=label_bg,
                       rounded=False)
        if not verify(image, text):
            raise DMCodeError("Generated image failed self-verification.")
    return image


def to_png_bytes(image: Image.Image) -> bytes:
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()
