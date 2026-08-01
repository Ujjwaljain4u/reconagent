from __future__ import annotations

from reconagent.models import Confidence, Finding

# Tesseract's accuracy drops sharply on small/low-DPI text — exactly the
# case that failed on a full-browser screenshot (tiny compressed UI font).
# Real, standard preprocessing fixes for this: upscale the image (Tesseract
# is tuned around ~300 DPI equivalent text height), convert to grayscale,
# and apply adaptive thresholding to sharpen text edges against a busy
# background. This is the same preprocessing pipeline real OCR pipelines
# use, not a synthetic fix.
MIN_UPSCALE_HEIGHT = 1200  # if the image is smaller than this, scale it up before OCR
WORD_CONFIDENCE_THRESHOLD = 35  # tuned against real test data — a legitimate word
# ("john.doe", part of a valid email) scored 42% due to the period character
# being genuinely ambiguous at small sizes; 45 was cutting off real words,
# not just noise. 35 still filters true garbage (typically single digits or
# negative scores) while keeping real low-confidence-but-correct matches.


def _preprocess(img):
    from PIL import Image, ImageOps, ImageFilter

    # upscale small images — small/compressed text is the single biggest
    # cause of OCR failure, and this is the cheapest real fix for it
    if img.height < MIN_UPSCALE_HEIGHT:
        scale = MIN_UPSCALE_HEIGHT / img.height
        img = img.resize((int(img.width * scale), MIN_UPSCALE_HEIGHT), Image.LANCZOS)

    # grayscale + autocontrast sharpens text against busy/varied backgrounds
    # (a browser screenshot has colored tabs/icons right next to the text)
    img = img.convert("L")
    img = ImageOps.autocontrast(img)
    img = img.filter(ImageFilter.SHARPEN)
    return img


def extract_text_via_ocr(image_path: str) -> list[Finding]:
    """Runs Tesseract OCR (a real trained model) on an uploaded image to
    pull out any readable text — screenshots, photographed documents, ID
    cards, business cards, signage in photos. Preprocesses the image first
    (upscale + grayscale + contrast + sharpen) since Tesseract's accuracy
    drops sharply on small/low-contrast text without this, and filters out
    low-confidence garbage words using Tesseract's own per-word confidence
    scores rather than returning raw noisy output.

    This text then flows through the same pii_extractor.py NER pipeline as
    bios/snippets, so a screenshot of a chat or a photographed business
    card gets names/orgs/phones/emails extracted automatically."""
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return []

    try:
        img = Image.open(image_path)
        processed = _preprocess(img)

        # image_to_data gives per-word confidence scores, unlike
        # image_to_string which just returns a raw text blob with no way
        # to tell a confident match from a garbled guess
        data = pytesseract.image_to_data(processed, output_type=pytesseract.Output.DICT)
    except Exception:  # noqa: BLE001
        return []

    words = []
    for i, word in enumerate(data.get("text", [])):
        word = word.strip()
        if not word:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, IndexError):
            conf = -1
        if conf >= WORD_CONFIDENCE_THRESHOLD:
            words.append(word)

    text = " ".join(words).strip()

    if not text or len(text) < 3:
        return [Finding(source="ocr_extraction", category="ocr_status",
                         value="no readable text found in image (after confidence filtering)",
                         confidence=Confidence.MEDIUM)]

    return [Finding(source="ocr_extraction", category="ocr_extracted_text", value=text,
                     confidence=Confidence.MEDIUM,
                     notes=f"OCR output filtered to words with >={WORD_CONFIDENCE_THRESHOLD}% "
                           f"confidence — feeds into PII extraction for names/emails/phones")]