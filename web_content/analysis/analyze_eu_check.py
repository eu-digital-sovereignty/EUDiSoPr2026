#!/usr/bin/env python3
import argparse
import csv
import hashlib
import html
import json
import os
import re
import sqlite3
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

try:
    from skimage.metrics import structural_similarity as ssim
except Exception:  # pragma: no cover
    ssim = None


THRESHOLD = 24
MAX_VERTICAL_SHIFT = 400
ALIGN_SAMPLE_STEP = 4
ALIGN_BANDS = 12
MIN_BAND_HEIGHT = 160
BLUR_RADIUS = 1.5
BLUR_DOWNSAMPLE = 2
WHITE_PIXEL_THRESHOLD = 245
BLANK_WHITE_FRACTION_THRESHOLD = 0.995
BLANK_SAMPLE_MAX = 200


def parse_args():
    parser = argparse.ArgumentParser(description='Analyze EU-check screenshot triplets.')
    parser.add_argument('--sqlite-path', default='crawler_eu_check.sqlite')
    parser.add_argument('--output-dir', default='eu_check_analysis')
    parser.add_argument('--page-url', default=None)
    return parser.parse_args()


def ensure_same_size(a: Image.Image, b: Image.Image):
    if a.size != b.size:
        width = min(a.width, b.width)
        height = min(a.height, b.height)
        a = a.crop((0, 0, width, height))
        b = b.crop((0, 0, width, height))
    return a, b


def normalize_html_text(content: str):
    return ' '.join(str(content or '').split())


def extract_visible_text(content: str):
    normalized = str(content or '')
    normalized = re.sub(r'(?is)<script\b[^>]*>.*?</script>', ' ', normalized)
    normalized = re.sub(r'(?is)<style\b[^>]*>.*?</style>', ' ', normalized)
    normalized = re.sub(r'(?is)<!--.*?-->', ' ', normalized)
    normalized = re.sub(r'(?s)<[^>]+>', ' ', normalized)
    normalized = html.unescape(normalized)
    return ' '.join(normalized.split())


def tokenize_text(content: str):
    return re.findall(r'[A-Za-z0-9_]{2,}', str(content or '').lower())


def html_metrics(left_path: str, right_path: str):
    if not left_path or not right_path or not os.path.exists(left_path) or not os.path.exists(right_path):
        return {
            'html_similarity_ratio': None,
            'html_equal': None,
            'html_left_length': None,
            'html_right_length': None,
            'html_left_sha256': None,
            'html_right_sha256': None,
            'content_similarity_ratio': None,
            'content_equal': None,
            'content_left_length': None,
            'content_right_length': None,
            'content_token_jaccard': None,
            'left_raw_contains_err_blocked_by_client': None,
            'right_raw_contains_err_blocked_by_client': None,
        }

    left_raw = Path(left_path).read_text(encoding='utf-8', errors='ignore')
    right_raw = Path(right_path).read_text(encoding='utf-8', errors='ignore')
    left_html = normalize_html_text(left_raw)
    right_html = normalize_html_text(right_raw)
    left_hash = hashlib.sha256(left_html.encode('utf-8')).hexdigest()
    right_hash = hashlib.sha256(right_html.encode('utf-8')).hexdigest()
    html_equal = int(left_hash == right_hash)
    max_len = max(len(left_html), len(right_html), 1)
    similarity_ratio = round(1.0 - (abs(len(left_html) - len(right_html)) / max_len), 6)

    left_content = extract_visible_text(left_html)
    right_content = extract_visible_text(right_html)
    left_content_hash = hashlib.sha256(left_content.encode('utf-8')).hexdigest()
    right_content_hash = hashlib.sha256(right_content.encode('utf-8')).hexdigest()
    content_equal = int(left_content_hash == right_content_hash)
    content_max_len = max(len(left_content), len(right_content), 1)
    content_similarity_ratio = round(1.0 - (abs(len(left_content) - len(right_content)) / content_max_len), 6)

    left_tokens = set(tokenize_text(left_content))
    right_tokens = set(tokenize_text(right_content))
    union = left_tokens | right_tokens
    token_jaccard = round(len(left_tokens & right_tokens) / len(union), 6) if union else 1.0

    return {
        'html_similarity_ratio': similarity_ratio,
        'html_equal': html_equal,
        'html_left_length': len(left_html),
        'html_right_length': len(right_html),
        'html_left_sha256': left_hash,
        'html_right_sha256': right_hash,
        'content_similarity_ratio': content_similarity_ratio,
        'content_equal': content_equal,
        'content_left_length': len(left_content),
        'content_right_length': len(right_content),
        'content_token_jaccard': token_jaccard,
        'left_raw_contains_err_blocked_by_client': int('ERR_BLOCKED_BY_CLIENT' in left_raw),
        'right_raw_contains_err_blocked_by_client': int('ERR_BLOCKED_BY_CLIENT' in right_raw),
    }


def find_best_vertical_shift(left_np: np.ndarray, right_np: np.ndarray):
    left_gray = (0.299 * left_np[:, :, 0] + 0.587 * left_np[:, :, 1] + 0.114 * left_np[:, :, 2]).astype(np.float32)
    right_gray = (0.299 * right_np[:, :, 0] + 0.587 * right_np[:, :, 1] + 0.114 * right_np[:, :, 2]).astype(np.float32)

    sample_step = ALIGN_SAMPLE_STEP
    left_small = left_gray[::sample_step, ::sample_step]
    right_small = right_gray[::sample_step, ::sample_step]
    max_shift_small = min(MAX_VERTICAL_SHIFT // sample_step, max(0, min(left_small.shape[0], right_small.shape[0]) - 10))

    best_shift = 0
    best_score = None
    for shift_small in range(-max_shift_small, max_shift_small + 1):
        if shift_small >= 0:
            left_slice = left_small[:left_small.shape[0] - shift_small, :]
            right_slice = right_small[shift_small:, :]
        else:
            left_slice = left_small[-shift_small:, :]
            right_slice = right_small[:right_small.shape[0] + shift_small, :]

        if left_slice.size == 0 or right_slice.size == 0:
            continue

        overlap_rows = min(left_slice.shape[0], right_slice.shape[0])
        overlap_cols = min(left_slice.shape[1], right_slice.shape[1])
        left_slice = left_slice[:overlap_rows, :overlap_cols]
        right_slice = right_slice[:overlap_rows, :overlap_cols]
        if overlap_rows < 20 or overlap_cols < 20:
            continue

        score = float(np.mean(np.abs(left_slice - right_slice)))
        if best_score is None or score < best_score:
            best_score = score
            best_shift = shift_small * sample_step

    return int(best_shift)


def apply_vertical_shift(left: Image.Image, right: Image.Image, shift_px: int):
    left, right = ensure_same_size(left, right)
    width = min(left.width, right.width)
    height = min(left.height, right.height)
    left = left.crop((0, 0, width, height))
    right = right.crop((0, 0, width, height))

    if shift_px > 0:
        aligned_left = left.crop((0, 0, width, height - shift_px))
        aligned_right = right.crop((0, shift_px, width, height))
    elif shift_px < 0:
        offset = -shift_px
        aligned_left = left.crop((0, offset, width, height))
        aligned_right = right.crop((0, 0, width, height - offset))
    else:
        aligned_left = left
        aligned_right = right

    return ensure_same_size(aligned_left, aligned_right)


def apply_band_alignment(left: Image.Image, right: Image.Image):
    left, right = ensure_same_size(left, right)
    width = min(left.width, right.width)
    height = min(left.height, right.height)
    left = left.crop((0, 0, width, height))
    right = right.crop((0, 0, width, height))

    band_count = max(1, min(ALIGN_BANDS, height // MIN_BAND_HEIGHT if height >= MIN_BAND_HEIGHT else 1))
    band_edges = np.linspace(0, height, band_count + 1, dtype=int)

    left_bands = []
    right_bands = []
    band_shifts = []

    for idx in range(band_count):
        y0 = int(band_edges[idx])
        y1 = int(band_edges[idx + 1])
        left_band = left.crop((0, y0, width, y1))
        right_band = right.crop((0, y0, width, y1))
        left_np = np.asarray(left_band, dtype=np.int16)
        right_np = np.asarray(right_band, dtype=np.int16)
        shift_px = find_best_vertical_shift(left_np, right_np)
        aligned_left_band, aligned_right_band = apply_vertical_shift(left_band, right_band, shift_px)
        left_bands.append(aligned_left_band)
        right_bands.append(aligned_right_band)
        band_shifts.append(int(shift_px))

    aligned_height = min(sum(img.height for img in left_bands), sum(img.height for img in right_bands))
    aligned_left = Image.new('RGB', (width, aligned_height))
    aligned_right = Image.new('RGB', (width, aligned_height))

    cursor = 0
    for left_band, right_band in zip(left_bands, right_bands):
        band_height = min(left_band.height, right_band.height, aligned_height - cursor)
        if band_height <= 0:
            break
        aligned_left.paste(left_band.crop((0, 0, width, band_height)), (0, cursor))
        aligned_right.paste(right_band.crop((0, 0, width, band_height)), (0, cursor))
        cursor += band_height

    if cursor < aligned_height:
        aligned_left = aligned_left.crop((0, 0, width, cursor))
        aligned_right = aligned_right.crop((0, 0, width, cursor))

    return aligned_left, aligned_right, band_shifts


def compute_diff_metrics(left_img: Image.Image, right_img: Image.Image, threshold: int):
    left_np = np.asarray(left_img, dtype=np.int16)
    right_np = np.asarray(right_img, dtype=np.int16)
    abs_diff = np.abs(left_np - right_np)
    diff_mask = (abs_diff.max(axis=2) >= threshold).astype(np.uint8)
    diff_pixels = int(diff_mask.sum())
    total_pixels = int(diff_mask.shape[0] * diff_mask.shape[1])
    diff_pct = round((diff_pixels / total_pixels) * 100, 4) if total_pixels else 0.0
    mean_abs_diff = round(float(abs_diff.mean()), 4)
    bbox = Image.fromarray((diff_mask * 255).astype(np.uint8)).getbbox()
    return {
        'diff_mask': diff_mask,
        'diff_pixels': diff_pixels,
        'total_pixels': total_pixels,
        'diff_pct': diff_pct,
        'mean_abs_diff': mean_abs_diff,
        'bbox': bbox,
    }


def blur_downsample(image: Image.Image):
    blurred = image.filter(ImageFilter.GaussianBlur(radius=BLUR_RADIUS))
    new_width = max(1, blurred.width // BLUR_DOWNSAMPLE)
    new_height = max(1, blurred.height // BLUR_DOWNSAMPLE)
    return blurred.resize((new_width, new_height), Image.Resampling.BILINEAR)


def load_rgb_image(image_path: str):
    with Image.open(image_path) as image:
        return image.convert('RGB')


def blank_white_metrics(image: Image.Image):
    sample = image.resize((min(BLANK_SAMPLE_MAX, image.width), min(BLANK_SAMPLE_MAX, image.height)), Image.Resampling.BILINEAR)
    sample_np = np.asarray(sample, dtype=np.uint8)
    white_mask = (sample_np[:, :, 0] >= WHITE_PIXEL_THRESHOLD) & (sample_np[:, :, 1] >= WHITE_PIXEL_THRESHOLD) & (sample_np[:, :, 2] >= WHITE_PIXEL_THRESHOLD)
    white_fraction = float(white_mask.mean()) if white_mask.size else 0.0
    return {
        'white_fraction': round(white_fraction, 6),
        'is_blank_white': int(white_fraction >= BLANK_WHITE_FRACTION_THRESHOLD),
    }


def image_metrics_from_images(left: Image.Image, right: Image.Image):
    left = left.copy()
    right = right.copy()
    left, right = ensure_same_size(left, right)

    left_aligned, right_aligned, band_shifts = apply_band_alignment(left, right)

    raw_metrics = compute_diff_metrics(left_aligned, right_aligned, THRESHOLD)

    blurred_left = blur_downsample(left_aligned)
    blurred_right = blur_downsample(right_aligned)
    blurred_metrics = compute_diff_metrics(blurred_left, blurred_right, THRESHOLD)

    ssim_value = None
    if ssim is not None:
        ssim_value = round(float(ssim(np.asarray(left_aligned), np.asarray(right_aligned), channel_axis=2)), 6)

    return {
        'left': left_aligned,
        'right': right_aligned,
        'diff_mask': raw_metrics['diff_mask'],
        'diff_pixels': raw_metrics['diff_pixels'],
        'total_pixels': raw_metrics['total_pixels'],
        'diff_pct': raw_metrics['diff_pct'],
        'mean_abs_diff': raw_metrics['mean_abs_diff'],
        'blurred_diff_pct': blurred_metrics['diff_pct'],
        'blurred_mean_abs_diff': blurred_metrics['mean_abs_diff'],
        'ssim': ssim_value,
        'bbox': raw_metrics['bbox'],
        'vertical_shift_px': int(round(float(np.median(band_shifts)))) if band_shifts else 0,
        'band_shifts_json': json.dumps(band_shifts),
    }


def save_overlay(base_image: Image.Image, diff_mask: np.ndarray, bbox, out_path: Path):
    overlay = base_image.copy().convert('RGBA')
    pixels = overlay.load()
    height, width = diff_mask.shape
    for y in range(height):
        for x in range(width):
            if diff_mask[y, x]:
                _, g, b, _ = pixels[x, y]
                pixels[x, y] = (255, max(0, g - 80), max(0, b - 80), 255)
    if bbox:
        draw = ImageDraw.Draw(overlay)
        draw.rectangle(bbox, outline=(255, 0, 0, 255), width=3)
    overlay.save(out_path)


def derive_html_path(screenshot_path: str):
    if not screenshot_path:
        return None
    return str(Path(screenshot_path).with_suffix('.html'))


def ensure_analysis_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS eu_check_analysis (
            page_id INTEGER PRIMARY KEY,
            endpoint_label TEXT NOT NULL,
            page_domain TEXT NOT NULL,
            page_url TEXT NOT NULL,
            dynamic_vertical_shift_px INTEGER,
            dynamic_band_shifts_json TEXT,
            dynamic_diff_pct REAL,
            dynamic_blurred_diff_pct REAL,
            dynamic_mean_abs_diff REAL,
            dynamic_blurred_mean_abs_diff REAL,
            blocked_vertical_shift_px INTEGER,
            blocked_band_shifts_json TEXT,
            blocked_diff_pct REAL,
            blocked_blurred_diff_pct REAL,
            blocked_mean_abs_diff REAL,
            blocked_blurred_mean_abs_diff REAL,
            net_blocked_minus_dynamic_diff_pct REAL,
            net_blocked_minus_dynamic_blurred_diff_pct REAL,
            dynamic_html_similarity_ratio REAL,
            dynamic_html_equal INTEGER,
            dynamic_content_similarity_ratio REAL,
            dynamic_content_equal INTEGER,
            dynamic_content_token_jaccard REAL,
            blocked_html_similarity_ratio REAL,
            blocked_html_equal INTEGER,
            blocked_content_similarity_ratio REAL,
            blocked_content_equal INTEGER,
            blocked_content_token_jaccard REAL,
            normal_1_white_fraction REAL,
            blocked_white_fraction REAL,
            normal_2_white_fraction REAL,
            normal_1_blank_white INTEGER,
            blocked_blank_white INTEGER,
            normal_2_blank_white INTEGER,
            blocked_browser_error INTEGER,
            blocked_error_marker TEXT,
            dynamic_overlay TEXT,
            blocked_overlay TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)



    for ddl in [
        "ALTER TABLE eu_check_analysis ADD COLUMN normal_1_white_fraction REAL",
        "ALTER TABLE eu_check_analysis ADD COLUMN blocked_white_fraction REAL",
        "ALTER TABLE eu_check_analysis ADD COLUMN normal_2_white_fraction REAL",
        "ALTER TABLE eu_check_analysis ADD COLUMN normal_1_blank_white INTEGER",
        "ALTER TABLE eu_check_analysis ADD COLUMN blocked_blank_white INTEGER",
        "ALTER TABLE eu_check_analysis ADD COLUMN normal_2_blank_white INTEGER",
    ]:
        try:
            conn.execute(ddl)
        except sqlite3.OperationalError:
            pass

    for ddl in [
        "ALTER TABLE eu_check_analysis ADD COLUMN blocked_browser_error INTEGER",
        "ALTER TABLE eu_check_analysis ADD COLUMN blocked_error_marker TEXT",
    ]:
        try:
            conn.execute(ddl)
        except sqlite3.OperationalError:
            pass

def upsert_analysis_row(conn, row):
    conn.execute("""
        INSERT INTO eu_check_analysis (
            page_id, endpoint_label, page_domain, page_url,
            dynamic_vertical_shift_px, dynamic_band_shifts_json, dynamic_diff_pct, dynamic_blurred_diff_pct,
            dynamic_mean_abs_diff, dynamic_blurred_mean_abs_diff,
            blocked_vertical_shift_px, blocked_band_shifts_json, blocked_diff_pct, blocked_blurred_diff_pct,
            blocked_mean_abs_diff, blocked_blurred_mean_abs_diff,
            net_blocked_minus_dynamic_diff_pct, net_blocked_minus_dynamic_blurred_diff_pct,
            dynamic_html_similarity_ratio, dynamic_html_equal, dynamic_content_similarity_ratio, dynamic_content_equal, dynamic_content_token_jaccard,
            blocked_html_similarity_ratio, blocked_html_equal, blocked_content_similarity_ratio, blocked_content_equal, blocked_content_token_jaccard,
            normal_1_white_fraction, blocked_white_fraction, normal_2_white_fraction,
            normal_1_blank_white, blocked_blank_white, normal_2_blank_white,
            blocked_browser_error, blocked_error_marker,
            dynamic_overlay, blocked_overlay, updated_at
        ) VALUES (
            :page_id, :endpoint_label, :page_domain, :page_url,
            :dynamic_vertical_shift_px, :dynamic_band_shifts_json, :dynamic_diff_pct, :dynamic_blurred_diff_pct,
            :dynamic_mean_abs_diff, :dynamic_blurred_mean_abs_diff,
            :blocked_vertical_shift_px, :blocked_band_shifts_json, :blocked_diff_pct, :blocked_blurred_diff_pct,
            :blocked_mean_abs_diff, :blocked_blurred_mean_abs_diff,
            :net_blocked_minus_dynamic_diff_pct, :net_blocked_minus_dynamic_blurred_diff_pct,
            :dynamic_html_similarity_ratio, :dynamic_html_equal, :dynamic_content_similarity_ratio, :dynamic_content_equal, :dynamic_content_token_jaccard,
            :blocked_html_similarity_ratio, :blocked_html_equal, :blocked_content_similarity_ratio, :blocked_content_equal, :blocked_content_token_jaccard,
            :normal_1_white_fraction, :blocked_white_fraction, :normal_2_white_fraction,
            :normal_1_blank_white, :blocked_blank_white, :normal_2_blank_white,
            :blocked_browser_error, :blocked_error_marker,
            :dynamic_overlay, :blocked_overlay, CURRENT_TIMESTAMP
        )
        ON CONFLICT(page_id) DO UPDATE SET
            endpoint_label = excluded.endpoint_label,
            page_domain = excluded.page_domain,
            page_url = excluded.page_url,
            dynamic_vertical_shift_px = excluded.dynamic_vertical_shift_px,
            dynamic_band_shifts_json = excluded.dynamic_band_shifts_json,
            dynamic_diff_pct = excluded.dynamic_diff_pct,
            dynamic_blurred_diff_pct = excluded.dynamic_blurred_diff_pct,
            dynamic_mean_abs_diff = excluded.dynamic_mean_abs_diff,
            dynamic_blurred_mean_abs_diff = excluded.dynamic_blurred_mean_abs_diff,
            blocked_vertical_shift_px = excluded.blocked_vertical_shift_px,
            blocked_band_shifts_json = excluded.blocked_band_shifts_json,
            blocked_diff_pct = excluded.blocked_diff_pct,
            blocked_blurred_diff_pct = excluded.blocked_blurred_diff_pct,
            blocked_mean_abs_diff = excluded.blocked_mean_abs_diff,
            blocked_blurred_mean_abs_diff = excluded.blocked_blurred_mean_abs_diff,
            net_blocked_minus_dynamic_diff_pct = excluded.net_blocked_minus_dynamic_diff_pct,
            net_blocked_minus_dynamic_blurred_diff_pct = excluded.net_blocked_minus_dynamic_blurred_diff_pct,
            dynamic_html_similarity_ratio = excluded.dynamic_html_similarity_ratio,
            dynamic_html_equal = excluded.dynamic_html_equal,
            dynamic_content_similarity_ratio = excluded.dynamic_content_similarity_ratio,
            dynamic_content_equal = excluded.dynamic_content_equal,
            dynamic_content_token_jaccard = excluded.dynamic_content_token_jaccard,
            blocked_html_similarity_ratio = excluded.blocked_html_similarity_ratio,
            blocked_html_equal = excluded.blocked_html_equal,
            blocked_content_similarity_ratio = excluded.blocked_content_similarity_ratio,
            blocked_content_equal = excluded.blocked_content_equal,
            blocked_content_token_jaccard = excluded.blocked_content_token_jaccard,
            normal_1_white_fraction = excluded.normal_1_white_fraction,
            blocked_white_fraction = excluded.blocked_white_fraction,
            normal_2_white_fraction = excluded.normal_2_white_fraction,
            normal_1_blank_white = excluded.normal_1_blank_white,
            blocked_blank_white = excluded.blocked_blank_white,
            normal_2_blank_white = excluded.normal_2_blank_white,
            blocked_browser_error = excluded.blocked_browser_error,
            blocked_error_marker = excluded.blocked_error_marker,
            dynamic_overlay = excluded.dynamic_overlay,
            blocked_overlay = excluded.blocked_overlay,
            updated_at = CURRENT_TIMESTAMP
    """, row)


def main():
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    overlay_dir = output_dir / 'diff_overlays'
    output_dir.mkdir(parents=True, exist_ok=True)
    overlay_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(args.sqlite_path)
    conn.row_factory = sqlite3.Row
    ensure_analysis_table(conn)
    query = '''
        SELECT id, endpoint_label, page_url, page_domain, output_dir,
               normal_1_screenshot, blocked_screenshot, normal_2_screenshot,
               normal_1_status, blocked_status, normal_2_status,
               blocked_request_count, blocked_foreign_ip_count, blocked_foreign_jurisdiction_count
        FROM eu_check_pages
    '''
    params = []
    if args.page_url:
        query += ' WHERE page_url = ?'
        params.append(args.page_url)
    query += ' ORDER BY endpoint_label, page_url'
    rows = conn.execute(query, params).fetchall()

    summary_rows = []
    for row in rows:
        normal_1 = row['normal_1_screenshot']
        blocked = row['blocked_screenshot']
        normal_2 = row['normal_2_screenshot']
        if not normal_1 or not blocked or not normal_2:
            continue
        if not (os.path.exists(normal_1) and os.path.exists(blocked) and os.path.exists(normal_2)):
            continue

        dynamic_html_metrics = html_metrics(derive_html_path(normal_1), derive_html_path(normal_2))
        blocked_html_metrics = html_metrics(derive_html_path(normal_1), derive_html_path(blocked))

        normal_1_image = load_rgb_image(normal_1)
        blocked_image = load_rgb_image(blocked)
        normal_2_image = load_rgb_image(normal_2)

        normal_1_blank = blank_white_metrics(normal_1_image)
        blocked_blank = blank_white_metrics(blocked_image)
        normal_2_blank = blank_white_metrics(normal_2_image)

        dynamic_metrics = None
        blocked_metrics = None
        if not (normal_1_blank['is_blank_white'] or normal_2_blank['is_blank_white']):
            dynamic_metrics = image_metrics_from_images(normal_1_image, normal_2_image)
        if not (normal_1_blank['is_blank_white'] or blocked_blank['is_blank_white']):
            blocked_metrics = image_metrics_from_images(normal_1_image, blocked_image)

        key = f"{row['endpoint_label']}__{row['id']}"
        dynamic_overlay = overlay_dir / f'{key}_dynamic.png'
        blocked_overlay = overlay_dir / f'{key}_blocked.png'
        if dynamic_metrics is not None:
            save_overlay(dynamic_metrics['left'], dynamic_metrics['diff_mask'], dynamic_metrics['bbox'], dynamic_overlay)
        if blocked_metrics is not None:
            save_overlay(blocked_metrics['left'], blocked_metrics['diff_mask'], blocked_metrics['bbox'], blocked_overlay)

        summary_row = {
            'page_id': row['id'],
            'endpoint_label': row['endpoint_label'],
            'page_domain': row['page_domain'],
            'page_url': row['page_url'],
            'normal_1_status': row['normal_1_status'],
            'blocked_status': row['blocked_status'],
            'normal_2_status': row['normal_2_status'],
            'blocked_request_count': row['blocked_request_count'],
            'blocked_foreign_ip_count': row['blocked_foreign_ip_count'],
            'blocked_foreign_jurisdiction_count': row['blocked_foreign_jurisdiction_count'],
            'dynamic_vertical_shift_px': dynamic_metrics['vertical_shift_px'] if dynamic_metrics is not None else None,
            'dynamic_band_shifts_json': dynamic_metrics['band_shifts_json'] if dynamic_metrics is not None else None,
            'dynamic_diff_pct': dynamic_metrics['diff_pct'] if dynamic_metrics is not None else None,
            'dynamic_blurred_diff_pct': dynamic_metrics['blurred_diff_pct'] if dynamic_metrics is not None else None,
            'dynamic_mean_abs_diff': dynamic_metrics['mean_abs_diff'] if dynamic_metrics is not None else None,
            'dynamic_blurred_mean_abs_diff': dynamic_metrics['blurred_mean_abs_diff'] if dynamic_metrics is not None else None,
            'dynamic_ssim': dynamic_metrics['ssim'] if dynamic_metrics is not None else None,
            'blocked_vertical_shift_px': blocked_metrics['vertical_shift_px'] if blocked_metrics is not None else None,
            'blocked_band_shifts_json': blocked_metrics['band_shifts_json'] if blocked_metrics is not None else None,
            'blocked_diff_pct': blocked_metrics['diff_pct'] if blocked_metrics is not None else None,
            'blocked_blurred_diff_pct': blocked_metrics['blurred_diff_pct'] if blocked_metrics is not None else None,
            'blocked_mean_abs_diff': blocked_metrics['mean_abs_diff'] if blocked_metrics is not None else None,
            'blocked_blurred_mean_abs_diff': blocked_metrics['blurred_mean_abs_diff'] if blocked_metrics is not None else None,
            'blocked_ssim': blocked_metrics['ssim'] if blocked_metrics is not None else None,
            'net_blocked_minus_dynamic_diff_pct': round(blocked_metrics['diff_pct'] - dynamic_metrics['diff_pct'], 4) if dynamic_metrics is not None and blocked_metrics is not None else None,
            'net_blocked_minus_dynamic_blurred_diff_pct': round(blocked_metrics['blurred_diff_pct'] - dynamic_metrics['blurred_diff_pct'], 4) if dynamic_metrics is not None and blocked_metrics is not None else None,
            'dynamic_html_similarity_ratio': dynamic_html_metrics['html_similarity_ratio'],
            'dynamic_html_equal': dynamic_html_metrics['html_equal'],
            'dynamic_html_left_sha256': dynamic_html_metrics['html_left_sha256'],
            'dynamic_html_right_sha256': dynamic_html_metrics['html_right_sha256'],
            'dynamic_content_similarity_ratio': dynamic_html_metrics['content_similarity_ratio'],
            'dynamic_content_equal': dynamic_html_metrics['content_equal'],
            'dynamic_content_token_jaccard': dynamic_html_metrics['content_token_jaccard'],
            'blocked_html_similarity_ratio': blocked_html_metrics['html_similarity_ratio'],
            'blocked_html_equal': blocked_html_metrics['html_equal'],
            'blocked_html_left_sha256': blocked_html_metrics['html_left_sha256'],
            'blocked_html_right_sha256': blocked_html_metrics['html_right_sha256'],
            'blocked_content_similarity_ratio': blocked_html_metrics['content_similarity_ratio'],
            'blocked_content_equal': blocked_html_metrics['content_equal'],
            'blocked_content_token_jaccard': blocked_html_metrics['content_token_jaccard'],
            'normal_1_white_fraction': normal_1_blank['white_fraction'],
            'blocked_white_fraction': blocked_blank['white_fraction'],
            'normal_2_white_fraction': normal_2_blank['white_fraction'],
            'normal_1_blank_white': normal_1_blank['is_blank_white'],
            'blocked_blank_white': blocked_blank['is_blank_white'],
            'normal_2_blank_white': normal_2_blank['is_blank_white'],
            'blocked_browser_error': int((row['blocked_status'] is None) and bool(blocked_html_metrics['right_raw_contains_err_blocked_by_client'])),
            'blocked_error_marker': 'ERR_BLOCKED_BY_CLIENT' if ((row['blocked_status'] is None) and bool(blocked_html_metrics['right_raw_contains_err_blocked_by_client'])) else None,
            'dynamic_overlay': str(dynamic_overlay) if dynamic_metrics is not None else None,
            'blocked_overlay': str(blocked_overlay) if blocked_metrics is not None else None,
        }
        summary_rows.append(summary_row)
        upsert_analysis_row(conn, summary_row)

    summary_rows.sort(key=lambda row: (-(row['blocked_diff_pct'] or -1), -(row['dynamic_diff_pct'] or -1), row['page_url']))

    csv_path = output_dir / 'eu_check_summary.csv'
    json_path = output_dir / 'eu_check_summary.json'
    fieldnames = [
        'page_id', 'endpoint_label', 'page_domain', 'page_url',
        'normal_1_status', 'blocked_status', 'normal_2_status',
        'blocked_request_count', 'blocked_foreign_ip_count', 'blocked_foreign_jurisdiction_count',
        'dynamic_vertical_shift_px', 'dynamic_band_shifts_json', 'dynamic_diff_pct', 'dynamic_blurred_diff_pct', 'dynamic_mean_abs_diff', 'dynamic_blurred_mean_abs_diff', 'dynamic_ssim',
        'blocked_vertical_shift_px', 'blocked_band_shifts_json', 'blocked_diff_pct', 'blocked_blurred_diff_pct', 'blocked_mean_abs_diff', 'blocked_blurred_mean_abs_diff', 'blocked_ssim',
        'net_blocked_minus_dynamic_diff_pct', 'net_blocked_minus_dynamic_blurred_diff_pct',
        'dynamic_html_similarity_ratio', 'dynamic_html_equal', 'dynamic_html_left_sha256', 'dynamic_html_right_sha256',
        'dynamic_content_similarity_ratio', 'dynamic_content_equal', 'dynamic_content_token_jaccard',
        'blocked_html_similarity_ratio', 'blocked_html_equal', 'blocked_html_left_sha256', 'blocked_html_right_sha256',
        'blocked_content_similarity_ratio', 'blocked_content_equal', 'blocked_content_token_jaccard',
        'normal_1_white_fraction', 'blocked_white_fraction', 'normal_2_white_fraction',
        'normal_1_blank_white', 'blocked_blank_white', 'normal_2_blank_white',
        'blocked_browser_error', 'blocked_error_marker',
        'dynamic_overlay', 'blocked_overlay',
    ]

    with csv_path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    with json_path.open('w', encoding='utf-8') as handle:
        json.dump(summary_rows, handle, indent=2)

    stats = {
        'pages_analyzed': len(summary_rows),
        'used_skimage_ssim': bool(ssim is not None),
        'mean_dynamic_diff_pct': round(float(np.mean([row['dynamic_diff_pct'] for row in summary_rows if row['dynamic_diff_pct'] is not None])), 4) if any(row['dynamic_diff_pct'] is not None for row in summary_rows) else None,
        'mean_dynamic_blurred_diff_pct': round(float(np.mean([row['dynamic_blurred_diff_pct'] for row in summary_rows if row['dynamic_blurred_diff_pct'] is not None])), 4) if any(row['dynamic_blurred_diff_pct'] is not None for row in summary_rows) else None,
        'mean_blocked_diff_pct': round(float(np.mean([row['blocked_diff_pct'] for row in summary_rows if row['blocked_diff_pct'] is not None])), 4) if any(row['blocked_diff_pct'] is not None for row in summary_rows) else None,
        'mean_blocked_blurred_diff_pct': round(float(np.mean([row['blocked_blurred_diff_pct'] for row in summary_rows if row['blocked_blurred_diff_pct'] is not None])), 4) if any(row['blocked_blurred_diff_pct'] is not None for row in summary_rows) else None,
        'mean_net_blocked_minus_dynamic_diff_pct': round(float(np.mean([row['net_blocked_minus_dynamic_diff_pct'] for row in summary_rows if row['net_blocked_minus_dynamic_diff_pct'] is not None])), 4) if any(row['net_blocked_minus_dynamic_diff_pct'] is not None for row in summary_rows) else None,
        'mean_net_blocked_minus_dynamic_blurred_diff_pct': round(float(np.mean([row['net_blocked_minus_dynamic_blurred_diff_pct'] for row in summary_rows if row['net_blocked_minus_dynamic_blurred_diff_pct'] is not None])), 4) if any(row['net_blocked_minus_dynamic_blurred_diff_pct'] is not None for row in summary_rows) else None,
        'normal_1_blank_white_count': int(sum(row['normal_1_blank_white'] for row in summary_rows)) if summary_rows else 0,
        'blocked_blank_white_count': int(sum(row['blocked_blank_white'] for row in summary_rows)) if summary_rows else 0,
        'normal_2_blank_white_count': int(sum(row['normal_2_blank_white'] for row in summary_rows)) if summary_rows else 0,
    }
    with (output_dir / 'eu_check_stats.json').open('w', encoding='utf-8') as handle:
        json.dump(stats, handle, indent=2)

    conn.commit()

    print(json.dumps(stats, indent=2))
    for row in summary_rows:
        print(
            f"DIFF_SCORE page={row['page_url']} dynamic_pct={row['dynamic_diff_pct']} dynamic_blur_pct={row['dynamic_blurred_diff_pct']} blocked_pct={row['blocked_diff_pct']} blocked_blur_pct={row['blocked_blurred_diff_pct']} net_pct={row['net_blocked_minus_dynamic_diff_pct']} net_blur_pct={row['net_blocked_minus_dynamic_blurred_diff_pct']} dynamic_shift_px={row['dynamic_vertical_shift_px']} blocked_shift_px={row['blocked_vertical_shift_px']} dynamic_bands={row['dynamic_band_shifts_json']} blocked_bands={row['blocked_band_shifts_json']} dynamic_html={row['dynamic_html_similarity_ratio']} blocked_html={row['blocked_html_similarity_ratio']} dynamic_content={row['dynamic_content_similarity_ratio']} blocked_content={row['blocked_content_similarity_ratio']} dynamic_jaccard={row['dynamic_content_token_jaccard']} blocked_jaccard={row['blocked_content_token_jaccard']} normal1_blank={row['normal_1_blank_white']} blocked_blank={row['blocked_blank_white']} normal2_blank={row['normal_2_blank_white']} normal1_white={row['normal_1_white_fraction']} blocked_white={row['blocked_white_fraction']} normal2_white={row['normal_2_white_fraction']} blocked_browser_error={row['blocked_browser_error']} blocked_error_marker={row['blocked_error_marker']} dynamic_ssim={row['dynamic_ssim']} blocked_ssim={row['blocked_ssim']}"
        )


if __name__ == '__main__':
    main()
