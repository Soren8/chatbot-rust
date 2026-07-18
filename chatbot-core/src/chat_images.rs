//! Image-aware helpers for chat context packing.
//!
//! User messages may embed attachments as `[IMAGE:data:image/...;base64,...]`.
//! Raw base64 is a terrible token proxy and will blow the context window estimate,
//! causing truncation that drops the *latest* image. These helpers:
//!
//! 1. Estimate vision cost with fixed per-image budgets (not base64 length / 4).
//! 2. Keep only the most recent N images at full resolution for the model.
//! 3. Downscale older attachments to small JPEG thumbnails (or a text placeholder).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use image::imageops::FilterType;
use image::DynamicImage;
use std::io::Cursor;
use tracing::debug;

/// Marker prefix used in stored user messages.
pub const IMAGE_TAG_PREFIX: &str = "[IMAGE:";
const IMAGE_TAG_SUFFIX: char = ']';

/// How many full-resolution images to send in one model request (including the
/// new user turn). Older images are thumbnailed or replaced with a placeholder.
pub const MAX_FULL_RES_IMAGES: usize = 1;

/// Rough vision-token estimate for one full-resolution attachment.
pub const FULL_IMAGE_TOKEN_ESTIMATE: f64 = 1_000.0;
/// Rough vision-token estimate for a small thumbnail.
pub const THUMB_IMAGE_TOKEN_ESTIMATE: f64 = 200.0;
/// Data-URL length below which we treat an image as already-thumbnail-sized.
const THUMB_DATA_URL_LEN_HINT: usize = 48_000;

/// Longest edge (px) for context thumbnails.
const THUMB_MAX_EDGE: u32 = 256;
/// JPEG quality for context thumbnails (size vs legibility).
const THUMB_JPEG_QUALITY: u8 = 55;

/// Placeholder when decode/resize fails for a non-priority image.
const IMAGE_OMITTED_PLACEHOLDER: &str = "[prior image omitted to fit context]";

/// Count `[IMAGE:...]` tags in a message.
pub fn count_images(text: &str) -> usize {
    let mut n = 0;
    let mut rest = text;
    while let Some(start) = rest.find(IMAGE_TAG_PREFIX) {
        rest = &rest[start + IMAGE_TAG_PREFIX.len()..];
        if let Some(end) = rest.find(IMAGE_TAG_SUFFIX) {
            n += 1;
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    n
}

/// True if the message contains at least one image attachment tag.
pub fn has_image(text: &str) -> bool {
    text.contains(IMAGE_TAG_PREFIX)
}

/// Approximate tokens for mixed text + image messages.
///
/// Text uses ~4 chars/token. Images use fixed vision estimates so multi‑MB
/// base64 blobs do not look like hundreds of thousands of tokens (which was
/// causing history truncation to strip the latest image).
pub fn approximate_content_tokens(text: &str) -> f64 {
    let mut tokens = 0.0;
    let mut rest = text;
    while let Some(start) = rest.find(IMAGE_TAG_PREFIX) {
        tokens += start as f64 / 4.0;
        rest = &rest[start + IMAGE_TAG_PREFIX.len()..];
        if let Some(end) = rest.find(IMAGE_TAG_SUFFIX) {
            let payload = &rest[..end];
            tokens += image_payload_token_estimate(payload);
            rest = &rest[end + 1..];
        } else {
            tokens += rest.len() as f64 / 4.0;
            return tokens;
        }
    }
    tokens += rest.len() as f64 / 4.0;
    tokens
}

fn image_payload_token_estimate(payload: &str) -> f64 {
    // payload is either a full data URL or bare base64.
    let len = payload.len();
    if len <= THUMB_DATA_URL_LEN_HINT {
        THUMB_IMAGE_TOKEN_ESTIMATE
    } else {
        FULL_IMAGE_TOKEN_ESTIMATE
    }
}

/// Walk images left→right, consuming `full_slots` for full-res keepers; the
/// rest become thumbnails (or a text placeholder if resize fails).
///
/// `full_slots` is shared across the request (new message first, then history
/// newest→oldest). Callers should process the newest content first.
pub fn transform_images_for_context(text: &str, full_slots: &mut usize) -> String {
    if !has_image(text) {
        return text.to_owned();
    }

    let mut out = String::with_capacity(text.len().min(64 * 1024));
    let mut rest = text;
    while let Some(start) = rest.find(IMAGE_TAG_PREFIX) {
        out.push_str(&rest[..start]);
        rest = &rest[start + IMAGE_TAG_PREFIX.len()..];
        if let Some(end) = rest.find(IMAGE_TAG_SUFFIX) {
            let payload = &rest[..end];
            rest = &rest[end + 1..];
            if *full_slots > 0 {
                *full_slots -= 1;
                out.push_str(IMAGE_TAG_PREFIX);
                out.push_str(payload);
                out.push(IMAGE_TAG_SUFFIX);
            } else {
                match thumbnail_payload(payload) {
                    Some(thumb) => {
                        out.push_str(IMAGE_TAG_PREFIX);
                        out.push_str(&thumb);
                        out.push(IMAGE_TAG_SUFFIX);
                    }
                    None => {
                        out.push_str(IMAGE_OMITTED_PLACEHOLDER);
                    }
                }
            }
        } else {
            out.push_str(IMAGE_TAG_PREFIX);
            out.push_str(rest);
            return out;
        }
    }
    out.push_str(rest);
    out
}

/// Consume full-res slots for images in `text` without rewriting (used for the
/// new user turn, which is always sent as provided).
pub fn reserve_full_image_slots(text: &str, full_slots: &mut usize) {
    let n = count_images(text);
    let take = n.min(*full_slots);
    *full_slots -= take;
}

/// Rewrite history pairs for model context: newest images keep full-res slots,
/// older ones are thumbnailed. Does not change durable storage — only the
/// outbound model payload.
pub fn prepare_history_images(
    history: &[(String, String)],
    full_slots: &mut usize,
) -> Vec<(String, String)> {
    if history.is_empty() {
        return Vec::new();
    }
    let mut pairs: Vec<(String, String)> = history
        .iter()
        .map(|(u, a)| (u.clone(), a.clone()))
        .collect();

    // Newest first so remaining full-res slots go to the most recent attachments.
    for i in (0..pairs.len()).rev() {
        if has_image(&pairs[i].0) {
            pairs[i].0 = transform_images_for_context(&pairs[i].0, full_slots);
        }
    }
    pairs
}

/// Build a compact `data:image/jpeg;base64,...` payload from a stored image tag body.
fn thumbnail_payload(payload: &str) -> Option<String> {
    let (mime, b64) = split_data_url_or_raw(payload)?;
    let bytes = STANDARD.decode(b64.trim()).ok()?;
    if bytes.is_empty() {
        return None;
    }

    // Already tiny — keep as-is (still counts as thumb in estimates).
    if payload.len() <= THUMB_DATA_URL_LEN_HINT && bytes.len() < 12_000 {
        let url = if payload.starts_with("data:") {
            payload.to_owned()
        } else {
            format!("data:{mime};base64,{b64}")
        };
        return Some(url);
    }

    let img = image::load_from_memory(&bytes).ok()?;
    let thumb = resize_to_max_edge(img, THUMB_MAX_EDGE);
    let mut jpeg = Vec::new();
    {
        let mut cursor = Cursor::new(&mut jpeg);
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, THUMB_JPEG_QUALITY);
        encoder.encode_image(&thumb).ok()?;
    }
    if jpeg.is_empty() {
        return None;
    }
    let encoded = STANDARD.encode(&jpeg);
    debug!(
        original_bytes = bytes.len(),
        thumb_bytes = jpeg.len(),
        "chat image thumbnailed for context packing"
    );
    Some(format!("data:image/jpeg;base64,{encoded}"))
}

fn split_data_url_or_raw(payload: &str) -> Option<(&str, &str)> {
    if let Some(rest) = payload.strip_prefix("data:") {
        let (meta, b64) = rest.split_once(',')?;
        // meta like "image/png;base64"
        let mime = meta.split(';').next().unwrap_or("image/jpeg");
        if !meta.contains("base64") {
            return None;
        }
        Some((mime, b64))
    } else {
        // Bare base64 — assume jpeg (matches message_utils fallback).
        Some(("image/jpeg", payload))
    }
}

fn resize_to_max_edge(img: DynamicImage, max_edge: u32) -> DynamicImage {
    let (w, h) = (img.width(), img.height());
    if w == 0 || h == 0 {
        return img;
    }
    let long = w.max(h);
    if long <= max_edge {
        return img;
    }
    let scale = max_edge as f32 / long as f32;
    let nw = ((w as f32 * scale).round() as u32).max(1);
    let nh = ((h as f32 * scale).round() as u32).max(1);
    img.resize(nw, nh, FilterType::Triangle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, ImageFormat, Rgb};

    fn tiny_png_data_url() -> String {
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
            ImageBuffer::from_fn(4, 4, |x, y| Rgb([(x * 40) as u8, (y * 40) as u8, 120]));
        let mut png = Vec::new();
        {
            let mut cursor = Cursor::new(&mut png);
            image::write_buffer_with_format(
                &mut cursor,
                img.as_raw(),
                4,
                4,
                image::ExtendedColorType::Rgb8,
                ImageFormat::Png,
            )
            .unwrap();
        }
        format!("data:image/png;base64,{}", STANDARD.encode(&png))
    }

    fn large_jpeg_data_url() -> String {
        // 400x400 solid image — large enough to force resize path.
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
            ImageBuffer::from_fn(400, 400, |x, y| Rgb([(x % 255) as u8, (y % 255) as u8, 80]));
        let mut jpeg = Vec::new();
        {
            let mut cursor = Cursor::new(&mut jpeg);
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, 90);
            enc.encode_image(&DynamicImage::ImageRgb8(img)).unwrap();
        }
        format!("data:image/jpeg;base64,{}", STANDARD.encode(&jpeg))
    }

    #[test]
    fn count_and_has_image() {
        assert_eq!(count_images("plain"), 0);
        assert!(!has_image("plain"));
        let s = format!("see [IMAGE:{}] and [IMAGE:{}]", tiny_png_data_url(), "abc");
        assert_eq!(count_images(&s), 2);
        assert!(has_image(&s));
    }

    #[test]
    fn token_estimate_not_dominated_by_base64_length() {
        let huge = format!("caption\n[IMAGE:{}]", "A".repeat(500_000));
        let tokens = approximate_content_tokens(&huge);
        // Base64/4 would be ~125k; vision estimate must stay small.
        assert!(tokens < 2_000.0, "tokens={tokens}");
        assert!(tokens > 100.0, "tokens={tokens}");
    }

    #[test]
    fn newest_keeps_full_older_gets_thumbnail() {
        let large = large_jpeg_data_url();
        let older = format!("old [IMAGE:{large}]");
        let newer = format!("new [IMAGE:{large}]");
        let history = vec![
            (older.clone(), "a1".into()),
            (newer.clone(), "a2".into()),
        ];
        let mut slots = MAX_FULL_RES_IMAGES;
        // Simulate new user message with no image — history gets the full slot.
        let prepared = prepare_history_images(&history, &mut slots);
        assert_eq!(prepared.len(), 2);
        // Newest (index 1) should still be large-ish / original
        assert!(
            prepared[1].0.contains("[IMAGE:data:image/jpeg;base64,"),
            "newest should keep image tag"
        );
        // Oldest should be smaller than original large payload
        assert!(
            prepared[0].0.len() < older.len(),
            "older should be thumbnailed ({} vs {})",
            prepared[0].0.len(),
            older.len()
        );
        assert!(prepared[0].0.contains("[IMAGE:data:image/jpeg;base64,"));
        assert_eq!(slots, 0);
    }

    #[test]
    fn new_message_consumes_full_slot_so_history_is_thumb() {
        let large = large_jpeg_data_url();
        let hist_msg = format!("hist [IMAGE:{large}]");
        let new_msg = format!("latest [IMAGE:{large}]");
        let mut slots = MAX_FULL_RES_IMAGES;
        reserve_full_image_slots(&new_msg, &mut slots);
        assert_eq!(slots, 0);
        let prepared = prepare_history_images(&[(hist_msg.clone(), "ok".into())], &mut slots);
        assert!(prepared[0].0.len() < hist_msg.len());
        assert!(prepared[0].0.contains("[IMAGE:"));
    }
}
