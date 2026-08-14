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
use std::collections::HashMap;
use std::io::Cursor;
use tracing::debug;

use crate::history::ImageId;

/// Marker prefix used in stored user messages.
pub const IMAGE_TAG_PREFIX: &str = "[IMAGE:";
const IMAGE_TAG_SUFFIX: char = ']';
/// Payload prefix for a stable image ref: `[IMAGE:img:<uuid>]`.
pub const IMAGE_REF_PREFIX: &str = "img:";
/// Wire/page placeholder when a stored image or thumb blob is missing.
pub const IMAGE_UNAVAILABLE: &str = "unavailable";

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
/// Longest edge (px) for chat-history UI thumbnails (click-to-expand).
const UI_THUMB_MAX_EDGE: u32 = 384;
/// JPEG quality for chat-history UI thumbnails.
const UI_THUMB_JPEG_QUALITY: u8 = 70;

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
    thumbnail_payload_with(payload, THUMB_MAX_EDGE, THUMB_JPEG_QUALITY)
}

fn thumbnail_payload_with(payload: &str, max_edge: u32, quality: u8) -> Option<String> {
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
    let thumb = resize_to_max_edge(img, max_edge);
    let mut jpeg = Vec::new();
    {
        let mut cursor = Cursor::new(&mut jpeg);
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, quality);
        encoder.encode_image(&thumb).ok()?;
    }
    if jpeg.is_empty() {
        return None;
    }
    let encoded = STANDARD.encode(&jpeg);
    debug!(
        original_bytes = bytes.len(),
        thumb_bytes = jpeg.len(),
        max_edge,
        "chat image thumbnailed"
    );
    Some(format!("data:image/jpeg;base64,{encoded}"))
}

/// Rewrite every `[IMAGE:...]` in a stored user message to a small JPEG thumbnail.
///
/// Used by `/load_set` so the browser does not parse multi-MB data URLs just to
/// show a 300×200 preview. Durable storage is unchanged.
pub fn replace_images_with_ui_thumbnails(text: &str) -> String {
    if !has_image(text) {
        return text.to_owned();
    }
    rewrite_image_payloads(text, |payload| {
        thumbnail_payload_with(payload, UI_THUMB_MAX_EDGE, UI_THUMB_JPEG_QUALITY)
            .unwrap_or_else(|| payload.to_owned())
    })
}

/// Replace each `[IMAGE:payload]` with `[IMAGE]` so UI thumbnails can match
/// stored full-resolution attachments on delete.
pub fn strip_image_payloads(text: &str) -> String {
    if !has_image(text) {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len().min(8 * 1024));
    let mut rest = text;
    while let Some(start) = rest.find(IMAGE_TAG_PREFIX) {
        out.push_str(&rest[..start]);
        out.push_str(IMAGE_TAG_PREFIX);
        out.push(IMAGE_TAG_SUFFIX);
        rest = &rest[start + IMAGE_TAG_PREFIX.len()..];
        if let Some(end) = rest.find(IMAGE_TAG_SUFFIX) {
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    out.push_str(rest);
    out
}

/// True when two user messages are the same aside from image payload bytes.
pub fn user_messages_match(a: &str, b: &str) -> bool {
    strip_image_payloads(a.trim()) == strip_image_payloads(b.trim())
}

/// Keep stored full-resolution attachments when the client sends a UI thumbnail
/// (or edits only the caption). Removing an image in the incoming text is honored.
pub fn coalesce_edit_user_message(incoming: &str, stored: &str) -> String {
    if incoming == stored {
        return incoming.to_owned();
    }
    if user_messages_match(incoming, stored) {
        return stored.to_owned();
    }
    let incoming_images = collect_image_payloads(incoming);
    if incoming_images.is_empty() {
        return incoming.to_owned();
    }
    let stored_images = collect_image_payloads(stored);
    if stored_images.is_empty() {
        return incoming.to_owned();
    }
    let mut stored_iter = stored_images.iter();
    rewrite_image_payloads(incoming, |inc_payload| match stored_iter.next() {
        Some(stored_payload) if inc_payload.len() < stored_payload.len() => {
            stored_payload.clone()
        }
        _ => inc_payload.to_owned(),
    })
}

/// One extracted attachment: new `ImageId`, mime, raw bytes, and durable thumb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedImage {
    pub image_id: ImageId,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub thumb_mime: String,
    pub thumb_bytes: Vec<u8>,
    pub thumb_fell_back: bool,
}

/// Result of normalizing a pair for a format-2 commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPair {
    pub user: String,
    pub image_ids: Vec<ImageId>,
    pub new_images: Vec<ExtractedImage>,
    pub dropped_image_ids: Vec<ImageId>,
}

/// Convert `data:` / bare-base64 image tags to `[IMAGE:img:<uuid>]`.
///
/// Existing `img:` refs and unknown/opaque tags are left unchanged. Only
/// decodable image payloads become blobs.
pub fn extract_images_from_user_message(text: &str) -> (String, Vec<ExtractedImage>) {
    if !has_image(text) {
        return (text.to_owned(), Vec::new());
    }
    let mut extracted = Vec::new();
    let rewritten = rewrite_image_payloads(text, |payload| {
        if parse_image_ref(payload).is_some() || payload == IMAGE_UNAVAILABLE {
            return payload.to_owned();
        }
        match decode_and_thumb_image(payload) {
            Some(img) => {
                let tag = format!("{}{}", IMAGE_REF_PREFIX, img.image_id.as_hyphenated());
                extracted.push(img);
                tag
            }
            None => payload.to_owned(),
        }
    });
    (rewritten, extracted)
}

/// Slot-aligned normalize used by format-2 `commit_snapshot`.
///
/// Occupied slots reuse `stored_image_ids[i]` (a `data:` URL there is a thumb,
/// not a new attachment). Tags past the stored list are extracted as new ids.
/// Trailing stored ids are dropped.
pub fn normalize_pair_for_commit(incoming_user: &str, stored_image_ids: &[ImageId]) -> NormalizedPair {
    let mut image_ids = Vec::new();
    let mut new_images = Vec::new();
    let mut slot = 0usize;
    let user = if has_image(incoming_user) {
        rewrite_image_payloads(incoming_user, |payload| {
            if slot < stored_image_ids.len() {
                let id = stored_image_ids[slot];
                slot += 1;
                image_ids.push(id);
                format!("{}{}", IMAGE_REF_PREFIX, id.as_hyphenated())
            } else if let Some(id) = parse_image_ref(payload) {
                slot += 1;
                image_ids.push(id);
                format!("{}{}", IMAGE_REF_PREFIX, id.as_hyphenated())
            } else if payload == IMAGE_UNAVAILABLE {
                slot += 1;
                payload.to_owned()
            } else if let Some(img) = decode_and_thumb_image(payload) {
                slot += 1;
                let tag = format!("{}{}", IMAGE_REF_PREFIX, img.image_id.as_hyphenated());
                image_ids.push(img.image_id);
                new_images.push(img);
                tag
            } else {
                slot += 1;
                payload.to_owned()
            }
        })
    } else {
        incoming_user.to_owned()
    };
    let dropped_image_ids = if slot < stored_image_ids.len() {
        stored_image_ids[slot..].to_vec()
    } else {
        Vec::new()
    };
    NormalizedPair {
        user,
        image_ids,
        new_images,
        dropped_image_ids,
    }
}

/// Replace `[IMAGE:img:<uuid>]` with thumbnail data URLs. Miss → `[IMAGE:unavailable]`.
pub fn materialize_thumbs(text: &str, thumbs: &HashMap<ImageId, (String, Vec<u8>)>) -> String {
    materialize_refs(text, |id| {
        thumbs.get(&id).map(|(mime, bytes)| encode_data_url(mime, bytes))
    })
}

/// Replace `[IMAGE:img:<uuid>]` with full-resolution data URLs. Miss → `[IMAGE:unavailable]`.
pub fn materialize_full(text: &str, images: &HashMap<ImageId, (String, Vec<u8>)>) -> String {
    materialize_refs(text, |id| {
        images
            .get(&id)
            .map(|(mime, bytes)| encode_data_url(mime, bytes))
    })
}

fn materialize_refs(text: &str, mut lookup: impl FnMut(ImageId) -> Option<String>) -> String {
    if !has_image(text) {
        return text.to_owned();
    }
    rewrite_image_payloads(text, |payload| {
        match parse_image_ref(payload) {
            Some(id) => lookup(id).unwrap_or_else(|| IMAGE_UNAVAILABLE.to_owned()),
            None => payload.to_owned(),
        }
    })
}

/// Parse `img:<hyphenated-uuid>` (canonical stored ref).
pub fn parse_image_ref(payload: &str) -> Option<ImageId> {
    let rest = payload.strip_prefix(IMAGE_REF_PREFIX)?;
    ImageId::parse(rest).ok().filter(|id| id.as_hyphenated() == rest)
}

/// Collect ordered `ImageId`s from `[IMAGE:img:…]` tags (skips opaque / data: tags).
pub fn collect_image_refs(text: &str) -> Vec<ImageId> {
    collect_image_payloads(text)
        .into_iter()
        .filter_map(|p| parse_image_ref(&p))
        .collect()
}

/// Keep stored `img:` refs when the client sends a shorter data URL (UI thumb).
pub fn coalesce_edit_user_message_refs(incoming: &str, stored: &str) -> String {
    if incoming == stored {
        return incoming.to_owned();
    }
    if user_messages_match(incoming, stored) {
        return stored.to_owned();
    }
    let incoming_images = collect_image_payloads(incoming);
    if incoming_images.is_empty() {
        return incoming.to_owned();
    }
    let stored_images = collect_image_payloads(stored);
    if stored_images.is_empty() {
        return incoming.to_owned();
    }
    let mut stored_iter = stored_images.iter();
    rewrite_image_payloads(incoming, |inc_payload| match stored_iter.next() {
        Some(stored_payload)
            if parse_image_ref(stored_payload).is_some()
                && (inc_payload.len() < stored_payload.len() || inc_payload.starts_with("data:")) =>
        {
            stored_payload.clone()
        }
        Some(stored_payload) if inc_payload.len() < stored_payload.len() => stored_payload.clone(),
        _ => inc_payload.to_owned(),
    })
}

fn encode_data_url(mime: &str, bytes: &[u8]) -> String {
    format!("data:{mime};base64,{}", STANDARD.encode(bytes))
}

fn decode_and_thumb_image(payload: &str) -> Option<ExtractedImage> {
    let (mime, bytes) = decode_image_data_url(payload)?;
    let image_id = ImageId::new();
    match encode_jpeg_thumb(&bytes, UI_THUMB_MAX_EDGE, UI_THUMB_JPEG_QUALITY) {
        Some(thumb) => Some(ExtractedImage {
            image_id,
            mime,
            bytes,
            thumb_mime: "image/jpeg".into(),
            thumb_bytes: thumb,
            thumb_fell_back: false,
        }),
        None => {
            debug!(image_id = %image_id, "history_thumb_fallback");
            Some(ExtractedImage {
                image_id,
                mime: mime.clone(),
                bytes: bytes.clone(),
                thumb_mime: mime,
                thumb_bytes: bytes,
                thumb_fell_back: true,
            })
        }
    }
}

fn encode_jpeg_thumb(bytes: &[u8], max_edge: u32, quality: u8) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let img = image::load_from_memory(bytes).ok()?;
    let thumb = resize_to_max_edge(img, max_edge);
    let mut jpeg = Vec::new();
    {
        let mut cursor = Cursor::new(&mut jpeg);
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, quality);
        encoder.encode_image(&thumb).ok()?;
    }
    if jpeg.is_empty() {
        return None;
    }
    Some(jpeg)
}

/// Downscale raw image bytes to a 256px / q55 JPEG for model packing.
pub fn model_thumb_data_url(bytes: &[u8]) -> Option<String> {
    let jpeg = encode_jpeg_thumb(bytes, THUMB_MAX_EDGE, THUMB_JPEG_QUALITY)?;
    Some(encode_data_url("image/jpeg", &jpeg))
}

/// Solid-color JPEG data URL for tests and integration fixtures.
pub fn fixture_jpeg_data_url(width: u32, height: u32) -> String {
    use image::{DynamicImage, ImageBuffer, Rgb};
    let w = width.max(1);
    let h = height.max(1);
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
        ImageBuffer::from_fn(w, h, |x, y| Rgb([(x % 255) as u8, (y % 255) as u8, 80]));
    let mut jpeg = Vec::new();
    {
        let mut cursor = Cursor::new(&mut jpeg);
        let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, 90);
        enc.encode_image(&DynamicImage::ImageRgb8(img)).expect("encode fixture jpeg");
    }
    format!("data:image/jpeg;base64,{}", STANDARD.encode(&jpeg))
}

/// Return the `index`-th image tag payload as a `data:` URL, if present.
pub fn nth_image_data_url(text: &str, index: usize) -> Option<String> {
    collect_image_payloads(text)
        .into_iter()
        .nth(index)
        .map(|payload| {
            if payload.starts_with("data:") {
                payload
            } else {
                format!("data:image/jpeg;base64,{payload}")
            }
        })
}

/// Decode a stored `[IMAGE:...]` payload or data URL to mime + bytes.
pub fn decode_image_data_url(payload: &str) -> Option<(String, Vec<u8>)> {
    let (mime, b64) = split_data_url_or_raw(payload)?;
    let bytes = STANDARD.decode(b64.trim()).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let mime = if mime.starts_with("image/") {
        mime.to_owned()
    } else {
        format!("image/{mime}")
    };
    Some((mime, bytes))
}

fn collect_image_payloads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(IMAGE_TAG_PREFIX) {
        rest = &rest[start + IMAGE_TAG_PREFIX.len()..];
        if let Some(end) = rest.find(IMAGE_TAG_SUFFIX) {
            out.push(rest[..end].to_owned());
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    out
}

fn rewrite_image_payloads(text: &str, mut rewrite: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len().min(64 * 1024));
    let mut rest = text;
    while let Some(start) = rest.find(IMAGE_TAG_PREFIX) {
        out.push_str(&rest[..start]);
        rest = &rest[start + IMAGE_TAG_PREFIX.len()..];
        if let Some(end) = rest.find(IMAGE_TAG_SUFFIX) {
            let payload = &rest[..end];
            rest = &rest[end + 1..];
            out.push_str(IMAGE_TAG_PREFIX);
            out.push_str(&rewrite(payload));
            out.push(IMAGE_TAG_SUFFIX);
        } else {
            out.push_str(IMAGE_TAG_PREFIX);
            out.push_str(rest);
            return out;
        }
    }
    out.push_str(rest);
    out
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
        fixture_jpeg_data_url(400, 400)
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

    #[test]
    fn ui_thumbnails_shrink_large_images_and_preserve_caption() {
        let large = large_jpeg_data_url();
        let original = format!("look at this\n[IMAGE:{large}]");
        let thumbed = replace_images_with_ui_thumbnails(&original);
        assert!(thumbed.starts_with("look at this\n[IMAGE:data:image/jpeg;base64,"));
        assert!(
            thumbed.len() < original.len(),
            "ui thumb should be smaller ({} vs {})",
            thumbed.len(),
            original.len()
        );
        assert!(user_messages_match(&original, &thumbed));
        assert_eq!(nth_image_data_url(&original, 0).as_deref(), Some(large.as_str()));
        let (mime, bytes) = decode_image_data_url(&large).expect("decode fixture");
        assert_eq!(mime, "image/jpeg");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn coalesce_keeps_stored_full_image_when_client_sends_thumb() {
        let large = large_jpeg_data_url();
        let stored = format!("caption\n[IMAGE:{large}]");
        let incoming = replace_images_with_ui_thumbnails(&stored);
        assert_ne!(incoming, stored);
        assert_eq!(coalesce_edit_user_message(&incoming, &stored), stored);
    }

    #[test]
    fn coalesce_applies_caption_edit_but_keeps_stored_image() {
        let large = large_jpeg_data_url();
        let stored = format!("old caption\n[IMAGE:{large}]");
        let incoming = format!(
            "new caption\n[IMAGE:{}]",
            replace_images_with_ui_thumbnails(&format!("[IMAGE:{large}]"))
                .trim_start_matches("[IMAGE:")
                .trim_end_matches(']')
        );
        let merged = coalesce_edit_user_message(&incoming, &stored);
        assert!(merged.starts_with("new caption\n[IMAGE:"));
        assert!(merged.contains(&large), "stored full payload must be kept");
    }

    #[test]
    fn coalesce_honors_image_removal() {
        let large = large_jpeg_data_url();
        let stored = format!("caption\n[IMAGE:{large}]");
        assert_eq!(coalesce_edit_user_message("caption only", &stored), "caption only");
    }

    #[test]
    fn strip_payloads_distinguishes_different_captions() {
        let a = "hello\n[IMAGE:data:image/jpeg;base64,AAA]";
        let b = "goodbye\n[IMAGE:data:image/jpeg;base64,BBB]";
        assert!(!user_messages_match(a, b));
        assert!(user_messages_match(a, "hello\n[IMAGE:data:image/jpeg;base64,ZZZ]"));
    }

    #[test]
    fn extract_converts_data_urls_and_leaves_opaque_tags() {
        let large = large_jpeg_data_url();
        let text = format!("see [IMAGE:{large}] and [IMAGE:cat]");
        let (rewritten, extracted) = extract_images_from_user_message(&text);
        assert_eq!(extracted.len(), 1);
        assert!(rewritten.contains("[IMAGE:img:"));
        assert!(rewritten.contains("[IMAGE:cat]"));
        assert!(!rewritten.contains("data:image"));
        let id = extracted[0].image_id;
        assert!(rewritten.contains(&id.as_hyphenated()));
        assert!(!extracted[0].thumb_bytes.is_empty());
    }

    #[test]
    fn normalize_reuses_occupied_slots_and_drops_trailing() {
        let stored = ImageId::new();
        let extra = ImageId::new();
        let large = large_jpeg_data_url();
        let incoming = format!("hi [IMAGE:{large}]");
        let out = normalize_pair_for_commit(&incoming, &[stored, extra]);
        assert_eq!(out.image_ids, vec![stored]);
        assert!(out.new_images.is_empty());
        assert_eq!(out.dropped_image_ids, vec![extra]);
        assert_eq!(
            out.user,
            format!("hi [IMAGE:img:{}]", stored.as_hyphenated())
        );
    }

    #[test]
    fn materialize_miss_is_unavailable_not_img_ref() {
        let id = ImageId::new();
        let text = format!("x [IMAGE:img:{}]", id.as_hyphenated());
        let empty: HashMap<ImageId, (String, Vec<u8>)> = HashMap::new();
        let out = materialize_full(&text, &empty);
        assert_eq!(out, "x [IMAGE:unavailable]");
        assert!(!out.contains("img:"));
        assert!(user_messages_match(&text, &out));
    }

    #[test]
    fn coalesce_refs_keeps_stored_img_when_client_sends_data_url() {
        let id = ImageId::new();
        let stored = format!("caption\n[IMAGE:img:{}]", id.as_hyphenated());
        let incoming = format!("caption\n[IMAGE:{}]", large_jpeg_data_url());
        assert_eq!(coalesce_edit_user_message_refs(&incoming, &stored), stored);
    }
}
