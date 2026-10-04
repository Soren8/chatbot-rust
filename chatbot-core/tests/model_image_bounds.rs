use std::{io::Cursor, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine};
use chatbot_core::{
    chat::{prepare_prompt_messages, prepare_prompt_messages_with, PromptInput},
    chat_images::{contains_svg_attachment, decode_image_data_url, nth_image_data_url, ImageFidelity, ImageResolver},
    enc_key::EncryptionKey,
    history::HistoryService,
};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};

fn png_url(width: u32, height: u32) -> String {
    let image = DynamicImage::ImageRgba8(ImageBuffer::from_pixel(
        width, height, Rgba([40, 80, 120, 160]),
    ));
    let mut bytes = Cursor::new(Vec::new());
    image.write_to(&mut bytes, ImageFormat::Png).unwrap();
    format!("data:image/png;base64,{}", STANDARD.encode(bytes.into_inner()))
}

fn input(history: &[(String, String)]) -> PromptInput<'_> {
    PromptInput {
        system_prompt: "Describe the images.", memory_text: "", history,
        send_thoughts: false, context_size: 32768,
    }
}

fn image_dimensions(message: &str, index: usize) -> (u32, u32) {
    let url = nth_image_data_url(message, index).expect("model message must retain the image");
    let (_, bytes) = decode_image_data_url(&url).expect("model image must be a data URL");
    let image = image::load_from_memory(&bytes).expect("model image must decode");
    (image.width(), image.height())
}

#[test]
fn portrait_png_that_crashed_inference_is_resized_without_changing_the_input() {
    let original = format!("portrait [IMAGE:{}]", png_url(1225, 1430));

    let prepared = prepare_prompt_messages(&input(&[]), &original);

    let message = &prepared.messages.last().unwrap().content;
    assert_eq!(image_dimensions(message, 0), (877, 1024));
    assert!(message.starts_with("portrait [IMAGE:"));
    assert_eq!(image_dimensions(&original, 0), (1225, 1430));
    let url = nth_image_data_url(message, 0).unwrap();
    let (_, bytes) = decode_image_data_url(&url).unwrap();
    assert_eq!(image::load_from_memory(&bytes).unwrap().to_rgba8().get_pixel(0, 0).0[3], 160);
}

#[test]
fn every_attachment_in_a_new_turn_is_bounded() {
    let message = format!("two photos [IMAGE:{}] [IMAGE:{}]", png_url(1430, 1225), png_url(2048, 512));

    let prepared = prepare_prompt_messages(&input(&[]), &message);

    let outgoing = &prepared.messages.last().unwrap().content;
    assert_eq!(image_dimensions(outgoing, 0), (1024, 877));
    assert_eq!(image_dimensions(outgoing, 1), (1024, 256));
}

#[test]
fn png_at_the_model_limit_is_not_reencoded_or_upscaled() {
    let message = format!("square [IMAGE:{}]", png_url(1024, 1024));

    let prepared = prepare_prompt_messages(&input(&[]), &message);

    assert_eq!(prepared.messages.last().unwrap().content, message);
}

#[test]
fn small_png_is_not_reencoded_or_upscaled() {
    let message = format!("small [IMAGE:{}]", png_url(640, 480));

    let prepared = prepare_prompt_messages(&input(&[]), &message);

    assert_eq!(prepared.messages.last().unwrap().content, message);
}

#[test]
fn retained_stored_image_is_bounded_while_durable_original_bytes_are_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let service = Arc::new(HistoryService::open_ephemeral(directory.path().join("history.redb")).unwrap());
    let key = EncryptionKey::from_header_value("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let set = service.create_set("photo_user", "photos", &key).unwrap();
    let original_url = png_url(1225, 1430);
    service.append_pair("photo_user", set.set_id, set.version,
        &format!("stored [IMAGE:{original_url}]"), "a portrait", &key).unwrap();
    let logical = service.load_logical("photo_user", set.set_id, &key).unwrap();
    let resolver_service = service.clone();
    let resolver_key = key.clone();
    let resolver = ImageResolver::new(move |id, fidelity| {
        resolver_service.stored_image_data_url("photo_user", set.set_id, id, fidelity, &resolver_key)
    });

    let prepared = prepare_prompt_messages_with(&input(&logical.history), "What color is it?", Some(&resolver));

    assert_eq!(image_dimensions(&prepared.messages[1].content, 0), (877, 1024));
    let stored = service.load("photo_user", set.set_id, &key).unwrap();
    assert_eq!(nth_image_data_url(&stored.history[0].0, 0).unwrap(), original_url);
}

#[test]
fn svg_and_unreadable_payloads_are_not_forwarded_as_model_images() {
    let svg = STANDARD.encode(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>");
    let message = format!("caption [IMAGE:data:image/svg+xml;base64,{svg}] [IMAGE:data:image/png;base64,not-an-image]");

    let prepared = prepare_prompt_messages(&input(&[]), &message);

    let outgoing = &prepared.messages.last().unwrap().content;
    assert!(outgoing.starts_with("caption"));
    assert!(!outgoing.contains("[IMAGE:"), "unsafe images must not reach the provider mapper");
    assert!(!outgoing.contains(&svg));
    assert!(contains_svg_attachment(&format!("[IMAGE:data:image/SVG+XML;base64,{svg}]")));

    let spoofed = STANDARD.encode(b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>");
    let spoofed_message = format!("caption [IMAGE:data:image/png;base64,{spoofed}]");
    assert!(!contains_svg_attachment(&spoofed_message));
    let prepared = prepare_prompt_messages(&input(&[]), &spoofed_message);
    assert!(!prepared.messages.last().unwrap().content.contains("[IMAGE:"));
}

#[test]
fn excessive_input_dimensions_are_rejected_without_decoding_or_forwarding() {
    let message = format!("caption [IMAGE:{}]", png_url(16_385, 1));

    let prepared = prepare_prompt_messages(&input(&[]), &message);

    let outgoing = &prepared.messages.last().unwrap().content;
    assert!(outgoing.starts_with("caption"));
    assert!(!outgoing.contains("[IMAGE:"));
}

#[test]
fn unreadable_full_and_thumbnail_history_renditions_are_plain_omission_text() {
    let older_id = chatbot_core::history::ImageId::new();
    let newest_id = chatbot_core::history::ImageId::new();
    let history = vec![
        (format!("older [IMAGE:img:{}]", older_id.as_hyphenated()), "a".into()),
        (format!("newest [IMAGE:img:{}]", newest_id.as_hyphenated()), "b".into()),
    ];
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let resolver_calls = calls.clone();
    let resolver = ImageResolver::new(move |id, fidelity| {
        resolver_calls.lock().unwrap().push((id, fidelity));
        Some("data:image/png;base64,not-an-image".into())
    });

    let prepared = prepare_prompt_messages_with(&input(&history), "follow up", Some(&resolver));

    let user_messages: Vec<_> = prepared.messages.iter()
        .filter(|message| message.role == chatbot_core::chat::ChatMessageRole::User)
        .collect();
    assert!(user_messages.iter().any(|message| message.content.contains("newest")
        && message.content.contains("[prior image omitted to fit context]")));
    assert!(user_messages.iter().any(|message| message.content.contains("older")
        && message.content.contains("[prior image omitted to fit context]")));
    assert!(user_messages.iter().all(|message| !message.content.contains("[IMAGE:")));
    assert!(!user_messages.iter().any(|message| message.content.contains("not-an-image")));
    assert_eq!(*calls.lock().unwrap(), vec![(newest_id, ImageFidelity::Full), (older_id, ImageFidelity::Thumb)]);
}

#[test]
fn image_marker_literals_in_system_and_assistant_text_are_preserved() {
    let system_literal = "Quoted literally: [IMAGE:data:image/png;base64,not-an-image]";
    let assistant_literal = "I saw [IMAGE:data:image/png;base64,not-an-image] in the prompt.";
    let history = vec![("Please quote the marker".into(), assistant_literal.into())];
    let input = PromptInput {
        system_prompt: system_literal,
        memory_text: "",
        history: &history,
        send_thoughts: true,
        context_size: 32_768,
    };

    let prepared = prepare_prompt_messages(&input, "continue");

    assert_eq!(prepared.messages[0].content, system_literal);
    assert_eq!(prepared.messages[2].content, assistant_literal);
}
