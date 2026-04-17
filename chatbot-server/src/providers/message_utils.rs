use crate::providers::openai::messages::{ContentPart, ImageUrlPart, MessageContent};

const IMAGE_PATTERN: &str = "[IMAGE:";
const IMAGE_TRAILER: char = ']';

pub fn parse_message_content(input: &str) -> MessageContent {
    if !input.contains(IMAGE_PATTERN) {
        return MessageContent::Text(input.to_string());
    }

    let mut parts = Vec::new();
    let mut current_text = String::new();
    let mut remaining = input;

    while let Some(image_start) = remaining.find(IMAGE_PATTERN) {
        if image_start > 0 {
            current_text.push_str(&remaining[..image_start]);
        }

        if current_text.trim().len() > 0 {
            parts.push(ContentPart::Text {
                text: current_text.trim().to_string(),
            });
            current_text.clear();
        }

        remaining = &remaining[image_start + IMAGE_PATTERN.len()..];

        if let Some(image_end) = remaining.find(IMAGE_TRAILER) {
            let image_data = &remaining[..image_end];
            let image_url = if image_data.starts_with("data:") {
                image_data.to_string()
            } else {
                format!("data:image/jpeg;base64,{}", image_data)
            };

            parts.push(ContentPart::ImageUrl {
                image_url: ImageUrlPart { url: image_url },
            });

            remaining = &remaining[image_end + 1..];
        } else {
            current_text.push_str(IMAGE_PATTERN);
            current_text.push_str(remaining);
            remaining = "";
        }
    }

    if !remaining.is_empty() {
        current_text.push_str(remaining);
    }

    if current_text.trim().len() > 0 {
        parts.push(ContentPart::Text {
            text: current_text.trim().to_string(),
        });
    }

    if parts.len() == 1 {
        if let Some(ContentPart::Text { text }) = parts.first() {
            return MessageContent::Text(text.clone());
        }
    }

    MessageContent::MultiModal(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_only() {
        let input = "Hello, how are you?";
        let result = parse_message_content(input);
        match result {
            MessageContent::Text(s) => assert_eq!(s, "Hello, how are you?"),
            _ => panic!("Expected Text variant"),
        }
    }

    #[test]
    fn test_image_only() {
        let input = "[IMAGE:data:image/png;base64,abc123]";
        let result = parse_message_content(input);
        match result {
            MessageContent::MultiModal(parts) => {
                assert_eq!(parts.len(), 1);
                match &parts[0] {
                    ContentPart::ImageUrl { image_url } => {
                        assert_eq!(image_url.url, "data:image/png;base64,abc123");
                    }
                    _ => panic!("Expected ImageUrl variant"),
                }
            }
            _ => panic!("Expected MultiModal variant"),
        }
    }

    #[test]
    fn test_text_and_image() {
        let input = "Look at this: [IMAGE:data:image/png;base64,abc123]";
        let result = parse_message_content(input);
        match result {
            MessageContent::MultiModal(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    ContentPart::Text { text } => assert_eq!(text, "Look at this:"),
                    _ => panic!("Expected Text variant"),
                }
                match &parts[1] {
                    ContentPart::ImageUrl { image_url } => {
                        assert_eq!(image_url.url, "data:image/png;base64,abc123");
                    }
                    _ => panic!("Expected ImageUrl variant"),
                }
            }
            _ => panic!("Expected MultiModal variant"),
        }
    }

    #[test]
    fn test_image_without_data_prefix() {
        let input = "[IMAGE:abc123]";
        let result = parse_message_content(input);
        match result {
            MessageContent::MultiModal(parts) => {
                assert_eq!(parts.len(), 1);
                match &parts[0] {
                    ContentPart::ImageUrl { image_url } => {
                        assert_eq!(image_url.url, "data:image/jpeg;base64,abc123");
                    }
                    _ => panic!("Expected ImageUrl variant"),
                }
            }
            _ => panic!("Expected MultiModal variant"),
        }
    }
}
