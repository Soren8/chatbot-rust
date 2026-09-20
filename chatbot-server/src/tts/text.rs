use once_cell::sync::Lazy;
use regex::Regex;
use tracing::debug;

static THINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new("(?s)<think>.*?</think>").expect("valid think regex"));

static EMOJI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\p{Emoji_Presentation}\p{Extended_Pictographic}\u{200d}\u{FE0F}]")
        .expect("valid emoji regex")
});

static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https?://[^\s]+|www\.[^\s]+").expect("valid url regex")
});

// Matches citation markers like [1], [2], [[1]], [[2]] (with optional surrounding whitespace)
static CITATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[?\[(\d+)\]\]?").expect("valid citation regex")
});

// ~100 / ≈100 -> "about 100"
static APPROX_NUMBER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[~≈][ \t]*(\d[\d,]*)").expect("valid approx number regex"));

// Tight-coupled magnitude suffixes: 10k / 2.5M / 2B / 4bn -> thousand/million/billion
static MAGNITUDE_SUFFIX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\d[\d,]*(?:\.\d+)?)(bn|b|m|k)\b").expect("valid magnitude suffix regex")
});

// Dotted numbers read wrong by TTS (3.6 sounds like a sentence end): spell as words
static DECIMAL_NUMBER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d[\d,]*(?:\.\d+)+\b").expect("valid decimal number regex"));

// Standalone two-digit integers read smoother as words ("fifty eight"). The
// token grab includes comma groups so 25,000 is never split mid-number.
static INTEGER_TOKEN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d+(?:,\d+)*)\b").expect("valid integer token regex"));

// Matches currency with magnitude words or suffixes: $12.6 billion, $12.6B, €5M, £10k, $12.6 billion dollars
static CURRENCY_MAGNITUDE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*(\d[\d,]*(?:\.\d+)?)\s*(trillion|billion|million|thousand|bn|b|m|k)\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency magnitude regex")
});

// Matches cents-only currency: $0.50, $0.01, €0.75, £0.25
static CURRENCY_CENTS_ONLY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*0\.(\d{1,2})\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency cents only regex")
});

// Matches currency with decimal cents: $12.50, $1.00, €5.20, £2.50
static CURRENCY_DECIMAL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*(\d[\d,]*)\.(\d{1,2})\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency decimal regex")
});

// Matches integer currency amounts: $5, $1, $100,000, €1, £5
static CURRENCY_INT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*(\d[\d,]*)\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency int regex")
});

// Matches dotted initialisms like U.S., U.S.A., A.I., D.C., Ph.D.
static DOTTED_INITIALISM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Z][a-z]?)\.([A-Z][a-z]?)\.(?:([A-Z][a-z]?)\.)*")
        .expect("valid dotted initialism regex")
});

// Common Latin abbreviations: e.g., i.e., etc., vs.
static EG_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\be\.g\.,?\s*").expect("valid eg regex"));
static IE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bi\.e\.,?\s*").expect("valid ie regex"));
static ETC_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\betc(?:\.|\b)").expect("valid etc regex"));
static VS_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bvs(?:\.|\b)").expect("valid vs regex"));

// Titles/honorifics
static TITLES_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(Dr|Mr|Mrs|Ms|Prof|Sr|Jr|Gen|Col|Sgt|Lt|Capt)\.\s*")
        .expect("valid titles regex")
});

// Common shortened words
static ABBREV_WORDS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(approx|dept|apt|est|govt|corp|inc|ltd|co)\.\s*")
        .expect("valid abbrev words regex")
});

// Time: 10 a.m. / 10 p.m.
static AM_PM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(\d+)\s*([ap])\.m\.\b").expect("valid am pm regex")
});

// Percentage: 58% -> 58 percent
static PERCENT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*%").expect("valid percent regex")
});

// Ampersand between words: AT&T -> AT and T
static AMPERSAND_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+)\s*&\s*(\w+)").expect("valid ampersand regex")
});

// Number sign before digits: #1 -> number 1
static NUMBER_SIGN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#(\d+)\b").expect("valid number sign regex")
});

// Temperature / angle degrees: 20°C -> 20 degrees Celsius, 70°F -> 70 degrees Fahrenheit
static DEGREE_C_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*°C\b").expect("valid degree c regex")
});
static DEGREE_F_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*°F\b").expect("valid degree f regex")
});
static DEGREE_SYMBOL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*°\b").expect("valid degree regex")
});

const DIGIT_WORDS: [&str; 10] = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
];
const TEEN_WORDS: [&str; 10] = [
    "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
    "eighteen", "nineteen",
];
const TENS_WORDS: [&str; 10] = [
    "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
];

/// Spells an integer 0..=999 as English words ("205" -> "two hundred five").
fn small_integer_to_words(n: u32) -> String {
    match n {
        0..=9 => DIGIT_WORDS[n as usize].to_string(),
        10..=19 => TEEN_WORDS[(n - 10) as usize].to_string(),
        20..=99 => {
            let ones = n % 10;
            let tens = format!("{}", TENS_WORDS[(n / 10) as usize]);
            if ones == 0 {
                tens
            } else {
                format!("{tens} {}", DIGIT_WORDS[ones as usize])
            }
        }
        _ => {
            let hundreds = format!("{} hundred", DIGIT_WORDS[(n / 100) as usize]);
            let rest = n % 100;
            if rest == 0 {
                hundreds
            } else {
                format!("{hundreds} {}", small_integer_to_words(rest))
            }
        }
    }
}

/// Spells an unsigned integer up to trillions as English words ("12000" -> "twelve thousand").
fn integer_to_words(n: u64) -> String {
    if n <= 999 {
        return small_integer_to_words(n as u32);
    }
    let mut parts = Vec::new();
    let trillions = n / 1_000_000_000_000;
    let billions = (n % 1_000_000_000_000) / 1_000_000_000;
    let millions = (n % 1_000_000_000) / 1_000_000;
    let thousands = (n % 1_000_000) / 1_000;
    let remainder = n % 1000;

    if trillions > 0 {
        parts.push(format!("{} trillion", small_integer_to_words(trillions as u32)));
    }
    if billions > 0 {
        parts.push(format!("{} billion", small_integer_to_words(billions as u32)));
    }
    if millions > 0 {
        parts.push(format!("{} million", small_integer_to_words(millions as u32)));
    }
    if thousands > 0 {
        parts.push(format!("{} thousand", small_integer_to_words(thousands as u32)));
    }
    if remainder > 0 {
        parts.push(small_integer_to_words(remainder as u32));
    }
    parts.join(" ")
}

/// Spells a standalone two-digit integer ("58" -> "fifty eight"); leaves
/// everything else alone.
fn two_digit_number_to_words(raw: &str) -> Option<String> {
    let n: u32 = raw.parse().ok()?;
    if !(10..=99).contains(&n) {
        return None;
    }
    Some(small_integer_to_words(n))
}

fn expand_decimal_token(raw: &str) -> String {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() == 2 {
        let int_clean = parts[0].replace(',', "");
        let int_spoken = if let Ok(n) = int_clean.parse::<u64>() {
            integer_to_words(n)
        } else {
            parts[0]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
                .collect::<Vec<_>>()
                .join(" ")
        };

        let frac_spoken = parts[1]
            .chars()
            .filter(|c| c.is_ascii_digit())
            .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
            .collect::<Vec<_>>()
            .join(" ");

        format!("{int_spoken} point {frac_spoken}")
    } else {
        parts
            .iter()
            .map(|part| {
                let clean = part.replace(',', "");
                if let Ok(n) = clean.parse::<u64>() {
                    integer_to_words(n)
                } else {
                    part.chars()
                        .filter(|c| c.is_ascii_digit())
                        .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            })
            .collect::<Vec<_>>()
            .join(" point ")
    }
}

fn currency_name(symbol: &str, plural: bool) -> &'static str {
    match symbol {
        "$" => if plural { "dollars" } else { "dollar" },
        "€" => if plural { "euros" } else { "euro" },
        "£" => if plural { "pounds" } else { "pound" },
        _ => if plural { "dollars" } else { "dollar" },
    }
}

fn cents_name(symbol: &str, cents: u32) -> String {
    if symbol == "£" {
        if cents == 1 {
            "1 penny".to_string()
        } else {
            format!("{cents} pence")
        }
    } else if cents == 1 {
        "1 cent".to_string()
    } else {
        format!("{cents} cents")
    }
}

fn expand_currency(input: &str) -> String {
    // 1. Currency with magnitudes: $12.6 billion, $12.6B, $12.6 billion dollars
    let with_mag = CURRENCY_MAGNITUDE_REGEX.replace_all(input, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let amount = caps[2].replace(',', "");
        let mag_raw = caps[3].to_ascii_lowercase();
        let mag_word = match mag_raw.as_str() {
            "k" | "thousand" => "thousand",
            "m" | "million" => "million",
            "b" | "bn" | "billion" => "billion",
            "trillion" => "trillion",
            _ => mag_raw.as_str(),
        };
        let curr_word = currency_name(symbol, true);
        format!("{amount} {mag_word} {curr_word}")
    });

    // 2. Cents-only amounts: $0.50, $0.01
    let with_cents = CURRENCY_CENTS_ONLY_REGEX.replace_all(&with_mag, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let cents_str = &caps[2];
        let cents: u32 = match cents_str.len() {
            1 => cents_str.parse::<u32>().unwrap_or(0) * 10,
            _ => cents_str.parse::<u32>().unwrap_or(0),
        };
        cents_name(symbol, cents)
    });

    // 3. Dollars and cents: $12.50, $1.00
    let with_dec = CURRENCY_DECIMAL_REGEX.replace_all(&with_cents, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let int_str = caps[2].replace(',', "");
        let cents_str = &caps[3];
        let cents: u32 = match cents_str.len() {
            1 => cents_str.parse::<u32>().unwrap_or(0) * 10,
            _ => cents_str.parse::<u32>().unwrap_or(0),
        };
        let int_val: u64 = int_str.parse().unwrap_or(0);
        let int_unit = currency_name(symbol, int_val != 1);

        if cents == 0 {
            format!("{int_str} {int_unit}")
        } else {
            let cents_str_spoken = cents_name(symbol, cents);
            format!("{int_str} {int_unit} and {cents_str_spoken}")
        }
    });

    // 4. Integer currency amounts: $5, $1, $100,000
    let with_int = CURRENCY_INT_REGEX.replace_all(&with_dec, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let amount = &caps[2];
        let clean = amount.replace(',', "");
        let val: u64 = clean.parse().unwrap_or(0);
        let unit = currency_name(symbol, val != 1);
        format!("{amount} {unit}")
    });

    with_int.into_owned()
}

fn is_at_sentence_end(rest: &str) -> bool {
    let trimmed = rest.trim_start_matches(|c: char| {
        c == '"' || c == '\'' || c == ')' || c == ']' || c == '}' || c == '”' || c == '’'
    });
    let trimmed = trimmed.trim_start();
    trimmed.is_empty() || trimmed.starts_with(|c: char| c.is_ascii_uppercase())
}

fn expand_abbreviations(input: &str) -> String {
    // Latin abbreviations
    let s = EG_REGEX.replace_all(input, "for example ");
    let s = IE_REGEX.replace_all(&s, "that is ");
    let s = ETC_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let full_match = caps.get(0).unwrap();
        let rest = &s[full_match.end()..];
        if is_at_sentence_end(rest) {
            "etcetera."
        } else {
            "etcetera"
        }
    });
    let s = VS_REGEX.replace_all(&s, "versus");

    // Titles / honorifics
    let s = TITLES_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let title = match &caps[1] {
            "Dr" => "Doctor",
            "Mr" => "Mister",
            "Mrs" => "Missus",
            "Ms" => "Ms",
            "Prof" => "Professor",
            "Sr" => "Senior",
            "Jr" => "Junior",
            "Gen" => "General",
            "Col" => "Colonel",
            "Sgt" => "Sergeant",
            "Lt" => "Lieutenant",
            "Capt" => "Captain",
            other => other,
        };
        format!("{title} ")
    });

    // Common shortened words
    let s = ABBREV_WORDS_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let word = match caps[1].to_ascii_lowercase().as_str() {
            "approx" => "approximately",
            "dept" => "department",
            "apt" => "apartment",
            "est" => "established",
            "govt" => "government",
            "corp" => "corporation",
            "inc" => "incorporated",
            "ltd" => "limited",
            "co" => "company",
            _ => &caps[1],
        };
        format!("{word} ")
    });

    // Time: 10 a.m. / 10 p.m.
    let s = AM_PM_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let hour = &caps[1];
        let ap = caps[2].to_ascii_uppercase();
        format!("{hour} {ap}M")
    });

    // Symbols
    let s = DEGREE_C_REGEX.replace_all(&s, "$1 degrees Celsius");
    let s = DEGREE_F_REGEX.replace_all(&s, "$1 degrees Fahrenheit");
    let s = DEGREE_SYMBOL_REGEX.replace_all(&s, "$1 degrees");
    let s = PERCENT_REGEX.replace_all(&s, "$1 percent");
    let s = AMPERSAND_REGEX.replace_all(&s, "$1 and $2");
    let s = NUMBER_SIGN_REGEX.replace_all(&s, "number $1");

    // Dotted initialisms: U.S., U.S.A., A.I., D.C., Ph.D.
    // Preserves sentence terminator dot if followed by uppercase or sentence end.
    let result = DOTTED_INITIALISM_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let full_match = caps.get(0).unwrap();
        let end_idx = full_match.end();
        let rest = &s[end_idx..];

        let letters: String = caps[0].chars().filter(|c| c.is_alphabetic()).collect();
        if is_at_sentence_end(rest) {
            format!("{letters}.")
        } else {
            letters
        }
    });

    result.into_owned()
}

fn expand_speech_numbers(input: &str) -> String {
    let with_about = APPROX_NUMBER_REGEX.replace_all(input, "about $1");

    let with_magnitudes = MAGNITUDE_SUFFIX_REGEX
        .replace_all(&with_about, |caps: &regex::Captures| {
            let number = caps[1].replace(',', "");
            let suffix = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            // Lowercase tight "m" is ambiguous (meters/miles/minutes vs
            // million): keep the letter, just spell the number as words.
            if suffix == "m" {
                let spoken = match number.parse::<u32>() {
                    Ok(n) if n <= 999 => small_integer_to_words(n),
                    _ => number.clone(),
                };
                return format!("{spoken} m");
            }
            let spoken = match suffix.to_ascii_lowercase().as_str() {
                "k" => "thousand",
                "m" => "million",
                "b" | "bn" => "billion",
                _ => return caps[0].to_string(),
            };
            format!("{number} {spoken}")
        })
        .into_owned();

    let expanded = DECIMAL_NUMBER_REGEX
        .replace_all(&with_magnitudes, |caps: &regex::Captures| {
            expand_decimal_token(&caps[0])
        })
        .into_owned();

    let expanded = INTEGER_TOKEN_REGEX
        .replace_all(&expanded, |caps: &regex::Captures| {
            two_digit_number_to_words(&caps[1]).unwrap_or_else(|| caps[1].to_string())
        })
        .into_owned();

    debug!(expanded_preview = ?expanded.get(..100.min(expanded.len())), "expand_speech_numbers: result");
    expanded
}

pub(super) fn sanitize_text(input: &str) -> String {
    debug!(input_len = input.len(), input_preview = ?input.get(..100.min(input.len())), "sanitize_text: starting");

    let mut no_think = THINK_REGEX.replace_all(input, "").into_owned();

    // Robustness: if we still see </think>, it means the start tag was missing.
    // Strip everything up to and including the first </think>.
    if let Some(pos) = no_think.find("</think>") {
        no_think = no_think[pos + 8..].to_string();
    }

    // Remove URLs BEFORE markdown parsing so [text](url) links are handled correctly
    let url_matches: Vec<_> = URL_REGEX.find_iter(&no_think).collect();
    debug!(url_match_count = url_matches.len(), matches = ?url_matches.iter().map(|m| m.as_str()).collect::<Vec<_>>(), "sanitize_text: URL matches before stripping");

    let no_urls = URL_REGEX.replace_all(&no_think, "");
    debug!(no_urls_preview = ?no_urls.get(..100.min(no_urls.len())), "sanitize_text: after URL removal");

    let no_emoji = EMOJI_REGEX.replace_all(&no_urls, "");

    let mut options = pulldown_cmark::Options::empty();
    options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    let parser = pulldown_cmark::Parser::new_ext(&no_emoji, options);

    let mut cleaned = String::with_capacity(no_emoji.len());
    for event in parser {
        match event {
            pulldown_cmark::Event::Text(t) => cleaned.push_str(&t),
            pulldown_cmark::Event::Code(t) => cleaned.push_str(&t),
            pulldown_cmark::Event::SoftBreak | pulldown_cmark::Event::HardBreak => cleaned.push(' '),
            _ => {}
        }
    }

    // Strip citation markers like [1], [[2]] that survive markdown parsing
    let no_citations = CITATION_REGEX.replace_all(&cleaned, "");

    // Expand currencies: $12.6 billion -> 12.6 billion dollars, $5 -> 5 dollars
    let with_currency = expand_currency(&no_citations);

    // Expand abbreviations, initialisms (U.S. -> US, e.g. -> for example, Dr. -> Doctor)
    // and symbols (58% -> 58 percent, AT&T -> AT and T)
    let with_abbreviations = expand_abbreviations(&with_currency);

    // Expand numeric patterns TTS garbles: ~N approximations, k/m/b magnitude
    // suffixes, and dotted numbers like 12.6 ("twelve point six")
    let expanded = expand_speech_numbers(&with_abbreviations);

    // Collapse multiple spaces into one
    let collapsed = expanded.split_whitespace().collect::<Vec<_>>().join(" ");

    let result = collapsed.trim().to_string();
    debug!(result_preview = ?result.get(..100.min(result.len())), "sanitize_text: final result");
    if !result.chars().any(|c| c.is_alphanumeric()) {
        return String::new();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_text_strips_emojis() {
        let input = "Hello 🌟! How are you doing today? 😊 (Thinking: <think>I am a bot</think>)";
        // pulldown_cmark might collapse spaces or handle them in specific ways.
        // Let's match what it actually produces.
        let result = sanitize_text(input);
        assert!(!result.contains("🌟"));
        assert!(!result.contains("😊"));
        assert!(!result.contains("I am a bot"));
        assert!(result.contains("Hello !"));
        assert!(result.contains("How are you doing today?"));
    }

    #[test]
    fn test_sanitize_text_strips_complex_emojis() {
        let input = "Family: 👨‍👩‍👧‍👦, Flag: 🇺🇸, Rainbow: 🌈";
        let result = sanitize_text(input);
        // Ensure no leftover ZWJ or other emoji components
        assert_eq!(result, "Family: , Flag: , Rainbow:");
    }

    #[test]
    fn test_sanitize_text_does_not_strip_standard_text() {
        let input = "Text with numbers 123 and punctuation !@#$%^&*()_+-=[]{};':\",./<>?";
        let result = sanitize_text(input);
        assert_eq!(result, "Text with numbers 123 and punctuation !@#$%^&*()_+-=[]{};':\",./<>?");
    }

    #[test]
    fn test_text_between_emojis() {
        let input = "🚀 Hello 🚀 World 🚀";
        let result = sanitize_text(input);
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_sanitize_text_strips_urls() {
        let input = "Check out https://example.com and www.test.org for more info";
        let result = sanitize_text(input);
        assert!(!result.contains("https://example.com"));
        assert!(!result.contains("www.test.org"));
        assert!(result.contains("Check out"));
        assert!(result.contains("for more info"));
    }

    #[test]
    fn test_sanitize_text_strips_http_urls() {
        let input = "Visit http://old-site.net today!";
        let result = sanitize_text(input);
        assert!(!result.contains("http://old-site.net"));
        assert!(result.contains("Visit"));
        assert!(result.contains("today!"));
    }

    #[test]
    fn test_sanitize_text_strips_long_url() {
        let input = "Check this out: https://example.com/news/article-title-goes-here-123456";
        let result = sanitize_text(input);
        eprintln!("Result: '{}'", result);
        assert!(!result.contains("example.com"), "example.com should be stripped but result is: {}", result);
        assert!(!result.contains("https://"), "https:// should be stripped but result is: {}", result);
        assert!(result.contains("Check this out:"), "Check this out: should remain but result is: {}", result);
    }

    #[test]
    fn test_url_regex_matches_full_url() {
        let url = "https://example.com/news/article-title-goes-here-123456";
        let caps: Vec<_> = URL_REGEX.find_iter(url).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].as_str(), url);
    }

    #[test]
    fn test_sanitize_text_strips_citations() {
        let input = "Some fact [1] and another fact [[2]] here.";
        let result = sanitize_text(input);
        assert!(!result.contains("[1]"), "citation [1] should be stripped but result is: {}", result);
        assert!(!result.contains("[2]"), "citation [2] should be stripped but result is: {}", result);
        assert!(result.contains("Some fact"));
        assert!(result.contains("another fact"));
    }

    #[test]
    fn test_sanitize_text_strips_markdown_link_citations() {
        let input = "Check this [[1]](https://example.com/article) for details.";
        let result = sanitize_text(input);
        assert!(!result.contains("[1]"), "citation should be stripped but result is: {}", result);
        assert!(!result.contains("example.com"), "URL should be stripped but result is: {}", result);
        assert!(result.contains("Check this"));
        assert!(result.contains("for details."));
    }

    #[test]
    fn test_sanitize_text_strips_bold_and_italic() {
        let input = "This is **bold** and *italic* text.";
        let result = sanitize_text(input);
        assert!(!result.contains("**"), "bold markers should be stripped but result is: {}", result);
        assert!(!result.contains("*italic*"), "italic markers should be stripped but result is: {}", result);
        assert_eq!(result, "This is bold and italic text.");
    }

    #[test]
    fn test_sanitize_text_expands_version_numbers() {
        let input = "We upgraded to version 3.6 last week.";
        let result = sanitize_text(input);
        assert!(
            result.contains("three point six"),
            "version 3.6 should be spoken as 'three point six' but result is: {}",
            result
        );
        assert!(!result.contains("3.6"), "raw version number should be gone but result is: {}", result);
        assert!(result.trim_end().ends_with('.'), "sentence-ending period must be preserved but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_expands_multi_part_versions() {
        let input = "The app now runs on Kotlin 1.2.3.";
        let result = sanitize_text(input);
        assert_eq!(result, "The app now runs on Kotlin one point two point three.");
    }

    #[test]
    fn test_sanitize_text_expands_two_digit_integers_only() {
        let input = "There are 200 cats, 7 birds, and 42 dogs here.";
        let result = sanitize_text(input);
        assert_eq!(result, "There are 200 cats, 7 birds, and forty two dogs here.");
    }

    #[test]
    fn test_sanitize_text_spells_teens_and_tens() {
        let input = "It took 13 days: 30 hours and 90 minutes in total.";
        let result = sanitize_text(input);
        assert_eq!(result, "It took thirteen days: thirty hours and ninety minutes in total.");
    }

    #[test]
    fn test_sanitize_text_keeps_lowercase_m_ambiguous() {
        let input = "He ran 200m today and swam 1500m yesterday.";
        let result = sanitize_text(input);
        assert!(
            result.contains("two hundred m"),
            "tight lowercase m should keep the letter with spelled words but result is: {}",
            result
        );
        assert!(!result.contains("million"), "ambiguous m must not expand to million but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_leaves_words_without_digits_alone() {
        let input = "This is a plain sentence with no numbers at all.";
        let result = sanitize_text(input);
        assert_eq!(result, "This is a plain sentence with no numbers at all.");
    }

    #[test]
    fn test_sanitize_text_expands_approximation_marker() {
        let input = "The cluster handles ~58m requests per day.";
        let result = sanitize_text(input);
        assert!(
            result.contains("about fifty eight m requests"),
            "~58m should become 'about fifty eight m' but result is: {}",
            result
        );
        assert!(!result.contains("~"), "tilde should be expanded but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_expands_magnitude_suffixes() {
        let result = sanitize_text("The video got 10k views and the fund raised 2B dollars.");
        assert!(result.contains("ten thousand views"), "k suffix should expand but result is: {}", result);
        assert!(result.contains("2 billion dollars"), "B suffix should expand but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_expands_decimal_with_magnitude_suffix() {
        let result = sanitize_text("It reached 2.5M users.");
        assert_eq!(result, "It reached two point five million users.");
    }

    #[test]
    fn test_sanitize_text_does_not_expand_units_like_ms_or_km() {
        let input = "The lap took 45 seconds and the run was 5km long with 30ms latency noted.";
        let result = sanitize_text(input);
        assert!(result.contains("5km"), "km must not be mis-expanded but result is: {}", result);
        assert!(result.contains("30ms"), "ms must not be mis-expanded but result is: {}", result);
    }

    /// Sentence chunks that are pure markdown structure (rules, empty headings,
    /// blockquote markers, HTML, entities) sanitize to nothing. The handler
    /// must treat these as silence, not as a 500 the client cannot fix.
    #[test]
    fn test_sanitize_text_empties_for_marker_only_chunks() {
        for input in ["---", "***", "___", "#", ">", "<!-- note -->", "&nbsp;", ")", ":", ": - )", "... "] {
            assert!(
                sanitize_text(input).is_empty(),
                "{input:?} should sanitize to empty"
            );
        }
        // Normal sentences must never sanitize to empty (the silence fallback
        // must not swallow speakable text).
        for input in [
            "Hello.",
            "- a list item.",
            "## A heading.",
            "> a quote.",
            "Section divider follows.\n\n---\n\nNext section.",
        ] {
            assert!(
                !sanitize_text(input).is_empty(),
                "{input:?} must survive sanitization as speakable text"
            );
        }
    }

    #[test]
    fn test_sanitize_text_expands_dollar_currency() {
        // Twelve point six billion dollars as a whole unit, not dollar sign one two point six billion
        let result = sanitize_text("The company is valued at $12.6 billion.");
        assert_eq!(result, "The company is valued at twelve point six billion dollars.");

        // Tight B magnitude suffix
        let result = sanitize_text("They raised $12.6B in new capital.");
        assert_eq!(result, "They raised twelve point six billion dollars in new capital.");

        // Does not duplicate "dollars" if already in text
        let result = sanitize_text("Total assets reached $12.6 billion dollars.");
        assert_eq!(result, "Total assets reached twelve point six billion dollars.");

        // Standard integer amounts
        assert_eq!(sanitize_text("He paid $5 for coffee."), "He paid 5 dollars for coffee.");
        assert_eq!(sanitize_text("The fee is $1."), "The fee is 1 dollar.");
        assert_eq!(sanitize_text("It costs $1.00."), "It costs 1 dollar.");
        assert_eq!(sanitize_text("A prize of $100,000 was awarded."), "A prize of 100,000 dollars was awarded.");

        // Dollars and cents
        assert_eq!(sanitize_text("The total is $12.50."), "The total is twelve dollars and fifty cents.");
        assert_eq!(sanitize_text("The candy costs $0.50."), "The candy costs fifty cents.");
        assert_eq!(sanitize_text("It was only $0.01."), "It was only 1 cent.");
    }

    #[test]
    fn test_sanitize_text_expands_other_currencies() {
        assert_eq!(sanitize_text("The fund is €12.6 billion."), "The fund is twelve point six billion euros.");
        assert_eq!(sanitize_text("Cost was €1."), "Cost was 1 euro.");
        assert_eq!(sanitize_text("Price is £5."), "Price is 5 pounds.");
        assert_eq!(sanitize_text("Entry is £1."), "Entry is 1 pound.");
        assert_eq!(sanitize_text("Ticket costs £2.50."), "Ticket costs 2 pounds and fifty pence.");
    }

    #[test]
    fn test_sanitize_text_expands_whole_units_for_decimals() {
        let result = sanitize_text("The measurement was 12.6 meters.");
        assert_eq!(result, "The measurement was twelve point six meters.");

        let result = sanitize_text("The speed was 42.5 km.");
        assert_eq!(result, "The speed was forty two point five km.");
    }

    #[test]
    fn test_sanitize_text_normalizes_dotted_initialisms() {
        let result = sanitize_text("The U.S. government announced new guidelines.");
        assert_eq!(result, "The US government announced new guidelines.");

        let result = sanitize_text("We traveled across the U.S.A. last summer.");
        assert_eq!(result, "We traveled across the USA last summer.");

        let result = sanitize_text("He works on A.I. research in Washington, D.C.");
        assert_eq!(result, "He works on AI research in Washington, DC.");

        let result = sanitize_text("She completed her Ph.D. in physics.");
        assert_eq!(result, "She completed her PhD in physics.");

        // Preserves sentence terminator period when dotted initialism ends sentence
        let result = sanitize_text("They live in the U.S. It is warm there.");
        assert_eq!(result, "They live in the US. It is warm there.");
    }

    #[test]
    fn test_sanitize_text_expands_common_abbreviations() {
        assert_eq!(
            sanitize_text("Bring snacks, e.g. fruit or nuts."),
            "Bring snacks, for example fruit or nuts."
        );
        assert_eq!(
            sanitize_text("Pick the default, i.e. option one."),
            "Pick the default, that is option one."
        );
        assert_eq!(
            sanitize_text("Supplies include pens, pencils, etc."),
            "Supplies include pens, pencils, etcetera."
        );
        assert_eq!(
            sanitize_text("Game one is Team A vs. Team B."),
            "Game one is Team A versus Team B."
        );
        assert_eq!(
            sanitize_text("Dr. Smith met with Mr. Jones."),
            "Doctor Smith met with Mister Jones."
        );
    }

    #[test]
    fn test_sanitize_text_expands_symbols_and_percentages() {
        assert_eq!(
            sanitize_text("Profits increased by 58% this year."),
            "Profits increased by fifty eight percent this year."
        );
        assert_eq!(
            sanitize_text("She works at AT&T headquarters."),
            "She works at AT and T headquarters."
        );
        assert_eq!(
            sanitize_text("He is ranked #1 in the league."),
            "He is ranked number 1 in the league."
        );
    }
}
