use std::{env, fs, path::PathBuf};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn set_management_flow() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "testuser";
    let password = "Sup3rS3cret!";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    let users_json = workspace.path().join("users.json");
    fs::write(
        &users_json,
        serde_json::to_string_pretty(&json!({
            username: {
                "password": hashed,
                "tier": "free"
            }
        }))
        .expect("serialize users"),
    )
    .expect("write users.json");

    let static_root = resolve_static_root();
    let app = build_router(static_root);
    let client = common::AuthedClient::login(app.clone(), username, password).await;

    let get_sets_response = app
        .clone()
        .oneshot(
            client
                .request(Method::GET, "/get_sets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /get_sets");

    assert_eq!(get_sets_response.status(), StatusCode::OK);
    let sets_body = to_bytes(get_sets_response.into_body(), 128 * 1024)
        .await
        .expect("sets body");
    let sets_json: serde_json::Value = serde_json::from_slice(&sets_body).expect("sets json");
    assert!(
        sets_json
            .as_array()
            .expect("expected array")
            .iter()
            .any(|s| s["name"] == "default"),
        "default set missing"
    );

    let new_set_name = "study";
    let create_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/create_set")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": new_set_name})).expect("create payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /create_set");

    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body = to_bytes(create_response.into_body(), 64 * 1024)
        .await
        .expect("create body");
    let create_json: serde_json::Value = serde_json::from_slice(&create_body).expect("create json");
    assert_eq!(
        create_json.get("status"),
        Some(&serde_json::Value::String("success".into()))
    );

    let get_sets_response = app
        .clone()
        .oneshot(
            client
                .request(Method::GET, "/get_sets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /get_sets after create");

    assert_eq!(get_sets_response.status(), StatusCode::OK);
    let sets_body = to_bytes(get_sets_response.into_body(), 128 * 1024)
        .await
        .expect("sets body after create");
    let sets_json: serde_json::Value =
        serde_json::from_slice(&sets_body).expect("sets json after create");
    assert!(
        sets_json
            .as_array()
            .expect("expected array")
            .iter()
            .any(|s| s["name"] == new_set_name),
        "new set not present"
    );

    seed_plaintext_set(&workspace.path().join("user_sets"), username, new_set_name);

    let load_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/load_set")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": new_set_name})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set");

    assert_eq!(load_response.status(), StatusCode::OK);
    let load_body = to_bytes(load_response.into_body(), 256 * 1024)
        .await
        .expect("load body");
    let load_json: serde_json::Value = serde_json::from_slice(&load_body).expect("load json");
    assert_eq!(
        load_json.get("system_prompt").and_then(|v| v.as_str()),
        Some("Study hard")
    );
    assert_eq!(
        load_json.get("memory").and_then(|v| v.as_str()),
        Some("Important notes")
    );
    let history_items = load_json
        .get("history")
        .and_then(|v| v.as_array())
        .expect("history array");
    assert_eq!(history_items.len(), 2);

    let delete_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/delete_set")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": new_set_name})).expect("delete payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_set");

    assert_eq!(delete_response.status(), StatusCode::OK);
    let delete_body = to_bytes(delete_response.into_body(), 64 * 1024)
        .await
        .expect("delete body");
    let delete_json: serde_json::Value = serde_json::from_slice(&delete_body).expect("delete json");
    assert_eq!(
        delete_json.get("status"),
        Some(&serde_json::Value::String("success".into()))
    );

    let user_set_dir = workspace.path().join("user_sets").join(username);
    assert!(!user_set_dir
        .join(format!("{}_memory.txt", new_set_name))
        .exists());
    assert!(!user_set_dir
        .join(format!("{}_history.json", new_set_name))
        .exists());

    let final_sets_response = app
        .clone()
        .oneshot(
            client
                .request(Method::GET, "/get_sets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /get_sets final");

    assert_eq!(final_sets_response.status(), StatusCode::OK);
    let final_body = to_bytes(final_sets_response.into_body(), 128 * 1024)
        .await
        .expect("final sets body");
    let final_json: serde_json::Value =
        serde_json::from_slice(&final_body).expect("final sets json");
    assert!(
        !final_json
            .as_array()
            .expect("expected array")
            .iter()
            .any(|s| s["name"] == new_set_name),
        "deleted set should not be present"
    );
}

fn seed_plaintext_set(root: &PathBuf, username: &str, set_name: &str) {
    let user_dir = root.join(username);
    fs::create_dir_all(&user_dir).expect("create user dir");

    let sets_path = user_dir.join("sets.json");
    let mut sets: serde_json::Value = if sets_path.exists() {
        let data = fs::read_to_string(&sets_path).expect("read sets");
        serde_json::from_str(&data).unwrap_or(json!({}))
    } else {
        json!({})
    };

    if let Some(obj) = sets.as_object_mut() {
        obj.insert(
            set_name.to_string(),
            json!({
                "created": 1_700_000_000.0,
                "encrypted": false
            }),
        );
    }

    fs::write(
        &sets_path,
        serde_json::to_string_pretty(&sets).expect("serialize sets"),
    )
    .expect("write sets.json");

    fs::write(
        user_dir.join(format!("{}_memory.txt", set_name)),
        b"Important notes",
    )
    .expect("write memory");

    fs::write(
        user_dir.join(format!("{}_prompt.txt", set_name)),
        b"Study hard",
    )
    .expect("write prompt");

    fs::write(
        user_dir.join(format!("{}_history.json", set_name)),
        serde_json::to_vec(&json!([["Hello", "Hi!"], ["Question", "Answer"]]))
            .expect("serialize history"),
    )
    .expect("write history");
}
