use chatbot_core::history::SetId;
use chatbot_server::{build_router_with_services, resolve_static_root, services::AppServices, set_privacy_coordinator::SetPrivacyCoordinator};
use axum::{body::{to_bytes, Body}, http::{header, Method, Request, StatusCode}, response::Response, routing::post, Router};
use bytes::Bytes;
use bcrypt::{hash, DEFAULT_COST};
use serde_json::{json, Value};
use tower::ServiceExt;
use std::{convert::Infallible, env, net::SocketAddr, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex, OnceLock}};
use tokio::{net::TcpListener, sync::{mpsc, oneshot}};

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn login(app: &axum::Router, username: &str, password: &str) -> (String, String, String) {
    let page = app.clone().oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = page.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).map(common::extract_cookie).unwrap();
    let body = to_bytes(page.into_body(), 64 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).unwrap();
    let form = format!("username={}&password={}&csrf_token={}", urlencoding::encode(username), urlencoding::encode(password), urlencoding::encode(&csrf));
    let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/login").header(header::CONTENT_TYPE,"application/x-www-form-urlencoded").header(header::COOKIE,&cookie).body(Body::from(form)).unwrap()).await.unwrap();
    let cookie = response.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).map(common::extract_cookie).unwrap_or(cookie);
    let _ = to_bytes(response.into_body(), 32 * 1024).await;
    let home = app.clone().oneshot(Request::builder().uri("/").header(header::COOKIE,&cookie).body(Body::empty()).unwrap()).await.unwrap();
    let cookie = home.headers().get(header::SET_COOKIE).and_then(|v|v.to_str().ok()).map(common::extract_cookie).unwrap_or(cookie);
    let body=to_bytes(home.into_body(),256*1024).await.unwrap();
    let html=std::str::from_utf8(&body).unwrap();
    let csrf=regex::Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).unwrap().captures(html).unwrap()[1].to_owned();
    (cookie,csrf,common::derive_encryption_key_header(username,password))
}

async fn post_json(app: &axum::Router, uri: &str, cookie: &str, csrf: Option<&str>, key: &str, payload: Value) -> (StatusCode, Value) {
    let mut request=Request::builder().method(Method::POST).uri(uri).header(header::CONTENT_TYPE,"application/json").header(header::COOKIE,cookie).header("X-Enc-Key",key);
    if let Some(csrf)=csrf { request=request.header("X-CSRF-Token",csrf); }
    let response=app.clone().oneshot(request.body(Body::from(serde_json::to_vec(&payload).unwrap())).unwrap()).await.unwrap();
    let status=response.status();
    let body=to_bytes(response.into_body(),512*1024).await.unwrap();
    (status,serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn start_chat(app: &Router, cookie: &str, csrf: &str, key: &str, set_id: &str) -> Response {
    let request=Request::builder().method(Method::POST).uri("/chat")
        .header(header::CONTENT_TYPE,"application/json").header(header::COOKIE,cookie)
        .header("X-CSRF-Token",csrf).header("X-Enc-Key",key)
        .body(Body::from(serde_json::to_vec(&json!({"message":"barrier prompt","set_id":set_id,"model_name":"default","web_search":true})).unwrap())).unwrap();
    app.clone().oneshot(request).await.unwrap()
}

async fn start_barrier_openai() -> (SocketAddr, mpsc::UnboundedReceiver<oneshot::Sender<()>>, Arc<AtomicUsize>, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let hits=Arc::new(AtomicUsize::new(0));
    let handler_hits=hits.clone();
    let (arrived_tx,arrived_rx)=mpsc::unbounded_channel::<oneshot::Sender<()>>();
    let app=Router::new().route("/v1/chat/completions",post(move || {
        let hits=handler_hits.clone();
        let arrived=arrived_tx.clone();
        async move {
            hits.fetch_add(1,Ordering::SeqCst);
            let (release_tx,release_rx)=oneshot::channel();
            let _=arrived.send(release_tx);
            let body=async_stream::stream! {
                let _=release_rx.await;
                yield Ok::<Bytes,Infallible>(Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"mock reply\"}}]}\n\n"));
                yield Ok(Bytes::from_static(b"data: [DONE]\n\n"));
            };
            (StatusCode::OK,[(header::CONTENT_TYPE,"text/event-stream")],Body::from_stream(body))
        }
    }));
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address=listener.local_addr().unwrap();
    let (shutdown_tx,shutdown_rx)=oneshot::channel();
    let server=tokio::spawn(async move { let _=axum::serve(listener,app).with_graceful_shutdown(async { let _=shutdown_rx.await; }).await; });
    (address,arrived_rx,hits,shutdown_tx,server)
}

async fn start_xai_search_mock() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let openai_hits=Arc::new(AtomicUsize::new(0));
    let xai_hits=Arc::new(AtomicUsize::new(0));
    let openai_counter=openai_hits.clone();
    let xai_counter=xai_hits.clone();
    let app=Router::new()
        .route("/v1/chat/completions",post(move || {
            let hits=openai_counter.clone();
            async move {
                hits.fetch_add(1,Ordering::SeqCst);
                (StatusCode::OK,[(header::CONTENT_TYPE,"text/event-stream")],
                    "data: {\"choices\":[{\"delta\":{\"content\":\"Brave approved answer\"}}]}\n\ndata: [DONE]\n\n")
            }
        }))
        .route("/v1/responses",post(move || {
            let hits=xai_counter.clone();
            async move {
                hits.fetch_add(1,Ordering::SeqCst);
                (StatusCode::OK,[(header::CONTENT_TYPE,"text/event-stream")],
                    "data: {\"type\":\"response.output_text.delta\",\"delta\":\"native XAI answer\"}\n\ndata: {\"type\":\"response.completed\"}\n\ndata: [DONE]\n\n")
            }
        }));
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address=listener.local_addr().unwrap();
    let (shutdown_tx,shutdown_rx)=oneshot::channel();
    let server=tokio::spawn(async move { let _=axum::serve(listener,app).with_graceful_shutdown(async { let _=shutdown_rx.await; }).await; });
    (address,openai_hits,xai_hits,shutdown_tx,server)
}

async fn listed_version(app: &Router, cookie: &str, key: &str, set_id: &str) -> u64 {
    let response=app.clone().oneshot(Request::builder().uri("/get_sets").header(header::COOKIE,cookie).header("X-Enc-Key",key).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(),StatusCode::OK);
    let body=to_bytes(response.into_body(),256*1024).await.unwrap();
    let sets:Value=serde_json::from_slice(&body).unwrap();
    sets.as_array().unwrap().iter().find(|item|item["set_id"]==set_id).unwrap()["version"].as_u64().unwrap()
}

#[tokio::test]
async fn active_content_permit_blocks_mode_update_without_blocking_other_set() {
    let coordinator = SetPrivacyCoordinator::default();
    let first = SetId::new();
    let other = SetId::new();
    let permit = coordinator.content(" Alice ", first).await;

    assert!(coordinator.try_update("alice", first).is_none());
    assert!(coordinator.try_update("alice", other).is_some());
    assert!(coordinator.try_update("bob", first).is_some());
    drop(permit);
    assert!(coordinator.try_update("ALICE", first).is_some());
}

#[tokio::test]
async fn cancelled_content_operation_releases_its_permit() {
    let coordinator = SetPrivacyCoordinator::default();
    let set_id = SetId::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let operation_coordinator = coordinator.clone();
    let operation = tokio::spawn(async move {
        let _permit = operation_coordinator.content("alice", set_id).await;
        let _ = ready_tx.send(());
        std::future::pending::<()>().await;
    });
    ready_rx.await.expect("operation acquired its permit");
    assert!(coordinator.try_update("alice", set_id).is_none());
    operation.abort();
    let _ = operation.await;
    assert!(coordinator.try_update("alice", set_id).is_some());
}

#[tokio::test]
async fn set_privacy_requires_csrf_updates_version_and_rejects_stale_cas() {
    let _guard=test_mutex().lock().unwrap_or_else(|error| error.into_inner());
    env::set_var("SECRET_KEY","integration_test_secret");
    let workspace=common::TestWorkspace::with_config(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-test
    base_url: https://api.openai.com/v1
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
    privacy_level: non_private
  - provider_name: private-model
    type: openai
    model_name: gpt-private-test
    base_url: https://api.openai.com/v1
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
    privacy_level: private
    search: true
"#);
    let password="PrivacyPass!234";
    let mut users=chatbot_core::user_store::UserStore::new().unwrap();
    let hashed=hash(password,DEFAULT_COST).unwrap();
    users.create_user("privacy-owner",&hashed).unwrap();
    drop(users);
    let coordinator=SetPrivacyCoordinator::default();
    let app=build_router_with_services(resolve_static_root(),AppServices::global().with_set_privacy_coordinator(coordinator.clone()));
    let (cookie,csrf,key)=login(&app,"privacy-owner",password).await;
    let response=app.clone().oneshot(Request::builder().uri("/").header(header::COOKIE,&cookie).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(),StatusCode::OK);
    let html=String::from_utf8(to_bytes(response.into_body(),256*1024).await.unwrap().to_vec()).unwrap();
    let app_data=html.split("<script id=\"app-data\" type=\"application/json\">").nth(1).unwrap().split("</script>").next().unwrap();
    let app_data:Value=serde_json::from_str(app_data).unwrap();
    let models=app_data["availableModels"].as_array().unwrap();
    assert_eq!(models.iter().find(|m|m["provider_name"]=="default").unwrap()["privacy_level"],"non_private");
    assert_eq!(models.iter().find(|m|m["provider_name"]=="private-model").unwrap()["privacy_level"],"private");
    assert_eq!(models.iter().find(|m|m["provider_name"]=="private-model").unwrap()["search_privacy_level"],"non_private");
    assert_eq!(app_data["voiceCapabilities"]["stt"]["privacy_level"],"non_private");
    assert_eq!(app_data["voiceCapabilities"]["tts"]["privacy_level"],"non_private");
    let serialized=app_data.to_string();
    assert!(!serialized.contains("api.openai.com") && !serialized.contains("api_key"),"APP_DATA must not expose provider endpoints or credentials");
    let (cookie_two,csrf_two,key_two)=login(&app,"privacy-owner",password).await;
    let (status,created)=post_json(&app,"/create_set",&cookie,Some(&csrf),&key,json!({"set_name":"policy"})).await;
    assert_eq!(status,StatusCode::OK,"{created}");
    assert_eq!(created["privacy_level"],"private");
    let set_id=created["set_id"].as_str().unwrap();
    let version=created["version"].as_u64().unwrap();
    let listed=app.clone().oneshot(Request::builder().uri("/get_sets").header(header::COOKIE,&cookie).header("X-Enc-Key",&key).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(listed.status(),StatusCode::OK);
    let entries:Value=serde_json::from_slice(&to_bytes(listed.into_body(),256*1024).await.unwrap()).unwrap();
    assert_eq!(entries.as_array().unwrap().iter().find(|entry|entry["set_id"]==set_id).unwrap()["privacy_level"],"private");
    let (status,loaded)=post_json(&app,"/load_set",&cookie,Some(&csrf),&key,json!({"set_id":set_id})).await;
    assert_eq!(status,StatusCode::OK,"{loaded}");
    assert_eq!(loaded["privacy_level"],"private");
    let content_permit=coordinator.content("privacy-owner",SetId::parse(set_id).unwrap()).await;
    let payload=json!({"set_id":set_id,"expected_version":version,"privacy_level":"non_private"});
    let (status,body)=post_json(&app,"/set_privacy",&cookie,None,&key,payload.clone()).await;
    assert_eq!(status,StatusCode::UNAUTHORIZED,"{body}");
    let (status,body)=post_json(&app,"/set_privacy",&cookie_two,Some(&csrf_two),&key_two,payload.clone()).await;
    assert_eq!(status,StatusCode::CONFLICT,"{body}");
    assert_eq!(body["error"],"privacy_busy");
    drop(content_permit);
    let (status,body)=post_json(&app,"/chat",&cookie_two,Some(&csrf_two),&key_two,json!({"message":"denied","set_id":set_id,"model_name":"default"})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{body}");
    assert_eq!(body["error"],"privacy_restricted");
    let (status,body)=post_json(&app,"/chat",&cookie_two,Some(&csrf_two),&key_two,json!({"message":"search denied","set_id":set_id,"model_name":"private-model","web_search":true})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{body}");
    assert_eq!(body["destination"],"brave_search");
    let (status,body)=post_json(&app,"/set_privacy",&cookie_two,Some(&csrf_two),&key_two,payload.clone()).await;
    assert_eq!(status,StatusCode::OK,"{body}");
    assert_eq!(body["privacy_level"],"non_private");
    assert_eq!(body["version"],version+1);
    let (status,loaded)=post_json(&app,"/load_set",&cookie_two,Some(&csrf_two),&key_two,json!({"set_id":set_id})).await;
    assert_eq!(status,StatusCode::OK,"{loaded}");
    assert_eq!(loaded["privacy_level"],"non_private");
    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS",r#"["seed"]"#);
    let (status,_body)=post_json(&app,"/chat",&cookie_two,Some(&csrf_two),&key_two,json!({"message":"seed","set_id":set_id,"model_name":"default"})).await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status,StatusCode::OK,"seed stream expected");
    let (status,body)=post_json(&app,"/set_privacy",&cookie_two,Some(&csrf_two),&key_two,json!({"set_id":set_id,"expected_version":version+2,"privacy_level":"private"})).await;
    assert_eq!(status,StatusCode::OK,"{body}");
    let (status,body)=post_json(&app,"/regenerate",&cookie_two,Some(&csrf_two),&key_two,json!({"message":"seed","set_id":set_id,"model_name":"default","pair_index":0})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{body}");
    assert_eq!(body["error"],"privacy_restricted");
    let (status,body)=post_json(&app,"/set_privacy",&cookie,Some(&csrf),&key,json!({"set_id":set_id,"expected_version":version,"privacy_level":"private"})).await;
    assert_eq!(status,StatusCode::CONFLICT,"{body}");
    assert_eq!(body["error"],"version_conflict");
    drop(workspace);
}

#[tokio::test]
async fn active_upstream_blocks_privacy_update_and_denial_and_drop_release_the_permit() {
    let _guard=test_mutex().lock().unwrap_or_else(|error| error.into_inner());
    env::set_var("SECRET_KEY","privacy_barrier_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let (address,mut arrivals,hits,shutdown,server)=start_barrier_openai().await;
    let config=format!(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-barrier
    base_url: "http://{address}/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
"#);
    let workspace=common::TestWorkspace::with_config(&config);
    let username="privacy-barrier-user";
    let password="BarrierPassword!42";
    let mut users=chatbot_core::user_store::UserStore::new().unwrap();
    users.create_user(username,&hash(password,DEFAULT_COST).unwrap()).unwrap();
    drop(users);
    let coordinator=SetPrivacyCoordinator::default();
    let app=build_router_with_services(resolve_static_root(),AppServices::global().with_set_privacy_coordinator(coordinator));
    let (cookie_one,csrf_one,key_one)=login(&app,username,password).await;
    let (cookie_two,csrf_two,key_two)=login(&app,username,password).await;
    let (status,created)=post_json(&app,"/create_set",&cookie_one,Some(&csrf_one),&key_one,json!({"set_name":"upstream barrier"})).await;
    assert_eq!(status,StatusCode::OK,"{created}");
    assert_eq!(created["privacy_level"],"private");
    let set_id=created["set_id"].as_str().unwrap().to_owned();
    let created_version=created["version"].as_u64().unwrap();
    let (status,opened)=post_json(&app,"/set_privacy",&cookie_one,Some(&csrf_one),&key_one,json!({"set_id":set_id,"expected_version":created_version,"privacy_level":"non_private"})).await;
    assert_eq!(status,StatusCode::OK,"{opened}");

    let response=start_chat(&app,&cookie_one,&csrf_one,&key_one,&set_id).await;
    assert_eq!(response.status(),StatusCode::OK);
    let body_task=tokio::spawn(async move { to_bytes(response.into_body(),512*1024).await.unwrap() });
    let release=arrivals.recv().await.expect("first request reached fake upstream");
    let (status,busy)=post_json(&app,"/set_privacy",&cookie_two,Some(&csrf_two),&key_two,json!({"set_id":set_id,"expected_version":created_version+1,"privacy_level":"private"})).await;
    assert_eq!(status,StatusCode::CONFLICT,"{busy}");
    assert_eq!(busy["error"],"privacy_busy");
    release.send(()).unwrap();
    let answer=body_task.await.unwrap();
    assert!(String::from_utf8_lossy(&answer).contains("mock reply"));
    let (status,fork)=post_json(&app,"/fork_set",&cookie_two,Some(&csrf_two),&key_two,json!({"set_id":set_id,"pair_index":0})).await;
    assert_eq!(status,StatusCode::OK,"{fork}");
    assert_eq!(fork["privacy_level"],"non_private");

    let (status,changed)=post_json(&app,"/set_privacy",&cookie_two,Some(&csrf_two),&key_two,json!({"set_id":set_id,"expected_version":created_version+2,"privacy_level":"private"})).await;
    assert_eq!(status,StatusCode::OK,"{changed}");
    let (status,denied)=post_json(&app,"/chat",&cookie_two,Some(&csrf_two),&key_two,json!({"message":"must not leave","set_id":set_id,"model_name":"default"})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{denied}");
    assert_eq!(denied["error"],"privacy_restricted");
    assert_eq!(hits.load(Ordering::SeqCst),1,"private denial must not contact the model");

    let private_version=changed["version"].as_u64().unwrap();
    let (status,non_private)=post_json(&app,"/set_privacy",&cookie_one,Some(&csrf_one),&key_one,json!({"set_id":set_id,"expected_version":private_version,"privacy_level":"non_private"})).await;
    assert_eq!(status,StatusCode::OK,"{non_private}");
    let response=start_chat(&app,&cookie_two,&csrf_two,&key_two,&set_id).await;
    let dropped_body=tokio::spawn(async move { to_bytes(response.into_body(),512*1024).await });
    let release=arrivals.recv().await.expect("cancellable request reached fake upstream");
    dropped_body.abort();
    let _=dropped_body.await;
    release.send(()).ok();
    let current=listed_version(&app,&cookie_one,&key_one,&set_id).await;
    let (status,after_drop)=post_json(&app,"/set_privacy",&cookie_one,Some(&csrf_one),&key_one,json!({"set_id":set_id,"expected_version":current,"privacy_level":"private"})).await;
    assert_eq!(status,StatusCode::OK,"drop must release the stream permit: {after_drop}");
    assert_eq!(hits.load(Ordering::SeqCst),2,"the cancelled request reached the fake upstream exactly once");

    shutdown.send(()).ok();
    server.await.unwrap();
    drop(workspace);
}

#[tokio::test]
async fn private_chat_can_use_private_brave_without_promoting_native_xai_search() {
    let _guard=test_mutex().lock().unwrap_or_else(|error| error.into_inner());
    env::set_var("SECRET_KEY","private_brave_search_secret");
    let previous_xai=env::var("XAI_API_KEY").ok();
    env::set_var("XAI_API_KEY","test-xai-key");
    let (address,brave_path_hits,native_hits,shutdown,server)=start_xai_search_mock().await;
    let config=format!(r#"
search_providers:
  brave:
    privacy_level: private
llms:
  - provider_name: default
    type: xai
    model_name: grok-private-search
    base_url: "http://{address}/v1"
    api_key: "${{XAI_API_KEY}}"
    context_size: 4096
    privacy_level: private
    xai_search: false
"#);
    let workspace=common::TestWorkspace::with_config(&config);
    env::set_var("BRAVE_API_KEY","test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY","private search query");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS","verified private Brave result");
    let username="private-brave-user";
    let password="BravePassword!42";
    let mut users=chatbot_core::user_store::UserStore::new().unwrap();
    users.create_user(username,&hash(password,DEFAULT_COST).unwrap()).unwrap();
    drop(users);
    let app=build_router_with_services(resolve_static_root(),AppServices::global());
    let (cookie,csrf,key)=login(&app,username,password).await;
    let (status,created)=post_json(&app,"/create_set",&cookie,Some(&csrf),&key,json!({"set_name":"private search"})).await;
    assert_eq!(status,StatusCode::OK,"{created}");
    let set_id=created["set_id"].as_str().unwrap();
    let response=start_chat(&app,&cookie,&csrf,&key,set_id).await;
    assert_eq!(response.status(),StatusCode::OK);
    let body=to_bytes(response.into_body(),512*1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Brave approved answer"),"chat stream: {}",String::from_utf8_lossy(&body));
    assert_eq!(brave_path_hits.load(Ordering::SeqCst),1,"approved Brave search must complete through the OpenAI-compatible final request");
    assert_eq!(native_hits.load(Ordering::SeqCst),0,"the Non-private native XAI search route must not receive the private prompt");

    env::remove_var("BRAVE_API_KEY");
    let request=Request::builder().method(Method::POST).uri("/chat")
        .header(header::CONTENT_TYPE,"application/json").header(header::COOKIE,&cookie)
        .header("X-CSRF-Token",&csrf).header("X-Enc-Key",&key)
        .body(Body::from(serde_json::to_vec(&json!({"message":"search without Brave","set_id":set_id,"model_name":"default","web_search":true})).unwrap())).unwrap();
    let denied=app.clone().oneshot(request).await.unwrap();
    assert_eq!(denied.status(),StatusCode::FORBIDDEN,"a private chat must not fall through to non-private native search");
    let denial=to_bytes(denied.into_body(),64*1024).await.unwrap();
    let denial:Value=serde_json::from_slice(&denial).unwrap();
    assert_eq!(denial["error"],"privacy_restricted");
    assert_eq!(denial["destination"],"native_search");
    assert_eq!(native_hits.load(Ordering::SeqCst),0,"native XAI must remain untouched when Brave is unavailable");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    if let Some(value)=previous_xai { env::set_var("XAI_API_KEY",value); } else { env::remove_var("XAI_API_KEY"); }
    shutdown.send(()).ok();
    server.await.unwrap();
    drop(workspace);
}

#[tokio::test]
async fn standard_chat_allows_standard_and_private_models_but_not_non_private() {
    let _guard=test_mutex().lock().unwrap_or_else(|error| error.into_inner());
    env::set_var("SECRET_KEY","standard_model_policy_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let (address,model_hits,_,shutdown,server)=start_xai_search_mock().await;
    let config=format!(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-standard
    base_url: "http://{address}/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
    privacy_level: standard
  - provider_name: private-model
    type: openai
    model_name: gpt-private
    base_url: "http://{address}/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
    privacy_level: private
  - provider_name: non-private-model
    type: openai
    model_name: gpt-non-private
    base_url: "http://{address}/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
    privacy_level: non_private
"#);
    let workspace=common::TestWorkspace::with_config(&config);
    let username="standard-model-user";
    let password="StandardPassword!42";
    let mut users=chatbot_core::user_store::UserStore::new().unwrap();
    users.create_user(username,&hash(password,DEFAULT_COST).unwrap()).unwrap();
    drop(users);
    let app=build_router_with_services(resolve_static_root(),AppServices::global());
    let (cookie,csrf,key)=login(&app,username,password).await;
    let (status,created)=post_json(&app,"/create_set",&cookie,Some(&csrf),&key,json!({"set_name":"standard models"})).await;
    assert_eq!(status,StatusCode::OK,"{created}");
    let set_id=created["set_id"].as_str().unwrap();
    let (status,changed)=post_json(&app,"/set_privacy",&cookie,Some(&csrf),&key,json!({"set_id":set_id,"expected_version":created["version"],"privacy_level":"standard"})).await;
    assert_eq!(status,StatusCode::OK,"{changed}");

    for model in ["default","private-model"] {
        let response=app.clone().oneshot(Request::builder().method(Method::POST).uri("/chat")
            .header(header::CONTENT_TYPE,"application/json").header(header::COOKIE,&cookie)
            .header("X-CSRF-Token",&csrf).header("X-Enc-Key",&key)
            .body(Body::from(json!({"message":"allowed","set_id":set_id,"model_name":model}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::OK,"model {model}");
        let body=to_bytes(response.into_body(),512*1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Brave approved answer"),"model {model}: {}",String::from_utf8_lossy(&body));
    }
    assert_eq!(model_hits.load(Ordering::SeqCst),2,"both eligible models must reach upstream");

    let (status,denied)=post_json(&app,"/chat",&cookie,Some(&csrf),&key,json!({"message":"must not leave","set_id":set_id,"model_name":"non-private-model"})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{denied}");
    assert_eq!(denied["error"],"privacy_restricted");
    assert_eq!(denied["destination"],"model");
    assert_eq!(model_hits.load(Ordering::SeqCst),2,"denied model must not receive the prompt");

    shutdown.send(()).ok();
    server.await.unwrap();
    drop(workspace);
}

#[tokio::test]
async fn set_privacy_accepts_standard_and_rejects_stale_version() {
    let _guard=test_mutex().lock().unwrap_or_else(|error| error.into_inner());
    env::set_var("SECRET_KEY","standard_cas_policy_secret");
    let workspace=common::TestWorkspace::with_config(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-test
    base_url: https://api.openai.com/v1
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
"#);
    let username="standard-cas-user";
    let password="StandardPassword!42";
    let mut users=chatbot_core::user_store::UserStore::new().unwrap();
    users.create_user(username,&hash(password,DEFAULT_COST).unwrap()).unwrap();
    drop(users);
    let app=build_router_with_services(resolve_static_root(),AppServices::global());
    let (cookie,csrf,key)=login(&app,username,password).await;
    let (status,created)=post_json(&app,"/create_set",&cookie,Some(&csrf),&key,json!({"set_name":"standard CAS"})).await;
    assert_eq!(status,StatusCode::OK,"{created}");
    let set_id=created["set_id"].as_str().unwrap();
    let version=created["version"].as_u64().unwrap();
    let payload=json!({"set_id":set_id,"expected_version":version,"privacy_level":"standard"});

    let (status,changed)=post_json(&app,"/set_privacy",&cookie,Some(&csrf),&key,payload.clone()).await;
    assert_eq!(status,StatusCode::OK,"{changed}");
    assert_eq!(changed["privacy_level"],"standard");
    assert_eq!(changed["version"],version+1);
    let (status,loaded)=post_json(&app,"/load_set",&cookie,Some(&csrf),&key,json!({"set_id":set_id})).await;
    assert_eq!(status,StatusCode::OK,"{loaded}");
    assert_eq!(loaded["privacy_level"],"standard");
    let (status,conflict)=post_json(&app,"/set_privacy",&cookie,Some(&csrf),&key,payload).await;
    assert_eq!(status,StatusCode::CONFLICT,"{conflict}");
    assert_eq!(conflict["error"],"version_conflict");
    assert_eq!(listed_version(&app,&cookie,&key,set_id).await,version+1);
    drop(workspace);
}

#[tokio::test]
async fn standard_chat_can_search_with_standard_brave_but_private_chat_cannot_use_standard_destinations() {
    let _guard=test_mutex().lock().unwrap_or_else(|error| error.into_inner());
    env::set_var("SECRET_KEY","standard_brave_policy_secret");
    env::set_var("BRAVE_API_KEY","test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY","standard search query");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS","standard Brave result");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let (address,model_hits,_,shutdown,server)=start_xai_search_mock().await;
    let config=format!(r#"
search_providers:
  brave:
    privacy_level: standard
llms:
  - provider_name: default
    type: openai
    model_name: gpt-standard-search
    base_url: "http://{address}/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
    privacy_level: standard
  - provider_name: private-model
    type: openai
    model_name: gpt-private-search
    base_url: "http://{address}/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
    privacy_level: private
"#);
    let workspace=common::TestWorkspace::with_config(&config);
    let username="standard-brave-user";
    let password="StandardPassword!42";
    let mut users=chatbot_core::user_store::UserStore::new().unwrap();
    users.create_user(username,&hash(password,DEFAULT_COST).unwrap()).unwrap();
    drop(users);
    let app=build_router_with_services(resolve_static_root(),AppServices::global());
    let (cookie,csrf,key)=login(&app,username,password).await;
    let (status,created)=post_json(&app,"/create_set",&cookie,Some(&csrf),&key,json!({"set_name":"standard Brave"})).await;
    assert_eq!(status,StatusCode::OK,"{created}");
    let set_id=created["set_id"].as_str().unwrap();
    let (status,denied)=post_json(&app,"/chat",&cookie,Some(&csrf),&key,json!({"message":"private cannot use standard model","set_id":set_id,"model_name":"default"})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{denied}");
    assert_eq!(denied["error"],"privacy_restricted");
    assert_eq!(denied["destination"],"model");
    assert_eq!(model_hits.load(Ordering::SeqCst),0,"private denial must not contact the standard model");
    let (status,denied_search)=post_json(&app,"/chat",&cookie,Some(&csrf),&key,json!({"message":"private cannot use standard Brave","set_id":set_id,"model_name":"private-model","web_search":true})).await;
    assert_eq!(status,StatusCode::FORBIDDEN,"{denied_search}");
    assert_eq!(denied_search["error"],"privacy_restricted");
    assert_eq!(denied_search["destination"],"brave_search");
    assert_eq!(model_hits.load(Ordering::SeqCst),0,"private denial must not contact upstream search or model");

    let (status,changed)=post_json(&app,"/set_privacy",&cookie,Some(&csrf),&key,json!({"set_id":set_id,"expected_version":created["version"],"privacy_level":"standard"})).await;
    assert_eq!(status,StatusCode::OK,"{changed}");
    let response=start_chat(&app,&cookie,&csrf,&key,set_id).await;
    assert_eq!(response.status(),StatusCode::OK);
    let body=to_bytes(response.into_body(),512*1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Brave approved answer"),"chat stream: {}",String::from_utf8_lossy(&body));
    assert_eq!(model_hits.load(Ordering::SeqCst),1,"standard Brave search must complete through the model");

    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    shutdown.send(()).ok();
    server.await.unwrap();
    drop(workspace);
}
