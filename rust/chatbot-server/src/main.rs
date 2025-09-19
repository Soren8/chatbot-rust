use anyhow::Result;
use chatbot_server::run;

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}
