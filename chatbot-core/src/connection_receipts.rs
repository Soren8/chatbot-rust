//! Encrypted receipts in the connection database's mutation transaction.
use redb::{ReadTransaction, WriteTransaction, ReadableTable, TableDefinition};
use crate::{agent_connections::ConnectionError, enc_key::EncryptionKey, operation_receipt::{OperationId, Receipt}};

const RECEIPTS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("connection_receipts");
fn scope(owner: &str, id: &OperationId) -> String { format!("{owner}\0{}", id.as_str()) }

pub fn read(tx: &ReadTransaction, owner: &str, id: &OperationId, key: &EncryptionKey, now: u64) -> Result<Option<Receipt>, ConnectionError> {
    let table = match tx.open_table(RECEIPTS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(_) => return Err(ConnectionError::Storage),
    };
    let value = table.get(scope(owner, id).as_str()).map_err(|_| ConnectionError::Storage)?;
    value.map(|value| Receipt::open(owner, id, value.value(), key).map_err(|_| ConnectionError::Corrupt))
        .transpose().map(|receipt| receipt.filter(|receipt| !receipt.expired(now)))
}

pub fn write(tx: &WriteTransaction, owner: &str, receipt: &Receipt, key: &EncryptionKey, now: u64) -> Result<(), ConnectionError> {
    let mut table = tx.open_table(RECEIPTS).map_err(|_| ConnectionError::Storage)?;
    let prefix = format!("{owner}\0");
    let mut expired = Vec::new();
    for row in table.iter().map_err(|_| ConnectionError::Storage)? {
        let (name, blob) = row.map_err(|_| ConnectionError::Storage)?;
        if let Some(id) = name.value().strip_prefix(&prefix) {
            let id = OperationId::parse(id).map_err(|_| ConnectionError::Corrupt)?;
            if Receipt::open(owner, &id, blob.value(), key).map_err(|_| ConnectionError::Corrupt)?.expired(now) {
                expired.push(name.value().to_owned());
            }
        }
    }
    for name in expired { table.remove(name.as_str()).map_err(|_| ConnectionError::Storage)?; }
    let blob = receipt.seal(owner, key).map_err(|_| ConnectionError::Corrupt)?;
    table.insert(scope(owner, &receipt.operation_id).as_str(), blob.as_slice()).map_err(|_| ConnectionError::Storage)?;
    Ok(())
}
