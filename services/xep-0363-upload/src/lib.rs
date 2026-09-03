//! XEP-0363 HTTP File Upload microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 7, 8, 19.1, 19.2).

use foundation_contracts::common::ErrorDetail;
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UploadSlot {
    pub slot_id: String,
    pub owner_bare_jid: String,
    pub filename: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub put_token: String,
    pub put_url: String,
    pub get_url: String,
    pub confirmed: bool,
}

pub struct UploadService {
    base_url: String,
    max_file_size: u64,
    slots: RwLock<HashMap<String, UploadSlot>>,
    outbox: InMemoryOutbox,
}

impl UploadService {
    pub fn new(base_url: impl Into<String>, max_file_size: u64) -> Self {
        Self {
            base_url: base_url.into(),
            max_file_size,
            slots: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn request_slot(
        &self,
        owner_bare_jid: &str,
        filename: &str,
        size_bytes: u64,
        content_type: &str,
    ) -> Result<UploadSlot, ErrorDetail> {
        if size_bytes == 0 || size_bytes > self.max_file_size {
            return Err(ErrorDetail::new(
                "NOT_ACCEPTABLE",
                format!(
                    "File size exceeds maximum allowed limit of {} bytes",
                    self.max_file_size
                ),
            ));
        }

        let slot_id = Uuid::new_v4().to_string();
        let put_token = {
            let mut hasher = Sha256::new();
            hasher.update(slot_id.as_bytes());
            hasher.update(filename.as_bytes());
            hasher.update(owner_bare_jid.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        let put_url = format!(
            "{}/upload/{}/{}?token={}",
            self.base_url, slot_id, filename, put_token
        );
        let get_url = format!("{}/files/{}/{}", self.base_url, slot_id, filename);

        let slot = UploadSlot {
            slot_id: slot_id.clone(),
            owner_bare_jid: owner_bare_jid.to_string(),
            filename: filename.to_string(),
            size_bytes,
            content_type: content_type.to_string(),
            put_token,
            put_url,
            get_url,
            confirmed: false,
        };

        let event = OutboxEvent::new(
            "upload",
            &slot_id,
            1,
            "upload.slot.reserved.v1",
            slot_id.as_bytes().to_vec(),
        );
        self.outbox.stage(event);

        self.slots.write().unwrap().insert(slot_id, slot.clone());
        Ok(slot)
    }

    pub fn confirm_upload(&self, slot_id: &str, token: &str) -> Result<(), ErrorDetail> {
        let mut slots = self.slots.write().unwrap();
        let Some(slot) = slots.get_mut(slot_id) else {
            return Err(ErrorDetail::new("ITEM_NOT_FOUND", "Slot not found"));
        };

        if slot.put_token != token {
            return Err(ErrorDetail::new("NOT_AUTHORIZED", "Invalid upload token"));
        }

        slot.confirmed = true;

        let event = OutboxEvent::new(
            "upload",
            slot_id,
            2,
            "upload.slot.confirmed.v1",
            slot_id.as_bytes().to_vec(),
        );
        self.outbox.stage(event);

        Ok(())
    }

    pub fn is_confirmed(&self, slot_id: &str) -> bool {
        self.slots
            .read()
            .unwrap()
            .get(slot_id)
            .map(|s| s.confirmed)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_slot_request_and_confirm_lifecycle() {
        let upload = UploadService::new("https://upload.example.com", 10 * 1024 * 1024); // 10MB max

        // 1. Oversize request fails
        let oversize = upload.request_slot(
            "alice@example.com",
            "huge.iso",
            20 * 1024 * 1024,
            "application/octet-stream",
        );
        assert!(oversize.is_err());
        assert_eq!(oversize.unwrap_err().code, "NOT_ACCEPTABLE");

        // 2. Normal slot request succeeds
        let slot = upload
            .request_slot("alice@example.com", "photo.jpg", 1024 * 1024, "image/jpeg")
            .unwrap();
        assert!(!slot.put_url.is_empty());
        assert!(!slot.get_url.is_empty());
        assert!(!slot.confirmed);

        // 3. Confirm upload with valid token
        assert!(upload
            .confirm_upload(&slot.slot_id, &slot.put_token)
            .is_ok());
        assert!(upload.is_confirmed(&slot.slot_id));
    }
}
