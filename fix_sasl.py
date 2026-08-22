import sys

with open('src/xmpp/protocol.rs', 'r', encoding='utf-8') as f:
    text = f.read()

start_idx = text.find('pub(crate) async fn authenticate(&mut self, root: Node<')
end_idx = text.find('pub(crate) async fn register(', start_idx)

auth_code = '''pub(crate) async fn authenticate(&mut self, root: Node<'_, '_>) -> Result<Action> {
        if !self.tls && !self.websocket {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "encryption-required",
            )));
        }
        
        let mechanism = root.attribute("mechanism").unwrap_or("");
        let payload = root.text().unwrap_or_default();
        
        let mut sasl_mech: Box<dyn crate::sasl::SaslMechanism> = match mechanism {
            "PLAIN" => Box::new(crate::sasl::PlainMechanism::new(self.state.config.domain.clone())),
            "SCRAM-SHA-256" => Box::new(crate::sasl::ScramSha256Mechanism::new(self.state.config.domain.clone())),
            _ => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "invalid-mechanism",
                )));
            }
        };

        let step = sasl_mech.initial_response(payload);
        self.process_sasl_step(sasl_mech, step).await
    }

    pub(crate) async fn sasl_response(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let payload = root.text().unwrap_or_default();
        
        let mut sasl_mech = match self.sasl_state.take() {
            Some(mech) => mech,
            None => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "not-authorized",
                )));
            }
        };

        let step = sasl_mech.response(payload);
        self.process_sasl_step(sasl_mech, step).await
    }

    async fn process_sasl_step(
        &mut self,
        mut sasl_mech: Box<dyn crate::sasl::SaslMechanism>,
        mut step: crate::sasl::SaslStep,
    ) -> Result<Action> {
        if let crate::sasl::SaslStep::NeedsCredentials(ref username) = step {
            if let Ok(Some(creds)) = db::get_scram_credentials(&self.state.pool, username).await {
                step = sasl_mech.provide_credentials(
                    creds.salt,
                    creds.iterations,
                    creds.stored_key,
                    creds.server_key,
                );
            } else {
                step = crate::sasl::SaslStep::Failure("not-authorized".into());
            }
        }

        match step {
            crate::sasl::SaslStep::Success(username, data_opt) => {
                let user = if sasl_mech.name() == "PLAIN" {
                    if let Some(password) = data_opt.as_ref() {
                        db::authenticate(&self.state.pool, &username, password).await.unwrap_or(None)
                    } else {
                        None
                    }
                } else {
                    db::find_user(&self.state.pool, &username).await.unwrap_or(None)
                };

                match user {
                    Some(user) => {
                        tracing::info!(username = %user.username, "XMPP authentication succeeded");
                        self.authenticated = Some(user);
                        let success_xml = if sasl_mech.name() == "SCRAM-SHA-256" {
                            if let Some(server_final) = data_opt {
                                use base64::Engine;
                                let b64 = base64::engine::general_purpose::STANDARD.encode(server_final);
                                format!("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</success>", b64)
                            } else {
                                "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".into()
                            }
                        } else {
                            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".into()
                        };
                        Ok(Action::Send(success_xml))
                    }
                    None => {
                        self.state
                            .metrics
                            .authentication_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        Ok(Action::Send(failure(
                            "urn:ietf:params:xml:ns:xmpp-sasl",
                            "not-authorized",
                        )))
                    }
                }
            }
            crate::sasl::SaslStep::Challenge(challenge_data) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(challenge_data);
                self.sasl_state = Some(sasl_mech);
                Ok(Action::Send(format!("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</challenge>", b64)))
            }
            crate::sasl::SaslStep::Failure(err) => {
                tracing::warn!("SASL authentication failed: {}", err);
                self.sasl_state = None;
                self.state
                    .metrics
                    .authentication_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "not-authorized",
                )))
            }
            crate::sasl::SaslStep::NeedsCredentials(_) => {
                unreachable!("NeedsCredentials should be handled above")
            }
        }
    }

'''

text = text[:start_idx] + auth_code + text[end_idx:]

with open('src/xmpp/protocol.rs', 'w', encoding='utf-8') as f:
    f.write(text)

with open('src/xmpp/dispatch.rs', 'r', encoding='utf-8') as f:
    dispatch = f.read()

dispatch = dispatch.replace('"auth" => self.authenticate(root).await,', '"auth" => self.authenticate(root).await,\n                "response" => self.sasl_response(root).await,')

with open('src/xmpp/dispatch.rs', 'w', encoding='utf-8') as f:
    f.write(dispatch)

