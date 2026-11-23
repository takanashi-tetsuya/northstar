ALTER TABLE mix_delivery_recipients ADD COLUMN recipient_local_user_id UUID NULL;
ALTER TABLE mix_delivery_dead_letters ADD COLUMN recipient_local_user_id UUID NULL;

UPDATE mix_delivery_recipients AS recipient
   SET recipient_local_user_id = account.id
  FROM mix_delivery_events AS event, users AS account
 WHERE event.event_id = recipient.event_id
   AND split_part(event.channel_jid, '@', 2) = 'mix.' || split_part(recipient.recipient_jid, '@', 2)
   AND account.username = split_part(recipient.recipient_jid, '@', 1);
