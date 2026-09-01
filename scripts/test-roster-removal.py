#!/usr/bin/env python3
"""Focused real-wire RFC 6121 section 2.5.2 roster-removal test."""

from __future__ import annotations

import importlib.util
import pathlib


support_path = pathlib.Path(__file__).with_name("integration-wsl.py")
spec = importlib.util.spec_from_file_location("northstar_integration_support", support_path)
if spec is None or spec.loader is None:
    raise RuntimeError(f"could not load integration support from {support_path}")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


ALICE = "roster_remove_alice_it"
BOB = "roster_remove_bob_it"
PASSWORD = support.PASSWORD
DOMAIN = support.DOMAIN


def roster_get(client, request_id: str) -> None:
    client.send(
        f"<iq xmlns='jabber:client' type='get' id='{request_id}'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    result, _ = client.receive_until(request_id)
    support.check("type='result'" in result, f"roster get failed: {result}")


def roster_add(client, contact: str, request_id: str) -> None:
    client.send(
        f"<iq xmlns='jabber:client' type='set' id='{request_id}'>"
        f"<query xmlns='jabber:iq:roster'><item jid='{contact}@{DOMAIN}'/></query></iq>"
    )
    result, _ = client.receive_until(request_id)
    support.check("type='result'" in result, f"roster add failed: {result}")
    push, _ = client.receive_until(f"jid='{contact}@{DOMAIN}'")
    support.check(
        "jabber:iq:roster" in push,
        f"roster add did not push the committed item: {push}",
    )


def run() -> None:
    support.wait_ready()
    for username in (ALICE, BOB):
        status, result = support.register_account(username, PASSWORD)
        support.check(status == 201, f"could not register {username}: {status} {result}")

    alice = support.XmppWebSocket(ALICE, PASSWORD, "remove-alice")
    bob = support.XmppWebSocket(BOB, PASSWORD, "remove-bob")
    try:
        roster_get(alice, "remove-alice-roster")
        roster_get(bob, "remove-bob-roster")
        roster_add(alice, BOB, "remove-add-bob")
        roster_add(bob, ALICE, "remove-add-alice")

        alice.send(
            f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribe'/>"
        )
        bob.receive_until("type='subscribe'")
        bob.send(
            f"<presence xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='subscribed'/>"
        )
        alice.receive_until("type='subscribed'")
        alice.receive_until("subscription='to'")
        bob.receive_until("subscription='from'")

        bob.send(
            f"<presence xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='subscribe'/>"
        )
        alice.receive_until("type='subscribe'")
        alice.send(
            f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribed'/>"
        )
        bob.receive_until("type='subscribed'")
        alice.receive_until("subscription='both'")
        bob.receive_until("subscription='both'")

        alice.send(
            "<iq xmlns='jabber:client' type='set' id='remove-mutual'>"
            f"<query xmlns='jabber:iq:roster'><item jid='{BOB}@{DOMAIN}' subscription='remove'/></query></iq>"
        )
        _, contact_frames = bob.receive_until("subscription='none'")
        unsubscribe_index = next(
            (
                index
                for index, frame in enumerate(contact_frames)
                if "<presence" in frame and "type='unsubscribe'" in frame
            ),
            None,
        )
        unsubscribed_index = next(
            (
                index
                for index, frame in enumerate(contact_frames)
                if "<presence" in frame and "type='unsubscribed'" in frame
            ),
            None,
        )
        push_index = next(
            index
            for index, frame in enumerate(contact_frames)
            if "jabber:iq:roster" in frame and "subscription='none'" in frame
        )
        support.check(
            unsubscribe_index is not None
            and unsubscribed_index is not None
            and unsubscribe_index < unsubscribed_index < push_index,
            f"cancellation notifications were not ordered before the contact roster push: {contact_frames}",
        )
        result, owner_frames = alice.receive_until("remove-mutual")
        if not any("subscription='remove'" in frame for frame in owner_frames):
            _, later_owner_frames = alice.receive_until("subscription='remove'")
            owner_frames.extend(later_owner_frames)
        support.check(
            "type='result'" in result
            and any(
                "jabber:iq:roster" in frame and "subscription='remove'" in frame
                for frame in owner_frames
            ),
            f"owner did not receive remove push and result: {owner_frames}",
        )

        alice.send(
            "<iq xmlns='jabber:client' type='set' id='remove-retry'>"
            f"<query xmlns='jabber:iq:roster'><item jid='{BOB}@{DOMAIN}' subscription='remove'/></query></iq>"
        )
        retry, _ = alice.receive_until("remove-retry")
        support.check(
            "type='error'" in retry and "item-not-found" in retry,
            f"duplicate removal was not rejected idempotently: {retry}",
        )
        bob.send(
            "<iq xmlns='jabber:client' type='get' id='remove-retry-barrier'>"
            "<ping xmlns='urn:xmpp:ping'/></iq>"
        )
        _, retry_frames = bob.receive_until("remove-retry-barrier")
        support.check(
            not any(
                "<presence" in frame
                and ("type='unsubscribe'" in frame or "type='unsubscribed'" in frame)
                for frame in retry_frames
            ),
            f"duplicate removal regenerated a cancellation: {retry_frames}",
        )
    finally:
        bob.close()
        alice.close()
    print("RFC 6121 roster-removal real-wire test passed")


if __name__ == "__main__":
    run()
