use super::*;
use crate::xmpp::protocol::mix::stage4_saved as mix;
use crate::xmpp::stage4_auth_publication as auth;
use crate::xmpp::stage4_native as native;
use anyhow::{anyhow, bail, ensure, Context, Result};
use northstar_stream::outbound::{OutboundItem, RouteEnqueue};
use std::{
    sync::{Arc, Mutex},
    task::Poll,
};
use tokio::sync::mpsc;

type Capture = driver::Capture;

// Root-only exits. Neither variant is a domain future's output, and this
// enum intentionally has no Error implementation. BudgetStop never enters
// anyhow, FrameFailure, a bool callback or a synthetic transport result.
#[derive(Debug)]
enum DispatchExit {
    Failed(anyhow::Error),
    Resource(BudgetStop),
}
type DispatchResult<T> = std::result::Result<T, DispatchExit>;
impl From<anyhow::Error> for DispatchExit {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}
fn driven<T>(actual: std::result::Result<Result<T>, BudgetStop>) -> DispatchResult<T> {
    match actual {
        Ok(result) => result.map_err(DispatchExit::Failed),
        Err(stop) => Err(DispatchExit::Resource(stop)),
    }
}
fn require_driver(condition: bool, message: &str) -> Result<()> {
    ensure!(condition, "{message}");
    Ok(())
}

// Role-checked data labels prepared before any real owner. These arrays do
// not own budgets, authorize work, reset state, or encode commands. Exactly
// the actual introduced item/operation ordinal indexes its immutable label.
struct Sites {
    native: [native::NativeSite; 5],
    bosh: [bosh::BoshSite; 4],
    credential: [auth::CredentialSite; 2],
    publication: auth::PublicationSite,
    claim: [mix::ClaimSites; 2],
    foreground: mix::ForegroundSite,
}
impl Sites {
    fn new(case: &ValidatedCase) -> Result<Self> {
        let sites = Self {
            native: [
                native::NativeSite::new(0)?,
                native::NativeSite::new(1)?,
                native::NativeSite::new(2)?,
                native::NativeSite::new(3)?,
                native::NativeSite::new(4)?,
            ],
            bosh: [
                bosh::BoshSite::new(0)?,
                bosh::BoshSite::new(1)?,
                bosh::BoshSite::new(2)?,
                bosh::BoshSite::new(3)?,
            ],
            credential: [auth::CredentialSite::new(0)?, auth::CredentialSite::new(1)?],
            publication: auth::PublicationSite::new(0)?,
            claim: [mix::ClaimSites::new(0)?, mix::ClaimSites::new(1)?],
            foreground: mix::ForegroundSite::new(0)?,
        };
        let check = |ordinal: usize, script: &WriteScript| {
            require_driver(
                native::preparation_valid(sites.native[ordinal], script),
                "invalid native site/script preparation",
            )
        };
        match &case.case().composition {
            Composition::Muc(input) => {
                if let Some(plan) = input.native.get() {
                    check(0, &plan.write)?;
                }
            }
            Composition::AuthThenMixNative(input) => {
                check(0, &input.auth_native.write)?;
                check(1, &input.delivery_native.write)?;
            }
            Composition::MixRecoveryNative(input) => check(1, &input.native.write)?,
            Composition::NativeAuth(input) => check(0, &input.native.write)?,
            Composition::ReplayMixQueuedAuth(_)
            | Composition::MixDefer(_)
            | Composition::BoshAuth(_) => {}
        }
        Ok(sites)
    }
}

// These are topology bounds, not JSON-selected execution commands. Ordinals
// describe actual item/operation introductions in this one case. No counter
// is persisted, used as authority, or included in the literal case input.
#[derive(Default)]
struct Ordinals {
    items: u8,
    bosh_operations: u8,
    credentials: u8,
}
impl Ordinals {
    fn item(&mut self) -> Result<u8> {
        Self::take(&mut self.items, 5, "logical output item")
    }
    fn bosh(&mut self) -> Result<u8> {
        Self::take(&mut self.bosh_operations, 4, "BOSH operation")
    }
    fn credential(&mut self) -> Result<u8> {
        Self::take(&mut self.credentials, 2, "credential invocation")
    }
    fn take(next: &mut u8, cap: u8, name: &str) -> Result<u8> {
        ensure!(*next < cap, "finite {name} introduction cap");
        let ordinal = *next;
        *next += 1;
        Ok(ordinal)
    }
}
fn lost(recorder: &Capture) {
    driver::lost(recorder);
}

// WorkerRun owns the reserve-before-poll call for its contained AttemptRun.
// Root does not meter or emit a duplicate wrapper poll. Pending is retained
// only for the actual queue handoff cut, then the same worker is resumed.
async fn worker_pending(run: &mut mix::WorkerRun) -> DispatchResult<()> {
    match futures::poll!(std::pin::Pin::new(run)) {
        Poll::Pending => Ok(()),
        Poll::Ready(Err(stop)) => Err(DispatchExit::Resource(stop)),
        Poll::Ready(Ok(Err(error))) => Err(DispatchExit::Failed(error)),
        Poll::Ready(Ok(Ok(()))) => Err(DispatchExit::Failed(anyhow!(
            "worker returned before retained local handoff"
        ))),
    }
}
async fn worker_returned(run: &mut mix::WorkerRun) -> DispatchResult<()> {
    // Every real AttemptRun repoll is charged by WorkerRun. No extra poll,
    // scheduled retry loop, or new transport completion is supplied here.
    driven(run.await)
}
fn auth_lookup(routes: &mix::RouteMap, route: &mix::RouteHandle, read: &auth::AuthRead) {
    routes.capture_lookup(
        RouteLookupOwner::Auth(OneId {
            id: EvidenceId::observed(read.frame_id()),
        }),
        route.full_jid(),
    );
}
fn initial_input(worker: &WorkerInput) -> Result<&DeliveryRow<Id>> {
    match &worker.origin {
        ClaimOrigin::InitialDurableRow(row) => Ok(row),
        ClaimOrigin::FreshProjection(_) => {
            bail!("initial-row recipe received projection origin")
        }
    }
}
fn initial_bridge(worker: &WorkerInput, recorder: &Capture) -> Result<mix::Bridge> {
    // The only domain source for an initial durable row is its explicit
    // canonical channel JID. No saved hidden domain or replacement row.
    let channel =
        northstar_xmpp_types::CanonicalJid::parse(initial_input(worker)?.channel_jid.as_str())?;
    mix::Bridge::new(channel.domainpart(), recorder.clone())
}
fn install_target(
    routes: &mix::RouteMap,
    input: &RouteEnvironment,
) -> Result<(mix::RouteHandle, mpsc::Receiver<OutboundItem>)> {
    let [target] = input.targets.as_slice() else {
        bail!("finite delivered environment requires one target")
    };
    routes.install(target, input.queue_capacity)
}
fn enqueue_auth(
    route: &mix::RouteHandle,
    queue: &mut mpsc::Receiver<OutboundItem>,
    item: OutboundItem,
) -> Result<OutboundItem> {
    // Clone only bytes for the existing bind gate. Never clone the actual
    // item, auth holder, durable permit, or transport completion sender.
    let actual_bytes = item.stanza.clone();
    let enqueue = RouteEnqueue::bind(item, None, &actual_bytes)
        .map_err(|_| anyhow!("actual auth item failed route binding"))?;
    route
        .sender()
        .try_send_route_item(enqueue)
        .map_err(|_| anyhow!("actual auth queue refused item"))?;
    queue
        .try_recv()
        .map_err(|_| anyhow!("actual auth queue item absent"))
}
async fn build_auth(
    input: &AuthInput,
    route: Option<mix::RouteHandle>,
    ordinals: &mut Ordinals,
    recorder: &Capture,
    sites: &Sites,
) -> DispatchResult<(OutboundItem, auth::AuthRead, auth::Publisher)> {
    let ordinal = ordinals.credential()?;
    let built = driven(
        auth::build(
            input,
            route,
            recorder.clone(),
            sites.credential[usize::from(ordinal)],
        )
        .await,
    )?;
    let (item, read, publisher) = built.split();
    // No spawned work exists. build's metered owner has returned/dropped,
    // the single driver stack is paused and read clones have no mutator.
    read.capture_frame_quiescent(Cut::AfterRunnerDrop);
    Ok((item, read, publisher))
}
fn publication_execution(
    returned: Option<bool>,
    dropped: bool,
    drive: AuthDrive,
    recorder: &Capture,
) -> Execution {
    match (returned, dropped, drive) {
        // A handled backend error is an observed return, not an adapter
        // failure. The independent reader judges its effects and fixture.
        (Some(_), false, _) => Execution::Complete,
        (None, true, AuthDrive::DropPublicationCommit) => Execution::Cancelled,
        _ => {
            lost(recorder);
            Execution::Failed
        }
    }
}
async fn native_auth(
    input: &NativeAuthInput,
    recorder: &Capture,
    ordinals: &mut Ordinals,
    sites: &Sites,
) -> DispatchResult<Execution> {
    let routes = mix::RouteMap::new(recorder.clone());
    let (route, mut queue) = routes.install_auth(&input.auth, 1)?;
    let (item, read, mut publisher) =
        build_auth(&input.auth, Some(route.clone()), ordinals, recorder, sites).await?;
    auth_lookup(&routes, &route, &read);
    let item = enqueue_auth(&route, &mut queue, item)?;
    let ordinal = ordinals.item()?;
    let owner = driven(
        native::write_auth(
            item,
            route.connection_id(),
            sites.native[usize::from(ordinal)],
            input.native.write.clone(),
            recorder.clone(),
        )
        .await,
    )?;
    let actual = driven(
        auth::publish_native(
            owner,
            &read,
            &mut publisher,
            input.drive,
            recorder,
            sites.publication,
        )
        .await,
    )?;
    auth_lookup(&routes, &route, &read);
    Ok(publication_execution(
        actual.returned,
        actual.dropped,
        input.drive,
        recorder,
    ))
}
async fn auth_then_mix(
    input: &FreshMixNativeInput,
    recorder: &Capture,
    ordinals: &mut Ordinals,
    sites: &Sites,
) -> DispatchResult<Execution> {
    let routes = mix::RouteMap::new(recorder.clone());
    let (route, mut queue) = install_target(&routes, &input.worker.attempt.route)?;
    let (item, read, mut publisher) =
        build_auth(&input.auth, Some(route.clone()), ordinals, recorder, sites).await?;
    auth_lookup(&routes, &route, &read);
    let item = enqueue_auth(&route, &mut queue, item)?;
    let auth_ordinal = ordinals.item()?;
    let owner = driven(
        native::write_auth(
            item,
            route.connection_id(),
            sites.native[usize::from(auth_ordinal)],
            input.auth_native.write.clone(),
            recorder.clone(),
        )
        .await,
    )?;
    let actual = driven(
        auth::publish_native(
            owner,
            &read,
            &mut publisher,
            AuthDrive::Complete,
            recorder,
            sites.publication,
        )
        .await,
    )?;
    auth_lookup(&routes, &route, &read);
    // Continue only after the real publication continuation returned. No
    // fixture field can activate the route; real lookup/worker policy below
    // still decides whether this same retained session is eligible.
    require_driver(
        !actual.dropped && actual.returned == Some(true),
        "auth continuation did not complete before MIX",
    )?;
    let bridge = mix::Bridge::new(
        input.foreground.configured_domain.as_str(),
        recorder.clone(),
    )?;
    let ClaimOrigin::FreshProjection(origin) = &input.worker.origin else {
        return Err(DispatchExit::Failed(anyhow!("fresh recipe origin missing")));
    };
    let row = driven(
        bridge
            .fresh(
                &input.foreground,
                origin,
                &input.worker.attempt.claim,
                sites.foreground,
            )
            .await,
    )?;
    let mut worker = driven(
        bridge
            .claim(row, &input.worker.attempt, sites.claim[0], routes.clone())
            .await,
    )?;
    worker_pending(&mut worker).await?;
    let item = queue
        .try_recv()
        .context("actual fresh MIX queue item absent")?;
    let ordinal = ordinals.item()?;
    worker.record_dequeued(&route, ordinal, &item);
    bridge.supply_native(&input.delivery_native)?;
    let service = bridge.service();
    driven(
        native::write_item(
            item,
            route.connection_id(),
            sites.native[usize::from(ordinal)],
            ItemOwner::Mix(MixItemOwner { attempt_ordinal: 0 }),
            input.delivery_native.write.clone(),
            Some(&service),
            recorder.clone(),
        )
        .await,
    )?;
    worker_returned(&mut worker).await?;
    drop(worker);
    Ok(Execution::Complete)
}
#[expect(
    clippy::too_many_arguments,
    reason = "Finite lane keeps owner, input, transport, route, queue, recorder, ordinal and poll-site dependencies explicit"
)]
async fn mix_bosh_lane(
    bridge: &mix::Bridge,
    worker_input: &WorkerInput,
    transport: &MixBoshTransport,
    routes: &mix::RouteMap,
    route: &mix::RouteHandle,
    queue: &mut mpsc::Receiver<OutboundItem>,
    recorder: &Capture,
    ordinals: &mut Ordinals,
    sites: &Sites,
) -> DispatchResult<bosh::Session> {
    let row = bridge.initial_row(initial_input(worker_input)?)?;
    let mut worker = driven(
        bridge
            .claim(row, &worker_input.attempt, sites.claim[0], routes.clone())
            .await,
    )?;
    worker_pending(&mut worker).await?;
    let item = queue
        .try_recv()
        .context("actual independent MIX queue item absent")?;
    let item_ordinal = ordinals.item()?;
    worker.record_dequeued(route, item_ordinal, &item);
    bridge.supply_bosh_transfer(&transport.transfer)?;
    let service = bridge.service();
    let mut session = bosh::Session::new(transport.session.clone(), recorder.clone())?;
    let transfer_ordinal = ordinals.bosh()?;
    let accepted = driven(
        session
            .push_mix(
                item,
                item_ordinal,
                sites.bosh[usize::from(transfer_ordinal)],
                &service,
            )
            .await,
    )?;
    require_driver(
        accepted,
        "actual independent MIX BOSH FIFO refused transfer",
    )?;
    // Only actual ServiceTransfer/record_and_push can signal the typed
    // BoshPersisted completion consumed by this still-live worker.
    worker_returned(&mut worker).await?;
    drop(worker);
    let response_ordinal = ordinals.bosh()?;
    let response = driven(
        session
            .respond(
                sites.bosh[usize::from(response_ordinal)],
                AuthDrive::Complete,
            )
            .await,
    )?;
    require_driver(
        !response.dropped && response.returned == Some(true),
        "independent MIX response did not complete before auth lane",
    )?;
    Ok(session)
}
async fn queued_auth(
    input: &ReplayMixQueuedAuth,
    recorder: &Capture,
    ordinals: &mut Ordinals,
    sites: &Sites,
) -> DispatchResult<Execution> {
    let routes = mix::RouteMap::new(recorder.clone());
    let (m_route, mut m_queue) = install_target(&routes, &input.mix.worker.attempt.route)?;
    // A exists while M performs actual lookup, but remains staged. The two
    // rows retain distinct queues, connection IDs, lifecycle and tokens.
    let (a_route, a_queue) = routes.install_auth(&input.auth.bound, 1)?;
    let bridge = mix::Bridge::new(
        input.mix.foreground.configured_domain.as_str(),
        recorder.clone(),
    )?;
    let _actual_replay_id = driven(bridge.replay(&input.mix.foreground, sites.foreground).await)?;
    let mut m = mix_bosh_lane(
        &bridge,
        &input.mix.worker,
        &input.mix.transport,
        &routes,
        &m_route,
        &mut m_queue,
        recorder,
        ordinals,
        sites,
    )
    .await?;
    let (u_item, u_read, u_publish) =
        build_auth(&input.auth.unbound, None, ordinals, recorder, sites).await?;
    let (b_item, b_read, b_publish) = build_auth(
        &input.auth.bound,
        Some(a_route.clone()),
        ordinals,
        recorder,
        sites,
    )
    .await?;
    auth_lookup(&routes, &a_route, &b_read);
    let mut a = bosh::Session::new(input.auth.session.clone(), recorder.clone())?;
    // All four exact supplied items exist before real selection. P/F are
    // the explicitly supplied fixed helper output, not handler evidence.
    a.push_plain(
        input.auth.padding.presence_xml.as_str().to_owned(),
        ordinals.item()?,
    )?;
    a.push_auth(u_item, u_read.clone(), u_publish, ordinals.item()?)?;
    a.push_plain(
        input.auth.padding.features_xml.as_str().to_owned(),
        ordinals.item()?,
    )?;
    a.push_auth(b_item, b_read.clone(), b_publish, ordinals.item()?)?;
    let response_ordinal = ordinals.bosh()?;
    let actual = driven(
        a.respond(
            sites.bosh[usize::from(response_ordinal)],
            AuthDrive::Complete,
        )
        .await,
    )?;
    auth_lookup(&routes, &a_route, &b_read);
    // No selection/callback/expected-count assertion here. Actual P/U and
    // remaining F/B, or any contradiction, are preserved for the reader.
    let result = publication_execution(
        actual.returned,
        actual.dropped,
        AuthDrive::Complete,
        recorder,
    );
    let ack = input
        .mix
        .transport
        .ack
        .get()
        .context("validated M ACK absent")?;
    let ack_ordinal = ordinals.bosh()?;
    driven(
        m.acknowledge(ack, sites.bosh[usize::from(ack_ordinal)])
            .await,
    )?;
    // ACK is actual renew/ACK plus a separate empty Payload response.
    // No EmptyControl, new logical item/frame, or fabricated callback.
    a.teardown()?;
    u_read.capture_frame_quiescent(Cut::AfterTeardown);
    b_read.capture_frame_quiescent(Cut::AfterTeardown);
    m.teardown()?;
    drop(a_queue);
    Ok(result)
}
async fn recovery(
    input: &RecoveryInput,
    recorder: &Capture,
    ordinals: &mut Ordinals,
    sites: &Sites,
) -> DispatchResult<Execution> {
    let bridge = initial_bridge(&input.worker, recorder)?;
    let original = bridge.initial_row(initial_input(&input.worker)?)?;
    let old_routes = mix::RouteMap::new(recorder.clone());
    let (old_route, mut old_queue) = install_target(&old_routes, &input.worker.attempt.route)?;
    let mut first = driven(
        bridge
            .claim(
                original.clone(),
                &input.worker.attempt,
                sites.claim[0],
                old_routes.clone(),
            )
            .await,
    )?;
    worker_pending(&mut first).await?;
    let old_item = old_queue
        .try_recv()
        .context("actual old queue item absent")?;
    first.record_dequeued(&old_route, ordinals.item()?, &old_item);
    let old_read = first.observation();
    // This is eligibility for the requested driver cut, not a settlement
    // policy or safety verdict. Observation-only join loss cannot supply
    // that eligibility: inspect the real still-live local request state.
    let actual_cut = old_read.snapshot();
    require_driver(
        actual_cut
            .local
            .last()
            .is_some_and(|local| local.started && local.enqueued && local.returned.is_none())
            && old_item.mix_delivery() == Some(old_read.row().source),
        "old drop did not reach its actual pending local handoff",
    )?;
    // Pending was genuinely returned by this WorkerRun, with its actual
    // item retained and local result absent. Drop the future, not input.
    drop(first);
    let new_routes = mix::RouteMap::new(recorder.clone());
    let (new_route, mut new_queue) = install_target(&new_routes, &input.replacement.route)?;
    let row = bridge.replacement_row(&original, &input.replacement.claim)?;
    let mut second = driven(
        bridge
            .claim(row, &input.replacement, sites.claim[1], new_routes.clone())
            .await,
    )?;
    worker_pending(&mut second).await?;
    let item = new_queue
        .try_recv()
        .context("actual replacement queue item absent")?;
    let ordinal = ordinals.item()?;
    second.record_dequeued(&new_route, ordinal, &item);
    bridge.supply_native(&input.native)?;
    let service = bridge.service();
    driven(
        native::write_item(
            item,
            new_route.connection_id(),
            sites.native[usize::from(ordinal)],
            ItemOwner::Mix(MixItemOwner { attempt_ordinal: 1 }),
            input.native.write.clone(),
            Some(&service),
            recorder.clone(),
        )
        .await,
    )?;
    worker_returned(&mut second).await?;
    drop(second);
    // Keep every old association and the unconsumed old transport item
    // through replacement completion. Never clear or retarget cancellation.
    drop(old_item);
    drop(old_read);
    drop(old_queue);
    drop(old_route);
    drop(old_routes);
    Ok(Execution::Complete)
}
async fn defer(input: &DeferInput, recorder: &Capture, sites: &Sites) -> DispatchResult<Execution> {
    let bridge = initial_bridge(&input.worker, recorder)?;
    let row = bridge.initial_row(initial_input(&input.worker)?)?;
    bridge.supply_defer(input.settlement_commit, input.updated)?;
    let routes = mix::RouteMap::new(recorder.clone());
    let mut worker = driven(
        bridge
            .claim(row, &input.worker.attempt, sites.claim[0], routes)
            .await,
    )?;
    // Actual shared route/classifier destroys its route scope, closes the
    // renewal scope, then settles Defer. Nothing drives a ten-second timer.
    worker_returned(&mut worker).await?;
    drop(worker);
    Ok(Execution::Complete)
}
async fn bosh_auth(
    input: &BoshAuthInput,
    recorder: &Capture,
    ordinals: &mut Ordinals,
    sites: &Sites,
) -> DispatchResult<Execution> {
    let routes = mix::RouteMap::new(recorder.clone());
    let (a_route, a_queue) = routes.install_auth(&input.auth.bound, 1)?;
    // M is an optional, wholly independent initial-row subtree. A never
    // receives its item/source. This exact structural branch permits the
    // same reduced literal bytes in baseline S13 and mutant M2/M3.
    let mut retained_m = None;
    if let Some(m) = input.mix.get() {
        let (route, mut queue) = install_target(&routes, &m.worker.attempt.route)?;
        let bridge = initial_bridge(&m.worker, recorder)?;
        let session = mix_bosh_lane(
            &bridge,
            &m.worker,
            &m.transport,
            &routes,
            &route,
            &mut queue,
            recorder,
            ordinals,
            sites,
        )
        .await?;
        retained_m = Some((session, route, queue, bridge));
    }
    // Complete M's actual response before constructing/starting A response.
    let (item, read, publisher) = build_auth(
        &input.auth.bound,
        Some(a_route.clone()),
        ordinals,
        recorder,
        sites,
    )
    .await?;
    auth_lookup(&routes, &a_route, &read);
    let mut a = bosh::Session::new(input.auth.session.clone(), recorder.clone())?;
    a.push_auth(item, read.clone(), publisher, ordinals.item()?)?;
    let response_ordinal = ordinals.bosh()?;
    let actual = driven(
        a.respond(sites.bosh[usize::from(response_ordinal)], input.auth.drive)
            .await,
    )?;
    auth_lookup(&routes, &a_route, &read);
    let result = publication_execution(actual.returned, actual.dropped, input.auth.drive, recorder);
    // Baseline error and mutant skipped callback are both emitted as actual
    // observations. Never assert callback count, BackendFailure or no-cache
    // here. The later independent safety reader owns the causal verdict.
    a.teardown()?;
    read.capture_frame_quiescent(Cut::AfterTeardown);
    if let Some((m, route, queue, bridge)) = retained_m {
        m.teardown()?;
        drop(queue);
        drop(route);
        drop(bridge);
    }
    drop(a_queue);
    Ok(result)
}

async fn dispatch(
    case: &ValidatedCase,
    recorder: &Capture,
    sites: &Sites,
) -> DispatchResult<Execution> {
    let mut ordinals = Ordinals::default();
    match &case.case().composition {
        Composition::Muc(input) => {
            crate::xmpp::protocol::muc::saved_stage4::run(input.clone(), recorder.clone())
                .await
                .map_err(DispatchExit::Resource)
        }
        Composition::AuthThenMixNative(input) => {
            auth_then_mix(input, recorder, &mut ordinals, sites).await
        }
        Composition::ReplayMixQueuedAuth(input) => {
            queued_auth(input, recorder, &mut ordinals, sites).await
        }
        Composition::MixRecoveryNative(input) => {
            recovery(input, recorder, &mut ordinals, sites).await
        }
        Composition::MixDefer(input) => defer(input, recorder, sites).await,
        Composition::NativeAuth(input) => native_auth(input, recorder, &mut ordinals, sites).await,
        Composition::BoshAuth(input) => bosh_auth(input, recorder, &mut ordinals, sites).await,
    }
}
fn finish_capture(recorder: Capture, result: DispatchResult<Execution>) -> Result<Envelope> {
    // dispatch has exited: every stack-owned future/item/route/publisher
    // has already returned or been dropped. No root owner alias escapes.
    let owned = Arc::try_unwrap(recorder)
        .map_err(|_| anyhow!("dispatcher retained a recorder owner after teardown"))?;
    let mut recorder = match owned.into_inner() {
        Ok(recorder) => recorder,
        Err(poisoned) => {
            let mut recorder = poisoned.into_inner();
            recorder.missing_observation();
            recorder
        }
    };
    if let Err(DispatchExit::Resource(stop)) = &result {
        // Stop metadata must already have been latched by actual admission
        // or the writer's real counter/preflight. Root never fabricates it.
        require_driver(
            recorder.resource_stop() == Some(&stop.resource_stop),
            "returned resource stop differs from first actual latch",
        )?;
    }
    if recorder.resource_stop().is_some() {
        return Ok(recorder.finish_resource_stopped()?);
    }
    match result {
        Ok(execution) => Ok(recorder.finish(execution)?),
        Err(DispatchExit::Failed(_actual_error)) => {
            recorder.missing_observation();
            Ok(recorder.finish(Execution::Failed)?)
        }
        Err(DispatchExit::Resource(_)) => {
            Err(anyhow!("resource stop returned without retained metadata"))
        }
    }
}
pub(super) async fn run_bytes(input: &[u8]) -> Result<Envelope> {
    // The closed schema is the sole input-validation/rejection authority, including
    // unsupported notification intent. Invalid inputs create no owner.
    let case = match decode(input) {
        Ok(case) => case,
        Err(reason) => return Ok(Envelope::rejected(input, reason)?),
    };
    let sites = Sites::new(&case)?; // labels/scripts validated before owners
    let recorder = Arc::new(Mutex::new(Recorder::new(&case)));
    // Supervisor retains the complete five-second process/stdio budget.
    // Normal nested service/Publisher callbacks are never extra poll sites.
    let result = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        dispatch(&case, &recorder, &sites),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(DispatchExit::Failed(anyhow!("finite dispatcher timed out"))),
    };
    finish_capture(recorder, result)
}

#[cfg(test)]
mod dispatcher_controls {
    use super::*;
    use crate::xmpp::stage4_auth_publication::ordinary as fixtures;

    // Bounded ordinary programmatic inputs using actual public builders in
    // the peer ordinary fixture. These are not frozen saved literal bytes,
    // expected evidence, record/replay output, or process-start contracts.
    fn native_case(drop_commit: bool) -> Case {
        let publication = if drop_commit {
            PublicationReply::CommitPending(EpochReply {
                epoch: Nullable::Null(()),
            })
        } else {
            PublicationReply::BackendError(Empty {})
        };
        let auth = fixtures::bound(TransportKind::Tcp, publication);
        Case {
            schema: fixtures::text(CASE_SCHEMA),
            case_id: fixtures::text("ordinary-dispatch"),
            adapter_contract: fixtures::text(ADAPTER_CONTRACT),
            composition: Composition::NativeAuth(NativeAuthInput {
                native: PlainNative {
                    connection_id: auth.frame.connection_id,
                    write: fixtures::write_ok(),
                },
                auth,
                drive: if drop_commit {
                    AuthDrive::DropPublicationCommit
                } else {
                    AuthDrive::Complete
                },
            }),
        }
    }
    async fn ordinary(case: &Case) -> Envelope {
        run_bytes(&serde_json::to_vec(case).unwrap()).await.unwrap()
    }
    fn complete_observations(envelope: &Envelope) {
        assert!(matches!(
            envelope.observation_status,
            ObservationStatus::Complete(_)
        ));
    }

    #[tokio::test]
    async fn rejected_duplicate_positional_and_relationship_inputs_have_no_owner_facts() {
        let case = native_case(false);
        let original = serde_json::to_string(&case).unwrap();
        let duplicate = format!("{{\"schema\":\"{CASE_SCHEMA}\",{}", &original[1..]).into_bytes();
        let mut positional = serde_json::to_value(&case).unwrap();
        positional["composition"]["data"]["auth"]["frame"] = serde_json::json!([]);
        let mut relationship = case.clone();
        let Composition::NativeAuth(input) = &mut relationship.composition else {
            unreachable!()
        };
        input.native.connection_id = fixtures::fixed(99);
        for (input, reason) in [
            (duplicate, Rejection::Json),
            (serde_json::to_vec(&positional).unwrap(), Rejection::Json),
            (
                serde_json::to_vec(&relationship).unwrap(),
                Rejection::Relationship,
            ),
        ] {
            let envelope = run_bytes(&input).await.unwrap();
            assert_eq!(envelope.rejection.get(), Some(&reason));
            assert!(envelope.execution.get().is_none());
            assert!(envelope.facts.is_empty());
            assert!(envelope.identity_map.is_empty());
            validate_envelope(&envelope, &input, None).unwrap();
        }
    }
    #[tokio::test]
    async fn unsupported_notification_is_rejected_before_any_owner_is_created() {
        let mut case = native_case(false);
        let Composition::NativeAuth(input) = &mut case.composition else {
            unreachable!()
        };
        input.auth.notification_expected = true;
        let envelope = ordinary(&case).await;
        assert_eq!(envelope.rejection.get(), Some(&Rejection::Unsupported));
        assert!(envelope.execution.get().is_none());
        assert!(envelope.facts.is_empty());
        assert!(envelope.identity_map.is_empty());
        let bytes = serde_json::to_vec(&case).unwrap();
        validate_envelope(&envelope, &bytes, None).unwrap();
        assert!(envelope.resource_stop.get().is_none());
    }
    #[tokio::test]
    async fn descriptive_case_id_does_not_select_dispatch_or_observed_behavior() {
        let first_case = native_case(false);
        let mut second_case = first_case.clone();
        second_case.case_id = fixtures::text("any-other-description");
        let first = ordinary(&first_case).await;
        let second = ordinary(&second_case).await;
        complete_observations(&first);
        complete_observations(&second);
        assert_ne!(first.input_sha256, second.input_sha256);
        assert_eq!(first.execution, second.execution);
        assert_eq!(first.facts, second.facts);
        assert_eq!(first.identity_map, second.identity_map);
    }
    #[tokio::test]
    async fn native_handled_error_and_actual_pending_drop_keep_distinct_executions() {
        for dropped in [false, true] {
            let envelope = ordinary(&native_case(dropped)).await;
            complete_observations(&envelope);
            assert_eq!(
                envelope.execution.get(),
                Some(&if dropped {
                    Execution::Cancelled
                } else {
                    Execution::Complete
                })
            );
            if dropped {
                assert!(envelope
                    .facts
                    .as_slice()
                    .iter()
                    .any(|record| matches!(&record.fact, Fact::Driver(p)
                    if p.owner == DriverOwner::Publication && p.result == PollResult::Pending)));
                assert!(envelope
                    .facts
                    .as_slice()
                    .iter()
                    .any(|record| matches!(&record.fact,
                    Fact::Control(ControlFact::LivePublication(p)) if p.cut == Cut::AfterRunnerDrop
                    && matches!(p.snapshot.publication, PublicationKnowledge::CommitCallEntered(_))
                    && p.snapshot.terminal.get() == Some(&PublicationTerminal::Cancelled))));
            } else {
                assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
                    Fact::Control(ControlFact::LivePublication(p))
                    if matches!(p.snapshot.returned.get(), Some(PublicationReturned::BackendFailure(_))))));
            }
        }
    }
    #[tokio::test]
    async fn reduced_bosh_backend_error_retains_selected_exposure_and_no_cache() {
        let case = Case {
            schema: fixtures::text(CASE_SCHEMA),
            case_id: fixtures::text("ordinary-reduced-auth"),
            adapter_contract: fixtures::text(ADAPTER_CONTRACT),
            composition: Composition::BoshAuth(BoshAuthInput {
                mix: Nullable::Null(()),
                auth: BoshAuthLane {
                    bound: fixtures::bound(
                        TransportKind::Bosh,
                        PublicationReply::BackendError(Empty {}),
                    ),
                    session: fixtures::session(2, 3, 22),
                    drive: AuthDrive::Complete,
                },
            }),
        };
        let envelope = ordinary(&case).await;
        complete_observations(&envelope);
        assert_eq!(envelope.execution.get(), Some(&Execution::Complete));
        assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
            Fact::Bosh(BoshFact::Selection(s)) if s.cut == Cut::BeforePublish && s.selection.selected_count == 1)));
        assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
            Fact::Bosh(BoshFact::Snapshot(s)) if s.snapshot.responses.as_slice().iter().any(|r| r.exposure_entered && r.accepted_responders == 1))));
        assert!(envelope
            .facts
            .as_slice()
            .iter()
            .all(|record| match &record.fact {
                Fact::Bosh(BoshFact::Cache(cache)) => cache.entries.is_empty(),
                _ => true,
            }));
    }
    #[tokio::test]
    async fn sticky_loss_preserves_native_behavior_without_duplicate_owner_charges() {
        let case = decode(&serde_json::to_vec(&native_case(false)).unwrap()).unwrap();
        let sites = Sites::new(&case).unwrap();
        let recorder = Arc::new(Mutex::new(Recorder::new(&case)));
        driver::lost(&recorder);
        let result = dispatch(&case, &recorder, &sites).await;
        assert!(matches!(result, Ok(Execution::Complete)));
        // Credential frame, native write and standalone publication, once
        // each. The nested bool callback/service calls are not extra sites.
        assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), 3);
        assert!(driver::resource_stop(&recorder).is_none());
        let envelope = finish_capture(recorder, result).unwrap();
        assert_eq!(envelope.execution.get(), Some(&Execution::Complete));
        assert!(envelope.resource_stop.get().is_none());
        assert!(matches!(
            envelope.observation_status,
            ObservationStatus::Lost(_)
        ));
    }
    #[tokio::test]
    async fn global_cut_before_planned_publication_drop_is_resource_metadata() {
        for sticky_loss in [false, true] {
            let bytes = serde_json::to_vec(&native_case(true)).unwrap();
            let case = decode(&bytes).unwrap();
            let sites = Sites::new(&case).unwrap();
            let recorder = Arc::new(Mutex::new(Recorder::new(&case)));
            if sticky_loss {
                driver::lost(&recorder);
            }
            // Ordinary-only priming uses actual ready futures and the exact
            // shared admission helper. No counter is reset or fixture field
            // added, and the saved entry never has this path.
            let site = PollSite::new(DriverOwner::Worker, 0).unwrap();
            for _ in 0..62 {
                let mut ready = Box::pin(std::future::ready(()));
                let actual = std::future::poll_fn(|cx| {
                    Poll::Ready(driver::poll_once(&recorder, site, ready.as_mut(), cx))
                })
                .await;
                assert!(matches!(actual, Ok(Poll::Ready(()))));
            }
            let result = dispatch(&case, &recorder, &sites).await;
            assert!(
                matches!(&result, Err(DispatchExit::Resource(BudgetStop { resource_stop: ResourceStop::DriverPoll(stop) }))
                if stop.owner == DriverOwner::Publication && stop.owner_ordinal == 0 && stop.admitted_calls == 64)
            );
            assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), 64);
            // dispatch has dropped the native OwnedPublication/publisher/read/
            // route/queue scopes. A planned Drop input cannot label this cutoff
            // Cancelled or Failed, and a safety mutant cannot qualify through it.
            let envelope = finish_capture(recorder, result).unwrap();
            assert!(envelope.execution.get().is_none() && envelope.rejection.get().is_none());
            assert!(matches!(
                envelope.resource_stop.get(),
                Some(ResourceStop::DriverPoll(_))
            ));
            validate_envelope(&envelope, &bytes, Some(&case)).unwrap();
            assert!(!envelope
                .facts
                .as_slice()
                .iter()
                .any(|record| matches!(&record.fact, Fact::Control(ControlFact::Callback(_)))));
            if sticky_loss {
                assert!(matches!(
                    envelope.observation_status,
                    ObservationStatus::Lost(_)
                ));
            }
        }
    }
}
