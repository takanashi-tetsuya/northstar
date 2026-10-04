"""Independent Stage3 oracle interface, currently incomplete.

The fixed literal corpus, wire DTO validation, input-derived ledger, normative
Safety checks, semantic projection and build/derivation reader are not yet
implemented. All public entry points fail closed. Framing and profile plumbing
in controlled_admission_supervision do not make this a runnable profile.

The eventual oracle must derive expectations from the literal Case and declared
adapter contracts before opening output. A child verdict or saved transcript is
never an expected-output source. Planned cancellations remain unqualified;
normative Safety precedes fixture comparison for both executable artifacts.
"""


class DirectCaseIncomplete(ValueError):
    """No partial Stage3 corpus or oracle may produce a fixture match."""


def require_implemented():
    raise DirectCaseIncomplete('stage3_literal_corpus_wire_oracle_and_build_record_incomplete')


def validate_provenance(provenance):
    require_implemented()


def check_current_provenance(contract):
    """Future reader checks the external build-record file hash before fields.

    That small record binds source-manifest/compiler/lock/command identities,
    target/features, original/runnable binary identities, exact strip tool and
    flags, and the optional single-statement no-flush ancestry. It never issues
    commands from the record or reads the oversized original executable during
    a saved pass. The runnable executable retains the fixed 128 MiB bound.
    """
    require_implemented()


def fixture_plan(profile_id):
    """Will return only the complete fixed16 or fixed4 literal input inventory."""
    require_implemented()


def evaluate_fixture(fixture, record, payload, profile_id):
    """Will return semantic projection, evaluation, fixture match and stop.

    Structural DTO checks must permit a truthful unsafe ACK transcript to reach
    the independent NativeAckWithoutSuccessfulFlush Safety predicate. Variable
    runtime sequence/time and libtest diagnostics must not enter replay equality.
    """
    require_implemented()


def shrink_relations(observations):
    """Will check the one deletion, exact same-target violations and control."""
    require_implemented()
