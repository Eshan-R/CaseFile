"""Tests for story grounding verifier, anti-hallucination checks, and template fallback."""

import pytest
from app.pipeline.report.verifier import generate_and_verify_story, verify_story
from app.schemas.facts import FactStep, IncidentFacts, ReachFacts, ReachFactTarget
from app.schemas.story import AttackStory, StoryAction, StoryStep


def make_fake_valid_story(facts: IncidentFacts) -> AttackStory:
    """Generate a strictly grounded story adhering to facts for testing verifier invariants."""
    story_steps = []
    for s in facts.steps:
        target_str = ", ".join(s.hosts) if s.hosts else "the target"
        story_steps.append(
            StoryStep(
                step_order=s.step_order,
                technique_id=s.technique_id,
                technique_name=s.technique_name,
                tactic=s.tactic,
                headline=f"{s.technique_name} on {target_str}",
                narrative=f"Observed {s.technique_name} on {target_str}.",
                cited_event_ids=s.evidence_event_ids[:2],
                entities_mentioned=[h for h in s.hosts if h],
                event_count=s.event_count,
                first_seen=s.first_seen,
                last_seen=s.last_seen,
            )
        )
    actions = []
    if facts.hosts:
        actions.append(
            StoryAction(
                priority=1,
                action="isolate_host",
                target=facts.hosts[0],
                rationale=f"Isolate host {facts.hosts[0]}.",
            )
        )
    if facts.src_ips:
        actions.append(
            StoryAction(
                priority=2,
                action="block_ip",
                target=facts.src_ips[0],
                rationale=f"Block IP {facts.src_ips[0]}.",
            )
        )
    return AttackStory(
        incident_id=facts.incident_id,
        headline=f"Campaign targeting {', '.join(facts.hosts)}",
        executive_summary=f"Incident {facts.incident_id} active attack targeting {', '.join(facts.hosts)}.",
        attack_path_summary="Adversary progressed through kill chain stages.",
        steps=story_steps,
        blast_radius_assessment="No lateral movement observed beyond initial detection scope.",
        recommended_actions=actions,
        story_source="llm",
        source="ai",
        provider="gemini",
        model="gemini-3.6-flash",
        facts_sha256=facts.facts_sha256,
        generated_at="2026-10-31T12:00:00Z",
    )


@pytest.fixture
def base_facts() -> IncidentFacts:
    step = FactStep(
        step_order=1,
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="credential_access",
        kill_chain_stage="Exploitation",
        first_seen="2026-10-23 08:00:00",
        last_seen="2026-10-23 08:15:00",
        hosts=["10.10.20.50"],
        occurrence_count=20,
        event_count=20,
        evidence_event_ids=["ev_1", "ev_2", "ev_3"],
    )

    return IncidentFacts(
        incident_id="inc_ver_1",
        title="Brute Force against Domain Member",
        severity=7,
        risk_score=7.0,
        status="open",
        detection_count=1,
        event_count=20,
        first_seen="2026-10-23 08:00:00",
        last_seen="2026-10-23 08:15:00",
        known_entities=["10.10.20.50", "198.51.100.2", "admin"],
        hosts=["10.10.20.50"],
        users=["admin"],
        src_ips=["198.51.100.2"],
        steps=[step],
        reach=ReachFacts(
            seed_hosts=["10.10.20.50"],
            hosts_count=1,
            users_count=0,
            critical_assets=[],
            reachable_targets=[
                ReachFactTarget(
                    target="10.10.20.60",
                    kind="host",
                    hops=1,
                    priority="low",
                    reason="test connection",
                )
            ],
        ),
        all_event_ids=["ev_1", "ev_2", "ev_3"],
    )


def test_valid_story_accepted(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    res = verify_story(story, base_facts)
    assert res.is_valid, f"Expected story to be valid but got errors: {res.errors}"
    assert len(res.errors) == 0


def test_reject_hallucinated_ip(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    # Inject an ungrounded IP address into executive summary
    story.executive_summary += " Traffic was observed flowing to suspicious IP 198.51.100.77."

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("Hallucinated IP address detected" in err and "198.51.100.77" in err for err in res.errors)


def test_reject_fake_event_id(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    # Step cites a fake/invented event ID
    story.steps[0].cited_event_ids.append("ev_fake_999999")

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("fake or unknown event ID" in err and "ev_fake_999999" in err for err in res.errors)


def test_reject_event_count_mismatch(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    # Fact records 20 events, story step claims 999
    story.steps[0].event_count = 999

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("event count mismatch" in err for err in res.errors)


def test_reject_timestamp_mismatch(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    story.steps[0].first_seen = "1999-01-01 00:00:00"

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("first_seen mismatch" in err for err in res.errors)


def test_reject_unapproved_action(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    story.recommended_actions.append(
        StoryAction(
            priority=1,
            action="nuke_server",
            target="10.10.20.50",
            rationale="Destroy compromised infrastructure",
            command="rm -rf /",
        )
    )

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("Unapproved response action 'nuke_server'" in err for err in res.errors)


def test_reject_action_target_unknown(base_facts: IncidentFacts):
    story = make_fake_valid_story(base_facts)

    story.recommended_actions.append(
        StoryAction(
            priority=1,
            action="isolate_host",
            target="ghost-workstation.corp",
            rationale="Isolate ungrounded host",
            command="",
        )
    )

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("not a known entity in incident facts" in err for err in res.errors)


def test_generate_and_verify_fallback(base_facts: IncidentFacts):
    # A broken LLM client that produces hallucinated stories
    class HallucinatingClient:
        def generate_story(self, facts):
            story = make_fake_valid_story(facts)
            story.executive_summary += " Injected fake IP 203.0.113.55."
            return story

    result_story = generate_and_verify_story(base_facts, llm_client=HallucinatingClient())

    # Fallback to template story
    assert result_story.story_source == "template"
    assert result_story.source == "template"
    assert result_story.incident_id == base_facts.incident_id
    assert "Grounding rejection" in (result_story.fallback_reason or "")
    # Template story itself is verified
    res = verify_story(result_story, base_facts)
    assert res.is_valid


def test_cidr_base_ip_accepted(base_facts: IncidentFacts):
    """Prose mentioning the base network address of a known CIDR is accepted."""
    base_facts.known_entities.append("71.54.76.0/24")
    story = make_fake_valid_story(base_facts)
    story.executive_summary += " Network perimeter traffic routed through 71.54.76.0."

    res = verify_story(story, base_facts)
    assert res.is_valid, f"Expected base IP 71.54.76.0 of 71.54.76.0/24 to be accepted, errors: {res.errors}"


def test_cidr_contained_ip_accepted(base_facts: IncidentFacts):
    """Prose mentioning an IP inside a known CIDR is accepted."""
    base_facts.known_entities.append("71.54.76.0/24")
    story = make_fake_valid_story(base_facts)
    story.executive_summary += " C2 channel communicated with 71.54.76.42."

    res = verify_story(story, base_facts)
    assert res.is_valid, f"Expected contained IP 71.54.76.42 in 71.54.76.0/24 to be accepted, errors: {res.errors}"


def test_cidr_external_ip_rejected(base_facts: IncidentFacts):
    """Prose mentioning an IP outside any known CIDR is strictly rejected as hallucinated."""
    base_facts.known_entities.append("71.54.76.0/24")
    story = make_fake_valid_story(base_facts)
    story.executive_summary += " Exfiltration attempted to 71.54.77.1."

    res = verify_story(story, base_facts)
    assert not res.is_valid
    assert any("Hallucinated IP address detected" in err and "71.54.77.1" in err for err in res.errors)


def test_story_metadata_fields(base_facts: IncidentFacts):
    """Verify provider, model, generated_at, source, and fallback_reason metadata."""
    story = generate_and_verify_story(base_facts)
    assert story.source in ("ai", "template")
    assert hasattr(story, "provider")
    assert hasattr(story, "model")
    assert hasattr(story, "generated_at")
    assert story.generated_at != ""
    assert hasattr(story, "fallback_reason")
    assert story.story_source == "template"
    assert "Gemini unavailable" in (story.fallback_reason or "")
