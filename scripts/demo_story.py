"""CLI demonstration of CaseFile Story & Graph Layer.

Demonstrates:
1. Deterministic Incident Facts extraction.
2. AI-written attack story generation (Mock or Live LLM).
3. Grounding verifier enforcement (detecting & rejecting hallucinations).
4. Automatic fallback to template story.

Usage:
    PYTHONPATH=backend python scripts/demo_story.py [incident_id]
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.pipeline.report.facts import build_incident_facts
from app.pipeline.report.llm_report import generate_template_story
from app.pipeline.report.verifier import verify_story
from app.schemas.story import AttackStory, StoryAction, StoryStep
from app.store import duck


class DemoLLMClient:
    """Demo-boundary story generator providing deterministic grounded narratives."""

    def generate_story(self, facts) -> AttackStory:
        story_steps = []
        for s in facts.steps:
            target_str = ", ".join(s.hosts) if s.hosts else "the environment"
            story_steps.append(
                StoryStep(
                    step_order=s.step_order,
                    technique_id=s.technique_id,
                    technique_name=s.technique_name,
                    tactic=s.tactic,
                    headline=f"{s.technique_name} on {target_str}",
                    narrative=(
                        f"During the {s.tactic} phase ({s.kill_chain_stage}), adversary activity matching "
                        f"technique {s.technique_id} ({s.technique_name}) was observed on host(s) {target_str}."
                    ),
                    cited_event_ids=s.evidence_event_ids[:2],
                    entities_mentioned=[h for h in s.hosts if h],
                    event_count=s.event_count,
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                )
            )
        actions = []
        prio = 1
        if facts.hosts:
            actions.append(
                StoryAction(
                    priority=prio,
                    action="isolate_host",
                    target=facts.hosts[0],
                    rationale=f"Prevent lateral movement from compromised host {facts.hosts[0]}.",
                    command=f"edr-cli isolate --host {facts.hosts[0]} --reason 'Incident containment'",
                )
            )
            prio += 1
        if facts.src_ips:
            actions.append(
                StoryAction(
                    priority=prio,
                    action="block_ip",
                    target=facts.src_ips[0],
                    rationale=f"Block inbound/outbound communications with external source {facts.src_ips[0]}.",
                    command=f"iptables -A INPUT -s {facts.src_ips[0]} -j DROP",
                )
            )
        return AttackStory(
            incident_id=facts.incident_id,
            headline=f"Confirmed Campaign on {', '.join(facts.hosts)}",
            executive_summary=f"Incident {facts.incident_id} active attack targeting {', '.join(facts.hosts)}.",
            attack_path_summary="Kill chain steps executed in sequence.",
            steps=story_steps,
            blast_radius_assessment="No lateral movement observed beyond initial scope.",
            recommended_actions=actions,
            story_source="llm",
            source="ai",
            provider="gemini",
            model="gemini-3.6-flash",
            facts_sha256=facts.facts_sha256,
            generated_at="2026-10-31T12:00:00Z",
        )


def run_demo(incident_id: str | None = None) -> None:
    print("=" * 70)
    print("[*] CaseFile Story & Graph Layer Demonstration")
    print("=" * 70)

    # 1. Resolve Target Incident
    if not incident_id:
        incs_res = duck.list_incidents(limit=5)
        inc_list = incs_res[1] if isinstance(incs_res[0], int) else incs_res[0]
        if not inc_list:
            print("[-] No incidents found in DuckDB. Ingest and analyse logs first.")
            return
        incident_id = inc_list[0]["incident_id"]

    print(f"\n[1] Extracting Deterministic Facts for: {incident_id}")
    facts = build_incident_facts(incident_id)

    print(f"  * Title:            {facts.title}")
    print(f"  * Severity / Risk:  {facts.severity}/10  (Score: {facts.risk_score:.1f}/10)")
    print(f"  * Kill Chain Steps: {len(facts.steps)}")
    print(f"  * Known Entities:   {len(facts.known_entities)} ({', '.join(facts.known_entities[:5])}...)")
    print(f"  * Facts SHA-256:    {facts.facts_sha256}")

    for s in facts.steps:
        print(f"    - Step {s.step_order}: {s.technique_id} ({s.technique_name}) | "
              f"Events: {s.event_count} | Hosts: {s.hosts} | Cited Evidence: {s.evidence_event_ids[:2]}")

    if facts.reach:
        print(f"  * Lateral Reach:    {facts.reach.hosts_count} hosts, {len(facts.reach.critical_assets)} critical assets")

    # 2. Generate Grounded AI Story
    print("\n[2] Generating Grounded Attack Story (Demo Generator)")
    client = DemoLLMClient()
    story = client.generate_story(facts)

    print(f"  * Headline:         {story.headline}")
    print(f"  * Story Source:     {story.story_source}")
    print(f"  * Executive Brief:  {story.executive_summary[:160]}...")
    print(f"  * Recommended Acts: {len(story.recommended_actions)}")
    for act in story.recommended_actions:
        print(f"    - [{act.action}] Target: {act.target} (Priority {act.priority})")
        if act.command:
            print(f"      Clipboard Cmd: {act.command}")

    # 3. Grounding Verifier Enforcement
    print("\n[3] Grounding Verifier Enforcement (Anti-Hallucination)")
    ver_clean = verify_story(story, facts)
    print(f"  * Clean Story Valid?  {ver_clean.is_valid} (Errors: {len(ver_clean.errors)})")

    # Simulate Adversarial / Hallucinating Model
    print("\n[4] Simulating Hallucinated Adversarial Output")
    story_corrupted = client.generate_story(facts)
    story_corrupted.executive_summary += " Attacker also exfiltrated data to foreign IP 198.51.100.77."
    story_corrupted.steps[0].cited_event_ids.append("ev_fake_999999")

    ver_corrupted = verify_story(story_corrupted, facts)
    print(f"  * Corrupted Story Valid? {ver_corrupted.is_valid}")
    print("  * Caught Grounding Violations:")
    for err in ver_corrupted.errors:
        print(f"    [-] {err}")

    # 4. Safe Fallback to Deterministic Template Story
    print("\n[5] Safe Fallback Triggered")
    fallback_story = generate_template_story(facts)
    ver_fallback = verify_story(fallback_story, facts)
    print(f"  * Fallback Source: {fallback_story.story_source}")
    print(f"  * Fallback Valid?  {ver_fallback.is_valid}")
    print(f"  * Fallback Title:  {fallback_story.headline}")

    print("\n" + "=" * 70)
    print("[+] Story & Graph Layer Demonstration Completed Successfully")
    print("=" * 70)


if __name__ == "__main__":
    inc_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_demo(inc_arg)
