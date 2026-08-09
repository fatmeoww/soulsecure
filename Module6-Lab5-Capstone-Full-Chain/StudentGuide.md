# Module 6 — Lab 5: Capstone — Full-Chain Engagement & Report Writeup

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — capstone, spans Modules 3–6
**Target:** SoulSecure Inc. — the full Module 3–5 stack, freshly reset
**Estimated time:** 3–4 hours (time-boxed — see Section 3)

---

## 1. A different kind of lab

Every other lab in this course scored you on flags you could paste into a checklist.
This one doesn't work that way, on purpose. **There are no embedded flags in this
lab.** Your deliverable is a single artifact: a professional penetration test report
covering the complete engagement, written the way SoulSecure's leadership would
actually need to read it.

> **Scope reminder:** the full `soulsecure.lab` environment (fresh reset, Module 3–5
> content, `LEVEL` 5 across all three modules). Rules of engagement from Module 1
> still apply. This is a graded assessment, not a race — read Section 3 before you
> start the clock.

## 2. Scenario

SoulSecure's leadership has asked for one consolidated report covering everything
this multi-module engagement found, from initial access through persistence. You'll
run the entire chain again, start to finish, against a freshly reset environment —
no partial credit for remembering exact commands from earlier modules, but full
credit for moving faster because you understand *why* each step worked.

## 3. Time-boxing

This lab is scoped to **one continuous sitting**, 3–4 hours. Re-solving a chain you
already understand should go noticeably faster than the first time through each
module — that speed is itself part of what's being assessed. If you're taking
meaningfully longer than a first-time pace on any one stage, that's worth noting in
your report as its own observation (real engagements have deadlines too).

## 4. Required chain (minimum bar)

Your report must document a complete, coherent path through at least:

1. **Initial access** — any Module 3 technique
2. **Privilege escalation** — any Module 4 technique, reaching admin-equivalent access
3. **Persistence** — at least one Module 5 mechanism, tested against
   `/admin/simulate-remediation`
4. **Lateral movement** — reaching at least one additional host/service beyond your
   initial foothold
5. **Impact/exfiltration** — a concrete data-exfiltration technique from Module 5 Lab 4

You may use any valid path through Modules 3–5's techniques — there is more than one
way to satisfy each stage. Optionally, corroborate one or more findings with a
Module 6 tool (Prowler/Pacu/trufflehog/checkov) for extra rigor in your writeup.

## 5. Report template

Your report must include, at minimum:

1. **Executive Summary** — plain-language, for a non-technical reader: what was at
   risk, in one paragraph
2. **Scope & Rules of Engagement**
3. **Methodology** — brief, references this course's phases (recon → initial access
   → privesc → persistence/lateral movement)
4. **Attack Narrative** — a timeline/kill-chain walkthrough of the specific path you
   took, chained end to end
5. **Findings Table** — every distinct finding, with a severity rating you assign and
   justify (not just "critical" on everything)
6. **Remediation Recommendations** — specific, prioritized, tied to each finding
7. **Appendix** — raw command evidence for each major step

## 6. Tools you'll want

- Everything from Modules 3–5 (`curl`, `ssh-keygen`, etc.)
- Optionally, Module 6's tools for corroboration

## 7. Deliverable

One report document (format: your instructor's preference — Markdown, PDF, or
Word). No flags to submit for this lab — the report itself is graded against the
rubric in the InstructorKey.

## 8. Course wrap-up

This is the last lab of the course. The report you produce here should read like
something you'd actually be comfortable handing to a client — because in every
respect except the fictional company name, it is one.
