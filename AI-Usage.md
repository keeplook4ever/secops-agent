## AI Usage Transparency

### 1. AI Tools Used

During this assignment, I leveraged multiple AI-assisted development tools to improve efficiency and design quality:

* Claude – primarily using *plan mode* for system design and *auto-accept edits mode* for implementation
* Cursor - code review 和 coding
* ChatGPT – for debugging, validating assumptions, and troubleshooting runtime issues

The workflow was iterative: design with Claude (plan mode), implement with Cursor (auto edits), and validate/debug with ChatGPT.

---

### 2. Critical Review and Correction of AI Outputs

I did not accept AI outputs blindly. Below are concrete examples where I reviewed and corrected AI-generated results:

* **Incorrect handling of missing tenant_id**
  The initial AI-generated design dropped logs without a `tenant_id`.
  → I explicitly revised the prompt to require *retention and proper recording* of such logs, as dropping them could lead to loss of critical security signals.

* **Misinterpretation of prompt injection scope**
  The AI incorrectly applied prompt-injection defenses to raw input logs.
  → I corrected this by clarifying that the protection should apply to the **SecOps agent layer**, not the raw log ingestion layer.

* **Over-masking of tenant_id in reports**
  The generated output still masked `tenant_id`, reducing operational usefulness.
  → I modified requirements to ensure **real tenant_id values are preserved in final reports** for traceability.

* **Lack of environment variable parameterization**
  Many configurations were hardcoded in the AI output.
  → I enforced parameterization via environment variables to align with production best practices.

* **Design vs. implementation gap validation**
  I manually compared:

  * `secops-agent/output/`
  * `DESIGN.md`
    → Identified missing implementations and guided the AI to fill those gaps.

* **Runtime troubleshooting (non-design issues)**
  Using ChatGPT, I debugged:

  * Initial `forbidden` errors (caused by missing VPN)
  * Incorrect or outdated model configuration

These corrections ensured the final system met both functional and security expectations.

---

### 3. System Prompt Design Rationale

To improve output quality and reliability, I deliberately engineered system prompts with specific constraints:

* **Role specialization**
  I added instructions such as *“you are a senior security expert”* to:

  * Encourage security-first reasoning
  * Improve threat modeling and defensive design quality

* **Explicit constraints and expectations**
  Prompts were refined to:

  * Prevent silent data loss (e.g., logs without tenant_id must be handled)
  * Enforce correct architectural boundaries (e.g., injection defense scope)
  * Require production-grade practices (e.g., env-based configuration)

* **Iterative prompt refinement**
  Instead of relying on a single prompt, I continuously updated prompts based on:

  * Observed AI misunderstandings
  * Gaps between design and implementation
  * Real execution feedback

This iterative approach significantly improved both correctness and robustness of AI-generated outputs.

---

### Summary

AI tools were used as **assistants, not authorities**. All outputs were critically evaluated, validated against requirements, and adjusted where necessary. The final solution reflects human-reviewed engineering decisions with AI support, rather than unverified AI-generated results.