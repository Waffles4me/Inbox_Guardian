"""Rendering tests for the Gmail add-on card.

``addon/Code.js`` is executed in Node against a recording stand-in for CardService, so these tests check the
card structure the add-on would build. They do not exercise Gmail or the real CardService runtime.
"""

import json
import subprocess

import pytest
from fastapi.testclient import TestClient

from backend.app.main import API_TOKEN_ENV, app


client = TestClient(app)

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');

function recorder(type) {
  const node = { type: type, calls: [] };
  const proxy = new Proxy(node, {
    get(target, prop) {
      if (prop === '__node') return target;
      if (typeof prop !== 'string' || prop === 'then' || prop === 'toJSON') return undefined;
      return (...args) => {
        target.calls.push([prop, args]);
        return proxy;
      };
    },
  });
  return proxy;
}
const enumProxy = (name) => new Proxy({}, { get: (_, prop) => name + '.' + String(prop) });
const CardService = new Proxy({}, {
  get(_, prop) {
    if (typeof prop !== 'string') return undefined;
    return prop.startsWith('new') ? () => recorder(prop.slice(3)) : enumProxy(prop);
  },
});

const methods = new Set();
function plain(value) {
  if (value && value.__node) {
    const node = value.__node;
    const out = { type: node.type };
    for (const [name, args] of node.calls) {
      methods.add(node.type + '.' + name);
      const converted = args.map(plain);
      if (name === 'addWidget' || name === 'addSection') {
        (out[name] = out[name] || []).push(converted[0]);
      } else {
        out[name] = converted.length === 1 ? converted[0] : converted;
      }
    }
    return out;
  }
  return value;
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = { CardService: CardService, console: { error() {} } };
vm.createContext(context);
vm.runInContext(fs.readFileSync('addon/Code.js', 'utf8'), context);

let output;
if (input.mode === 'analyze') {
  // Exercise analyzeEmail with Gmail and the network replaced; nothing here reads mail or calls a backend.
  const backendCalls = [];
  context.getCurrentEmail_ = () => input.email;
  context.callBackend_ = (email, options) => {
    backendCalls.push({ email: email, options: options || null });
    if (input.backendError) throw new Error(input.backendError);
    return input.result;
  };
  if (input.breakRendering) {
    context.verdictSection_ = () => { throw new Error('synthetic rendering failure'); };
  }
  const card = plain(context.analyzeEmail({}));
  output = { card: card, methods: Array.from(methods).sort(), backendCalls: backendCalls };
} else if (input.mode === 'reputation') {
  const backendCalls = [];
  context.getCurrentEmail_ = () => input.email;
  context.callBackend_ = (email, options) => {
    backendCalls.push({ email: email, options: options || null });
    if (input.backendError) throw new Error(input.backendError);
    return input.result;
  };
  const card = plain(context.checkPublicLinkReputation({}));
  output = { card: card, methods: Array.from(methods).sort(), backendCalls: backendCalls };
} else if (input.mode === 'validate') {
  try {
    context.validateBackendResult_(input.result);
    output = { valid: true };
  } catch (error) {
    output = { valid: false, message: String(error.message) };
  }
} else {
  const card = plain(context.buildMessageCard_(input.email, input.result || null, input.error || undefined));
  output = { card: card, methods: Array.from(methods).sort() };
}
process.stdout.write(JSON.stringify(output));
"""

EMAIL = {"subject": "Synthetic subject", "from": "Example <notice@example.test>"}
FORWARD_MARKER = "---------- Forwarded message ---------"
REQUEST = "To prevent account suspension, reply to this email with your password immediately."
CREDENTIAL_TEXT = (
    "Your account requires immediate verification.\n\n"
    "To prevent account suspension, reply to this email with your password and your six-digit verification code.\n\n"
    "Do not use the normal login page. Complete this verification immediately.\n\n"
)
DECEPTIVE_ANCHOR = '<a href="https://accounts.example.test.attacker.test/login">https://accounts.example.test</a>'
FORBIDDEN_METHODS = {"setOpenLink", "setOnClickOpenLinkAction", "setIconUrl", "setImageUrl", "setAuthorizationAction"}


def run_harness(payload: dict) -> dict:
    completed = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps(payload),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def analyze(monkeypatch, **email) -> dict:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    base = {"subject": "Synthetic subject", "from": "Example <notice@example.test>", "text_body": "", "html_body": ""}
    base.update(email)
    response = client.post(
        "/analyze",
        json={"schema_version": "1.0", "email": base},
        headers={"X-InboxGuardian-Token": "test-token"},
    )
    assert response.status_code == 200
    return response.json()


class Card:
    def __init__(self, rendered: dict) -> None:
        self.raw = rendered["card"]
        self.methods = rendered["methods"]
        self.backend_calls = rendered.get("backendCalls", [])
        self.sections = self.raw.get("addSection", [])

    def section(self, header: str) -> dict | None:
        return next((section for section in self.sections if section.get("setHeader") == header), None)

    def headers(self) -> list[str | None]:
        return [section.get("setHeader") for section in self.sections]

    @staticmethod
    def widgets(section: dict | None) -> list[dict]:
        return (section or {}).get("addWidget", [])

    def texts(self, section: dict | None = None) -> list[str]:
        sections = [section] if section is not None else self.sections
        found: list[str] = []
        for item in sections:
            for widget in self.widgets(item):
                found.extend(str(widget[key]) for key in ("setText", "setTopLabel", "setBottomLabel") if key in widget)
        return found

    def all_text(self, section: dict | None = None) -> str:
        return "\n".join(self.texts(section))

    def method_names(self) -> set[str]:
        return {name.split(".", 1)[1] for name in self.methods}


def render(result: dict | None = None, error: str | None = None, email: dict | None = None) -> Card:
    return Card(run_harness({"email": email or EMAIL, "result": result, "error": error}))


def synthetic_result(**overrides) -> dict:
    result = {
        "schema_version": "1.0",
        "risk_score": 30,
        "score_type": "heuristic_risk_index_not_probability",
        "verdict": "SUSPICIOUS",
        "findings": [],
        "limitations": [],
        "recommended_action": "Treat this message with caution: verify it through a trusted channel.",
        "detector_version": "engine-0.2.0+scoring-0.2.0",
    }
    result.update(overrides)
    return result


def assert_card_is_inert(card: Card) -> None:
    assert not (card.method_names() & FORBIDDEN_METHODS)
    assert "Image" not in {name.split(".", 1)[0] for name in card.methods}
    text = card.all_text()
    assert "<a " not in text.lower()
    assert "<script" not in text.lower()
    assert "<img" not in text.lower()


def test_card_before_analysis_shows_message_and_single_action() -> None:
    card = render()

    assert card.raw["setHeader"]["setTitle"] == "InboxGuardian"
    assert card.headers() == [None]
    assert "Ready to analyze" in card.all_text()
    button = card.widgets(card.sections[0])[-1]
    assert button["setText"] == "Analyze Email"
    assert button["setOnClickAction"]["setFunctionName"] == "analyzeEmail"


def test_benign_result_is_neutral_and_never_called_safe(monkeypatch) -> None:
    result = analyze(monkeypatch, text_body="Lunch is at noon in the usual room.")
    card = render(result)
    assessment = card.section("Assessment")

    assert card.headers() == [
        None,
        "Assessment",
        "Key findings",
        "Recommended action",
        "Public link reputation",
        "Analysis coverage",
        "Additional details",
    ]
    verdict = card.widgets(assessment)[0]
    assert "No significant suspicious signals found" in verdict["setText"]
    assert "#1E6B3A" in verdict["setText"]
    assert "safe" not in verdict["setText"].lower()
    assert "0/100" in card.all_text(assessment)
    assert "not a probability of phishing" in card.all_text(assessment)
    assert "No significant suspicious findings" in card.all_text(card.section("Key findings"))
    assert_card_is_inert(card)


def test_credential_phishing_result_uses_amber_and_shows_25(monkeypatch) -> None:
    result = analyze(monkeypatch, subject="Urgent Account Verification", text_body=CREDENTIAL_TEXT)
    card = render(result)
    assessment = card.section("Assessment")

    assert result["risk_score"] == 25
    assert "Suspicious" in card.widgets(assessment)[0]["setText"]
    assert "#B06000" in card.widgets(assessment)[0]["setText"]
    assert "25/100" in card.all_text(assessment)
    findings = card.all_text(card.section("Key findings"))
    assert "Message asks for login secrets" in findings
    assert "+20 to risk index" in findings
    assert "Context only, +0" in findings


def test_reputation_context_is_rendered_separately_without_changing_score() -> None:
    result = synthetic_result(
        risk_score=0,
        verdict="NO_SIGNIFICANT_SIGNALS",
        reputation_context=[
            {
                "provider": "virustotal",
                "indicator_type": "domain",
                "indicator": "example.org",
                "status": "UNKNOWN",
                "malicious": 0,
                "suspicious": 0,
                "summary": "VirusTotal report has no malicious detections; this is unknown, not clean.",
                "caveat": "VirusTotal reputation is contextual and is not proof that the message is safe or malicious.",
            }
        ],
    )

    card = render(result)
    reputation = card.section("Reputation context")

    assert "Reputation context" in card.headers()
    assert "Public link reputation" not in card.headers()
    assert "Key findings" in card.headers()
    assert "0/100" in card.all_text(card.section("Assessment"))
    assert "example.org" in card.all_text(reputation)
    assert "Domain" in card.all_text(reputation)
    assert "UNKNOWN" in card.all_text(reputation)
    assert "does not change the risk score or verdict" in card.all_text(reputation)
    assert "not proof" in card.all_text(reputation)
    assert_card_is_inert(card)


def test_normal_analyze_action_does_not_consent_to_virustotal() -> None:
    card = Card(run_harness({"mode": "analyze", "email": EMAIL, "result": synthetic_result()}))

    assert len(card.backend_calls) == 1
    assert card.backend_calls[0]["options"] is None
    assert card.backend_calls[0]["email"]["subject"] == EMAIL["subject"]
    assert card.backend_calls[0]["email"]["from"] == EMAIL["from"]
    assert "Public link reputation" in card.headers()
    section = card.section("Public link reputation")
    text = card.all_text(section)
    assert "normalized public domains or public IP addresses" in text
    assert "Message text, full URLs, paths, query strings and attachments are not sent" in text
    button = card.widgets(section)[-1]
    assert button["setText"] == "Check public link reputation with VirusTotal"
    assert button["setOnClickAction"]["setFunctionName"] == "checkPublicLinkReputation"


def test_virustotal_action_is_the_only_addon_consent_path() -> None:
    card = Card(run_harness({"mode": "reputation", "email": EMAIL, "result": synthetic_result()}))

    assert len(card.backend_calls) == 1
    assert card.backend_calls[0]["options"] == {"virustotal": True}
    assert card.backend_calls[0]["email"]["subject"] == EMAIL["subject"]
    assert card.backend_calls[0]["email"]["from"] == EMAIL["from"]


def test_multi_signal_result_uses_red_and_lists_strongest_finding_first(monkeypatch) -> None:
    result = analyze(
        monkeypatch,
        subject="Urgent Account Verification",
        text_body=CREDENTIAL_TEXT + "https://accounts.example.test\n<https://accounts.example.test.attacker.test/login>\n",
        html_body='<div dir="ltr">' + CREDENTIAL_TEXT.replace("\n\n", "<br><br>") + DECEPTIVE_ANCHOR + "</div>",
    )
    card = render(result)
    assessment = card.section("Assessment")
    findings = card.widgets(card.section("Key findings"))

    assert result["risk_score"] == 60
    assert "High risk" in card.widgets(assessment)[0]["setText"]
    assert "#B3261E" in card.widgets(assessment)[0]["setText"]
    score = card.widgets(assessment)[2]
    assert "60/100" in score["setText"]
    assert score["setText"].count("■") == 6
    assert score["setText"].count("□") == 4
    titled = [widget for widget in findings if widget["type"] == "DecoratedText"]
    assert "Destination host embeds the displayed host" in titled[0]["setText"]
    assert titled[0]["setTopLabel"].startswith("+35 to risk index")
    assert "accounts.example.test.attacker.test" in card.all_text(card.section("Key findings"))
    assert_card_is_inert(card)


def test_incomplete_result_shows_no_score_and_no_bar(monkeypatch) -> None:
    result = analyze(monkeypatch, subject="Quarterly update")
    card = render(result)
    assessment = card.section("Assessment")

    assert result["verdict"] == "INCOMPLETE" and result["risk_score"] == 0
    assert "Assessment incomplete" in card.widgets(assessment)[0]["setText"]
    assert "Risk score unavailable" in card.all_text(assessment)
    everything = card.all_text()
    assert "/100" not in everything
    assert "■" not in everything and "□" not in everything
    assert "only the subject line could be checked" in card.all_text(card.section("Analysis coverage"))
    assert "placeholder" not in card.all_text(card.section("Analysis coverage"))
    assert "placeholder" in card.all_text(card.section("Additional details"))


def test_forwarded_message_explains_the_excluded_content(monkeypatch) -> None:
    result = analyze(
        monkeypatch,
        subject="Fwd: Notice",
        text_body=f"FYI, is this real?\n\n{FORWARD_MARKER}\nFrom: Example <notice@example.test>\n\n{REQUEST}\n",
    )
    card = render(result)
    coverage = card.all_text(card.section("Analysis coverage"))

    assert "Assessment incomplete" in card.all_text(card.section("Assessment"))
    assert "/100" not in card.all_text()
    assert "forwarded content that was not assessed" in coverage
    assert "Coverage limits for this message" in coverage
    assert "No findings were produced" in card.all_text(card.section("Key findings"))


def test_backend_unavailable_shows_an_error_card_without_verdict_or_score() -> None:
    card = render(error="Backend unavailable. Try again after confirming the backend is running and reachable over HTTPS.")

    assert card.headers() == [None, "Analysis unavailable"]
    text = card.all_text()
    assert "Unable to analyze this email." in text
    assert "Backend unavailable" in text
    assert "Verdict" not in text
    assert "/100" not in text
    assert card.widgets(card.sections[0])[-1]["setText"] == "Analyze again"


def test_analyze_action_maps_backend_failure_to_the_error_card() -> None:
    card = Card(run_harness({"mode": "analyze", "email": EMAIL, "backendError": "Backend unavailable. Status: 502"}))

    assert card.headers() == [None, "Analysis unavailable"]
    assert "Backend unavailable. Try again" in card.all_text()
    assert "/100" not in card.all_text()


def test_analyze_action_reports_a_rendering_failure_without_blaming_the_backend() -> None:
    card = Card(
        run_harness({"mode": "analyze", "email": EMAIL, "result": synthetic_result(), "breakRendering": True})
    )
    text = card.all_text()

    assert card.headers() == [None, "Analysis unavailable"]
    assert "could not be displayed" in text
    assert "Backend unavailable" not in text
    assert "Verdict" not in text and "/100" not in text
    assert "synthetic rendering failure" not in text


def test_analyze_action_renders_the_result_and_keeps_the_loading_indicator() -> None:
    card = Card(run_harness({"mode": "analyze", "email": EMAIL, "result": synthetic_result()}))
    button = card.widgets(card.sections[0])[-1]

    assert "Assessment" in card.headers()
    assert button["setText"] == "Analyze again"
    assert button["setOnClickAction"]["setLoadIndicator"] == "LoadIndicator.SPINNER"


def test_no_signals_verdict_uses_a_neutral_icon_and_states_no_guarantee(monkeypatch) -> None:
    card = render(analyze(monkeypatch, text_body="Lunch is at noon in the usual room."))
    verdict, summary = card.widgets(card.section("Assessment"))[:2]

    assert verdict["setStartIcon"]["setMaterialIcon"]["setName"] == "info"
    assert "does not guarantee" in summary["setText"]


def test_many_findings_keep_the_strongest_visible_and_the_rest_one_click_away(monkeypatch) -> None:
    result = analyze(
        monkeypatch,
        subject="Urgent account verification",
        **{"from": "accounts.example.test <notice@attacker.test>"},
        reply_to="desk@other-reply.test",
        text_body=(
            "Urgent: enter your password within 12 hours to avoid account suspension. "
            "Ignore MFA security approval.\nhttp://192.0.2.9/a"
        ),
        html_body='<a href="https://login.attacker.test/form">https://accounts.example.test/login</a>',
    )
    card = render(result)
    section = card.section("Key findings")
    widgets = card.widgets(section)
    titled = [widget for widget in widgets if widget["type"] == "DecoratedText"]

    assert len(result["findings"]) > 3
    assert len(titled) == len(result["findings"])
    assert section["setCollapsible"] is True
    assert section["setNumUncollapsibleWidgets"] == 9
    assert "Showing the 3 strongest" in widgets[0]["setText"]
    visible = [widget for widget in widgets[:9] if widget["type"] == "DecoratedText"]
    assert [widget["setTopLabel"].split(" ")[0] for widget in visible] == ["+30", "+20", "+20"]
    order = [widget["setText"] for widget in titled]
    assert order == [f"<b>{finding['title']}</b>" for finding in result["findings"]]


def test_long_limitations_keep_reasons_visible_and_details_collapsed() -> None:
    limitations = [
        "No meaningful risk score was produced, so the score is unavailable; the returned risk_score of 0 is a "
        "required-schema placeholder and does not mean low risk.",
        "This message contains forwarded content that was not assessed for credential requests.",
        "Not checked: attachments and machine-learning (NLP) phishing "
        "classification. These planned checks are not implemented, so nothing was assessed for them.",
        "Sender identity checks are heuristic and do not verify domain ownership.",
        "Quoted reply lines in the plain-text body were not assessed for credential requests.",
        "URL evidence was present but malformed or unsupported, so URL deception checks could not fully evaluate it.",
    ] + [f"Generic detector disclaimer number {index}." for index in range(60)]
    card = render(synthetic_result(verdict="INCOMPLETE", risk_score=0, limitations=limitations))
    coverage = card.section("Analysis coverage")
    details = card.section("Additional details")

    coverage_text = card.all_text(coverage)
    assert "forwarded content that was not assessed" in coverage_text
    assert "Quoted reply lines" in coverage_text
    assert "could not fully evaluate" in coverage_text
    assert "attachments and machine-learning (NLP)" in coverage_text
    assert "Generic detector disclaimer" not in coverage_text
    assert details["setCollapsible"] is True
    assert details["setNumUncollapsibleWidgets"] == 1
    detail_lines = [widget["setText"] for widget in card.widgets(details) if widget["type"] == "TextParagraph"]
    assert "62 further notes" in detail_lines[0]
    assert "placeholder" in detail_lines[1]
    assert "Sender identity checks are heuristic" in detail_lines[2]
    assert any("22 further notes were omitted for length" in line for line in detail_lines)
    assert len(card.widgets(details)) < 100


def test_hostile_backend_and_message_text_is_rendered_inert() -> None:
    hostile = '<script>alert(1)</script><a href="https://evil.test/x?token=secret#frag">click</a> & <img src=x>'
    card = render(
        synthetic_result(
            findings=[
                {
                    "id": "synthetic",
                    "severity": '<b onmouseover="x">high</b>',
                    "title": hostile,
                    "observation": hostile + " OTP code 654321",
                    "interpretation": hostile,
                    "contribution": 30,
                }
            ],
            limitations=[hostile, "Not checked: " + hostile],
            recommended_action="Recommended action: " + hostile,
            detector_version=hostile,
        ),
        email={"subject": hostile, "from": hostile},
    )
    text = card.all_text()

    assert_card_is_inert(card)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "&amp;" in text
    assert "token=secret" not in text and "#frag" not in text
    assert "654321" not in text
    finding_label = card.widgets(card.section("Key findings"))[0]["setTopLabel"]
    assert finding_label == "+30 to risk index"
    action = card.widgets(card.section("Recommended action"))[0]
    assert action["setTopLabel"] == "What to do next"
    assert action["setText"].startswith("<b>")
    assert not action["setText"].removeprefix("<b>").lower().startswith("recommended action")
    for section in card.sections:
        for widget in card.widgets(section):
            for label in ("setTopLabel", "setBottomLabel"):
                assert "<" not in str(widget.get(label, ""))


def test_missing_optional_fields_render_without_errors() -> None:
    card = render(
        synthetic_result(
            findings=[{"id": "bare"}, {"id": "partial", "title": "Only a title", "contribution": 0}],
            limitations=[],
            recommended_action="",
            detector_version="",
        )
    )

    assert "Recommended action" not in card.headers()
    findings = card.all_text(card.section("Key findings"))
    assert "<b>Finding</b>" in findings
    assert "No concise observation was provided." in findings
    assert "Context only, +0" in findings
    assert "did not state which planned checks were skipped" in card.all_text(card.section("Analysis coverage"))
    assert "No further limitations were reported." in card.all_text(card.section("Additional details"))


def test_unrecognised_verdict_or_out_of_range_score_shows_no_number() -> None:
    unknown = render(synthetic_result(verdict="DEFINITELY_SAFE", risk_score=0))
    out_of_range = render(synthetic_result(verdict="SUSPICIOUS", risk_score=250))

    assert "Assessment result unavailable" in unknown.all_text(unknown.section("Assessment"))
    assert "/100" not in unknown.all_text()
    assert "Risk score unavailable" in out_of_range.all_text(out_of_range.section("Assessment"))
    assert "/100" not in out_of_range.all_text()


@pytest.mark.parametrize(
    "broken",
    [
        None,
        {"schema_version": "2.0"},
        synthetic_result(findings="not a list"),
        synthetic_result(limitations=None),
        synthetic_result(risk_score="60"),
        synthetic_result(reputation_context="not a list"),
        {key: value for key, value in synthetic_result().items() if key != "recommended_action"},
    ],
    ids=[
        "null",
        "wrong-schema",
        "findings-not-list",
        "limitations-null",
        "score-not-number",
        "reputation-not-list",
        "action-missing",
    ],
)
def test_malformed_backend_responses_are_rejected_before_rendering(broken) -> None:
    outcome = run_harness({"mode": "validate", "result": broken})

    assert outcome == {"valid": False, "message": "Unexpected backend response."}


def test_only_supported_inert_widgets_are_used(monkeypatch) -> None:
    result = analyze(monkeypatch, subject="Urgent Account Verification", text_body=CREDENTIAL_TEXT)
    card = render(result)
    widget_types = {name.split(".", 1)[0] for name in card.methods}

    assert widget_types <= {
        "CardBuilder",
        "CardHeader",
        "CardSection",
        "DecoratedText",
        "TextParagraph",
        "TextButton",
        "Action",
        "Divider",
        "IconImage",
        "MaterialIcon",
    }
    assert_card_is_inert(card)


# ---------------------------------------------------------------------------
# Dashboard presentation: display interpretations never change the backend verdict or score.
# ---------------------------------------------------------------------------

WEAK_LABEL = "Weak indicator detected — Review findings"
WEAK_FINDING = {
    "id": "attachment_html_extension",
    "severity": "low",
    "title": "Attachment is an HTML page",
    "observation": "One attachment name ends in .html.",
    "interpretation": "HTML attachments can imitate sign-in pages.",
    "contribution": 10,
}


@pytest.mark.parametrize(
    ("verdict", "score", "headline", "weak", "shown_score", "filled"),
    [
        ("NO_SIGNIFICANT_SIGNALS", 0, "No significant suspicious signals found", False, "0/100", 0),
        ("NO_SIGNIFICANT_SIGNALS", 5, "No significant suspicious signals found", True, "5/100", 1),
        ("NO_SIGNIFICANT_SIGNALS", 10, "No significant suspicious signals found", True, "10/100", 1),
        ("NO_SIGNIFICANT_SIGNALS", 19, "No significant suspicious signals found", True, "19/100", 2),
        ("SUSPICIOUS", 20, 'Suspicious</font></b><font color="#B06000"> — Verification recommended', False, "20/100", 2),
        ("HIGH_RISK", 60, 'High risk</font></b><font color="#B3261E"> — Treat with caution', False, "60/100", 6),
        ("INCOMPLETE", 0, 'Assessment incomplete</font></b><font color="#7A5C00"> — Not a low-risk result', False,
         None, None),
    ],
    ids=["nss-0", "nss-5", "nss-10", "nss-19", "suspicious-20", "high-60", "incomplete"],
)
def test_verdict_presentation_by_score(verdict, score, headline, weak, shown_score, filled) -> None:
    findings = [WEAK_FINDING] if score else []
    card = render(synthetic_result(verdict=verdict, risk_score=score, findings=findings))
    assessment = card.section("Assessment")
    widgets = card.widgets(assessment)
    text = card.all_text(assessment)

    assert headline in widgets[0]["setText"]
    assert widgets[0]["setTopLabel"] == "Verdict"
    assert (WEAK_LABEL in text) is weak
    if weak:
        note = widgets[1]
        assert note["setTopLabel"] == "Display interpretation"
        assert "backend verdict above is unchanged" in note["setBottomLabel"]
        assert "not confirmed malicious" in widgets[2]["setText"]
        assert "does not guarantee" in widgets[2]["setText"]
        assert "#1E6B3A" not in next(w["setText"] for w in widgets if "/100" in w.get("setText", ""))
    if shown_score is None:
        assert "/100" not in card.all_text()
        assert "■" not in card.all_text()
    else:
        score_widget = next(w for w in widgets if w.get("setTopLabel") == "Risk index")
        assert shown_score in score_widget["setText"]
        assert score_widget["setText"].count("■") == filled
        assert score_widget["setText"].count("■") + score_widget["setText"].count("□") == 10
    assert "safe" not in widgets[0]["setText"].lower()
    main = [w for w in widgets if w.get("setTopLabel") == "Main finding"]
    if findings and shown_score is not None:
        assert main and main[0]["setText"] == WEAK_FINDING["title"]
    else:
        assert not main


def analyze_attachment(monkeypatch, filename: str, content_type: str) -> dict:
    return analyze(
        monkeypatch,
        text_body="Lunch is at noon in the usual room.",
        attachment_metadata=[
            {"filename": filename, "content_type": content_type, "size_bytes": 10, "unavailable_fields": []}
        ],
        attachment_collection={"state": "COLLECTED", "regular_count": 1, "inline_count": 0, "omitted_count": 0,
                               "omitted_extensions": [], "omitted_name_flags": [], "reasons": []},
    )


def test_weak_indicator_from_the_real_backend_keeps_its_verdict(monkeypatch) -> None:
    result = analyze_attachment(monkeypatch, "ig-page.html", "text/html")
    assert result["verdict"] == "NO_SIGNIFICANT_SIGNALS" and 0 < result["risk_score"] < 20
    card = render(result)
    text = card.all_text(card.section("Assessment"))

    assert "No significant suspicious signals found" in text
    assert WEAK_LABEL in text
    assert f"{result['risk_score']}/100" in text


def test_finding_separates_observation_from_interpretation_and_drops_repeats() -> None:
    repeated = dict(WEAK_FINDING, id="repeat", interpretation=WEAK_FINDING["observation"])
    only_interpretation = dict(WEAK_FINDING, id="interp", observation="")
    card = render(synthetic_result(findings=[WEAK_FINDING, repeated, only_interpretation]))
    widgets = card.widgets(card.section("Key findings"))
    paragraphs = [widget["setText"] for widget in widgets if widget["type"] == "TextParagraph"]

    assert paragraphs[0] == (
        "One attachment name ends in .html.<br><i>Why it matters:</i> HTML attachments can imitate sign-in pages."
    )
    assert paragraphs[1] == "One attachment name ends in .html."
    assert paragraphs[2] == "<i>Why it matters:</i> HTML attachments can imitate sign-in pages."
    assert widgets[0]["setTopLabel"] == "+10 to risk index · Weak on its own · Low severity"


def test_long_finding_text_shares_one_bounded_budget() -> None:
    long_finding = dict(WEAK_FINDING, title="T" * 500, observation="o" * 600, interpretation="z" * 600)
    card = render(synthetic_result(findings=[long_finding]))
    widgets = card.widgets(card.section("Key findings"))

    assert widgets[0]["setText"] == "<b>" + "T" * 120 + "</b>"
    body = widgets[1]["setText"]
    assert body.count("o") == 600
    assert body.count("z") == 100


def test_hostile_interpretation_is_escaped_separately() -> None:
    finding = dict(WEAK_FINDING, observation="<b>x</b>", interpretation='<a href="https://evil.test/?t=1">go</a>')
    card = render(synthetic_result(findings=[finding]))
    body = card.widgets(card.section("Key findings"))[1]["setText"]

    assert "&lt;b&gt;x&lt;/b&gt;" in body
    assert "&lt;a href=" in body and "t=1" not in body
    assert_card_is_inert(card)


def test_reputation_follows_the_action_and_is_labelled_external() -> None:
    hostile_status = '<b onmouseover="x">CLEAN</b>'
    result = synthetic_result(
        reputation_context=[
            {"indicator_type": "domain", "indicator": "example.org", "status": "UNKNOWN",
             "summary": "No malicious detections; unknown, not clean.", "caveat": "Context only."},
            {"indicator_type": "ip_address", "indicator": "192.0.2.1", "status": hostile_status},
        ],
    )
    card = render(result)
    headers = card.headers()
    reputation = card.section("Reputation context")
    labels = [widget.get("setTopLabel", "") for widget in card.widgets(reputation)]
    text = card.all_text(reputation)

    assert headers.index("Recommended action") < headers.index("Reputation context")
    assert headers.index("Reputation context") < headers.index("Analysis coverage")
    assert "External enrichment · VirusTotal" in labels
    assert "Domain · VirusTotal · UNKNOWN" in labels
    assert "IP address · VirusTotal · UNKNOWN" in labels
    assert "CLEAN" not in text
    assert "Â" not in card.all_text()
    assert "zero detections do not mean an indicator is safe" in text
    assert "full URLs, paths, query strings and attachments were not sent" in text
    assert_card_is_inert(card)


def test_coverage_groups_attachment_status_and_never_implies_safety() -> None:
    limitations = [
        "Attachments: Gmail listed 30 and details for 25 were assessed; the rest were not assessed.",
        "Quoted reply lines in the plain-text body were not assessed for credential requests.",
        "Not checked: machine-learning (NLP) phishing classification.",
    ]
    card = render(synthetic_result(verdict="NO_SIGNIFICANT_SIGNALS", risk_score=0, limitations=limitations))
    coverage = card.section("Analysis coverage")
    widgets = card.widgets(coverage)
    attachment = next(widget for widget in widgets if widget.get("setTopLabel") == "Attachments")

    assert attachment["setText"].startswith("Gmail listed 30 and details for 25")
    assert any(widget.get("setTopLabel") == "Not checked" for widget in widgets)
    assert "Quoted reply lines" in card.all_text(coverage)
    assert "does not guarantee that a message is safe" in widgets[-1]["setText"]
    assert "Gmail listed 30" not in card.all_text(card.section("Additional details"))


OLD_BACKEND_NOT_CHECKED = (
    "Not checked: payment or financial-fraud requests and machine-learning (NLP) phishing classification. "
    "These planned checks are not implemented, so nothing was assessed for them."
)
NEW_BACKEND_NOT_CHECKED = (
    "Not checked: machine-learning (NLP) phishing classification. "
    "These planned checks are not implemented, so nothing was assessed for them."
)


def checked_labels(limitations: list[str]) -> tuple[str, str]:
    card = render(synthetic_result(verdict="NO_SIGNIFICANT_SIGNALS", risk_score=0, limitations=limitations))
    widgets = card.widgets(card.section("Analysis coverage"))
    checked = next((w["setText"] for w in widgets if w.get("setTopLabel") == "Checked"), "")
    not_checked = next((w["setText"] for w in widgets if w.get("setTopLabel") == "Not checked"), "")
    return checked, not_checked


def test_coverage_lists_only_checks_the_backend_did_not_exclude() -> None:
    checked, not_checked = checked_labels([OLD_BACKEND_NOT_CHECKED])

    assert "Financial fraud wording" not in checked
    assert "Sender identity" in checked and "Credential-request wording" in checked
    assert "payment or financial-fraud requests" in not_checked

    checked, _ = checked_labels([NEW_BACKEND_NOT_CHECKED])
    for label in ("Sender identity", "Link (URL) deception", "Credential-request wording",
                  "Financial fraud wording", "Attachment metadata assessed"):
        assert label in checked


def test_legacy_attachment_line_removes_attachments_from_checked() -> None:
    checked, not_checked = checked_labels(
        ["Not checked: attachments. This request included no attachment information, so they were not assessed."]
    )

    assert "Attachment metadata" not in checked
    assert "Financial fraud wording" in checked
    assert "attachments" in not_checked


def test_strong_finding_is_not_marked_weak() -> None:
    strong = dict(WEAK_FINDING, id="strong", contribution=30, severity="high")
    card = render(synthetic_result(findings=[strong, WEAK_FINDING]))
    labels = [w["setTopLabel"] for w in card.widgets(card.section("Key findings")) if w["type"] == "DecoratedText"]

    assert labels == [
        "+30 to risk index · High severity",
        "+10 to risk index · Weak on its own · Low severity",
    ]
    main = next(w for w in card.widgets(card.section("Assessment")) if w.get("setTopLabel") == "Main finding")
    assert main["setBottomLabel"] == "+30 to risk index · High severity"


def test_main_finding_title_is_escaped_and_bounded() -> None:
    hostile = dict(WEAK_FINDING, title="<script>x</script>" + "T" * 300, contribution=30)
    card = render(synthetic_result(findings=[hostile]))
    main = next(w for w in card.widgets(card.section("Assessment")) if w.get("setTopLabel") == "Main finding")

    assert main["setText"].startswith("&lt;script&gt;")
    assert len(main["setText"]) <= 140
    assert_card_is_inert(card)
