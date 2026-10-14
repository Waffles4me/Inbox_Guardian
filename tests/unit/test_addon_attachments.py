"""Attachment metadata collection in the Gmail add-on (WBS 2.5 Stage 1).

``addon/Code.js`` runs in Node against fake GmailApp, CardService and network objects. Every scenario runs in a
single Node process because starting Node is slow on some machines. Nothing here reads real mail.
"""

import json
import subprocess

import pytest

from backend.app.models import AnalyzeRequest
from backend.app.parsing import NAME_FLAG_RANGES, AttachmentCollectionState, EvidenceSource, parse_email_payload


HARNESS = r"""
const fs = require('fs');
const vm = require('vm');

const ALLOWED = new Set(['getName', 'getContentType', 'getSize']);
const touched = new Set();

function fakeAttachment(spec) {
  const methods = {
    getName: () => { if (spec.nameThrows) throw new Error('name failure'); return spec.name; },
    getContentType: () => { if (spec.typeThrows) throw new Error('type failure'); return spec.type; },
    getSize: () => { if (spec.sizeThrows) throw new Error('size failure'); return spec.size; },
  };
  return new Proxy({}, {
    get(_, prop) {
      if (typeof prop !== 'string') return undefined;
      touched.add(prop);
      if (!ALLOWED.has(prop)) throw new Error('non-approved attachment member: ' + prop);
      return methods[prop];
    },
  });
}

function fakeGmail(scenario, calls) {
  const message = {
    getSubject: () => 'Synthetic subject',
    getFrom: () => 'Example <notice@example.test>',
    getReplyTo: () => '',
    getPlainBody: () => 'Synthetic body',
    getBody: () => '<p>Synthetic body</p>',
    getAttachments: (options) => {
      calls.push(JSON.stringify(options));
      const inlineOnly = options.includeInlineImages === true && options.includeAttachments === false;
      if (inlineOnly) {
        if (scenario.inlineThrows) throw new Error('inline failure');
        return (scenario.inline || []).map(fakeAttachment);
      }
      if (scenario.attachThrows) throw new Error('Required permissions: https://mail.google.com/');
      if (scenario.listBreaks) {
        // A list that fails only when used, outside the guarded Gmail calls inside the collector.
        return { get length() { throw new Error(scenario.listBreaks); }, forEach() { throw new Error(scenario.listBreaks); } };
      }
      return (scenario.regular || []).map(fakeAttachment);
    },
  };
  return {
    setCurrentMessageAccessToken: () => {},
    getMessageById: () => {
      if (scenario.messageThrows) throw new Error('message failure');
      return message;
    },
  };
}

function recorder() {
  const proxy = new Proxy({}, { get: (_, prop) => (typeof prop === 'string' && prop !== 'then') ? () => proxy : undefined });
  return proxy;
}
const CardService = new Proxy({}, { get: () => () => recorder() });

function load(scenario, calls, extra) {
  let clock = 0;
  const context = Object.assign({
    CardService: CardService,
    GmailApp: fakeGmail(scenario, calls),
    console: { error() {} },
    Date: { now: () => { clock += scenario.msPerCall || 0; return clock; } },
  }, extra || {});
  vm.createContext(context);
  vm.runInContext(fs.readFileSync('addon/Code.js', 'utf8'), context);
  return context;
}

const EVENT = { gmail: { messageId: 'synthetic-id', accessToken: 'synthetic-token' } };
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const output = { scenarios: {}, ranges: null };

for (const [name, scenario] of Object.entries(input.scenarios)) {
  const calls = [];
  const context = load(scenario, calls);
  output.scenarios[name] = { result: context.collectAttachmentMetadata_(EVENT), calls: calls };
}

// Message open must not read attachments; Analyze Email must send what was collected.
const openCalls = [];
load({ regular: [{ name: 'ig-a.pdf', type: 'application/pdf', size: 1 }] }, openCalls).onGmailMessageOpen(EVENT);
output.openCalls = openCalls;

const analyzeCalls = [];
let sentPayload = null;
const network = {
  PropertiesService: { getScriptProperties: () => ({ getProperty: () => 'https://backend.example.test' }) },
  UrlFetchApp: {
    fetch: (url, options) => {
      sentPayload = JSON.parse(options.payload);
      return { getResponseCode: () => 503, getContentText: () => '' };
    },
  },
};
load({ regular: [{ name: 'ig-a.pdf', type: 'application/pdf', size: 1 }] }, analyzeCalls, network).analyzeEmail(EVENT);
output.analyzeCalls = analyzeCalls;
output.sentPayload = sentPayload;

// An unexpected failure inside collection must not stop the analysis, and its message must not reach the
// logs or the request. Run once with a successful backend and once with a failing one.
output.failure = {};
for (const statusCode of [200, 503]) {
  const logged = [];
  let payload = null;
  const failingNetwork = {
    PropertiesService: network.PropertiesService,
    UrlFetchApp: {
      fetch: (url, options) => {
        payload = JSON.parse(options.payload);
        return { getResponseCode: () => statusCode, getContentText: () => JSON.stringify(input.backendResult) };
      },
    },
    console: { error: (...args) => logged.push(args.map(String).join(' ')) },
  };
  const context = load({ listBreaks: input.sentinel }, [], failingNetwork);
  let card = null;
  let thrown = null;
  try {
    card = context.analyzeEmail(EVENT);
  } catch (error) {
    thrown = String(error);
  }
  output.failure[statusCode] = { payload: payload, logged: logged, rendered: Boolean(card), thrown: thrown };
}

output.ranges = load({}, []).NAME_FLAG_RANGES;
output.touched = Array.from(touched).sort();
process.stdout.write(JSON.stringify(output));
"""


def named(prefix: str, count: int, extension: str = "txt") -> list[dict]:
    return [{"name": f"{prefix}-{index:02d}.{extension}", "type": "text/plain", "size": 10} for index in range(count)]


BIDI = chr(0x202E)
EMOJI = chr(0x1F600)
HEBREW = "".join(chr(code) for code in (0x05D3, 0x05D5, 0x05D7))
FAILURE_SENTINEL = "IG-SENTINEL-unexpected-collection-failure"
BACKEND_RESULT = {
    "schema_version": "1.0",
    "risk_score": 0,
    "score_type": "heuristic_risk_index_not_probability",
    "verdict": "NO_SIGNIFICANT_SIGNALS",
    "findings": [],
    "limitations": ["Attachments: attachment information could not be collected from Gmail, so attachments were not assessed."],
    "recommended_action": "Continue using normal caution.",
    "detector_version": "engine-0.2.0+scoring-0.2.0",
}

SCENARIOS = {
    "none": {"regular": []},
    "three": {
        "regular": [
            {"name": "ig-agenda.pdf", "type": "application/pdf", "size": 2048},
            {"name": f"ig-{HEBREW}.txt", "type": "text/plain", "size": 10},
            {"name": f"ig-report{BIDI}txt.pdf", "type": "application/pdf", "size": 10},
        ],
        "inline": [{"name": "ig-pixel.png", "type": "image/png", "size": 70}],
    },
    "thirty": {
        "regular": named("ig-many", 25)
        + [
            {"name": "ig-page.html", "type": "text/html", "size": 1},
            {"name": "ig-logo.SVG", "type": "image/svg+xml", "size": 1},
            {"name": "ig-invoice.pdf.html", "type": "text/html", "size": 1},
            {"name": f"ig{BIDI}x.txt", "type": "text/plain", "size": 1},
            {"name": "ig-noextension", "type": "text/plain", "size": 1},
        ]
    },
    "over-read-limit": {"regular": named("ig-bulk", 120)},
    "time-limit": {"regular": named("ig-slow", 10), "msPerCall": 1000},
    "attach-throws": {"attachThrows": True},
    "message-throws": {"messageThrows": True},
    "inline-throws": {"regular": named("ig-one", 1), "inlineThrows": True},
    "field-failures": {
        "regular": [
            {"nameThrows": True, "type": "text/plain", "size": 1},
            {"name": "ig-type.txt", "typeThrows": True, "size": 1},
            {"name": "ig-size.txt", "type": "text/plain", "sizeThrows": True},
            {"name": "ig-badsize.txt", "type": "text/plain", "size": -5},
            {"name": "ig-fraction.txt", "type": "text/plain", "size": 1.5},
        ]
    },
    "long-names": {
        "regular": [
            # 64-code-point head, then a middle with a bidi override and dots, then the kept tail.
            {"name": "h" * 63 + EMOJI + "m." + BIDI + "m" * 300 + "." + "t" * 186 + ".exe", "type": "x", "size": 1},
            {"name": "ig-pad.pdf" + " " * 400 + ".exe", "type": "x", "size": 1},
            {"name": "ig-ok-" + "a" * 245 + ".txt", "type": "x", "size": 1},
        ]
    },
    "long-type": {"regular": [{"name": "ig-type.bin", "type": "application/" + "x" * 300, "size": 1}]},
    "worst-case": {
        "regular": [
            {"name": (EMOJI + "." + BIDI) * 400 + ".html", "type": EMOJI * 400, "size": 99_999_999}
            for _ in range(200)
        ]
    },
}


@pytest.fixture(scope="module")
def harness() -> dict:
    completed = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"scenarios": SCENARIOS, "sentinel": FAILURE_SENTINEL, "backendResult": BACKEND_RESULT}),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def collected(harness: dict, name: str) -> tuple[dict, list[dict]]:
    result = harness["scenarios"][name]["result"]
    return result["collection"], result["items"]


def validate(collection: dict, items: list[dict]):
    request = AnalyzeRequest.model_validate(
        {
            "schema_version": "1.0",
            "email": {
                "from": "Example <notice@example.test>",
                "text_body": "Synthetic body",
                "attachment_metadata": items,
                "attachment_collection": collection,
            },
        }
    )
    return parse_email_payload(request.email)


def test_only_name_type_and_size_are_ever_read(harness) -> None:
    assert harness["touched"] == ["getContentType", "getName", "getSize"]


def test_message_open_reads_no_attachments(harness) -> None:
    assert harness["openCalls"] == []


def test_analyze_email_sends_the_collected_metadata(harness) -> None:
    email = harness["sentPayload"]["email"]

    assert harness["sentPayload"]["schema_version"] == "1.0"
    assert email["attachment_collection"]["state"] == "COLLECTED"
    assert email["attachment_metadata"] == [
        {"filename": "ig-a.pdf", "content_type": "application/pdf", "size_bytes": 1, "unavailable_fields": []}
    ]
    assert harness["analyzeCalls"][0] == json.dumps({"includeInlineImages": False, "includeAttachments": True},
                                                    separators=(",", ":"))


def test_no_attachments_is_none_with_zero_counts(harness) -> None:
    collection, items = collected(harness, "none")

    assert (collection["state"], collection["regular_count"], collection["inline_count"]) == ("NONE", 0, 0)
    assert items == []


def test_regular_attachments_are_collected_and_inline_images_only_counted(harness) -> None:
    collection, items = collected(harness, "three")

    assert collection["state"] == "COLLECTED"
    assert (collection["regular_count"], collection["inline_count"]) == (3, 1)
    assert [item["filename"] for item in items] == ["ig-agenda.pdf", f"ig-{HEBREW}.txt", f"ig-report{BIDI}txt.pdf"]
    assert items[0]["content_type"] == "application/pdf" and items[0]["size_bytes"] == 2048
    assert "ig-pixel.png" not in json.dumps(harness["scenarios"]["three"])


def test_more_than_25_attachments_are_truncated_with_omitted_names_summarised(harness) -> None:
    collection, items = collected(harness, "thirty")

    assert collection["state"] == "TRUNCATED"
    assert collection["reasons"] == ["count_limit"]
    assert (len(items), collection["regular_count"], collection["omitted_count"]) == (25, 30, 5)
    assert collection["omitted_extensions"] == ["html", "svg", "txt"]
    assert sorted(collection["omitted_name_flags"]) == ["BIDI_CONTROL", "MULTIPLE_DOTS"]


def test_names_past_the_read_limit_are_reported_as_not_read(harness) -> None:
    collection, items = collected(harness, "over-read-limit")

    assert len(items) == 25
    assert collection["omitted_count"] == 95
    assert collection["reasons"] == ["count_limit", "names_not_read"]


def test_time_budget_stops_reading_and_says_so(harness) -> None:
    collection, items = collected(harness, "time-limit")

    assert collection["state"] == "TRUNCATED"
    assert "time_limit" in collection["reasons"] and "names_not_read" in collection["reasons"]
    assert len(items) + collection["omitted_count"] == collection["regular_count"] == 10
    assert len(items) < 10


@pytest.mark.parametrize("name", ["attach-throws", "message-throws"])
def test_collection_failure_is_unavailable_not_none(harness, name: str) -> None:
    collection, items = collected(harness, name)

    assert collection["state"] == "UNAVAILABLE"
    assert collection["reasons"] == ["collection_error"]
    assert collection["regular_count"] is None
    assert items == []
    assert "mail.google.com" not in json.dumps(harness["scenarios"][name])


def test_inline_count_failure_does_not_fail_collection(harness) -> None:
    collection, items = collected(harness, "inline-throws")

    assert collection["state"] == "COLLECTED"
    assert collection["inline_count"] is None
    assert len(items) == 1


def test_field_failures_are_marked_unavailable_not_empty(harness) -> None:
    collection, items = collected(harness, "field-failures")

    assert collection["state"] == "TRUNCATED"
    assert collection["reasons"] == ["field_unavailable"]
    assert [item["unavailable_fields"] for item in items] == [
        ["filename"], ["content_type"], ["size_bytes"], ["size_bytes"], ["size_bytes"]
    ]
    assert all(item["size_bytes"] is None for item in items[2:])


def test_long_names_keep_head_and_tail_and_describe_the_removed_middle(harness) -> None:
    collection, items = collected(harness, "long-names")
    first, padded, intact = items

    assert collection["reasons"] == ["field_limit"]
    assert first["name_clip"]["at"] == 64
    assert first["filename"][:64].startswith("h" * 63) and first["filename"].endswith(".exe")
    assert len(first["filename"]) == 255
    assert first["filename"][63] == EMOJI  # an astral character at the cut is kept whole
    assert first["name_clip"]["removed_flags"] == ["BIDI_CONTROL"]
    assert first["name_clip"]["removed_dot_count"] == 1  # the dot before the kept tail stays in the tail
    assert first["name_clip"]["removed_whitespace_only"] is False
    assert padded["name_clip"]["removed_whitespace_only"] is True
    assert "name_clip" not in intact and len(intact["filename"]) == 255


def test_long_content_type_is_clipped_and_marked(harness) -> None:
    collection, items = collected(harness, "long-type")

    assert items[0]["content_type_clipped"] is True
    assert len(items[0]["content_type"]) == 255
    assert collection["reasons"] == ["field_limit"]


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_collector_output_validates_and_parses_consistently(harness, name: str) -> None:
    collection, items = collected(harness, name)
    parsed = validate(collection, items)

    assert parsed.attachment_coverage.state == AttachmentCollectionState(collection["state"])
    assert not [issue for issue in parsed.issues if issue.source == EvidenceSource.ATTACHMENTS]


def test_clipped_names_parse_into_separate_segments(harness) -> None:
    parsed = validate(*collected(harness, "long-names"))
    first = parsed.attachments[0]

    assert len(first.name_segments) == 2
    assert first.name_segments[0].startswith("h" * 63)
    assert first.name_segments[1].endswith(".exe")
    assert "BIDI_CONTROL" in first.name_flags


@pytest.mark.parametrize("status_code", ["200", "503"])
def test_unexpected_collection_failure_is_unavailable_and_analysis_continues(harness, status_code: str) -> None:
    run = harness["failure"][status_code]
    email = run["payload"]["email"]

    assert run["thrown"] is None
    assert run["rendered"] is True
    assert email["attachment_collection"]["state"] == "UNAVAILABLE"
    assert email["attachment_collection"]["reasons"] == ["unexpected_error"]
    assert email["attachment_metadata"] == []
    assert FAILURE_SENTINEL not in json.dumps(run)
    parsed = validate(email["attachment_collection"], email["attachment_metadata"])
    assert parsed.attachment_coverage.state == AttachmentCollectionState.UNAVAILABLE


def test_unexpected_collection_failure_logs_nothing_with_a_working_backend(harness) -> None:
    assert harness["failure"]["200"]["logged"] == []


def test_name_flag_ranges_match_the_backend(harness) -> None:
    backend = {flag: [list(pair) for pair in ranges] for flag, ranges in NAME_FLAG_RANGES.items()}

    assert harness["ranges"] == backend


RENDER_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');

function recorder(type) {
  const node = { type: type, calls: [] };
  const proxy = new Proxy(node, {
    get(target, prop) {
      if (prop === '__node') return target;
      if (typeof prop !== 'string' || prop === 'then' || prop === 'toJSON') return undefined;
      return (...args) => { target.calls.push([prop, args]); return proxy; };
    },
  });
  return proxy;
}
const CardService = new Proxy({}, {
  get(_, prop) {
    if (typeof prop !== 'string') return undefined;
    return prop.startsWith('new') ? () => recorder(prop.slice(3)) : new Proxy({}, { get: (__, key) => String(key) });
  },
});

// Returns, for each card section, its header and every text the section's widgets carry.
function sections(card) {
  const builder = card.__node;
  return builder.calls.filter((call) => call[0] === 'addSection').map((call) => {
    const section = call[1][0].__node;
    const header = (section.calls.find((c) => c[0] === 'setHeader') || [null, [null]])[1][0];
    const texts = section.calls.filter((c) => c[0] === 'addWidget').map((c) => c[1][0].__node.calls
      .filter((w) => ['setText', 'setTopLabel', 'setBottomLabel'].includes(w[0]))
      .map((w) => String(w[1][0])).join('\n'));
    return { header: header, text: texts.join('\n') };
  });
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = { CardService: CardService, console: { error() {} } };
vm.createContext(context);
vm.runInContext(fs.readFileSync('addon/Code.js', 'utf8'), context);
const email = { subject: 'Synthetic subject', from: 'Example <notice@example.test>' };
const output = {};
for (const [name, result] of Object.entries(input)) {
  output[name] = sections(context.buildMessageCard_(email, result));
}
process.stdout.write(JSON.stringify(output));
"""


def analyze_for_render(monkeypatch, **extra) -> dict:
    from fastapi.testclient import TestClient

    from backend.app.main import API_TOKEN_ENV, app

    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    email = {"subject": "Synthetic subject", "from": "Example <notice@example.test>",
             "text_body": "Lunch is at noon in the usual room.", **extra}
    response = TestClient(app).post(
        "/analyze", json={"schema_version": "1.0", "email": email}, headers={"X-InboxGuardian-Token": "test-token"}
    )
    assert response.status_code == 200
    return response.json()


def test_attachment_status_is_shown_under_analysis_coverage(monkeypatch) -> None:
    results = {
        "collected": analyze_for_render(
            monkeypatch,
            attachment_metadata=[{"filename": "ig-private-agenda.pdf", "content_type": "application/pdf",
                                  "size_bytes": 10, "unavailable_fields": []}],
            attachment_collection={"state": "COLLECTED", "regular_count": 1, "inline_count": 0, "omitted_count": 0,
                                   "omitted_extensions": [], "omitted_name_flags": [], "reasons": []},
        ),
        "legacy": analyze_for_render(monkeypatch),
    }
    completed = subprocess.run(
        ["node", "-e", RENDER_HARNESS], input=json.dumps(results), check=True, capture_output=True, text=True,
        encoding="utf-8",
    )
    rendered = json.loads(completed.stdout)
    coverage = {name: next(s["text"] for s in sections if s["header"] == "Analysis coverage")
                for name, sections in rendered.items()}
    collected_text = "\n".join(section["text"] for section in rendered["collected"])

    assert (
        "Attachments: Gmail listed 1. Only attachment names were checked; attachment content was not inspected."
        in coverage["collected"]
    )
    assert "Coverage limits for this message" in coverage["collected"]
    checks_and_not_checked = coverage["collected"].split("Coverage limits")[0]
    assert "Attachment metadata assessed (names only; attachment content not inspected)" in checks_and_not_checked
    assert "attachments, payment" not in checks_and_not_checked
    assert "ig-private-agenda" not in collected_text
    legacy_text = "\n".join(section["text"] for section in rendered["legacy"])
    assert "Attachments:" not in legacy_text
    assert "attachments, payment or financial-fraud requests" in legacy_text
    # Collection changes only the limitations: the verdict and score are those of the legacy request.
    assert (results["collected"]["verdict"], results["collected"]["risk_score"]) == (
        results["legacy"]["verdict"], results["legacy"]["risk_score"])
