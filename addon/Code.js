var BACKEND_URL_PROPERTY = 'INBOXGUARDIAN_BACKEND_URL';
var API_TOKEN_PROPERTY = 'INBOXGUARDIAN_API_TOKEN';
var MAX_BODY_CHARS = 50000;

// Attachment metadata bounds. The backend rejects a request over its limits, so clipping happens here,
// and every clip or omission is reported in attachment_collection rather than dropped silently.
var MAX_ATTACHMENTS_SENT = 25;
var MAX_ATTACHMENTS_READ = 100;
var MAX_ATTACHMENT_COLLECTION_MS = 5000;
var MAX_ATTACHMENT_NAME_CODE_POINTS = 255;
var ATTACHMENT_NAME_HEAD_CODE_POINTS = 64;
var MAX_ATTACHMENT_TYPE_CODE_POINTS = 255;
var MAX_EXTENSION_CODE_POINTS = 16;
var MAX_OMITTED_EXTENSIONS = 50;
var MAX_ATTACHMENT_COUNT_VALUE = 1000000;
// Filename character classes as code point ranges, so this file contains no invisible characters itself.
// They must match NAME_FLAG_RANGES in backend/app/parsing.py; a test compares the two.
var NAME_FLAG_RANGES = {
  BIDI_CONTROL: [[0x202A, 0x202E], [0x2066, 0x2069]],
  ZERO_WIDTH: [[0x200B, 0x200D], [0x2060, 0x2060], [0xFEFF, 0xFEFF]],
  CONTROL_CHAR: [[0x0000, 0x001F], [0x007F, 0x009F]]
};
var NAME_FLAG_PATTERNS = buildNameFlagPatterns_(NAME_FLAG_RANGES);

// Rendering bounds. Backend text is untrusted, so every list and string shown on the card is capped.
var MAX_PRIMARY_FINDINGS = 3;
var MAX_RENDERED_FINDINGS = 12;
var MAX_FINDING_TITLE_CHARS = 120;
var MAX_FINDING_SUMMARY_CHARS = 700;
var MAX_COVERAGE_NOTES = 5;
var MAX_DETAIL_LIMITATIONS = 40;
var MAX_LIMITATION_CHARS = 300;
var MAX_ACTION_CHARS = 600;
var MAX_VERSION_CHARS = 80;
var RISK_BAR_SEGMENTS = 10;

// Presentation only: labels, colours and icons per backend verdict. Verdicts are never reclassified here.
var VERDICT_STYLES = {
  HIGH_RISK: {
    label: 'High risk',
    color: '#B3261E',
    icon: 'gpp_bad',
    showScore: true,
    summary: 'Strong suspicious evidence was found. This is not proof of phishing or malware.'
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    color: '#B06000',
    icon: 'warning',
    showScore: true,
    summary: 'Suspicious evidence was found. Verify this message before acting on it.'
  },
  NO_SIGNIFICANT_SIGNALS: {
    label: 'No significant suspicious signals found',
    color: '#1E6B3A',
    icon: 'info',
    showScore: true,
    summary: 'The checks that ran found no significant suspicious evidence. This does not guarantee the message is legitimate.'
  },
  INCOMPLETE: {
    label: 'Assessment incomplete',
    color: '#7A5C00',
    icon: 'help',
    showScore: false,
    summary: 'There was not enough assessed content to reach a verdict. This is not a low-risk result.'
  }
};
var UNKNOWN_VERDICT_STYLE = {
  label: 'Assessment result unavailable',
  color: '#5F6368',
  icon: 'help',
  showScore: false,
  summary: 'The backend returned a verdict this add-on does not recognise, so no score is shown.'
};
var SEVERITY_LABELS = {
  info: 'Informational',
  low: 'Low severity',
  medium: 'Medium severity',
  high: 'High severity'
};
var RESULT_DISPLAY_ERROR = 'The analysis finished but its result could not be displayed. No verdict is shown.';
var IMPLEMENTED_CHECKS =['Sender identity', 'Link (URL) deception', 'Credential-request wording'];

// How backend limitation lines are grouped for display. Grouping never removes a line.
var NOT_CHECKED_RE = /^\s*not checked:\s*/i;
var SCORE_PLACEHOLDER_RE = /required-schema placeholder/i;
var COVERAGE_NOTE_RE = /not assessed|not analy[sz]ed|could not (?:be |fully )?(?:evaluat|assess)|did not run|must not be treated as clean/i;
var SPECIFIC_LIMITATION_RE = /malformed|unsupported|truncated|was capped|parser recorded|lacked enough|no supported url evidence|inconsistent/i;

function buildHomepage() {
  return buildCard_(
    'InboxGuardian',
    [
      textParagraph_(
        'Open a Gmail message to analyze it. InboxGuardian only runs when you choose Analyze Email.'
      )
    ]
  );
}

function onGmailMessageOpen(e) {
  var email = getCurrentEmail_(e);
  return buildMessageCard_(email, null);
}

function analyzeEmail(e) {
  var email = getCurrentEmail_(e);
  // Attachments are read only when the user asks for an analysis, never on message open.
  var attachments = collectAttachmentsSafely_(e);
  email.attachmentCollection = attachments.collection;
  email.attachments = attachments.items;
  var result;
  try {
    result = callBackend_(email);
  } catch (error) {
    console.error('InboxGuardian backend call failed: ' + error);
    return buildMessageCard_(email, null, userSafeError_(error));
  }
  // A failure while building the result card is not a backend failure and must not show a partial verdict.
  try {
    return buildMessageCard_(email, result);
  } catch (renderError) {
    console.error('InboxGuardian result rendering failed: ' + renderError);
    return buildMessageCard_(email, null, RESULT_DISPLAY_ERROR);
  }
}

function getCurrentEmail_(e) {
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    throw new Error('No opened Gmail message is available.');
  }

  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);
  return {
    subject: safeString_(message.getSubject()),
    from: safeString_(message.getFrom()),
    replyTo: safeString_(message.getReplyTo()),
    textBody: truncate_(safeString_(message.getPlainBody()), MAX_BODY_CHARS),
    htmlBody: truncate_(safeString_(message.getBody()), MAX_BODY_CHARS)
  };
}

function callBackend_(email) {
  var scriptProperties = PropertiesService.getScriptProperties();
  var backendUrl = scriptProperties.getProperty(BACKEND_URL_PROPERTY);
  var apiToken = scriptProperties.getProperty(API_TOKEN_PROPERTY);

  if (!backendUrl || !apiToken) {
    throw new Error('InboxGuardian backend is not configured.');
  }

  var response = UrlFetchApp.fetch(backendUrl.replace(/\/$/, '') + '/analyze', {
    method: 'post',
    contentType: 'application/json',
    muteHttpExceptions: true,
    headers: {
      'X-InboxGuardian-Token': apiToken
    },
    payload: JSON.stringify({
      schema_version: '1.0',
      email: {
        subject: email.subject,
        from: email.from,
        reply_to: email.replyTo,
        text_body: email.textBody,
        html_body: email.htmlBody,
        headers: {},
        attachment_metadata: email.attachments || [],
        attachment_collection: email.attachmentCollection
      }
    })
  });

  var statusCode = response.getResponseCode();
  if (statusCode === 401 || statusCode === 403) {
    throw new Error('Backend authentication failed.');
  }
  if (statusCode < 200 || statusCode >= 300) {
    throw new Error('Backend unavailable. Status: ' + statusCode);
  }

  var parsed;
  try {
    parsed = JSON.parse(response.getContentText());
  } catch (parseError) {
    throw new Error('Unexpected backend response.');
  }

  validateBackendResult_(parsed);
  return parsed;
}

function validateBackendResult_(result) {
  if (!result || result.schema_version !== '1.0' || typeof result.verdict !== 'string') {
    throw new Error('Unexpected backend response.');
  }
  if (!Array.isArray(result.findings) || !Array.isArray(result.limitations)) {
    throw new Error('Unexpected backend response.');
  }
  if (typeof result.risk_score !== 'number' || typeof result.score_type !== 'string') {
    throw new Error('Unexpected backend response.');
  }
  if (typeof result.recommended_action !== 'string' || typeof result.detector_version !== 'string') {
    throw new Error('Unexpected backend response.');
  }
}

// ---------------------------------------------------------------------------
// Attachment metadata collection
// ---------------------------------------------------------------------------

// Attachment metadata is optional evidence: an unexpected failure while collecting it must not stop the
// analysis. It is reported as UNAVAILABLE, never as NONE, and the error is neither logged nor shown.
function collectAttachmentsSafely_(e) {
  try {
    return collectAttachmentMetadata_(e);
  } catch (error) {
    return unavailableAttachments_('unexpected_error');
  }
}

function unavailableAttachments_(reason) {
  return {
    collection: {
      state: 'UNAVAILABLE',
      regular_count: null,
      inline_count: null,
      omitted_count: 0,
      omitted_extensions: [],
      omitted_name_flags: [],
      reasons: [reason]
    },
    items: []
  };
}

// Reads only each attachment's name, declared type and size. Content methods (getBytes, copyBlob,
// getDataAsString, getAs, getHash) are never called, and nothing collected here is logged.
// Relies on getCurrentEmail_ having set the current-message access token in this execution.
function collectAttachmentMetadata_(e) {
  var started = Date.now();
  var message;
  var attachments;
  try {
    message = GmailApp.getMessageById(e.gmail.messageId);
    attachments = message.getAttachments({includeInlineImages: false, includeAttachments: true});
  } catch (error) {
    return unavailableAttachments_('collection_error');
  }
  var collection = {
    state: 'COLLECTED',
    regular_count: Math.min(attachments.length, MAX_ATTACHMENT_COUNT_VALUE),
    inline_count: countInlineImages_(message),
    omitted_count: 0,
    omitted_extensions: [],
    omitted_name_flags: [],
    reasons: []
  };

  var items = [];
  var omittedExtensions = {};
  var omittedFlags = {};
  attachments.forEach(function(attachment, index) {
    var inBudget = index < MAX_ATTACHMENTS_READ && Date.now() - started < MAX_ATTACHMENT_COLLECTION_MS;
    if (inBudget && items.length < MAX_ATTACHMENTS_SENT) {
      items.push(describeAttachment_(attachment));
      return;
    }
    collection.omitted_count += 1;
    addAttachmentReason_(collection.reasons, items.length < MAX_ATTACHMENTS_SENT ? 'time_limit' : 'count_limit');
    var name = inBudget ? readAttachmentField_(function() { return attachment.getName(); }) : null;
    if (name === null) {
      addAttachmentReason_(collection.reasons, 'names_not_read');
      return;
    }
    name = String(name);
    var extension = finalExtension_(name);
    if (extension && !omittedExtensions[extension]) {
      if (Object.keys(omittedExtensions).length < MAX_OMITTED_EXTENSIONS) {
        omittedExtensions[extension] = true;
      } else {
        addAttachmentReason_(collection.reasons, 'extensions_limit');
      }
    }
    nameFlags_(name).forEach(function(flag) {
      omittedFlags[flag] = true;
    });
    if ((name.replace(/[.\s]+$/, '').match(/\./g) || []).length >= 2) {
      omittedFlags.MULTIPLE_DOTS = true;
    }
  });
  items.forEach(function(item) {
    if (item.name_clip || item.content_type_clipped) {
      addAttachmentReason_(collection.reasons, 'field_limit');
    }
    if (item.unavailable_fields.length) {
      addAttachmentReason_(collection.reasons, 'field_unavailable');
    }
  });
  collection.omitted_extensions = Object.keys(omittedExtensions);
  collection.omitted_name_flags = Object.keys(omittedFlags);
  if (!attachments.length) {
    collection.state = 'NONE';
  } else {
    collection.state = collection.reasons.length ? 'TRUNCATED' : 'COLLECTED';
  }
  return {collection: collection, items: items};
}

function countInlineImages_(message) {
  try {
    return Math.min(
      message.getAttachments({includeInlineImages: true, includeAttachments: false}).length,
      MAX_ATTACHMENT_COUNT_VALUE
    );
  } catch (error) {
    return null;
  }
}

function describeAttachment_(attachment) {
  var item = {filename: '', content_type: '', size_bytes: null, unavailable_fields: []};
  var name = readAttachmentField_(function() { return attachment.getName(); });
  var type = readAttachmentField_(function() { return attachment.getContentType(); });
  var size = readAttachmentField_(function() { return attachment.getSize(); });
  if (name === null) {
    item.unavailable_fields.push('filename');
  } else {
    var clipped = clipAttachmentName_(String(name));
    item.filename = clipped.filename;
    if (clipped.nameClip) {
      item.name_clip = clipped.nameClip;
    }
  }
  if (type === null) {
    item.unavailable_fields.push('content_type');
  } else {
    var typePoints = Array.from(String(type));
    item.content_type = typePoints.slice(0, MAX_ATTACHMENT_TYPE_CODE_POINTS).join('');
    if (typePoints.length > MAX_ATTACHMENT_TYPE_CODE_POINTS) {
      item.content_type_clipped = true;
    }
  }
  if (typeof size === 'number' && isFinite(size) && size >= 0 && Math.floor(size) === size) {
    item.size_bytes = size;
  } else {
    item.unavailable_fields.push('size_bytes');
  }
  return item;
}

function readAttachmentField_(read) {
  try {
    var value = read();
    return value === null || value === undefined ? null : value;
  } catch (error) {
    return null;
  }
}

// Long names keep their start and end, where decoy and real extensions sit. The removed middle is
// summarised so dots, padding and hidden characters in it still reach the backend; name_clip.at marks
// where the two kept parts meet, and they must not be read as adjacent in the original name.
function clipAttachmentName_(name) {
  var points = Array.from(name);
  if (points.length <= MAX_ATTACHMENT_NAME_CODE_POINTS) {
    return {filename: name, nameClip: null};
  }
  var tail = MAX_ATTACHMENT_NAME_CODE_POINTS - ATTACHMENT_NAME_HEAD_CODE_POINTS;
  var removed = points.slice(ATTACHMENT_NAME_HEAD_CODE_POINTS, points.length - tail).join('');
  return {
    filename: points.slice(0, ATTACHMENT_NAME_HEAD_CODE_POINTS).concat(points.slice(points.length - tail)).join(''),
    nameClip: {
      at: ATTACHMENT_NAME_HEAD_CODE_POINTS,
      original_length: Math.min(points.length, MAX_ATTACHMENT_COUNT_VALUE),
      removed_dot_count: Math.min((removed.match(/\./g) || []).length, MAX_ATTACHMENT_COUNT_VALUE),
      removed_whitespace_only: /^\s+$/.test(removed),
      removed_flags: nameFlags_(removed)
    }
  };
}

function buildNameFlagPatterns_(rangesByFlag) {
  var escape = function(codePoint) {
    return String.fromCharCode(92) + 'u{' + codePoint.toString(16) + '}';
  };
  var patterns = {};
  Object.keys(rangesByFlag).forEach(function(flag) {
    var body = rangesByFlag[flag].map(function(range) {
      return escape(range[0]) + '-' + escape(range[1]);
    }).join('');
    patterns[flag] = new RegExp('[' + body + ']', 'u');
  });
  return patterns;
}

function nameFlags_(value) {
  return Object.keys(NAME_FLAG_PATTERNS).filter(function(flag) {
    return NAME_FLAG_PATTERNS[flag].test(value);
  });
}

function finalExtension_(name) {
  var trimmed = name.replace(/[.\s]+$/, '');
  var dot = trimmed.lastIndexOf('.');
  if (dot < 0) {
    return '';
  }
  return Array.from(trimmed.substring(dot + 1).toLowerCase()).slice(0, MAX_EXTENSION_CODE_POINTS).join('');
}

function addAttachmentReason_(reasons, reason) {
  if (reasons.indexOf(reason) < 0) {
    reasons.push(reason);
  }
}

function buildMessageCard_(email, result, errorMessage) {
  var sections = [messageSection_(email, result, errorMessage)];

  if (errorMessage) {
    sections.push(errorSection_(errorMessage));
  } else if (result) {
    sections = sections.concat(resultSections_(result));
  }

  return buildSectionedCard_(sections);
}

function resultSections_(result) {
  var limitations = splitLimitations_(result.limitations);
  return [
    verdictSection_(result),
    findingsSection_(result),
    actionSection_(result),
    coverageSection_(result, limitations),
    detailsSection_(result, limitations)
  ].filter(function(section) {
    return section !== null;
  });
}

// ---------------------------------------------------------------------------
// Message and error sections
// ---------------------------------------------------------------------------

function messageSection_(email, result, errorMessage) {
  var section = CardService.newCardSection()
    .addWidget(decoratedText_('Subject', email.subject || '(No subject)'))
    .addWidget(decoratedText_('From', email.from || '(Unknown sender)'));

  if (!result && !errorMessage) {
    section.addWidget(
      textParagraph_('Ready to analyze this message with the configured InboxGuardian backend.')
    );
  }

  section.addWidget(
    CardService.newTextButton()
      .setText(result || errorMessage ? 'Analyze again' : 'Analyze Email')
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName('analyzeEmail')
          .setLoadIndicator(CardService.LoadIndicator.SPINNER)
      )
  );
  return section;
}

function errorSection_(errorMessage) {
  return CardService.newCardSection()
    .setHeader('Analysis unavailable')
    .addWidget(
      iconText_({
        icon: 'cloud_off',
        iconLabel: 'Analysis unavailable',
        html: '<b>Unable to analyze this email.</b>'
      })
    )
    .addWidget(textParagraph_(escapeHtml_(errorMessage)))
    .addWidget(
      textParagraph_('No verdict or risk score is shown because no reliable result was received.')
    );
}

// ---------------------------------------------------------------------------
// A. Verdict and risk summary
// ---------------------------------------------------------------------------

function verdictSection_(result) {
  var style = verdictStyle_(result.verdict);
  return CardService.newCardSection()
    .setHeader('Assessment')
    .addWidget(
      iconText_({
        topLabel: 'Verdict',
        icon: style.icon,
        iconLabel: style.label,
        html: '<b>' + colored_(style.label, style.color) + '</b>'
      })
    )
    .addWidget(textParagraph_(style.summary))
    .addWidget(riskScoreWidget_(result, style));
}

function verdictStyle_(verdict) {
  return VERDICT_STYLES[verdict] || UNKNOWN_VERDICT_STYLE;
}

function verdictLabel_(verdict) {
  return verdictStyle_(verdict).label;
}

function riskScoreWidget_(result, style) {
  var score = meaningfulScore_(result);
  if (score === null) {
    return iconText_({
      topLabel: 'Risk index',
      html: '<b>Risk score unavailable</b>',
      bottomLabel: 'No meaningful score was produced for this message'
    });
  }
  return iconText_({
    topLabel: 'Risk index',
    html: '<b>' + colored_(score + '/100', style.color) + '</b>  ' + colored_(riskBar_(score), style.color),
    bottomLabel: 'Heuristic risk index, not a probability of phishing'
  });
}

// Returns null whenever a number must not be shown: incomplete or unrecognised verdicts, and
// scores outside the documented range. The placeholder 0 of an incomplete result is never rendered.
function meaningfulScore_(result) {
  if (!VERDICT_STYLES[result.verdict] || !VERDICT_STYLES[result.verdict].showScore) {
    return null;
  }
  if (typeof result.risk_score !== 'number' || !(result.risk_score >= 0 && result.risk_score <= 100)) {
    return null;
  }
  return Math.round(result.risk_score);
}

function riskScoreText_(result) {
  var score = meaningfulScore_(result);
  return score === null ? 'Risk score unavailable' : score + '/100 heuristic risk index';
}

function riskBar_(score) {
  var filled = Math.min(RISK_BAR_SEGMENTS, Math.round((score / 100) * RISK_BAR_SEGMENTS));
  var bar = '';
  for (var index = 0; index < RISK_BAR_SEGMENTS; index++) {
    bar += index < filled ? '■' : '□';
  }
  return bar;
}

// ---------------------------------------------------------------------------
// B. Key findings
// ---------------------------------------------------------------------------

function findingsSection_(result) {
  var section = CardService.newCardSection().setHeader('Key findings');
  var findings = result.findings.slice(0, MAX_RENDERED_FINDINGS);

  if (!findings.length) {
    section.addWidget(textParagraph_(noFindingsText_(result.verdict)));
    return section;
  }

  // The backend returns findings strongest first; that order is kept as is.
  var hasMore = findings.length > MAX_PRIMARY_FINDINGS;
  if (hasMore) {
    section.addWidget(
      textParagraph_(
        'Showing the ' + MAX_PRIMARY_FINDINGS + ' strongest of ' + result.findings.length +
        ' findings. Expand this section to see the rest.'
      )
    );
  }

  findings.forEach(function(finding, index) {
    if (index > 0) {
      section.addWidget(CardService.newDivider());
    }
    findingWidgets_(finding, result.verdict).forEach(function(widget) {
      section.addWidget(widget);
    });
  });

  if (result.findings.length > findings.length) {
    section.addWidget(CardService.newDivider());
    section.addWidget(
      textParagraph_((result.findings.length - findings.length) + ' further findings are not shown.')
    );
  }

  if (hasMore) {
    // Intro line plus two widgets per primary finding and the dividers between them.
    section.setCollapsible(true).setNumUncollapsibleWidgets(MAX_PRIMARY_FINDINGS * 3);
  }
  return section;
}

function noFindingsText_(verdict) {
  if (verdict === 'NO_SIGNIFICANT_SIGNALS') {
    return 'No significant suspicious findings were returned by the checks that ran.';
  }
  if (verdict === 'INCOMPLETE') {
    return 'No findings were produced. See Analysis coverage for what could not be assessed.';
  }
  return 'No findings were returned with this result.';
}

function findingWidgets_(finding, verdict) {
  return [
    iconText_({
      topLabel: findingLabel_(finding, verdict),
      icon: 'report',
      iconLabel: 'Finding',
      html: '<b>' + escapeHtml_(findingTitle_(finding)) + '</b>'
    }),
    textParagraph_(escapeHtml_(findingSummary_(finding)))
  ];
}

function findingTitle_(finding) {
  return truncate_(safeString_(finding && finding.title ? finding.title : 'Finding'), MAX_FINDING_TITLE_CHARS);
}

function findingSummary_(finding) {
  var parts = [];
  var observation = safeString_(finding && finding.observation);
  var interpretation = safeString_(finding && finding.interpretation);
  if (observation) {
    parts.push(observation);
  }
  if (interpretation) {
    parts.push(interpretation);
  }
  if (!parts.length) {
    parts.push('No concise observation was provided.');
  }
  return truncate_(parts.join(' '), MAX_FINDING_SUMMARY_CHARS);
}

// Labels are plain text in CardService, so they are built only from numbers and known words.
function findingLabel_(finding, verdict) {
  var parts = [];
  var contribution = finding && typeof finding.contribution === 'number' ? Math.round(finding.contribution) : null;
  if (contribution !== null && contribution > 0) {
    parts.push(
      verdict === 'INCOMPLETE' ? 'Finding weight +' + contribution : '+' + contribution + ' to risk index'
    );
  } else if (contribution === 0) {
    parts.push('Context only, +0');
  }
  var severity = SEVERITY_LABELS[safeString_(finding && finding.severity)];
  if (severity) {
    parts.push(severity);
  }
  return parts.join(' · ') || 'Finding';
}

// ---------------------------------------------------------------------------
// C. Recommended action
// ---------------------------------------------------------------------------

function actionSection_(result) {
  var action = recommendedActionText_(result);
  if (!action) {
    return null;
  }
  return CardService.newCardSection()
    .setHeader('Recommended action')
    .addWidget(
      iconText_({
        icon: 'task_alt',
        iconLabel: 'Recommended action',
        html: escapeHtml_(action)
      })
    );
}

// The section header already says "Recommended action", so a repeated label in the text is removed.
function recommendedActionText_(result) {
  return truncate_(
    safeString_(result.recommended_action).replace(/^\s*recommended action:\s*/i, '').trim(),
    MAX_ACTION_CHARS
  );
}

// ---------------------------------------------------------------------------
// D. Analysis coverage
// ---------------------------------------------------------------------------

function coverageSection_(result, limitations) {
  var section = CardService.newCardSection()
    .setHeader('Analysis coverage')
    .addWidget(
      iconText_({
        topLabel: 'Checks in this version',
        icon: 'rule',
        iconLabel: 'Checks in this version',
        html: IMPLEMENTED_CHECKS.join(' · '),
        bottomLabel: 'A listed check can still be inconclusive for a given message'
      })
    );

  if (limitations.notChecked) {
    section.addWidget(
      iconText_({
        topLabel: 'Not checked',
        icon: 'block',
        iconLabel: 'Not checked',
        html: escapeHtml_(limitations.notChecked)
      })
    );
  } else {
    section.addWidget(
      textParagraph_('The backend did not state which planned checks were skipped. See Additional details.')
    );
  }

  if (limitations.coverageNotes.length) {
    section.addWidget(textParagraph_('<b>Coverage limits for this message</b>'));
    limitations.coverageNotes.forEach(function(note) {
      section.addWidget(
        iconText_({
          icon: 'error',
          iconLabel: 'Coverage limit',
          html: escapeHtml_(note)
        })
      );
    });
  } else if (result.verdict === 'INCOMPLETE') {
    section.addWidget(
      textParagraph_('The reason this assessment is incomplete was not stated. See Additional details.')
    );
  } else {
    section.addWidget(textParagraph_('No message-specific coverage limits were reported.'));
  }
  return section;
}

// Splits the backend limitations for display without dropping any of them:
//   notChecked    - the backend's own statement of planned checks that did not run
//   coverageNotes - reasons that are specific to this message (incomplete reasons, excluded content)
//   details       - everything else, message-specific notes first
function splitLimitations_(limitations) {
  var lines = [];
  var seen = {};
  limitations.forEach(function(value) {
    var line = truncate_(safeString_(value).trim(), MAX_LIMITATION_CHARS);
    if (line && !seen[line]) {
      seen[line] = true;
      lines.push(line);
    }
  });

  var notChecked = '';
  var coverageNotes = [];
  var specific = [];
  var generic = [];
  var beforeNotChecked = lines.some(function(line) {
    return NOT_CHECKED_RE.test(line);
  });

  lines.forEach(function(line) {
    if (!notChecked && NOT_CHECKED_RE.test(line)) {
      notChecked = line.replace(NOT_CHECKED_RE, '').trim();
      beforeNotChecked = false;
    } else if (SCORE_PLACEHOLDER_RE.test(line)) {
      specific.push(line);
    } else if ((beforeNotChecked || COVERAGE_NOTE_RE.test(line)) && coverageNotes.length < MAX_COVERAGE_NOTES) {
      coverageNotes.push(line);
    } else if (beforeNotChecked || COVERAGE_NOTE_RE.test(line) || SPECIFIC_LIMITATION_RE.test(line)) {
      specific.push(line);
    } else {
      generic.push(line);
    }
  });

  return {
    notChecked: notChecked,
    coverageNotes: coverageNotes,
    details: specific.concat(generic)
  };
}

// ---------------------------------------------------------------------------
// E. Additional details
// ---------------------------------------------------------------------------

function detailsSection_(result, limitations) {
  var details = limitations.details;
  var shown = details.slice(0, MAX_DETAIL_LIMITATIONS);
  var section = CardService.newCardSection()
    .setHeader('Additional details')
    .addWidget(
      textParagraph_(
        details.length
          ? details.length + ' further notes on the limits of this analysis. Expand to read them.'
          : 'No further limitations were reported.'
      )
    );

  shown.forEach(function(line) {
    section.addWidget(textParagraph_('• ' + escapeHtml_(line)));
  });
  if (details.length > shown.length) {
    section.addWidget(
      textParagraph_((details.length - shown.length) + ' further notes were omitted for length.')
    );
  }

  section.addWidget(
    decoratedText_('Score type', 'Heuristic risk index, not a probability of phishing')
  );
  var version = truncate_(safeString_(result.detector_version), MAX_VERSION_CHARS);
  if (version) {
    section.addWidget(decoratedText_('Analysis version', version));
  }

  return section.setCollapsible(true).setNumUncollapsibleWidgets(1);
}

// ---------------------------------------------------------------------------
// Widget helpers
// ---------------------------------------------------------------------------

function buildSectionedCard_(sections) {
  var builder = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('InboxGuardian').setSubtitle('Email risk analysis')
  );
  sections.forEach(function(section) {
    builder.addSection(section);
  });
  return builder.build();
}

function buildCard_(title, widgets) {
  var section = CardService.newCardSection();
  widgets.forEach(function(widget) {
    section.addWidget(widget);
  });

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title))
    .addSection(section)
    .build();
}

// Untrusted text shown under a fixed label. The label is plain text and never comes from the backend.
function decoratedText_(label, text) {
  return CardService.newDecoratedText()
    .setTopLabel(label)
    .setText(escapeHtml_(safeString_(text)))
    .setWrapText(true);
}

// options.html must already be safe: fixed markup around values passed through escapeHtml_.
// Labels and icon names are fixed strings chosen in this file.
function iconText_(options) {
  var widget = CardService.newDecoratedText().setText(options.html).setWrapText(true);
  if (options.topLabel) {
    widget.setTopLabel(options.topLabel);
  }
  if (options.bottomLabel) {
    widget.setBottomLabel(options.bottomLabel);
  }
  var icon = options.icon ? materialIcon_(options.icon, options.iconLabel) : null;
  if (icon) {
    widget.setStartIcon(icon);
  }
  return widget;
}

// Built-in Material icons only: no image URLs are requested. A missing icon never blocks the card.
function materialIcon_(name, altText) {
  try {
    return CardService.newIconImage()
      .setMaterialIcon(CardService.newMaterialIcon().setName(name))
      .setAltText(altText || name);
  } catch (error) {
    return null;
  }
}

function colored_(safeHtml, color) {
  return '<font color="' + color + '">' + safeHtml + '</font>';
}

function textParagraph_(text) {
  return CardService.newTextParagraph().setText(text);
}

function userSafeError_(error) {
  var message = safeString_(error && error.message ? error.message : error);
  if (message.indexOf('not configured') !== -1) {
    return 'Backend settings are missing. Configure the HTTPS backend URL and API token in Script Properties.';
  }
  if (message.indexOf('authentication') !== -1) {
    return 'Backend authentication failed. Check the configured API token.';
  }
  if (message.indexOf('Unexpected backend response') !== -1) {
    return 'Unexpected backend response. No result was displayed.';
  }
  if (message.indexOf('Status: 422') !== -1) {
    return 'The backend rejected the message format. No result was displayed.';
  }
  if (message.indexOf('Status: 500') !== -1) {
    return 'Backend analysis failed. No reliable result was displayed.';
  }
  return 'Backend unavailable. Try again after confirming the backend is running and reachable over HTTPS.';
}

function safeString_(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value);
}

function truncate_(value, maxLength) {
  if (value.length <= maxLength) {
    return value;
  }
  return value.substring(0, maxLength);
}

function escapeHtml_(value) {
  return redactSensitiveText_(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function redactSensitiveText_(value) {
  return safeString_(value)
    .replace(/(https?:\/\/[^\s"'<>?#]+)(?:\?[^\s"'<>#]*)?(?:#[^\s"'<>]*)?/gi, '$1')
    .replace(/\b((?:otp|mfa|2fa|verification|security|login|authentication)\s*(?:code|token)?\s*(?:is|:)?\s*)(\d{4,8})\b/gi, '$1[redacted-code]')
    .replace(/\b((?:code|token)\s*[:#-]?\s*)(\d{4,8})\b/gi, '$1[redacted-code]');
}
