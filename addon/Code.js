var BACKEND_URL_PROPERTY = 'INBOXGUARDIAN_BACKEND_URL';
var API_TOKEN_PROPERTY = 'INBOXGUARDIAN_API_TOKEN';
var MAX_BODY_CHARS = 50000;
var MAX_RESULT_FINDINGS = 4;
var MAX_FINDING_TITLE_CHARS = 120;
var MAX_FINDING_SUMMARY_CHARS = 700;
var MAX_LIMITATIONS = 6;
var MAX_LIMITATION_CHARS = 300;

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
  try {
    var result = callBackend_(email);
    return buildMessageCard_(email, result);
  } catch (error) {
    console.error('InboxGuardian backend call failed: ' + error);
    return buildMessageCard_(email, null, userSafeError_(error));
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
        attachment_metadata: []
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

function buildMessageCard_(email, result, errorMessage) {
  var widgets = [
    decoratedText_('Subject', email.subject || '(No subject)'),
    decoratedText_('From', email.from || '(Unknown sender)')
  ];

  if (errorMessage) {
    widgets.push(textParagraph_('<b>Unable to analyze this email.</b> ' + escapeHtml_(errorMessage)));
  } else if (result) {
    widgets = widgets.concat(resultWidgets_(result));
  } else {
    widgets.push(textParagraph_('Ready to analyze this message with the configured InboxGuardian backend.'));
  }

  widgets.push(
    CardService.newTextButton()
      .setText('Analyze Email')
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName('analyzeEmail')
          .setLoadIndicator(CardService.LoadIndicator.SPINNER)
      )
  );

  return buildCard_('InboxGuardian', widgets);
}

function resultWidgets_(result) {
  var widgets = [
    CardService.newDivider(),
    decoratedText_('Verdict', verdictLabel_(result.verdict)),
    decoratedText_('Risk score', riskScoreText_(result)),
    textParagraph_('<b>Score type:</b> Heuristic risk index, not a probability of phishing.')
  ];

  var findings = result.findings.slice(0, MAX_RESULT_FINDINGS);
  if (findings.length) {
    widgets.push(textParagraph_('<b>Findings:</b>'));
    findings.forEach(function(finding) {
      widgets.push(decoratedText_(findingTitle_(finding), findingSummary_(finding)));
    });
  } else if (result.verdict === 'NO_SIGNIFICANT_SIGNALS') {
    widgets.push(textParagraph_('No significant suspicious findings were returned by the checks that ran.'));
  }

  if (result.limitations.length) {
    widgets.push(textParagraph_('<b>Limitations:</b><br>' + escapedLines_(result.limitations)));
  }

  if (result.recommended_action) {
    widgets.push(textParagraph_('<b>Recommended action:</b> ' + escapeHtml_(result.recommended_action)));
  }

  return widgets;
}

function verdictLabel_(verdict) {
  var labels = {
    HIGH_RISK: 'High risk',
    SUSPICIOUS: 'Suspicious',
    NO_SIGNIFICANT_SIGNALS: 'No significant suspicious signals found',
    INCOMPLETE: 'Assessment incomplete'
  };
  return labels[verdict] || 'Assessment result unavailable';
}

function riskScoreText_(result) {
  if (result.verdict === 'INCOMPLETE') {
    return 'Risk score unavailable';
  }
  if (typeof result.risk_score !== 'number' || result.risk_score < 0 || result.risk_score > 100) {
    return 'Risk score unavailable';
  }
  return Math.round(result.risk_score) + '/100 heuristic risk index';
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
  if (finding && typeof finding.contribution === 'number' && finding.contribution > 0) {
    parts.push('Finding contribution: ' + Math.round(finding.contribution) + '.');
  }
  if (!parts.length) {
    parts.push('No concise observation was provided.');
  }
  return truncate_(parts.join(' '), MAX_FINDING_SUMMARY_CHARS);
}

function escapedLines_(values) {
  var lines = values
    .slice(0, MAX_LIMITATIONS)
    .map(function(value) {
      return escapeHtml_(truncate_(safeString_(value), MAX_LIMITATION_CHARS));
    });
  if (values.length > MAX_LIMITATIONS) {
    lines.push('Additional limitations omitted for readability.');
  }
  return lines.join('<br>');
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

function decoratedText_(label, text) {
  return CardService.newDecoratedText()
    .setTopLabel(label)
    .setText(escapeHtml_(safeString_(text)));
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
