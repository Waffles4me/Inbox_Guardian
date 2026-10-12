var BACKEND_URL_PROPERTY = 'INBOXGUARDIAN_BACKEND_URL';
var API_TOKEN_PROPERTY = 'INBOXGUARDIAN_API_TOKEN';
var MAX_BODY_CHARS = 50000;

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
    widgets.push(textParagraph_('Ready to send minimal message fields to the backend for a demo connectivity check.'));
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
    decoratedText_('Demo connection result', result.verdict),
    textParagraph_('<b>DEMO / NOT ANALYZED.</b> No security score has been produced.')
  ];

  result.findings.slice(0, 3).forEach(function(finding) {
    widgets.push(decoratedText_(finding.title || 'Finding', finding.observation || 'No observation provided.'));
  });

  if (result.limitations.length) {
    widgets.push(textParagraph_('<b>Limitations:</b> ' + escapeHtml_(result.limitations.join(' '))));
  }

  if (result.recommended_action) {
    widgets.push(textParagraph_('<b>Recommended action:</b> ' + escapeHtml_(result.recommended_action)));
  }

  return widgets;
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
  return safeString_(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
