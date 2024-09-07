import json
from datetime import datetime, timezone
from unittest.mock import ANY

from django.test import tag

from anymail.exceptions import AnymailConfigurationError
from anymail.signals import AnymailTrackingEvent
from anymail.webhooks.brevo import BrevoTrackingWebhookView

from .webhook_cases import WebhookBasicAuthTestCase, WebhookTestCase


@tag("brevo")
class BrevoWebhookSecurityTestCase(WebhookBasicAuthTestCase):
    def call_webhook(self):
        return self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps({}),
        )

    # Actual tests are in WebhookBasicAuthTestCase


@tag("brevo")
class BrevoDeliveryTestCase(WebhookTestCase):
    # Brevo's webhook payload data is documented at
    # https://developers.brevo.com/docs/transactional-webhooks.
    # The payloads below were obtained through live testing.

    def test_sent_event(self):
        raw_event = {
            "event": "request",
            "email": "recipient@example.com",
            "id": 9999999,  # this seems to be Brevo account id (not an event id)
            "message-id": "<201803062010.27287306012@smtp-relay.mailin.fr>",
            "subject": "Test subject",
            # From a message sent at 2018-03-06 11:10:23-08:00
            # (2018-03-06 19:10:23+00:00)...
            "date": "2018-03-06 11:10:23",  # tz from Brevo account's preferences
            "ts": 1520331023,  # 2018-03-06 10:10:23 -- what time zone is this?
            "ts_event": 1520331023,  # unclear if this ever differs from "ts"
            "ts_epoch": 1520363423000,  # 2018-03-06 19:10:23.000+00:00 -- UTC (msec)
            "X-Mailin-custom": '{"meta": "data"}',
            # "tag" is JSON-serialized tags array if `tags` param set on send,
            #   else single tag string if `X-Mailin-Tag` header set on send,
            #   else template name if sent using a template,
            #   else not present.
            # "tags" is tags list if `tags` param set on send, else not present.
            "tag": '["tag1","tag2"]',
            "tags": ["tag1", "tag2"],
            "template_id": 12,
            "sending_ip": "333.33.33.33",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertIsInstance(event, AnymailTrackingEvent)
        self.assertEqual(event.event_type, "queued")
        self.assertEqual(event.esp_event, raw_event)
        self.assertEqual(
            event.timestamp,
            datetime(2018, 3, 6, 19, 10, 23, microsecond=0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            event.message_id, "<201803062010.27287306012@smtp-relay.mailin.fr>"
        )
        # Brevo does not provide a unique event id:
        self.assertIsNone(event.event_id)
        self.assertEqual(event.recipient, "recipient@example.com")
        self.assertEqual(event.metadata, {"meta": "data"})
        self.assertEqual(event.tags, ["tag1", "tag2"])

    def test_delivered_event(self):
        raw_event = {
            # For brevity, this and following tests omit some webhook data
            # that was tested earlier, or that is not used by Anymail
            "event": "delivered",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertIsInstance(event, AnymailTrackingEvent)
        self.assertEqual(event.event_type, "delivered")
        self.assertEqual(event.esp_event, raw_event)
        self.assertEqual(
            event.message_id, "<201803011158.9876543210@smtp-relay.mailin.fr>"
        )
        self.assertEqual(event.recipient, "recipient@example.com")
        # empty dict when no X-Mailin-custom header given:
        self.assertEqual(event.metadata, {})
        self.assertEqual(event.tags, [])  # empty list when no tags given

    def test_hard_bounce(self):
        raw_event = {
            "event": "hard_bounce",
            "email": "not-a-user@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
            # the leading space in the reason is as received in actual testing:
            "reason": " RecipientError: 550 5.5.0"
            " Requested action not taken: mailbox unavailable.",
            "tag": "header-tag",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "bounced")
        self.assertEqual(event.reject_reason, "bounced")
        self.assertEqual(
            event.mta_response,
            " RecipientError: 550 5.5.0"
            " Requested action not taken: mailbox unavailable.",
        )
        self.assertEqual(event.tags, ["header-tag"])

    def test_soft_bounce_event(self):
        raw_event = {
            "event": "soft_bounce",
            "email": "recipient@no-mx.example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
            "reason": "undefined Unable to find MX of domain no-mx.example.com",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "bounced")
        self.assertEqual(event.reject_reason, "bounced")
        # no human-readable description consistently available:
        self.assertIsNone(event.description)
        self.assertEqual(
            event.mta_response,
            "undefined Unable to find MX of domain no-mx.example.com",
        )

    def test_blocked(self):
        raw_event = {
            "event": "blocked",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
            "reason": "blocked : due to blacklist user",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "rejected")
        self.assertEqual(event.reject_reason, "blocked")
        self.assertEqual(event.mta_response, "blocked : due to blacklist user")

    def test_spam(self):
        # "When a person who received your email reported that it is a spam."
        # (haven't observed "spam" event in actual testing; payload below is a guess)
        raw_event = {
            "event": "spam",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "complained")
        self.assertEqual(event.reject_reason, "spam")

    def test_complaint(self):
        # Sadly, this is not well documented in the official Brevo API documentation.
        raw_event = {
            "event": "complaint",
            "email": "example@domain.com",
            "id": "xxxxx",
            "date": "2020-10-09 00:00:00",
            "ts": 1604933619,
            "message-id": "201798300811.5787683@relay.domain.com",
            "ts_event": 1604933654,
            "X-Mailin-custom": '{"meta": "data"}',
            "tags": ["transac_messages"],
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "complained")
        self.assertEqual(event.reject_reason, "spam")

    def test_invalid_email(self):
        # "If a ISP again indicated us that the email is not valid or if we discovered
        # that the email is not valid." (unclear whether this error originates with the
        # receiving MTA or with Brevo pre-send) (haven't observed "invalid_email"
        # event in actual testing; payload below is a guess)
        raw_event = {
            "event": "invalid_email",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
            "reason": "(guessing invalid_email includes a reason)",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "bounced")
        self.assertEqual(event.reject_reason, "invalid")
        self.assertEqual(
            event.mta_response, "(guessing invalid_email includes a reason)"
        )

    def test_error_email(self):
        # Sadly, this is not well documented in the official Brevo API documentation.
        raw_event = {
            "event": "error",
            "email": "example@domain.com",
            "id": "xxxxx",
            "date": "2020-10-09 00:00:00",
            "ts": 1604933619,
            "message-id": "201798300811.5787683@relay.domain.com",
            "ts_event": 1604933654,
            "subject": "My first Transactional",
            "X-Mailin-custom": '{"meta": "data"}',
            "template_id": 22,
            "tags": ["transac_messages"],
            "ts_epoch": 1604933623,
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "failed")
        self.assertEqual(event.reject_reason, None)

    def test_deferred_event(self):
        # Note: the example below is an actual event capture (with 'example.com'
        # substituted for the real receiving domain). It's pretty clearly a bounce, not
        # a deferral. It looks like Brevo mis-categorizes this SMTP response code.
        raw_event = {
            "event": "deferred",
            "email": "notauser@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
            "reason": "550 RecipientError: 550 5.1.1 <notauser@example.com>: Recipient"
            " address rejected: User unknown in virtual alias table",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "deferred")
        # no human-readable description consistently available:
        self.assertIsNone(event.description)
        self.assertEqual(
            event.mta_response,
            "550 RecipientError: 550 5.1.1 <notauser@example.com>:"
            " Recipient address rejected: User unknown in virtual alias table",
        )

    def test_opened_event(self):
        # Brevo delivers 'unique_opened' only on the first open, and 'opened'
        # only on the second or later tracking pixel views. (But they used to deliver
        # both on the first open.)
        raw_event = {
            "event": "opened",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "opened")
        self.assertIsNone(event.user_agent)  # Brevo doesn't report user agent

    def test_unique_opened_event(self):
        # See note in test_opened_event above
        raw_event = {
            "event": "unique_opened",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "opened")

    def test_proxy_open_event(self):
        # Equivalent to "Loaded via Proxy" in the Brevo UI.
        # This is sent when a tracking pixel is loaded via a 'privacy proxy server'.
        # This technique is used by Apple Mail, for example, to protect user's IP
        # addresses.
        raw_event = {
            "event": "proxy_open",
            "email": "example@domain.com",
            "id": 1,
            "date": "2020-10-09 00:00:00",
            "message-id": "201798300811.5787683@relay.domain.com",
            "subject": "My first Transactional",
            "tag": ["transactionalTag"],
            "sending_ip": "xxx.xxx.xxx.xxx",
            "s_epoch": 1534486682000,
            "template_id": 1,
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "opened")

    def test_unique_proxy_open_event(self):
        # Sadly, undocumented in Brevo.
        # Equivalent to "First Open but loaded via Proxy".
        # This is sent when a tracking pixel is loaded via a 'privacy proxy server'.
        # This technique is used by Apple Mail, for example, to protect user's IP
        # addresses.
        raw_event = {
            "event": "unique_proxy_open",
            "email": "example@domain.com",
            "id": 1,
            "date": "2020-10-09 00:00:00",
            "message-id": "201798300811.5787683@relay.domain.com",
            "subject": "My first Transactional",
            "tag": ["transactionalTag"],
            "sending_ip": "xxx.xxx.xxx.xxx",
            "s_epoch": 1534486682000,
            "template_id": 1,
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "opened")

    def test_clicked_event(self):
        raw_event = {
            "event": "click",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
            "link": "https://example.com/click/me",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "clicked")
        self.assertEqual(event.click_url, "https://example.com/click/me")
        self.assertIsNone(event.user_agent)  # Brevo doesn't report user agent

    def test_unsubscribe(self):
        # "When a person unsubscribes from the email received."
        # (haven't observed "unsubscribe" event in actual testing;
        # payload below is a guess)
        raw_event = {
            "event": "unsubscribe",
            "email": "recipient@example.com",
            "ts_epoch": 1520363423000,
            "message-id": "<201803011158.9876543210@smtp-relay.mailin.fr>",
        }
        response = self.client.post(
            "/anymail/brevo/tracking/",
            content_type="application/json",
            data=json.dumps(raw_event),
        )
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=BrevoTrackingWebhookView,
            event=ANY,
            esp_name="Brevo",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "unsubscribed")

    def test_misconfigured_inbound(self):
        errmsg = (
            "You seem to have set Brevo's *inbound* webhook URL"
            " to Anymail's Brevo *tracking* webhook URL."
        )
        with self.assertRaisesMessage(AnymailConfigurationError, errmsg):
            self.client.post(
                "/anymail/brevo/tracking/",
                content_type="application/json",
                data={"items": []},
            )
