import os
import unittest
from email.utils import formataddr

from django.test import SimpleTestCase, override_settings, tag

from anymail.exceptions import AnymailAPIError
from anymail.message import AnymailMessage

from .utils import AnymailTestMixin, sample_image_path

ANYMAIL_TEST_MAILJET_API_KEY = os.getenv("ANYMAIL_TEST_MAILJET_API_KEY")
ANYMAIL_TEST_MAILJET_SECRET_KEY = os.getenv("ANYMAIL_TEST_MAILJET_SECRET_KEY")
ANYMAIL_TEST_MAILJET_DOMAIN = os.getenv("ANYMAIL_TEST_MAILJET_DOMAIN")


@tag("mailjet", "live")
@unittest.skipUnless(
    ANYMAIL_TEST_MAILJET_API_KEY
    and ANYMAIL_TEST_MAILJET_SECRET_KEY
    and ANYMAIL_TEST_MAILJET_DOMAIN,
    "Set ANYMAIL_TEST_MAILJET_API_KEY and ANYMAIL_TEST_MAILJET_SECRET_KEY"
    " and ANYMAIL_TEST_MAILJET_DOMAIN environment variables to run Mailjet"
    " integration tests",
)
@override_settings(
    ANYMAIL={
        "MAILJET_API_KEY": ANYMAIL_TEST_MAILJET_API_KEY,
        "MAILJET_SECRET_KEY": ANYMAIL_TEST_MAILJET_SECRET_KEY,
        "MAILJET_SEND_DEFAULTS": {
            "esp_extra": {"SandboxMode": True}  # don't actually send mail
        },
    },
    EMAIL_BACKEND="anymail.backends.mailjet.EmailBackend",
)
class MailjetBackendIntegrationTests(AnymailTestMixin, SimpleTestCase):
    """
    Mailjet API integration tests

    These tests run against the **live** Mailjet API, using the environment variables
    `ANYMAIL_TEST_MAILJET_API_KEY` and `ANYMAIL_TEST_MAILJET_SECRET_KEY` as the API key
    and API secret key, respectively, and `ANYMAIL_TEST_MAILJET_DOMAIN` as a validated
    Mailjet sending domain. If those variables are not set, these tests won't run.

    These tests enable Mailjet's SandboxMode to avoid sending any email;
    remove the esp_extra setting above if you are trying to actually send test messages.
    """

    def setUp(self):
        super().setUp()
        self.from_email = "test@%s" % ANYMAIL_TEST_MAILJET_DOMAIN
        self.message = AnymailMessage(
            "Anymail Mailjet integration test",
            "Text content",
            self.from_email,
            ["test+to1@anymail.dev"],
        )
        self.message.attach_alternative("<p>HTML content</p>", "text/html")

    def test_simple_send(self):
        # Example of getting the Mailjet send status and message id from the message
        sent_count = self.message.send()
        self.assertEqual(sent_count, 1)

        anymail_status = self.message.anymail_status
        sent_status = anymail_status.recipients["test+to1@anymail.dev"].status
        message_id = anymail_status.recipients["test+to1@anymail.dev"].message_id

        self.assertEqual(sent_status, "sent")
        self.assertRegex(message_id, r".+")
        # set of all recipient statuses:
        self.assertEqual(anymail_status.status, {sent_status})
        self.assertEqual(anymail_status.message_id, message_id)

    def test_all_options(self):
        message = AnymailMessage(
            subject="Anymail Mailjet all-options integration test",
            body="This is the text body",
            from_email=formataddr(("Test Sender, Inc.", self.from_email)),
            to=["test+to1@anymail.dev", '"Recipient, 2nd" <test+to2@anymail.dev>'],
            cc=["test+cc1@anymail.dev", "Copy 2 <test+cc1@anymail.dev>"],
            bcc=["test+bcc1@anymail.dev", "Blind Copy 2 <test+bcc2@anymail.dev>"],
            # Mailjet only supports single reply_to:
            reply_to=['"Reply, To" <reply2@example.com>'],
            headers={"X-Anymail-Test": "value"},
            metadata={"meta1": "simple string", "meta2": 2},
            tags=["tag 1"],  # Mailjet only allows a single tag
            track_clicks=True,
            track_opens=True,
        )
        message.attach("attachment1.txt", "Here is some\ntext for you", "text/plain")
        message.attach("attachment2.csv", "ID,Name\n1,Amy Lina", "text/csv")
        cid = message.attach_inline_image_file(sample_image_path())
        message.attach_alternative(
            "<p><b>HTML:</b> with <a href='http://example.com'>link</a>"
            "and image: <img src='cid:%s'></div>" % cid,
            "text/html",
        )

        message.send()
        self.assertEqual(message.anymail_status.status, {"sent"})

    def test_merge_data(self):
        message = AnymailMessage(
            # Mailjet doesn't support merge fields in the subject
            subject="Anymail Mailjet merge_data test",
            body="This body includes merge data: [[var:value]]\n"
            "And global merge data: [[var:global]]",
            from_email=formataddr(("Test From", self.from_email)),
            to=["test+to1@anymail.dev", "Recipient 2 <test+to2@anymail.dev>"],
            merge_data={
                "test+to1@anymail.dev": {"value": "one"},
                "test+to2@anymail.dev": {"value": "two"},
            },
            merge_global_data={"global": "global_value"},
            metadata={"customer-id": "unknown", "meta2": 2},
            merge_metadata={
                "test+to1@anymail.dev": {"customer-id": "ZXK9123"},
                "test+to2@anymail.dev": {"customer-id": "ZZT4192"},
            },
            headers={
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Unsubscribe": "<mailto:unsubscribe@example.com>",
            },
            merge_headers={
                "test+to1@anymail.dev": {
                    "List-Unsubscribe": "<https://example.com/a/>",
                },
                "test+to2@anymail.dev": {
                    "List-Unsubscribe": "<https://example.com/b/>",
                },
            },
        )
        message.send()
        recipient_status = message.anymail_status.recipients
        self.assertEqual(recipient_status["test+to1@anymail.dev"].status, "sent")
        self.assertEqual(recipient_status["test+to2@anymail.dev"].status, "sent")

    def test_stored_template(self):
        message = AnymailMessage(
            # ID of the real template named 'test-template' in our Mailjet test account:
            template_id="176375",
            to=["test+to1@anymail.dev"],
            merge_data={
                "test+to1@anymail.dev": {
                    "name": "Test Recipient",
                }
            },
            merge_global_data={
                "order": "12345",
            },
        )
        message.from_email = None  # use the template's sender email/name
        message.send()
        recipient_status = message.anymail_status.recipients
        self.assertEqual(recipient_status["test+to1@anymail.dev"].status, "sent")

    @override_settings(
        ANYMAIL={
            "MAILJET_API_KEY": "Hey, that's not an API key!",
            "MAILJET_SECRET_KEY": "and this isn't the secret for it",
        }
    )
    def test_invalid_api_key(self):
        with self.assertRaises(AnymailAPIError) as cm:
            self.message.send()
        err = cm.exception
        self.assertEqual(err.status_code, 401)
        self.assertIn("API key authentication/authorization failure", str(err))
