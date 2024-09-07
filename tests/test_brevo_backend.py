import json
from base64 import b64decode, b64encode
from datetime import date, datetime, timezone
from decimal import Decimal
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage

from django.core import mail
from django.test import SimpleTestCase, override_settings, tag
from django.utils.timezone import (
    get_fixed_timezone,
    override as override_current_timezone,
)

from anymail.exceptions import (
    AnymailAPIError,
    AnymailConfigurationError,
    AnymailSerializationError,
    AnymailUnsupportedFeature,
)
from anymail.message import AnymailMessage, attach_inline_image_file

from .mock_requests_backend import (
    RequestsBackendMockAPITestCase,
    SessionSharingTestCases,
)
from .utils import (
    SAMPLE_IMAGE_FILENAME,
    AnymailTestMixin,
    sample_image_content,
    sample_image_path,
)


@tag("brevo")
@override_settings(
    EMAIL_BACKEND="anymail.backends.brevo.EmailBackend",
    ANYMAIL={"BREVO_API_KEY": "test_api_key"},
)
class BrevoBackendMockAPITestCase(RequestsBackendMockAPITestCase):
    DEFAULT_RAW_RESPONSE = (
        b'{"messageId":"<201801020304.1234567890@smtp-relay.mailin.fr>"}'
    )
    DEFAULT_STATUS_CODE = 201  # Brevo v3 uses '201 Created' for success (in most cases)

    def setUp(self):
        super().setUp()
        # Simple message useful for many tests
        self.message = mail.EmailMultiAlternatives(
            "Subject", "Text Body", "from@example.com", ["to@example.com"]
        )


@tag("brevo")
class BrevoBackendStandardEmailTests(BrevoBackendMockAPITestCase):
    """Test backend support for Django standard email features"""

    def test_send_mail(self):
        """Test basic API for simple send"""
        mail.send_mail(
            "Subject here",
            "Here is the message.",
            "from@sender.example.com",
            ["to@example.com"],
            fail_silently=False,
        )
        self.assert_esp_called("https://api.brevo.com/v3/smtp/email")
        http_headers = self.get_api_call_headers()
        self.assertEqual(http_headers["api-key"], "test_api_key")
        self.assertEqual(http_headers["Content-Type"], "application/json")

        data = self.get_api_call_json()
        self.assertEqual(data["subject"], "Subject here")
        self.assertEqual(data["textContent"], "Here is the message.")
        self.assertEqual(data["sender"], {"email": "from@sender.example.com"})
        self.assertEqual(data["to"], [{"email": "to@example.com"}])

    def test_name_addr(self):
        """Make sure RFC2822 name-addr format (with display-name) is allowed

        (Test both sender and recipient addresses)
        """
        msg = mail.EmailMessage(
            "Subject",
            "Message",
            "From Name <from@example.com>",
            ["Recipient #1 <to1@example.com>", "to2@example.com"],
            cc=["Carbon Copy <cc1@example.com>", "cc2@example.com"],
            bcc=["Blind Copy <bcc1@example.com>", "bcc2@example.com"],
        )
        msg.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["sender"], {"email": "from@example.com", "name": "From Name"}
        )
        self.assertEqual(
            data["to"],
            [
                {"email": "to1@example.com", "name": "Recipient #1"},
                {"email": "to2@example.com"},
            ],
        )
        self.assertEqual(
            data["cc"],
            [
                {"email": "cc1@example.com", "name": "Carbon Copy"},
                {"email": "cc2@example.com"},
            ],
        )
        self.assertEqual(
            data["bcc"],
            [
                {"email": "bcc1@example.com", "name": "Blind Copy"},
                {"email": "bcc2@example.com"},
            ],
        )

    def test_email_message(self):
        email = mail.EmailMessage(
            "Subject",
            "Body goes here",
            "from@example.com",
            ["to1@example.com", "Also To <to2@example.com>"],
            bcc=["bcc1@example.com", "Also BCC <bcc2@example.com>"],
            cc=["cc1@example.com", "Also CC <cc2@example.com>"],
            headers={
                "Reply-To": "another@example.com",
                "X-MyHeader": "my value",
                # should override backend msgid:
                "Message-ID": "<mycustommsgid@sales.example.com>",
            },
        )
        email.send()
        data = self.get_api_call_json()
        self.assertEqual(data["sender"], {"email": "from@example.com"})
        self.assertEqual(data["subject"], "Subject")
        self.assertEqual(data["textContent"], "Body goes here")
        self.assertEqual(data["replyTo"], {"email": "another@example.com"})
        self.assertEqual(
            data["headers"],
            {
                "X-MyHeader": "my value",
                "Message-ID": "<mycustommsgid@sales.example.com>",
            },
        )

    def test_html_message(self):
        text_content = "This is an important message."
        html_content = "<p>This is an <strong>important</strong> message.</p>"
        email = mail.EmailMultiAlternatives(
            "Subject", text_content, "from@example.com", ["to@example.com"]
        )
        email.attach_alternative(html_content, "text/html")
        email.send()
        data = self.get_api_call_json()
        self.assertEqual(data["textContent"], text_content)
        self.assertEqual(data["htmlContent"], html_content)

        # Don't accidentally send the html part as an attachment:
        self.assertNotIn("attachments", data)

    def test_html_only_message(self):
        html_content = "<p>This is an <strong>important</strong> message.</p>"
        email = mail.EmailMessage(
            "Subject", html_content, "from@example.com", ["to@example.com"]
        )
        email.content_subtype = "html"  # Main content is now text/html
        email.send()
        data = self.get_api_call_json()
        self.assertEqual(data["htmlContent"], html_content)
        self.assertNotIn("textContent", data)

    def test_extra_headers(self):
        self.message.extra_headers = {
            "X-Custom": "string",
            "X-Num": 123,
            "Reply-To": '"Do Not Reply" <noreply@example.com>',
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["headers"]["X-Custom"], "string")
        # Header values must be strings (changed 11/2022)
        self.assertEqual(data["headers"]["X-Num"], "123")
        # Reply-To must be moved to separate param
        self.assertNotIn("Reply-To", data["headers"])
        self.assertEqual(
            data["replyTo"], {"name": "Do Not Reply", "email": "noreply@example.com"}
        )

    def test_extra_headers_serialization_error(self):
        self.message.extra_headers = {"X-Custom": Decimal(12.5)}
        with self.assertRaisesMessage(AnymailSerializationError, "Decimal"):
            self.message.send()

    def test_reply_to(self):
        self.message.reply_to = ['"Reply recipient" <reply@example.com']
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["replyTo"], {"name": "Reply recipient", "email": "reply@example.com"}
        )

    def test_multiple_reply_to(self):
        # Brevo v3 only allows a single reply address
        self.message.reply_to = [
            '"Reply recipient" <reply@example.com',
            "reply2@example.com",
        ]
        with self.assertRaises(AnymailUnsupportedFeature):
            self.message.send()

    @override_settings(ANYMAIL_IGNORE_UNSUPPORTED_FEATURES=True)
    def test_multiple_reply_to_ignore_unsupported(self):
        # Should use first Reply-To if ignoring unsupported features
        self.message.reply_to = [
            '"Reply recipient" <reply@example.com',
            "reply2@example.com",
        ]
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["replyTo"], {"name": "Reply recipient", "email": "reply@example.com"}
        )

    def test_attachments(self):
        text_content = "* Item one\n* Item two\n* Item three"
        self.message.attach(
            filename="test.txt", content=text_content, mimetype="text/plain"
        )

        # Should guess mimetype if not provided...
        png_content = b"PNG\xb4 pretend this is the contents of a png file"
        self.message.attach(filename="test.png", content=png_content)

        # Should work with a MIMEBase object (also tests no filename)...
        pdf_content = b"PDF\xb4 pretend this is valid pdf data"
        mimeattachment = MIMEBase("application", "pdf")
        mimeattachment.set_payload(pdf_content)
        self.message.attach(mimeattachment)

        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(len(data["attachment"]), 3)

        attachments = data["attachment"]
        self.assertEqual(
            attachments[0],
            {
                "name": "test.txt",
                "content": b64encode(text_content.encode("utf-8")).decode("ascii"),
            },
        )
        self.assertEqual(
            attachments[1],
            {"name": "test.png", "content": b64encode(png_content).decode("ascii")},
        )
        self.assertEqual(
            attachments[2],
            {"name": "", "content": b64encode(pdf_content).decode("ascii")},
        )

    def test_unicode_attachment_correctly_decoded(self):
        self.message.attach(
            "Une pièce jointe.html", "<p>\u2019</p>", mimetype="text/html"
        )
        self.message.send()
        attachment = self.get_api_call_json()["attachment"][0]
        self.assertEqual(attachment["name"], "Une pièce jointe.html")
        self.assertEqual(
            b64decode(attachment["content"]).decode("utf-8"), "<p>\u2019</p>"
        )

    def test_embedded_images(self):
        # Brevo doesn't support inline image
        # inline image are just added as a content attachment

        image_filename = SAMPLE_IMAGE_FILENAME
        image_path = sample_image_path(image_filename)

        cid = attach_inline_image_file(self.message, image_path)  # Read from a png file
        html_content = (
            '<p>This has an <img src="cid:%s" alt="inline" /> image.</p>' % cid
        )
        self.message.attach_alternative(html_content, "text/html")

        with self.assertRaises(AnymailUnsupportedFeature):
            self.message.send()

    def test_attached_images(self):
        image_filename = SAMPLE_IMAGE_FILENAME
        image_path = sample_image_path(image_filename)
        image_data = sample_image_content(image_filename)

        # option 1: attach as a file
        self.message.attach_file(image_path)

        # option 2: construct the MIMEImage and attach it directly
        image = MIMEImage(image_data)
        self.message.attach(image)

        self.message.send()

        image_data_b64 = b64encode(image_data).decode("ascii")
        data = self.get_api_call_json()
        self.assertEqual(
            data["attachment"][0],
            {
                "name": image_filename,  # the named one
                "content": image_data_b64,
            },
        )
        self.assertEqual(
            data["attachment"][1],
            {
                "name": "",  # the unnamed one
                "content": image_data_b64,
            },
        )

    def test_multiple_html_alternatives(self):
        self.message.body = "Text body"
        self.message.attach_alternative("<p>First html is OK</p>", "text/html")
        self.message.attach_alternative(
            "<p>And maybe second html, too</p>", "text/html"
        )

        with self.assertRaises(AnymailUnsupportedFeature):
            self.message.send()

    def test_non_html_alternative(self):
        self.message.body = "Text body"
        self.message.attach_alternative("{'maybe': 'allowed'}", "application/json")

        with self.assertRaises(AnymailUnsupportedFeature):
            self.message.send()

    def test_api_failure(self):
        self.set_mock_response(status_code=400)
        with self.assertRaisesMessage(AnymailAPIError, "Brevo API response 400"):
            mail.send_mail("Subject", "Body", "from@example.com", ["to@example.com"])

        # Make sure fail_silently is respected
        self.set_mock_response(status_code=400)
        sent = mail.send_mail(
            "Subject",
            "Body",
            "from@example.com",
            ["to@example.com"],
            fail_silently=True,
        )
        self.assertEqual(sent, 0)

    def test_api_error_includes_details(self):
        """AnymailAPIError should include ESP's error message"""
        # JSON error response:
        error_response = b"""{
            "code": "invalid_parameter",
            "message": "valid sender email required"
        }"""
        self.set_mock_response(status_code=400, raw=error_response)
        with self.assertRaises(AnymailAPIError) as cm:
            self.message.send()
        err = cm.exception
        self.assertIn("code", str(err))
        self.assertIn("message", str(err))

        # No content in the error response:
        self.set_mock_response(status_code=502, raw=None)
        with self.assertRaises(AnymailAPIError):
            self.message.send()


@tag("brevo")
class BrevoBackendAnymailFeatureTests(BrevoBackendMockAPITestCase):
    """Test backend support for Anymail added features"""

    def test_envelope_sender(self):
        # Brevo does not have a way to change envelope sender.
        self.message.envelope_sender = "anything@bounces.example.com"
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "envelope_sender"):
            self.message.send()

    def test_metadata(self):
        self.message.metadata = {"user_id": "12345", "items": 6, "float": 98.6}
        self.message.send()

        data = self.get_api_call_json()

        metadata = json.loads(data["headers"]["X-Mailin-custom"])
        self.assertEqual(metadata["user_id"], "12345")
        self.assertEqual(metadata["items"], 6)
        self.assertEqual(metadata["float"], 98.6)

    def test_send_at(self):
        utc_plus_6 = get_fixed_timezone(6 * 60)
        utc_minus_8 = get_fixed_timezone(-8 * 60)

        with override_current_timezone(utc_plus_6):
            # Timezone-aware datetime converted to UTC:
            self.message.send_at = datetime(
                2016, 3, 4, 5, 6, 7, 8000, tzinfo=utc_minus_8
            )
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["scheduledAt"], "2016-03-04T05:06:07.008-08:00")

            # Explicit UTC:
            self.message.send_at = datetime(2016, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["scheduledAt"], "2016-03-04T05:06:07.000+00:00")

            # Timezone-naive datetime assumed to be Django current_timezone
            # (also checks stripping microseconds)
            self.message.send_at = datetime(2022, 10, 11, 12, 13, 14, 567)
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["scheduledAt"], "2022-10-11T12:13:14.000+06:00")

            # Date-only treated as midnight in current timezone
            self.message.send_at = date(2022, 10, 22)
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["scheduledAt"], "2022-10-22T00:00:00.000+06:00")

            # POSIX timestamp
            self.message.send_at = 1651820889  # 2022-05-06 07:08:09 UTC
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["scheduledAt"], "2022-05-06T07:08:09.000+00:00")

            # String passed unchanged (this is *not* portable between ESPs)
            self.message.send_at = "2022-10-13T18:02:00.123-11:30"
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["scheduledAt"], "2022-10-13T18:02:00.123-11:30")

    def test_tag(self):
        self.message.tags = ["receipt", "multiple"]
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["tags"], ["receipt", "multiple"])

    def test_tracking(self):
        # Test one way...
        self.message.track_clicks = False
        self.message.track_opens = True

        with self.assertRaises(AnymailUnsupportedFeature):
            self.message.send()

        # ...and the opposite way
        self.message.track_clicks = True
        self.message.track_opens = False
        with self.assertRaises(AnymailUnsupportedFeature):
            self.message.send()

    def test_template_id(self):
        # subject, body, and from_email must be None for Brevo template send:
        message = mail.EmailMessage(
            subject="My Subject",
            body=None,
            from_email="from@example.com",
            # single 'to' recommended (all 'to' get the same message)
            to=["Recipient <to@example.com>"],
            cc=["Recipient <cc1@example.com>", "Recipient <cc2@example.com>"],
            bcc=["Recipient <bcc@example.com>"],
            reply_to=["Recipient <reply@example.com>"],
        )
        # Brevo uses per-account numeric ID to identify templates:
        message.template_id = 12
        message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["templateId"], 12)
        self.assertEqual(data["subject"], "My Subject")
        self.assertEqual(data["to"], [{"email": "to@example.com", "name": "Recipient"}])

    _mock_batch_response = {
        "messageIds": [
            "<202403182259.64789700810.1@smtp-relay.mailin.fr>",
            "<202403182259.64789700810.2@smtp-relay.mailin.fr>",
        ]
    }

    def test_merge_data(self):
        self.set_mock_response(json_data=self._mock_batch_response)
        message = AnymailMessage(
            from_email="from@example.com",
            template_id=1234567,
            to=["alice@example.com", "Bob <bob@example.com>"],
            merge_data={
                "alice@example.com": {"name": "Alice", "group": "Developers"},
                "bob@example.com": {"name": "Bob"},  # and leave group undefined
                "nobody@example.com": {"name": "Not a recipient for this message"},
            },
            merge_global_data={"group": "Users", "site": "ExampleCo"},
        )
        message.send()

        # batch send uses same API endpoint as regular send:
        self.assert_esp_called("/v3/smtp/email")
        data = self.get_api_call_json()
        versions = data["messageVersions"]
        self.assertEqual(len(versions), 2)
        self.assertEqual(
            versions[0],
            {
                "to": [{"email": "alice@example.com"}],
                "params": {"name": "Alice", "group": "Developers"},
            },
        )
        self.assertEqual(
            versions[1],
            {
                "to": [{"email": "bob@example.com", "name": "Bob"}],
                "params": {"name": "Bob"},
            },
        )
        self.assertEqual(data["params"], {"group": "Users", "site": "ExampleCo"})

        recipients = message.anymail_status.recipients
        self.assertEqual(recipients["alice@example.com"].status, "queued")
        self.assertEqual(
            recipients["alice@example.com"].message_id,
            "<202403182259.64789700810.1@smtp-relay.mailin.fr>",
        )
        self.assertEqual(recipients["bob@example.com"].status, "queued")
        self.assertEqual(
            recipients["bob@example.com"].message_id,
            "<202403182259.64789700810.2@smtp-relay.mailin.fr>",
        )

    def test_merge_global_data(self):
        self.message.merge_global_data = {"a": "b"}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["params"], {"a": "b"})

    def test_merge_metadata(self):
        self.set_mock_response(json_data=self._mock_batch_response)
        self.message.to = ["alice@example.com", "Bob <bob@example.com>"]
        self.message.merge_metadata = {
            "alice@example.com": {"order_id": 123, "tier": "premium"},
            "bob@example.com": {"order_id": 678},
        }
        self.message.metadata = {"notification_batch": "zx912"}
        self.message.send()

        data = self.get_api_call_json()
        versions = data["messageVersions"]
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]["to"], [{"email": "alice@example.com"}])
        # metadata and merge_metadata[recipient] are combined:
        self.assertEqual(
            json.loads(versions[0]["headers"]["X-Mailin-custom"]),
            {"order_id": 123, "tier": "premium", "notification_batch": "zx912"},
        )
        self.assertEqual(
            versions[1]["to"], [{"name": "Bob", "email": "bob@example.com"}]
        )
        self.assertEqual(
            json.loads(versions[1]["headers"]["X-Mailin-custom"]),
            {"order_id": 678, "notification_batch": "zx912"},
        )
        # default metadata still sent in base headers:
        self.assertEqual(
            json.loads(data["headers"]["X-Mailin-custom"]),
            {"notification_batch": "zx912"},
        )

    def test_merge_headers(self):
        self.set_mock_response(json_data=self._mock_batch_response)
        self.message.to = ["alice@example.com", "Bob <bob@example.com>"]
        self.message.extra_headers = {
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            "List-Unsubscribe": "<mailto:unsubscribe@example.com>",
        }
        self.message.merge_headers = {
            "alice@example.com": {
                "List-Unsubscribe": "<https://example.com/a/>",
            },
            "bob@example.com": {
                "List-Unsubscribe": "<https://example.com/b/>",
            },
        }

        self.message.send()

        data = self.get_api_call_json()
        versions = data["messageVersions"]
        self.assertEqual(len(versions), 2)
        self.assertEqual(
            versions[0]["headers"], {"List-Unsubscribe": "<https://example.com/a/>"}
        )
        self.assertEqual(
            versions[1]["headers"], {"List-Unsubscribe": "<https://example.com/b/>"}
        )
        self.assertNotIn("params", versions[0])  # because no merge_data
        # non-merge headers still in base data
        self.assertEqual(
            data["headers"],
            {
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Unsubscribe": "<mailto:unsubscribe@example.com>",
            },
        )

    def test_default_omits_options(self):
        """Make sure by default we don't send any ESP-specific options.

        Options not specified by the caller should be omitted entirely from
        the API call (*not* sent as False or empty). This ensures
        that your ESP account settings apply by default.
        """
        self.message.send()
        data = self.get_api_call_json()
        self.assertNotIn("attachment", data)
        self.assertNotIn("bcc", data)
        self.assertNotIn("cc", data)
        self.assertNotIn("headers", data)
        self.assertNotIn("messageVersions", data)
        self.assertNotIn("params", data)
        self.assertNotIn("replyTo", data)
        self.assertNotIn("schedule", data)
        self.assertNotIn("tags", data)
        self.assertNotIn("templateId", data)

    def test_esp_extra(self):
        self.message.esp_extra = {
            "batchId": "5c6cfa04-eed9-42c2-8b5c-6d470d978e9d",
        }
        self.message.send()
        data = self.get_api_call_json()
        # merged from esp_extra:
        self.assertEqual(data["batchId"], "5c6cfa04-eed9-42c2-8b5c-6d470d978e9d")

    # noinspection PyUnresolvedReferences
    def test_send_attaches_anymail_status(self):
        """The anymail_status should be attached to the message when it is sent"""
        # the DEFAULT_RAW_RESPONSE above is the *only* success response Brevo
        # returns, so no need to override it here
        msg = mail.EmailMessage(
            "Subject",
            "Message",
            "from@example.com",
            ["to1@example.com"],
        )
        sent = msg.send()
        self.assertEqual(sent, 1)
        self.assertEqual(msg.anymail_status.status, {"queued"})
        self.assertEqual(
            msg.anymail_status.recipients["to1@example.com"].status, "queued"
        )
        self.assertEqual(
            msg.anymail_status.esp_response.content, self.DEFAULT_RAW_RESPONSE
        )

        self.assertEqual(
            msg.anymail_status.message_id,
            json.loads(msg.anymail_status.esp_response.content.decode("utf-8"))[
                "messageId"
            ],
        )
        self.assertEqual(
            msg.anymail_status.recipients["to1@example.com"].message_id,
            json.loads(msg.anymail_status.esp_response.content.decode("utf-8"))[
                "messageId"
            ],
        )

    # noinspection PyUnresolvedReferences
    def test_send_failed_anymail_status(self):
        """If the send fails, anymail_status should contain initial values"""
        self.set_mock_response(status_code=500)
        sent = self.message.send(fail_silently=True)
        self.assertEqual(sent, 0)
        self.assertIsNone(self.message.anymail_status.status)
        self.assertEqual(self.message.anymail_status.recipients, {})
        self.assertIsNone(self.message.anymail_status.esp_response)

    def test_json_serialization_errors(self):
        """Try to provide more information about non-json-serializable data"""
        self.message.esp_extra = {"total": Decimal("19.99")}
        with self.assertRaises(AnymailSerializationError) as cm:
            self.message.send()
        err = cm.exception
        self.assertIsInstance(err, TypeError)  # compatibility with json.dumps
        # our added context:
        self.assertIn("Don't know how to send this data to Brevo", str(err))
        # original message
        self.assertRegex(str(err), r"Decimal.*is not JSON serializable")


@tag("brevo")
class BrevoBackendRecipientsRefusedTests(BrevoBackendMockAPITestCase):
    """
    Should raise AnymailRecipientsRefused when *all* recipients are rejected or invalid
    """

    # Brevo doesn't check email bounce or complaint lists at time of send --
    # it always just queues the message. You'll need to listen for the "rejected"
    # and "failed" events to detect refused recipients.
    pass  # not applicable to this backend


@tag("brevo")
class BrevoBackendSessionSharingTestCase(
    SessionSharingTestCases, BrevoBackendMockAPITestCase
):
    """Requests session sharing tests"""

    pass  # tests are defined in SessionSharingTestCases


@tag("brevo")
@override_settings(EMAIL_BACKEND="anymail.backends.brevo.EmailBackend")
class BrevoBackendImproperlyConfiguredTests(AnymailTestMixin, SimpleTestCase):
    """Test ESP backend without required settings in place"""

    def test_missing_auth(self):
        with self.assertRaisesRegex(AnymailConfigurationError, r"\bBREVO_API_KEY\b"):
            mail.send_mail("Subject", "Message", "from@example.com", ["to@example.com"])
