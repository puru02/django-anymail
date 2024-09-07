from base64 import b64decode, b64encode
from calendar import timegm
from datetime import date, datetime
from decimal import Decimal
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from unittest.mock import patch

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
    AnymailWarning,
)
from anymail.message import attach_inline_image_file

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


@tag("sendgrid")
@override_settings(
    EMAIL_BACKEND="anymail.backends.sendgrid.EmailBackend",
    ANYMAIL={"SENDGRID_API_KEY": "test_api_key"},
)
class SendGridBackendMockAPITestCase(RequestsBackendMockAPITestCase):
    # SendGrid v3 success responses are empty:
    DEFAULT_RAW_RESPONSE = b""
    # SendGrid v3 uses '202 Accepted' for success (in most cases):
    DEFAULT_STATUS_CODE = 202

    def setUp(self):
        super().setUp()

        # Patch uuid4 to generate predictable anymail_ids for testing
        patch_uuid4 = patch(
            "anymail.backends.sendgrid.uuid.uuid4",
            side_effect=["mocked-uuid-%d" % n for n in range(1, 5)],
        )
        patch_uuid4.start()
        self.addCleanup(patch_uuid4.stop)

        # Simple message useful for many tests
        self.message = mail.EmailMultiAlternatives(
            "Subject", "Text Body", "from@example.com", ["to@example.com"]
        )


@tag("sendgrid")
class SendGridBackendStandardEmailTests(SendGridBackendMockAPITestCase):
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
        self.assert_esp_called("https://api.sendgrid.com/v3/mail/send")
        http_headers = self.get_api_call_headers()
        self.assertEqual(http_headers["Authorization"], "Bearer test_api_key")
        self.assertEqual(http_headers["Content-Type"], "application/json")

        data = self.get_api_call_json()
        self.assertEqual(data["subject"], "Subject here")
        self.assertEqual(
            data["content"], [{"type": "text/plain", "value": "Here is the message."}]
        )
        self.assertEqual(data["from"], {"email": "from@sender.example.com"})
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "to@example.com"}],
                    # make sure the backend assigned the anymail_id
                    # for event tracking and notification
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                }
            ],
        )

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
            data["from"], {"email": "from@example.com", "name": "From Name"}
        )

        # single message (single "personalization") sent to all those recipients
        # (note workaround for SendGrid v3 API bug quoting display-name
        # in personalizations)
        self.assertEqual(len(data["personalizations"]), 1)
        self.assertEqual(
            data["personalizations"][0]["to"],
            [
                {"name": '"Recipient #1"', "email": "to1@example.com"},
                {"email": "to2@example.com"},
            ],
        )
        self.assertEqual(
            data["personalizations"][0]["cc"],
            [
                {"name": '"Carbon Copy"', "email": "cc1@example.com"},
                {"email": "cc2@example.com"},
            ],
        )
        self.assertEqual(
            data["personalizations"][0]["bcc"],
            [
                {"name": '"Blind Copy"', "email": "bcc1@example.com"},
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
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [
                        {"email": "to1@example.com"},
                        {"email": "to2@example.com", "name": '"Also To"'},
                    ],
                    "cc": [
                        {"email": "cc1@example.com"},
                        {"email": "cc2@example.com", "name": '"Also CC"'},
                    ],
                    "bcc": [
                        {"email": "bcc1@example.com"},
                        {"email": "bcc2@example.com", "name": '"Also BCC"'},
                    ],
                    # make sure custom Message-ID also added to custom_args
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                }
            ],
        )

        self.assertEqual(data["from"], {"email": "from@example.com"})
        self.assertEqual(data["subject"], "Subject")
        self.assertEqual(
            data["content"], [{"type": "text/plain", "value": "Body goes here"}]
        )
        self.assertEqual(data["reply_to_list"], [{"email": "another@example.com"}])
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
        # SendGrid requires content in text, html order:
        self.assertEqual(len(data["content"]), 2)
        self.assertEqual(
            data["content"][0], {"type": "text/plain", "value": text_content}
        )
        self.assertEqual(
            data["content"][1], {"type": "text/html", "value": html_content}
        )
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
        self.assertEqual(len(data["content"]), 1)
        self.assertEqual(
            data["content"][0], {"type": "text/html", "value": html_content}
        )

    def test_extra_headers(self):
        self.message.extra_headers = {
            "X-Custom": "string",
            "X-Num": 123,
            "Reply-To": '"Do Not Reply" <noreply@example.com>',
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["headers"]["X-Custom"], "string")
        # number converted to string (undocumented SendGrid requirement):
        self.assertEqual(data["headers"]["X-Num"], "123")
        # Reply-To must be moved to separate param
        self.assertNotIn("Reply-To", data["headers"])
        self.assertEqual(
            data["reply_to_list"],
            [{"name": "Do Not Reply", "email": "noreply@example.com"}],
        )

    def test_extra_headers_serialization_error(self):
        self.message.extra_headers = {"X-Custom": Decimal(12.5)}
        with self.assertRaisesMessage(AnymailSerializationError, "Decimal"):
            self.message.send()

    def test_reply_to(self):
        self.message.reply_to = [
            '"Reply recipient" <reply@example.com',
            "reply2@example.com",
        ]
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["reply_to_list"],
            [
                {"name": "Reply recipient", "email": "reply@example.com"},
                {"email": "reply2@example.com"},
            ],
        )
        self.assertNotIn("reply_to", data)  # not allowed with reply_to_list

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
        self.assertEqual(len(data["attachments"]), 3)

        attachments = data["attachments"]
        self.assertEqual(
            attachments[0],
            {
                "filename": "test.txt",
                "content": b64encode(text_content.encode("utf-8")).decode("ascii"),
                "type": "text/plain",
            },
        )
        self.assertEqual(
            attachments[1],
            {
                "filename": "test.png",
                "content": b64encode(png_content).decode("ascii"),
                "type": "image/png",  # (type inferred from filename)
            },
        )
        self.assertEqual(
            attachments[2],
            {
                "filename": "",  # no filename -- but param is required
                "content": b64encode(pdf_content).decode("ascii"),
                "type": "application/pdf",
            },
        )

    def test_unicode_attachment_correctly_decoded(self):
        self.message.attach(
            "Une pièce jointe.html", "<p>\u2019</p>", mimetype="text/html"
        )
        self.message.send()
        attachment = self.get_api_call_json()["attachments"][0]
        self.assertEqual(attachment["filename"], "Une pièce jointe.html")
        self.assertEqual(
            b64decode(attachment["content"]).decode("utf-8"), "<p>\u2019</p>"
        )

    def test_embedded_images(self):
        image_filename = SAMPLE_IMAGE_FILENAME
        image_path = sample_image_path(image_filename)
        image_data = sample_image_content(image_filename)

        cid = attach_inline_image_file(self.message, image_path)  # Read from a png file
        html_content = (
            '<p>This has an <img src="cid:%s" alt="inline" /> image.</p>' % cid
        )
        self.message.attach_alternative(html_content, "text/html")

        self.message.send()
        data = self.get_api_call_json()

        self.assertEqual(
            data["attachments"][0],
            {
                "filename": image_filename,
                "content": b64encode(image_data).decode("ascii"),
                "type": "image/png",  # (type inferred from filename)
                "disposition": "inline",
                "content_id": cid,
            },
        )

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
            data["attachments"][0],
            {
                "filename": image_filename,  # the named one
                "content": image_data_b64,
                "type": "image/png",
            },
        )
        self.assertEqual(
            data["attachments"][1],
            {
                "filename": "",  # the unnamed one
                "content": image_data_b64,
                "type": "image/png",
            },
        )

    def test_multiple_html_alternatives(self):
        # SendGrid's v3 API allows all kinds of content alternatives.
        # It's unclear whether this would permit multiple text/html parts
        # (the API docs warn that "If included, text/plain and text/html must be
        # the first indices of the [content] array in this order"), but Anymail
        # generally passes whatever the API structure supports -- deferring any
        # limitations to the ESP.
        self.message.body = "Text body"
        self.message.attach_alternative("<p>First html is OK</p>", "text/html")
        self.message.attach_alternative(
            "<p>And maybe second html, too</p>", "text/html"
        )

        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["content"],
            [
                {"type": "text/plain", "value": "Text body"},
                {"type": "text/html", "value": "<p>First html is OK</p>"},
                {"type": "text/html", "value": "<p>And maybe second html, too</p>"},
            ],
        )

    def test_non_html_alternative(self):
        self.message.body = "Text body"
        self.message.attach_alternative("{'maybe': 'allowed'}", "application/json")
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["content"],
            [
                {"type": "text/plain", "value": "Text body"},
                {"type": "application/json", "value": "{'maybe': 'allowed'}"},
            ],
        )

    def test_api_failure(self):
        self.set_mock_response(status_code=400)
        with self.assertRaisesMessage(AnymailAPIError, "SendGrid API response 400"):
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
        error_response = b"""{"errors":[
            {"message":"Helpful explanation from SendGrid",
             "field":"subject","help":null},
            {"message":"Another error","field":null,"help":null}
        ]}"""
        self.set_mock_response(status_code=400, raw=error_response)
        with self.assertRaises(AnymailAPIError) as cm:
            self.message.send()
        err = cm.exception
        self.assertIn("Helpful explanation from SendGrid", str(err))
        self.assertIn("Another error", str(err))

        # Non-JSON error response:
        self.set_mock_response(status_code=500, raw=b"Ack! Bad proxy!")
        with self.assertRaisesMessage(AnymailAPIError, "Ack! Bad proxy!"):
            self.message.send()

        # No content in the error response:
        self.set_mock_response(status_code=502, raw=None)
        with self.assertRaises(AnymailAPIError):
            self.message.send()


@tag("sendgrid")
class SendGridBackendAnymailFeatureTests(SendGridBackendMockAPITestCase):
    """Test backend support for Anymail added features"""

    def test_envelope_sender(self):
        # SendGrid does not have a way to change envelope sender.
        self.message.envelope_sender = "anything@bounces.example.com"
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "envelope_sender"):
            self.message.send()

    def test_metadata(self):
        self.message.metadata = {"user_id": "12345", "items": 6, "float": 98.6}
        self.message.send()
        data = self.get_api_call_json()
        # remove anymail_id we added for tracking:
        data["custom_args"].pop("anymail_id", None)
        self.assertEqual(
            data["custom_args"],
            {
                "user_id": "12345",
                "items": "6",  # int converted to a string,
                "float": "98.6",  # float converted to a string (watch binary rounding!)
            },
        )

    def test_send_at(self):
        utc_plus_6 = get_fixed_timezone(6 * 60)
        utc_minus_8 = get_fixed_timezone(-8 * 60)

        with override_current_timezone(utc_plus_6):
            # Timezone-aware datetime converted to UTC:
            self.message.send_at = datetime(2016, 3, 4, 5, 6, 7, tzinfo=utc_minus_8)
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(
                data["send_at"], timegm((2016, 3, 4, 13, 6, 7))
            )  # 05:06 UTC-8 == 13:06 UTC

            # Timezone-naive datetime assumed to be Django current_timezone
            self.message.send_at = datetime(
                2022, 10, 11, 12, 13, 14, 567
            )  # microseconds should get stripped
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(
                data["send_at"], timegm((2022, 10, 11, 6, 13, 14))
            )  # 12:13 UTC+6 == 06:13 UTC

            # Date-only treated as midnight in current timezone
            self.message.send_at = date(2022, 10, 22)
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(
                data["send_at"], timegm((2022, 10, 21, 18, 0, 0))
            )  # 00:00 UTC+6 == 18:00-1d UTC

            # POSIX timestamp
            self.message.send_at = 1651820889  # 2022-05-06 07:08:09 UTC
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["send_at"], 1651820889)

    def test_tags(self):
        self.message.tags = ["receipt", "repeat-user"]
        self.message.send()
        data = self.get_api_call_json()
        self.assertCountEqual(data["categories"], ["receipt", "repeat-user"])

    def test_tracking(self):
        # Test one way...
        self.message.track_clicks = False
        self.message.track_opens = True
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["tracking_settings"]["click_tracking"], {"enable": False})
        self.assertEqual(data["tracking_settings"]["open_tracking"], {"enable": True})

        # ...and the opposite way
        self.message.track_clicks = True
        self.message.track_opens = False
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["tracking_settings"]["click_tracking"], {"enable": True})
        self.assertEqual(data["tracking_settings"]["open_tracking"], {"enable": False})

    def test_template_id(self):
        self.message.template_id = "5997fcf6-2b9f-484d-acd5-7e9a99f0dc1f"
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["template_id"], "5997fcf6-2b9f-484d-acd5-7e9a99f0dc1f")

    def test_template_id_with_empty_body(self):
        # v2 API required *some* text and html in message to render those template
        # bodies, so the v2 backend set those to " " when necessary.
        # But per v3 docs:
        #   "If you use a template that contains content and a subject (either text or
        #   html), you do not need to specify those in the respective personalizations
        #   or message level parameters."
        # So make sure we aren't adding body content where not needed:
        message = mail.EmailMessage(
            from_email="from@example.com", to=["to@example.com"]
        )
        message.template_id = "5997fcf6-2b9f-484d-acd5-7e9a99f0dc1f"
        message.send()
        data = self.get_api_call_json()
        self.assertNotIn("content", data)  # neither text nor html body
        self.assertNotIn("subject", data)

    def test_merge_data(self):
        # A template_id starting with "d-" indicates you are using SendGrid's newer
        # (non-legacy) "dynamic" transactional templates
        self.message.template_id = "d-5a963add2ec84305813ff860db277d7a"

        self.message.from_email = "from@example.com"
        self.message.to = [
            "alice@example.com",
            "Bob <bob@example.com>",
            "celia@example.com",
        ]
        # cc gets applied to *each* recipient in a merge:
        self.message.cc = ["cc@example.com"]

        self.message.merge_data = {
            "alice@example.com": {"name": "Alice", "group": "Developers"},
            "bob@example.com": {"name": "Bob"},  # and leave group undefined
            # and no data for celia@example.com
        }
        self.message.merge_global_data = {
            "group": "Users",
            "site": "ExampleCo",
        }
        self.message.send()

        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "cc": [{"email": "cc@example.com"}],  # all recipients get the cc
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "dynamic_template_data": {
                        "name": "Alice",
                        "group": "Developers",
                        "site": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "cc": [{"email": "cc@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-2"},
                    "dynamic_template_data": {
                        "name": "Bob",
                        "group": "Users",
                        "site": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "celia@example.com"}],
                    "cc": [{"email": "cc@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-3"},
                    "dynamic_template_data": {"group": "Users", "site": "ExampleCo"},
                },
            ],
        )
        self.assertNotIn("sections", data)  # 'sections' not used with dynamic templates

    def test_explicit_dynamic_template(self):
        # undocumented esp_extra['use_dynamic_template']
        # can be used to force dynamic/legacy params
        self.message.merge_data = {"to@example.com": {"test": "data"}}

        self.message.template_id = "apparently-not-dynamic"  # doesn't start with "d-"
        self.message.esp_extra = {"use_dynamic_template": True}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "to@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "dynamic_template_data": {"test": "data"},
                }
            ],
        )

        self.message.template_id = "d-apparently-not-legacy"
        self.message.esp_extra = {
            "use_dynamic_template": False,
            "merge_field_format": "<%{}%>",
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "to@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-2"},
                    "substitutions": {"<%test%>": "data"},
                }
            ],
        )

    def test_merge_data_global_only(self):
        # a template with only global data can be used to send the same message
        # to multiple recipients (non-batch)
        self.message.template_id = "d-5a963add2ec84305813ff860db277d7a"
        self.message.merge_global_data = {"test": "data"}
        self.message.to = ["one@example.com", "two@example.com"]
        self.message.send()

        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [  # not batch
                        {"email": "one@example.com"},
                        {"email": "two@example.com"},
                    ],
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "dynamic_template_data": {"test": "data"},
                }
            ],
        )

    def test_legacy_merge_data(self):
        # unless a new "dynamic template" is specified, Anymail assumes the legacy
        # "substitutions" format for merge data
        self.message.from_email = "from@example.com"
        self.message.to = [
            "alice@example.com",
            "Bob <bob@example.com>",
            "celia@example.com",
        ]
        # cc gets applied to *each* recipient in a merge:
        self.message.cc = ["cc@example.com"]
        # SendGrid template_id is not required to use merge.
        # You can just supply (legacy) template content as the message (e.g.):
        self.message.body = "Hi :name. Welcome to :group at :site."
        self.message.merge_data = {
            # You must either include merge field delimiters in the keys
            # (':name' rather than just 'name') as shown here, or use one of the
            # merge_field_format options shown in the test cases below
            "alice@example.com": {":name": "Alice", ":group": "Developers"},
            "bob@example.com": {":name": "Bob"},  # and leave :group undefined
            # and no data for celia@example.com
        }
        self.message.merge_global_data = {
            ":group": "Users",
            ":site": "ExampleCo",
        }
        self.message.send()

        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "cc": [{"email": "cc@example.com"}],  # all recipients get the cc
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "substitutions": {
                        ":name": "Alice",
                        ":group": "Developers",
                        ":site": "ExampleCo",  # merge_global_data merged
                    },
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "cc": [{"email": "cc@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-2"},
                    "substitutions": {
                        ":name": "Bob",
                        ":group": "Users",
                        ":site": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "celia@example.com"}],
                    "cc": [{"email": "cc@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-3"},
                    "substitutions": {":group": "Users", ":site": "ExampleCo"},
                },
            ],
        )
        # 'sections' no longer used for merge_global_data:
        self.assertNotIn("sections", data)

    @override_settings(
        ANYMAIL_SENDGRID_MERGE_FIELD_FORMAT=":{}"  # :field as shown in SG examples
    )
    def test_legacy_merge_field_format_setting(self):
        # Provide merge field delimiters in settings.py
        self.message.to = ["alice@example.com", "Bob <bob@example.com>"]
        self.message.merge_data = {
            "alice@example.com": {"name": "Alice", "group": "Developers"},
            "bob@example.com": {"name": "Bob"},  # and leave group undefined
        }
        self.message.merge_global_data = {"site": "ExampleCo"}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "substitutions": {
                        ":name": "Alice",
                        ":group": "Developers",  # keys changed to :field
                        ":site": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "custom_args": {"anymail_id": "mocked-uuid-2"},
                    "substitutions": {":name": "Bob", ":site": "ExampleCo"},
                },
            ],
        )

    def test_legacy_merge_field_format_esp_extra(self):
        # Provide merge field delimiters for an individual message
        self.message.to = ["alice@example.com", "Bob <bob@example.com>"]
        self.message.merge_data = {
            "alice@example.com": {"name": "Alice", "group": "Developers"},
            "bob@example.com": {"name": "Bob"},  # and leave group undefined
        }
        self.message.merge_global_data = {"site": "ExampleCo"}
        # match Mandrill/MailChimp *|field|* delimiters:
        self.message.esp_extra = {"merge_field_format": "*|{}|*"}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "substitutions": {
                        "*|name|*": "Alice",
                        "*|group|*": "Developers",
                        "*|site|*": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "custom_args": {"anymail_id": "mocked-uuid-2"},
                    "substitutions": {"*|name|*": "Bob", "*|site|*": "ExampleCo"},
                },
            ],
        )
        # Make sure our esp_extra merge_field_format doesn't get sent to SendGrid API:
        self.assertNotIn("merge_field_format", data)

    def test_legacy_warn_if_no_merge_field_delimiters(self):
        self.message.to = ["alice@example.com"]
        self.message.merge_data = {
            "alice@example.com": {"name": "Alice", "group": "Developers"},
        }
        with self.assertWarnsRegex(AnymailWarning, r"SENDGRID_MERGE_FIELD_FORMAT"):
            self.message.send()

    def test_legacy_warn_if_no_global_merge_field_delimiters(self):
        self.message.merge_global_data = {"site": "ExampleCo"}
        with self.assertWarnsRegex(AnymailWarning, r"SENDGRID_MERGE_FIELD_FORMAT"):
            self.message.send()

    def test_merge_metadata(self):
        self.message.to = ["alice@example.com", "Bob <bob@example.com>"]
        self.message.merge_metadata = {
            "alice@example.com": {"order_id": 123},
            "bob@example.com": {"order_id": 678, "tier": "premium"},
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    # anymail_id added to other custom_args
                    "custom_args": {"anymail_id": "mocked-uuid-1", "order_id": "123"},
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "custom_args": {
                        "anymail_id": "mocked-uuid-2",
                        "order_id": "678",
                        "tier": "premium",
                    },
                },
            ],
        )

    def test_metadata_with_merge_metadata(self):
        # Per SendGrid docs: "personalizations[x].custom_args will be merged
        # with message level custom_args, overriding any conflicting keys."
        # So there's no need to merge global metadata with per-recipient merge_metadata
        # (like we have to for template merge_global_data and merge_data).
        self.message.to = ["alice@example.com", "Bob <bob@example.com>"]
        self.message.metadata = {"tier": "basic", "batch": "ax24"}
        self.message.merge_metadata = {
            "alice@example.com": {"order_id": 123},
            "bob@example.com": {"order_id": 678, "tier": "premium"},
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-1", "order_id": "123"},
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "custom_args": {
                        "anymail_id": "mocked-uuid-2",
                        "order_id": "678",
                        "tier": "premium",
                    },
                },
            ],
        )
        self.assertEqual(data["custom_args"], {"tier": "basic", "batch": "ax24"})

    def test_merge_metadata_with_merge_data(self):
        # (using dynamic templates)
        self.message.to = [
            "alice@example.com",
            "Bob <bob@example.com>",
            "celia@example.com",
        ]
        # cc gets applied to *each* recipient in a merge:
        self.message.cc = ["cc@example.com"]
        self.message.template_id = "d-5a963add2ec84305813ff860db277d7a"
        self.message.merge_data = {
            "alice@example.com": {"name": "Alice", "group": "Developers"},
            "bob@example.com": {"name": "Bob"},
            # and no data for celia@example.com
        }
        self.message.merge_global_data = {
            "group": "Users",
            "site": "ExampleCo",
        }
        self.message.merge_metadata = {
            "alice@example.com": {"order_id": 123},
            "bob@example.com": {"order_id": 678, "tier": "premium"},
            # and no metadata for celia@example.com
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "cc": [{"email": "cc@example.com"}],  # all recipients get the cc
                    "dynamic_template_data": {
                        "name": "Alice",
                        "group": "Developers",
                        "site": "ExampleCo",
                    },
                    "custom_args": {"anymail_id": "mocked-uuid-1", "order_id": "123"},
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "cc": [{"email": "cc@example.com"}],
                    "dynamic_template_data": {
                        "name": "Bob",
                        "group": "Users",
                        "site": "ExampleCo",
                    },
                    "custom_args": {
                        "anymail_id": "mocked-uuid-2",
                        "order_id": "678",
                        "tier": "premium",
                    },
                },
                {
                    "to": [{"email": "celia@example.com"}],
                    "cc": [{"email": "cc@example.com"}],
                    "dynamic_template_data": {"group": "Users", "site": "ExampleCo"},
                    "custom_args": {"anymail_id": "mocked-uuid-3"},
                },
            ],
        )

    def test_merge_metadata_with_legacy_template(self):
        self.message.to = [
            "alice@example.com",
            "Bob <bob@example.com>",
            "celia@example.com",
        ]
        # cc gets applied to *each* recipient in a merge:
        self.message.cc = ["cc@example.com"]
        self.message.template_id = "5a963add2ec84305813ff860db277d7a"
        self.message.esp_extra = {"merge_field_format": ":{}"}
        self.message.merge_data = {
            "alice@example.com": {"name": "Alice", "group": "Developers"},
            "bob@example.com": {"name": "Bob"},
            # and no data for celia@example.com
        }
        self.message.merge_global_data = {
            "group": "Users",
            "site": "ExampleCo",
        }
        self.message.merge_metadata = {
            "alice@example.com": {"order_id": 123},
            "bob@example.com": {"order_id": 678, "tier": "premium"},
            # and no metadata for celia@example.com
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "alice@example.com"}],
                    "cc": [{"email": "cc@example.com"}],  # all recipients get the cc
                    "custom_args": {"anymail_id": "mocked-uuid-1", "order_id": "123"},
                    "substitutions": {
                        ":name": "Alice",
                        ":group": "Developers",
                        ":site": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "bob@example.com", "name": '"Bob"'}],
                    "cc": [{"email": "cc@example.com"}],
                    "custom_args": {
                        "anymail_id": "mocked-uuid-2",
                        "order_id": "678",
                        "tier": "premium",
                    },
                    "substitutions": {
                        ":name": "Bob",
                        ":group": "Users",
                        ":site": "ExampleCo",
                    },
                },
                {
                    "to": [{"email": "celia@example.com"}],
                    "cc": [{"email": "cc@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-3"},
                    "substitutions": {":group": "Users", ":site": "ExampleCo"},
                },
            ],
        )

    def test_merge_headers(self):
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
        personalizations = data["personalizations"]
        self.assertEqual(len(personalizations), 2)

        self.assertEqual(personalizations[0]["to"][0]["email"], "alice@example.com")
        self.assertEqual(
            personalizations[0]["headers"],
            {"List-Unsubscribe": "<https://example.com/a/>"},
        )
        self.assertEqual(personalizations[1]["to"][0]["email"], "bob@example.com")
        self.assertEqual(
            personalizations[1]["headers"],
            {"List-Unsubscribe": "<https://example.com/b/>"},
        )

        # non-merge headers still in globals:
        self.assertEqual(
            data["headers"],
            {
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Unsubscribe": "<mailto:unsubscribe@example.com>",
            },
        )

    @override_settings(
        ANYMAIL_SENDGRID_GENERATE_MESSAGE_ID=False  # else we force custom_args
    )
    def test_default_omits_options(self):
        """Make sure by default we don't send any ESP-specific options.

        Options not specified by the caller should be omitted entirely from
        the API call (*not* sent as False or empty). This ensures
        that your ESP account settings apply by default.
        """
        self.message.send()
        data = self.get_api_call_json()
        self.assertNotIn("asm", data)
        self.assertNotIn("attachments", data)
        self.assertNotIn("batch_id", data)
        self.assertNotIn("categories", data)
        self.assertNotIn("custom_args", data)
        self.assertNotIn("headers", data)
        self.assertNotIn("ip_pool_name", data)
        self.assertNotIn("mail_settings", data)
        self.assertNotIn("reply_to", data)
        self.assertNotIn("reply_to_list", data)
        self.assertNotIn("sections", data)
        self.assertNotIn("send_at", data)
        self.assertNotIn("template_id", data)
        self.assertNotIn("tracking_settings", data)

        for personalization in data["personalizations"]:
            self.assertNotIn("custom_args", personalization)
            self.assertNotIn("dynamic_template_data", personalization)
            self.assertNotIn("headers", personalization)
            self.assertNotIn("send_at", personalization)
            self.assertNotIn("substitutions", personalization)

    def test_esp_extra(self):
        self.message.tags = ["tag"]
        self.message.track_clicks = True
        self.message.esp_extra = {
            "ip_pool_name": "transactional",
            "asm": {  # subscription management
                "group_id": 1,
            },
            "tracking_settings": {
                "subscription_tracking": {
                    "enable": True,
                    "substitution_tag": "[unsubscribe_url]",
                },
            },
        }
        self.message.send()
        data = self.get_api_call_json()
        # merged from esp_extra:
        self.assertEqual(data["ip_pool_name"], "transactional")
        self.assertEqual(data["asm"], {"group_id": 1})
        self.assertEqual(
            data["tracking_settings"]["subscription_tracking"],
            {"enable": True, "substitution_tag": "[unsubscribe_url]"},
        )
        # make sure we didn't overwrite Anymail message options:
        self.assertEqual(data["categories"], ["tag"])
        self.assertEqual(data["tracking_settings"]["click_tracking"], {"enable": True})

    def test_esp_extra_pesonalizations(self):
        self.message.to = ["First recipient <first@example.com>", "second@example.com"]
        self.message.merge_data = {}  # force separate messages for each 'to'

        # esp_extra['personalizations'] dict
        # merges with message-derived personalizations
        self.message.esp_extra = {"personalizations": {"future_feature": "works"}}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "first@example.com", "name": '"First recipient"'}],
                    "custom_args": {"anymail_id": "mocked-uuid-1"},
                    "future_feature": "works",
                },
                {
                    "to": [{"email": "second@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-2"},
                    "future_feature": "works",  # merged into *every* recipient
                },
            ],
        )

        # but esp_extra['personalizations'] list just overrides entire personalizations
        # (for backwards compatibility)
        self.message.esp_extra = {
            "personalizations": [
                {"to": [{"email": "custom@example.com"}], "future_feature": "works"}
            ]
        }
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"],
            [
                {
                    "to": [{"email": "custom@example.com"}],
                    "custom_args": {"anymail_id": "mocked-uuid-3"},
                    "future_feature": "works",
                },
            ],
        )

    # noinspection PyUnresolvedReferences
    def test_send_attaches_anymail_status(self):
        """The anymail_status should be attached to the message when it is sent"""
        # the DEFAULT_RAW_RESPONSE above is the *only* success response SendGrid
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
        self.assertEqual(msg.anymail_status.message_id, "mocked-uuid-1")
        self.assertEqual(
            msg.anymail_status.recipients["to1@example.com"].status, "queued"
        )
        self.assertEqual(
            msg.anymail_status.recipients["to1@example.com"].message_id, "mocked-uuid-1"
        )
        self.assertEqual(
            msg.anymail_status.esp_response.content, self.DEFAULT_RAW_RESPONSE
        )

    def test_batch_recipients_get_unique_message_ids(self):
        """In a batch send, each recipient should get a distinct own message_id"""
        msg = mail.EmailMessage(
            "Subject",
            "Message",
            "from@example.com",
            ["to1@example.com", "Someone Else <to2@example.com>"],
            cc=["cc@example.com"],
        )
        msg.merge_data = {}  # force batch send
        msg.send()
        self.assertEqual(
            msg.anymail_status.message_id, {"mocked-uuid-1", "mocked-uuid-2"}
        )
        self.assertEqual(
            msg.anymail_status.recipients["to1@example.com"].message_id, "mocked-uuid-1"
        )
        self.assertEqual(
            msg.anymail_status.recipients["to2@example.com"].message_id, "mocked-uuid-2"
        )
        # cc's (and bcc's) get copied for all batch recipients,
        # but we can only communicate one message_id:
        self.assertEqual(
            msg.anymail_status.recipients["cc@example.com"].message_id, "mocked-uuid-2"
        )

    @override_settings(ANYMAIL_SENDGRID_GENERATE_MESSAGE_ID=False)
    def test_disable_generate_message_id(self):
        msg = mail.EmailMessage(
            "Subject",
            "Message",
            "from@example.com",
            ["to1@example.com"],
        )
        msg.send()
        self.assertIsNone(msg.anymail_status.message_id)
        self.assertIsNone(msg.anymail_status.recipients["to1@example.com"].message_id)

    # noinspection PyUnresolvedReferences
    def test_send_failed_anymail_status(self):
        """If the send fails, anymail_status should contain initial values"""
        self.set_mock_response(status_code=500)
        sent = self.message.send(fail_silently=True)
        self.assertEqual(sent, 0)
        self.assertIsNone(self.message.anymail_status.status)
        self.assertIsNone(self.message.anymail_status.message_id)
        self.assertEqual(self.message.anymail_status.recipients, {})
        self.assertIsNone(self.message.anymail_status.esp_response)

    def test_json_serialization_errors(self):
        """Try to provide more information about non-json-serializable data"""
        self.message.metadata = {"total": Decimal("19.99")}
        with self.assertRaises(AnymailSerializationError) as cm:
            self.message.send()
        err = cm.exception
        self.assertIsInstance(err, TypeError)  # compatibility with json.dumps
        # our added context:
        self.assertIn("Don't know how to send this data to SendGrid", str(err))
        # original message:
        self.assertRegex(str(err), r"Decimal.*is not JSON serializable")

    @override_settings(ANYMAIL_SENDGRID_WORKAROUND_NAME_QUOTE_BUG=False)
    def test_undocumented_workaround_name_quote_bug_setting(self):
        mail.send_mail(
            "Subject",
            "Body",
            '"Sender, Inc." <from@example.com',
            ['"Recipient, Ltd." <to@example.com>'],
        )
        data = self.get_api_call_json()
        self.assertEqual(
            data["personalizations"][0]["to"][0],
            {
                "email": "to@example.com",
                "name": "Recipient, Ltd.",  # no extra quotes on name
            },
        )
        self.assertEqual(
            data["from"], {"email": "from@example.com", "name": "Sender, Inc."}
        )


@tag("sendgrid")
class SendGridBackendRecipientsRefusedTests(SendGridBackendMockAPITestCase):
    """
    Should raise AnymailRecipientsRefused when *all* recipients are rejected or invalid
    """

    # SendGrid doesn't check email bounce or complaint lists at time of send --
    # it always just queues the message. You'll need to listen for the "rejected"
    # and "failed" events to detect refused recipients.
    pass  # not applicable to this backend


@tag("sendgrid")
class SendGridBackendSessionSharingTestCase(
    SessionSharingTestCases, SendGridBackendMockAPITestCase
):
    """Requests session sharing tests"""

    pass  # tests are defined in SessionSharingTestCases


@tag("sendgrid")
@override_settings(EMAIL_BACKEND="anymail.backends.sendgrid.EmailBackend")
class SendGridBackendImproperlyConfiguredTests(AnymailTestMixin, SimpleTestCase):
    """Test ESP backend without required settings in place"""

    def test_missing_auth(self):
        with self.assertRaisesRegex(AnymailConfigurationError, r"\bSENDGRID_API_KEY\b"):
            mail.send_mail("Subject", "Message", "from@example.com", ["to@example.com"])


@tag("sendgrid")
@override_settings(EMAIL_BACKEND="anymail.backends.sendgrid.EmailBackend")
class SendGridBackendDisallowsV2Tests(AnymailTestMixin, SimpleTestCase):
    """Using v2-API-only features should cause errors with v3 backend"""

    @override_settings(
        ANYMAIL={"SENDGRID_USERNAME": "sg_username", "SENDGRID_PASSWORD": "sg_password"}
    )
    def test_user_pass_auth(self):
        """Make sure v2-only USERNAME/PASSWORD auth raises error"""
        with self.assertRaisesMessage(
            AnymailConfigurationError,
            "SendGrid v3 API doesn't support username/password auth;"
            " Please change to API key.",
        ):
            mail.send_mail("Subject", "Message", "from@example.com", ["to@example.com"])

    @override_settings(ANYMAIL={"SENDGRID_API_KEY": "test_api_key"})
    def test_esp_extra_smtpapi(self):
        """x-smtpapi in the esp_extra indicates a desire to use the v2 api"""
        message = mail.EmailMessage(
            "Subject", "Body", "from@example.com", ["to@example.com"]
        )
        message.esp_extra = {"x-smtpapi": {"asm_group_id": 1}}
        with self.assertRaisesMessage(
            AnymailConfigurationError,
            "You are attempting to use SendGrid v2 API-style x-smtpapi params with the"
            " SendGrid v3 API. Please update your `esp_extra` to the new API.",
        ):
            message.send()
