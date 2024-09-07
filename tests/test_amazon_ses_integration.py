import os
import unittest
from email.utils import formataddr

from django.test import SimpleTestCase, override_settings, tag

from anymail.exceptions import AnymailAPIError
from anymail.message import AnymailMessage

from .utils import AnymailTestMixin, sample_image_path

ANYMAIL_TEST_AMAZON_SES_ACCESS_KEY_ID = os.getenv(
    "ANYMAIL_TEST_AMAZON_SES_ACCESS_KEY_ID"
)
ANYMAIL_TEST_AMAZON_SES_SECRET_ACCESS_KEY = os.getenv(
    "ANYMAIL_TEST_AMAZON_SES_SECRET_ACCESS_KEY"
)
ANYMAIL_TEST_AMAZON_SES_REGION_NAME = os.getenv(
    "ANYMAIL_TEST_AMAZON_SES_REGION_NAME", "us-east-1"
)
ANYMAIL_TEST_AMAZON_SES_DOMAIN = os.getenv("ANYMAIL_TEST_AMAZON_SES_DOMAIN")


@unittest.skipUnless(
    ANYMAIL_TEST_AMAZON_SES_ACCESS_KEY_ID
    and ANYMAIL_TEST_AMAZON_SES_SECRET_ACCESS_KEY
    and ANYMAIL_TEST_AMAZON_SES_DOMAIN,
    "Set ANYMAIL_TEST_AMAZON_SES_ACCESS_KEY_ID and"
    " ANYMAIL_TEST_AMAZON_SES_SECRET_ACCESS_KEY and ANYMAIL_TEST_AMAZON_SES_DOMAIN"
    " environment variables to run Amazon SES integration tests",
)
@override_settings(
    EMAIL_BACKEND="anymail.backends.amazon_ses.EmailBackend",
    ANYMAIL={
        "AMAZON_SES_CLIENT_PARAMS": {
            # This setting provides Anymail-specific AWS credentials to boto3.client(),
            # overriding any credentials in the environment or boto config. It's often
            # *not* the best approach. See the Anymail and boto3 docs for other options.
            "aws_access_key_id": ANYMAIL_TEST_AMAZON_SES_ACCESS_KEY_ID,
            "aws_secret_access_key": ANYMAIL_TEST_AMAZON_SES_SECRET_ACCESS_KEY,
            "region_name": ANYMAIL_TEST_AMAZON_SES_REGION_NAME,
            # Can supply any other boto3.client params,
            # including botocore.config.Config as dict
            "config": {"retries": {"max_attempts": 2}},
        },
        # actual config set in Anymail test account:
        "AMAZON_SES_CONFIGURATION_SET_NAME": "TestConfigurationSet",
    },
)
@tag("amazon_ses", "live")
class AmazonSESBackendIntegrationTests(AnymailTestMixin, SimpleTestCase):
    """Amazon SES API integration tests

    These tests run against the **live** Amazon SES API, using the environment
    variables `ANYMAIL_TEST_AMAZON_SES_ACCESS_KEY_ID` and
    `ANYMAIL_TEST_AMAZON_SES_SECRET_ACCESS_KEY` as AWS credentials.
    If those variables are not set, these tests won't run.

    (You can also set the environment variable `ANYMAIL_TEST_AMAZON_SES_REGION_NAME`
    to test SES using a region other than the default "us-east-1".)

    Amazon SES doesn't offer a test mode -- it tries to send everything you ask.
    To avoid stacking up a pile of undeliverable @example.com
    emails, the tests use Amazon's @simulator.amazonses.com addresses.
    https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mailbox-simulator.html
    """

    def setUp(self):
        super().setUp()
        self.from_email = f"test@{ANYMAIL_TEST_AMAZON_SES_DOMAIN}"
        self.message = AnymailMessage(
            "Anymail Amazon SES integration test",
            "Text content",
            self.from_email,
            ["success@simulator.amazonses.com"],
        )
        self.message.attach_alternative("<p>HTML content</p>", "text/html")

    def test_simple_send(self):
        # Example of getting the Amazon SES send status and message id from the message
        sent_count = self.message.send()
        self.assertEqual(sent_count, 1)

        anymail_status = self.message.anymail_status
        sent_status = anymail_status.recipients[
            "success@simulator.amazonses.com"
        ].status
        message_id = anymail_status.recipients[
            "success@simulator.amazonses.com"
        ].message_id

        # Amazon SES always queues (or raises an error):
        self.assertEqual(sent_status, "queued")
        # Amazon SES message ids are groups of hex chars:
        self.assertRegex(message_id, r"[0-9a-f-]+")
        # set of all recipient statuses:
        self.assertEqual(anymail_status.status, {sent_status})
        self.assertEqual(anymail_status.message_id, message_id)

    def test_all_options(self):
        message = AnymailMessage(
            subject="Anymail Amazon SES all-options integration test",
            body="This is the text body",
            from_email=formataddr(("Test From, with comma", self.from_email)),
            to=[
                "success+to1@simulator.amazonses.com",
                "Recipient 2 <success+to2@simulator.amazonses.com>",
            ],
            cc=[
                "success+cc1@simulator.amazonses.com",
                "Copy 2 <success+cc2@simulator.amazonses.com>",
            ],
            bcc=[
                "success+bcc1@simulator.amazonses.com",
                "Blind Copy 2 <success+bcc2@simulator.amazonses.com>",
            ],
            reply_to=["reply1@example.com", "Reply 2 <reply2@example.com>"],
            headers={"X-Anymail-Test": "value"},
            metadata={"meta1": "simple_string", "meta2": 2},
            tags=["Re-engagement", "Cohort 12/2017"],
            envelope_sender=f"bounce-handler@{ANYMAIL_TEST_AMAZON_SES_DOMAIN}",
        )
        message.attach("attachment1.txt", "Here is some\ntext for you", "text/plain")
        message.attach("attachment2.csv", "ID,Name\n1,Amy Lina", "text/csv")
        cid = message.attach_inline_image_file(sample_image_path())
        message.attach_alternative(
            "<p><b>HTML:</b> with <a href='http://example.com'>link</a>"
            "and image: <img src='cid:%s'></div>" % cid,
            "text/html",
        )

        message.attach_alternative(
            "Amazon SES SendRawEmail actually supports multiple alternative parts",
            "text/x-note-for-email-geeks",
        )

        message.send()
        self.assertEqual(message.anymail_status.status, {"queued"})

    def test_stored_template(self):
        # Using a template created like this:
        # boto3.client('sesv2').create_email_template(
        #     TemplateName="TestTemplate",
        #     TemplateContent={
        #         "Subject": "Your order {{order}} shipped",
        #         "Html": "<h1>Dear {{name}}:</h1>"
        #                 "<p>Your order {{order}} shipped {{ship_date}}.</p>",
        #         "Text": "Dear {{name}}:\r\n"
        #                 "Your order {{order}} shipped {{ship_date}}."
        #     },
        # )
        message = AnymailMessage(
            template_id="TestTemplate",
            from_email=formataddr(("Test From", self.from_email)),
            to=[
                "First Recipient <success+to1@simulator.amazonses.com>",
                "success+to2@simulator.amazonses.com",
            ],
            merge_data={
                "success+to1@simulator.amazonses.com": {
                    "order": 12345,
                    "name": "Test Recipient",
                },
                "success+to2@simulator.amazonses.com": {"order": 6789},
            },
            merge_global_data={"name": "Customer", "ship_date": "today"},  # default
            headers={
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            },
            merge_headers={
                "success+to1@simulator.amazonses.com": {
                    "List-Unsubscribe": "<https://example.com/unsubscribe/to1>"
                },
                "success+to2@simulator.amazonses.com": {
                    "List-Unsubscribe": "<https://example.com/unsubscribe/to2>"
                },
            },
            tags=["Live integration test", "Template send"],
            metadata={"test": "data"},
            merge_metadata={"success+to2@simulator.amazonses.com": {"user-id": "2"}},
        )
        message.send()
        recipient_status = message.anymail_status.recipients
        self.assertEqual(
            recipient_status["success+to1@simulator.amazonses.com"].status, "queued"
        )
        self.assertRegex(
            recipient_status["success+to1@simulator.amazonses.com"].message_id,
            r"[0-9a-f-]+",
        )
        self.assertEqual(
            recipient_status["success+to2@simulator.amazonses.com"].status, "queued"
        )
        self.assertRegex(
            recipient_status["success+to2@simulator.amazonses.com"].message_id,
            r"[0-9a-f-]+",
        )

    @override_settings(
        ANYMAIL={
            "AMAZON_SES_CLIENT_PARAMS": {
                "aws_access_key_id": "test-invalid-access-key-id",
                "aws_secret_access_key": "test-invalid-secret-access-key",
                "region_name": ANYMAIL_TEST_AMAZON_SES_REGION_NAME,
            }
        }
    )
    def test_invalid_aws_credentials(self):
        # Make sure the exception message includes AWS's response:
        with self.assertRaisesMessage(
            AnymailAPIError, "The security token included in the request is invalid"
        ):
            self.message.send()
