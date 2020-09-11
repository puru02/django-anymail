.. _performance:

Batch send performance
======================

If you are sending batches of hundreds of emails at a time, you can improve
performance slightly by reusing a single HTTP connection to your ESP's
API, rather than creating (and tearing down) a new connection for each message.

Most Anymail EmailBackends automatically reuse their HTTP connections when
used with Django's batch-sending functions :func:`~django.core.mail.send_mass_mail` or
:meth:`connection.send_messages`. See :ref:`django:topics-sending-multiple-emails`
in the Django docs for more info and an example.

If you need even more performance, you may want to consider your ESP's batch-sending
features. When supported by your ESP, Anymail can send multiple messages with a single
API call. See :ref:`batch-send` for details, and be sure to check the
:ref:`ESP-specific info <supported-esps>` because batch sending capabilities vary
significantly between ESPs.
