"""
This file demonstrates two different styles of tests (one doctest and one
unittest). These will both pass when you run "manage.py test".

Replace these with more appropriate tests for your application.
"""

from django.test import TestCase

from idpauth.models import CustomUser

class AuthTest(TestCase):
    def setUp(self):
        self.c = CustomUser.objects.create(name="Test", idp="local", username="test")

    def test_custom_user(self):
        self.assertEquals(self.c.username, "Test")
