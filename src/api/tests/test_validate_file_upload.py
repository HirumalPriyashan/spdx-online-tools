# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017 Rohit Lodha
# Copyright (c) 2017 Rohit Lodha
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APITestCase

from api.models import ValidateFileUpload
import os

def getExamplePath(filename):
    return os.path.join(settings.EXAMPLES_DIR, filename)


class ValidateFileUploadTests(APITestCase):
    """Test for validate api with all
    possible combination of POST and GET
    request with login enabled.
    """

    def setUp(self):
        self.username = "validateapitestuser"
        self.password = "validateapitestpass"
        self.tearDown()
        self.credentials = {"username": self.username, "password": self.password}
        u = User.objects.create_user(**self.credentials)
        u.is_staff = True
        u.save()
        self.tv_file = open(getExamplePath("SPDXTagExample-v2.0.spdx"))
        self.rdf_file = open(getExamplePath("SPDXRdfExample-v2.0.rdf"))
        self.invalid_tv_file = open(getExamplePath("SPDXTagExample-v2.0_invalid.spdx"))
        self.invalid_rdf_file = open(getExamplePath("SPDXRdfExample-v2.0_invalid.rdf"))

    def tearDown(self):
        try:
            u = User.objects.get_by_natural_key(self.username)
            u.delete()
        except ObjectDoesNotExist:
            pass
        ValidateFileUpload.objects.all().delete()

    def test_validate_api(self):
        """Access get without login"""
        resp1 = self.client.get(reverse("validate-api"))
        self.assertTrue(resp1.status_code, 403)
        self.client.login(username=self.username, password=self.password)
        """ Access get after login"""
        resp2 = self.client.get(reverse("validate-api"))
        self.assertTrue(resp2.status_code, 200)
        """ Valid Tag Value File"""
        resp3 = self.client.post(
            reverse("validate-api"),
            {"file": self.tv_file, "format": "TAG"},
            format="multipart",
        )
        self.assertEqual(resp3.status_code, 200)
        self.assertEqual(
            resp3.data["owner"], User.objects.get_by_natural_key(self.username).id
        )
        self.assertEqual(resp3.data["result"], "This SPDX Document is valid.")
        """ Valid RDF File"""
        resp4 = self.client.post(
            reverse("validate-api"),
            {"file": self.rdf_file, "format": "RDFXML"},
            format="multipart",
        )
        self.assertEqual(resp4.status_code, 200)
        self.assertEqual(
            resp4.data["owner"], User.objects.get_by_natural_key(self.username).id
        )
        self.assertEqual(resp4.data["result"], "This SPDX Document is valid.")
        """ Invalid Tag Value File"""
        resp5 = self.client.post(
            reverse("validate-api"),
            {"file": self.invalid_tv_file, "format": "TAG"},
            format="multipart",
        )
        self.assertEqual(
            resp5.data["owner"], User.objects.get_by_natural_key(self.username).id
        )
        self.assertEqual(resp5.status_code, 400)
        self.assertNotEqual(resp5.data["result"], "This SPDX Document is valid.")
        """ Invalid RDF File"""
        resp6 = self.client.post(
            reverse("validate-api"),
            {"file": self.invalid_rdf_file, "format": "RDFXML"},
            format="multipart",
        )
        self.assertEqual(
            resp6.data["owner"], User.objects.get_by_natural_key(self.username).id
        )
        self.assertEqual(resp6.status_code, 400)
        self.assertNotEqual(resp6.data["result"], "This SPDX Document is valid.")
        self.client.logout()
        self.tearDown()

    def test_validate_without_argument(self):
        self.client.login(username=self.username, password=self.password)
        resp7 = self.client.post(reverse("validate-api"), {}, format="multipart")
        self.assertEqual(resp7.status_code, 400)
        self.client.logout()
        self.tearDown()
