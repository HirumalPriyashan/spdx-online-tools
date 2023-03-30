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
# limitations under the License.

from django import forms
from django.contrib.auth.models import User
from django.contrib.admin import widgets

from app.models import UserID, LicenseNamespace, OrganisationName
from app.widgets import RelatedFieldWidgetCanAdd

OSI_CHOICES = (
    (0, "-"),
    ("Approved", "Approved"),
    ("Not Submitted", "Not Submitted"),
    ("Pending", "Submitted, but pending"),
    ("Rejected", "Rejected"),
    ("Unknown", "Don't know")
)

class UserRegisterForm(forms.ModelForm):

    password = forms.CharField(widget=forms.PasswordInput())
    confirm_password = forms.CharField(widget=forms.PasswordInput())
    def clean_username(self):
        users = self.cleaned_data["username"]
        if User.objects.filter(username=users).count() > 0:
            raise forms.ValidationError("This username already exists.")
        return users
    def clean(self):
        password = self.cleaned_data.get('password')
        confirm_password = self.cleaned_data.get('confirm_password')
        if password and password != confirm_password:
            raise forms.ValidationError("Passwords don't match.")
        return self.cleaned_data
    class Meta:
        model = User
        fields = ('first_name','last_name','email','username','password','confirm_password')

class UserProfileForm(forms.ModelForm):

    class Meta:
        model = UserID
        fields = ('organisation',)

class InfoForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('first_name','last_name','email')

class OrgInfoForm(forms.ModelForm):

    class Meta:
        model = UserID
        fields = ('organisation',)

class LicenseRequestForm(forms.Form):

    def __init__(self, *args, **kwargs):
        if 'email' in kwargs:
            self.email = kwargs.pop('email')
        else:
            self.email = ""
        super(LicenseRequestForm, self).__init__(*args,**kwargs)
        self.fields["userEmail"] = forms.EmailField(label='Email', initial=self.email, max_length=35, required=False)

    licenseAuthorName = forms.CharField(label="License Author name", max_length=100, required=False)
    fullname = forms.CharField(label="Fullname", max_length=70)
    shortIdentifier = forms.CharField(label='Short identifier', max_length=25)
    sourceUrl = forms.CharField(label='Source / URL', required=False)
    osiApproved = forms.CharField(label="OSI Status", widget=forms.Select(choices=OSI_CHOICES))
    exampleUrl = forms.CharField(label='Example Projects / URL', required=True)
    comments = forms.CharField(label='Comments', required=True, widget=forms.Textarea(attrs={'rows': 4, 'cols': 40}))
    licenseHeader = forms.CharField(label='Standard License Header', widget=forms.Textarea(attrs={'rows': 3, 'cols': 40}), required=False)
    text = forms.CharField(label='Text', widget=forms.Textarea(attrs={'rows': 4, 'cols': 40}))


class LicenseNamespaceRequestForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        if 'email' in kwargs:
            self.email = kwargs.pop('email')
        else:
            self.email = ""
        super(LicenseNamespaceRequestForm, self).__init__(*args, **kwargs)
        self.fields['shortIdentifier'].required = False
        self.fields['url'].required = True
        self.fields['license_list_url'].required = False
        self.fields['github_repo_url'].required = False
        self.fields['organisation'].required = False
        self.fields["userEmail"] = forms.EmailField(label='Email', initial=self.email, max_length=35, required=False)

    organisation = forms.ModelChoiceField(
       required=False,
       queryset=OrganisationName.objects.all(),
       widget=RelatedFieldWidgetCanAdd(OrganisationName))

    class Meta:
        model = LicenseNamespace
        fields = ('organisation', 'licenseAuthorName',
                  'fullname', 'userEmail', 'url',
                  'license_list_url', 'github_repo_url',
                  'publiclyShared', 'namespace',
                  'description', 'archive', 'shortIdentifier')
