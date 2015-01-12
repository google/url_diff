#!/usr/bin/env python
"""
Copyright 2014 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""
Tests for url_diff
"""

import unittest
import url_diff

class TestUrlDiffer(unittest.TestCase):
  NORMALIZED_URL_WITHOUT_PARAMS = 'http://localhost/'
  NORMALIZED_URL_WITH_PARMAS = ('%s?key=val&aperture=science&cake=lie' %
      NORMALIZED_URL_WITHOUT_PARAMS)
  NORMALIZED_URLS = [NORMALIZED_URL_WITHOUT_PARAMS, NORMALIZED_URL_WITH_PARMAS]
  sample_urls = {
      'http://www.nytimes.com/2013/12/31/science/viewing-where-the-internet-goes.html?_r=0':
      'www.nytimes.com',
      'https://twitter.com':
      'twitter.com',
      'https://mail.google.com/mail/u/0/?ui=2&shva=1#inbox':
      'mail.google.com',
      'http://something.localdomain/search?site=default_collection&client=default_frontend&output=xml_no_dtd&proxystylesheet=default_frontend&proxycustom=%3CHOME/%3E':
      'something.localdomain',
      '/~macpd/url_diff/':
      '',
      '/2/library/unittest.html#assert-methods':
      ''}

  def setUp(self):
    self.empty_differ = url_diff.UrlDiffer('', '')

  def testGetHostname(self):
    """Test hostname correctly parsed from URL."""
    for url in self.sample_urls:
      self.assertEquals(self.empty_differ._get_hostname(url),
                        self.sample_urls.get(url))

  def testNormalizeUrlWithoutParams(self):
    """Tests url whitespace trimmed, and truncated at hash."""
    for normalized_url in self.NORMALIZED_URLS:
      spaces_on_each_end = '  %s  ' % normalized_url
      hash_at_end =  '%s#' % normalized_url
      hash_with_trailing_chars = ('%s#to%%20be%%20removed' %
          normalized_url)
      self.assertEqual(self.empty_differ._normalize_url(spaces_on_each_end),
                       normalized_url)
      self.assertEqual(self.empty_differ._normalize_url(hash_at_end),
                       normalized_url)
      self.assertEqual(
          self.empty_differ._normalize_url(hash_with_trailing_chars),
          normalized_url)
      # alse confirm normalized URL not changed
      self.assertEqual(
          self.empty_differ._normalize_url(normalized_url),
          normalized_url)

  def testEmptyURLsAreEqual(self):
    """Tests empty URLs are considered equal."""
    self.assertFalse(self.empty_differ.are_different())

  def testUrlDecode(self):
    """Tests percent encoded strings are correctly decoded to ASCII."""
    self.assertEqual('<HOME/>', self.empty_differ._url_decode('%3CHOME/%3E'))
