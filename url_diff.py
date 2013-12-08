#!/usr/bin/python2
"""
Copyright 2013 Google Inc. All Rights Reserved.

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

"""A tool to show the differnce in URLs.

A tool for showing the differnces between URLs.  This is inspired by the unix
utility diff.
"""

import argparse
import copy
import logging
import sys

class Error(Exception):
  """Base exception class."""
  pass

class ParamDiffTypeError(Error):
  """Raised when an incorrect diff type used."""
  pass

class HostnameParseError(Error):
  """Raised when unable to parse hostname from URL."""
  pass

# TODO(macpd): investigate making this a namedtuple
class ParamDiffEntry(object):
  """Represents difference of 2 URL params with same name."""
  LEFT_ONLY = 1
  RIGHT_ONLY = 2
  BOTH_DIFFER = 3
  LEFT_VALUE_FORMAT = '{0}\n< {1}'
  RIGHT_VALUE_FORMAT = '{0}\n> {1}'

  def __init__(self, name, left_value, right_value, diff_type):
    self._name = name
    self._left_val = left_value
    self._right_val = right_value
    try:
      if self._valid_diff_type(diff_type):
        self._type = diff_type
    except ParamDiffTypeError:
      logging.error("Incorrect diff type: %s", diff_type)
      self._type = self.BOTH_DIFFER

  def _valid_diff_type(self, diff_type):
    if (diff_type != self.LEFT_ONLY and diff_type != self.RIGHT_ONLY and
        diff_type != self.BOTH_DIFFER):
      raise ParamDiffTypeError('%s is not a valid diff type. ', diff_type)
    return True

  @property
  def name(self):
    return self._name

  def __str__(self):
    ret = self._name
    if self._type == self.LEFT_ONLY or self._type == self.BOTH_DIFFER:
      ret = self.LEFT_VALUE_FORMAT.format(ret, self._left_val)
    if self._type == self.RIGHT_ONLY or self._type == self.BOTH_DIFFER:
      ret = self.RIGHT_VALUE_FORMAT.format(ret, self._right_val)
    return ret


class UrlDiffer(object):
  """Object to diff URLs.

  Diffs URLs upon intialization."""

  PATH_DELIM = '?'
  PARAM_DELIM = '&'
  NAME_VAL_DELIM = '='
  SCHEME_DELIM = '://'
  UNIX_SLASH = '/'
  ESCAPE_SEQ_LEN = 3

  def __init__(self, left_url, right_url, names_only=False, hostnames=False,
      url_decode_params=False):
    """Initializes object and performs URL diffing."""
    self._left_url = self._normalize_url(left_url)
    self._right_url = self._normalize_url(right_url)
    self._names_only = names_only
    self._wants_hostname_diff = hostnames
    self._url_decode_params = url_decode_params
    self._diffs = []
    self._do_diff()

  def __str__(self):
    ret = []
    for diff in self._diffs:
      if self._names_only:
        ret.append(diff.name)
      else:
        ret.append(str(diff))
    join_delim = '\n' if self._names_only else '\n\n'
    return join_delim.join(ret)

  def _normalize_url(self, url):
    """Strips white space, and removes all chars after #"""
    ret = url.strip()
    if '#' in ret:
      idx = ret.index('#')
      ret = ret[:idx]
    return ret

  def _get_hostname(self, url):
    """Parses the hostname from a URL."""
    # find hostname between scheme and first unix slash
    if self.SCHEME_DELIM in url:
      scheme_idx = url.index(self.SCHEME_DELIM)
      hostname_begin = scheme_idx + len(self.SCHEME_DELIM)
    else:
      hostname_begin = 0

    if self.UNIX_SLASH in url[hostname_begin:]:
      hostname_end = url.index(self.UNIX_SLASH, hostname_begin)
    else:
      hostname_end = len(url[hostname_begin:])

    return url[hostname_begin:hostname_end]

  def _diff_hostnames(self, left, right):
    """Diffs hostnames, if different appends ParamDiffEntry to diffs list.

    Args:
      left: String; left hostname.
      right: String; right hostname.
    Returns:
      Bool; True if different, else False.
    """
    if left == right:
      self._hostnames_differ = False
    else:
      self._hostnames_differ = True
      self._diffs.append(ParamDiffEntry('Hostname', left, right,
          ParamDiffEntry.BOTH_DIFFER))

    return self._hostnames_differ

  def _get_params(self, url):
    """Returns a dict of the url params.

      Args:
        url: String; URL to get parameter names and values from.
      Returns:
        Dict of parameter names that map to their values."""
    param_dict = {}
    if self.PATH_DELIM not in url:
      return param_dict
    params_pos = url.find(self.PATH_DELIM) + 1
    for token in url[params_pos:].split(self.PARAM_DELIM):
      if not token:
        continue
      if self._url_decode_params:
        token = self._url_decode(token)
      if '=' not in token:
        param_dict[token] = ''
      else:
        partitioned_param = token.partition(self.NAME_VAL_DELIM)
        param_dict[partitioned_param[0]] = partitioned_param[2]
    return param_dict

  def _diff_params(self, left_params, right_params):
    """Returns a list of the diffence between dicts on key/values.

    Args:
      left_param: dict; param name -> value dict of the left URL.
      right_param: dict; param name -> value dict of the right URL.

    Returns:
      List of ParamDiffEntry of differences between the left and right params.
    """
    diffs = []
    for left_key in left_params.iterkeys():
      if left_key in right_params:
        if left_params[left_key] != right_params[left_key]:
          diffs.append(ParamDiffEntry(
            left_key, left_params[left_key], right_params[left_key],
            ParamDiffEntry.BOTH_DIFFER))
      else:
        diffs.append(ParamDiffEntry(
          left_key, left_params[left_key], None, ParamDiffEntry.LEFT_ONLY))

    for right_key in right_params.iterkeys():
      if right_key not in left_params:
        diffs.append(ParamDiffEntry(
          right_key, None, right_params[right_key], ParamDiffEntry.RIGHT_ONLY))

    return diffs

  def _do_diff(self):
    """Performs all appropriate diffing operations."""
    if self._wants_hostname_diff:
      self._left_hostname = self._get_hostname(self._left_url)
      self._right_hostname = self._get_hostname(self._right_url)
      self._diff_hostnames(self._left_hostname, self._right_hostname)
    self._left_params_dict = self._get_params(self._left_url)
    self._right_params_dict = self._get_params(self._right_url)
    if not self._left_params_dict == self._right_params_dict:
      self._diffs.extend(self._diff_params(
          self._left_params_dict, self._right_params_dict))

  def _url_decode(self, token):
    """URL decodes provided string.

    Replaces all instances of %NN with the ascii value of hex(NN).

    Args:
      token: String to be decoded.
    Returns:
      String; deocded string.
    """
    if '%' not in token:
      return token
    new_token = []
    cur = prev = 0
    cur = token.find('%', prev)
    while(cur != -1):
      new_token.append(token[prev:cur])
      new_token.append(token[cur+1:cur+self.ESCAPE_SEQ_LEN].decode('hex'))
      prev = cur + self.ESCAPE_SEQ_LEN
      cur = token.find('%', prev)

    new_token.append(token[prev:])
    return ''.join(new_token)

  def left_params(self):
    """Returns a deep coy of the left params dict."""
    return copy.deepcopy(self._left_params_dict)

  def right_params(self):
    """Returns a deep coy of the left params dict."""
    return copy.deepcopy(self._right_params_dict)

  def are_different(self):
    """Returns True if URLs differ, else false."""
    return len(self._diffs) != 0

  @property
  def diff(self):
    return copy.deepcopy(self._diffs)


def main():
  # TODO(macpd): main function documentation
  # TODO(macpd): usage string
  # TODO(macpd): provide option to diff case insensitively
  # TODO(macpd): provide verbosity option
  # TODO(macpd): handle duplicate keys with different values in same URL
  arg_parser = argparse.ArgumentParser(
      description='show the difference between 2 urls. Inspired by the unix utility diff',
      epilog='Currenty this tool discards everything after # if present. see https://github.com/google/url_diff for more information.')
  arg_parser.add_argument('--hostname', default=False, required=False,
      help='also diff URL hostname', action='store_true', dest='diff_hostname')
  arg_parser.add_argument('--names', '-n', default=False, required=False,
      help='only diff URL parameter names.', action='store_true', dest='names_only')
  arg_parser.add_argument('--decode', '-d', default=False, required=False,
      help='URL decode parameter names and values (if applicable). Decoded params will be used for comparison and printing.',
      action='store_true', dest='decode_params')
  arg_parser.add_argument('left_url', type=str, help='URL to diff against.  Logically handled as the left argurmnt of diff.', metavar='<left URL>')
  arg_parser.add_argument('right_url', type=str, help='URL to diff against.  Logically handled as the right argurmnt of diff.', metavar='<right URL>', nargs='?', default='')
  arg_parser.add_argument('--quiet', '-q', action='store_true', help='suppress output and return non-zero if URLs differ.',
                          default=False, required=False)

  args = arg_parser.parse_args()

  differ = UrlDiffer(args.left_url,
                     args.right_url,
                     names_only=args.names_only,
                     hostnames=args.diff_hostname,
                     url_decode_params=args.decode_params)

  if not args.quiet:
    print differ

  sys.exit(1 if differ.are_different() else 0)

if __name__ == '__main__':
  main()
