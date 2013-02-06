# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier, Vmon"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
from client.jailreader import JailReader

class JailReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""

	def tearDown(self):
		"""Call after every test case."""

	def testSplitAction(self):
		action = "mail-whois[name=SSH]"
		expected = ['mail-whois', {'name': 'SSH'}]
		result = JailReader.splitAction(action)
		self.assertEquals(expected, result)
		
	def testFailModelRead(self):
		"""
		Test that the client can successfully read a fail model and
		send it to the server
		"""
		#Naive way to reach "testcases/files"
		#TODO: Look at other tests and see how thay do that. I suspect
		#that it all happens in fail2ban-testcases
		from os.path import dirname
		test_dir  = dirname(__file__)

		
		fail_model_jail = JailReader("ats-ddos-model")
		fail_model_jail.setBaseDir(test_dir + "/files")
		fail_model_jail.read()
		fail_model_jail.getOptions()
