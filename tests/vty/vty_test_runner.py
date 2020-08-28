#!/usr/bin/env python3

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# (C) 2019 by sysmocom s.f.m.c. GmbH
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys
import time
import unittest
import socket
import subprocess
import time

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assertTrue(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assertTrue(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)

class TestVTYSTP(TestVTYBase):

    def vty_command(self):
        return ["./stp/osmo-stp", "-c",
                "../doc/examples/osmo-stp-multihome.cfg"]

    def vty_app(self):
        return (4239, "./stp/osmo-stp", "OsmoSTP", "stp")

    def check_sctp_sock_local(self, laddr_list, lport):
            path = "/proc/net/sctp/eps"
            try:
                with open(path, "r") as fp:
                    #drop first line, contains column names:
                    fp.readline()
                    while True:
                        # Read next line
                        line = fp.readline().strip()
                        if not line:
                            return False
                        print("%s: parsing line: %s" %(path, line))
                        it = line.split()
                        if lport == int(it[5]):
                            print("%s: local port %d found" %(path, lport))
                            itaddr_list = it[8:]
                            if len(itaddr_list) != len(laddr_list):
                                print("%s: addr list mismatch: %r vs %r" % (path, repr(itaddr_list), repr(laddr_list)))
                                continue
                            for addr in laddr_list:
                                if addr not in itaddr_list:
                                    print("%s: addr not found in list: %s vs %r" % (path, addr, repr(itaddr_list)))
                                    return False
                            return True
                    return False
            except IOError as e:
                print("I/O error({0}): {1}".format(e.errno, e.strerror))
                return False

    def testMultiHome(self):
        # first check if STP is listening in required addresses:
        found = False
        for i in range(5):
            if self.check_sctp_sock_local(['127.0.0.1', '127.0.0.2',
                                           '0000:0000:0000:0000:0000:0000:0000:0001'],
                                          2905):
                found = True
                break
            else:
                print("[%d] osmo-stp not yet available, retrying in a second" % i)
                time.sleep(1)
        self.assertTrue(found)
        try:
            proto = socket.IPPROTO_SCTP
        except AttributeError: # it seems to be not defined under python2?
            proto = 132
        # IPv4:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
        s.bind(('127.0.0.3', 0))
        try:
            s.connect(('127.0.0.2',2905))
        except socket.error as msg:
            s.close()
            self.assertTrue(False)
        print("Connected to STP through SCTP (IPv4)")
        s.close()
        # IPv6:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, proto)
        s.bind(('::1', 0))
        try:
            s.connect(('::1',2905))
        except socket.error as msg:
            s.close()
            self.assertTrue(False)
        print("Connected to STP through SCTP (IPv6)")
        s.close()

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific VTY commands")
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYSTP))

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
