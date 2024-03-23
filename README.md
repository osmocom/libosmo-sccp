libosmo-sccp - Osmocom SCCP, SIGTRAN and STP
============================================

This repository contains

* *libosmo-sigtran*, a C-language library implementation of a variety of telecom signaling protocols, such as M3UA, SUA, SCCP
  (connection oriented and connectionless)
* *OsmoSTP*, a SS7 Transfer Point that can be used to act as router and translator between M3UA, SUA and/or
  SCCPlite
* *libosmo-sccp*, a legacy C-language [static] library that we used in prehistoric osmocom code before we had
  libosmo-sigtran.

Homepage
--------

The official homepage of libosmo-sccp is at <https://osmocom.org/projects/libosmo-sccp/wiki>

The official homepage of osmo-stp is at <https://osmocom.org/projects/osmo-stp/wiki>

GIT Repository
--------------

You can clone from the official git repository using

	git clone https://gitea.osmocom.org/osmocom/libosmo-sccp

There is a web interface at <https://gitea.osmocom.org/osmocom/libosmo-sccp>

Documentation
-------------

osmo-stp User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmostp-usermanual.pdf)
as well as the VTY reference manuals
* [VTY Reference Manual for osmo-stp](https://ftp.osmocom.org/docs/latest/osmostp-vty-reference.pdf)

Mailing List
------------

Discussions related to osmo-stp are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We us a gerrit based patch submission/review process for managing contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for more details

The current patch queue can be seen at <https://gerrit.osmocom.org/#/q/project:libosmo-sccp+status:open>
