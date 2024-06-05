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

Forum
-----

We welcome any libosmo-sigtran + osmo-stp related discussions in the
[Cellular Network Infrastructure -> 2G/3G Core Network](https://discourse.osmocom.org/c/cni/2g-3g-cn/)
section of the osmocom discourse (web based Forum).

Mailing List
------------

Discussions related to osmo-stp are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Issue Tracker
-------------

We use the issue trackers of smocom.org for tracking the state of bug reports and feature requests.  Feel free
to submit any issues you may find, or help us out by resolving existing issues.

* [osmo-stp issue tracker](https://osmocom.org/projects/osmo-stp/issues)
* [libosmo-sigtran issue tracker](https://osmocom.org/projects/libosmo-sccp/issues)

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We use a Gerrit based patch submission/review process for managing contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for more details

The current patch queue can be seen at <https://gerrit.osmocom.org/#/q/project:libosmo-sccp+status:open>
