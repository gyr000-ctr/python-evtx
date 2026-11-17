#!/usr/bin/env python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v0.1.1
import sys
import mmap

import Evtx.Evtx as evtx
import Evtx.Views as e_views
import Evtx.Recovery as e_recovery


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Dump a binary EVTX file into XML.")
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file")
    parser.add_argument(
        "--recover",
        action="store_true",
        help="tolerate corrupt or truncated chunks: scan for chunk signatures, "
        "skip damaged chunks, cut truncated chunks at the last complete event, "
        "and print a recovery report (with file offsets and chunk numbers) to stderr",
    )
    args = parser.parse_args()

    if args.recover:
        # mmap keeps memory bounded (pages are loaded on demand), and
        # recover_records() streams events chunk-by-chunk without
        # buffering them all in memory.
        with open(args.evtx, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                report = e_recovery.RecoveryReport()
                print(e_views.XML_HEADER)
                print("<Events>")
                for record in e_recovery.recover_records(buf, report):
                    try:
                        print(record.xml())
                    except Exception as e:  # a single bad event must not abort recovery
                        report.render_errors += 1
                        print("<!-- failed to render record at 0x{:x}: {} -->".format(record._offset, e))
                print("</Events>")
                sys.stderr.write(report.render() + "\n")
        return

    with evtx.Evtx(args.evtx) as log:
        print(e_views.XML_HEADER)
        print("<Events>")
        for record in log.records():
            print(record.xml())
        print("</Events>")


if __name__ == "__main__":
    main()
