#!/usr/bin/env python3
# ##################################################
# NAME:
#   nview.py
# DESCRIPTION:
#   View and filter nmap results.
# AUTHOR:
#   bytebutcher
# ##################################################
import argparse
import logging
import traceback
import os
import sys

from libnmap.objects import NmapHost

try:
    from libnmap.parser import NmapParser
except:
    sys.stderr.write("Missing python3 package python-libnmap! ")
    sys.stderr.write("Please install requirements using 'pip3 install -r requirements.txt" + os.linesep)
    sys.exit(1)

try:
    import pandas as pd
except:
    sys.stderr.write("Missing python3 package pandas! ")
    sys.stderr.write("Please install requirements using 'pip3 install -r requirements.txt" + os.linesep)
    sys.exit(1)

try:
    import numpy as np
except:
    sys.stderr.write("Missing python3 package numpy! ")
    sys.stderr.write("Please install requirements using 'pip3 install -r requirements.txt" + os.linesep)
    sys.exit(1)

app_name = "nview"
app_version = "1.1"
app_description = "View and filter nmap results."


def init_logger(app_id, log_format="%(msg)s", log_level=logging.DEBUG):
    logger = logging.getLogger(app_id)
    logging.root.setLevel(log_level)
    try:
        import coloredlogs
        coloredlogs.install(logger=logger, level=log_level)
    except:
        logger.debug("Coloredlogs not installed. Falling back to default loggging.")
    hdlr = logging.StreamHandler(sys.stderr)
    hdlr.setFormatter(logging.Formatter(log_format))
    logger.addHandler(hdlr)
    return logger


class NView(object):

    def __init__(self, nmap_xml_files, columns, pack_ports, pack_ports_separator):
        self._data_columns = ["address", "port", "protocol", "status", "banner"]
        self._view_columns = self.__init_view_columns(columns)
        self._pack_ports = pack_ports
        self._pack_ports_separator = pack_ports_separator
        self.__init_pack_ports(pack_ports)
        self._data = self.__parse_nmap_xml_files(nmap_xml_files)

    def __init_pack_ports(self, pack_ports):
        if pack_ports:
            if "banner" in self._view_columns:
                self._view_columns.pop() # Do not view banner
            self._data_columns.pop() # Do not process banner

    def __init_view_columns(self, columns_string):
        columns = self.__parse_comma_separated_values(columns_string, self._data_columns)
        if not columns:
            return list(self._data_columns)
        else:
            return [column for column in self._data_columns if column in columns] # keep order

    def __parse_comma_separated_values(self, values, valid_values):
        result = None
        if values:
            splitted_values = values.split(",")
            result = [value for value in valid_values if value in splitted_values] # Keep order
            invalid_values = [value for value in splitted_values if value not in valid_values]
            if invalid_values:
                raise Exception("Invalid values {}".format(",".join(invalid_values)))
        return result

    def __parse_host(self, host: NmapHost):
        data = []

        status_ports_map = {
            "open": [(p.port, p.protocol) for p in host.services if p.state == 'open'],
            "closed": [(p.port, p.protocol) for p in host.services if p.state == 'closed'],
            "filtered": [(p.port, p.protocol) for p in host.services if p.state == 'filtered']
        }

        for status, ports in status_ports_map.items():
            if self._pack_ports:
                ports_tcp = [str(port_spec[0]) for port_spec in ports if port_spec[1] == "tcp"]
                if ports_tcp:
                    data.append(np.array([host.address, self._pack_ports_separator.join(ports_tcp), "tcp", status]))

                ports_udp = [str(port_spec[0]) for port_spec in ports if port_spec[1] == "udp"]
                if ports_udp:
                    data.append(np.array([host.address, self._pack_ports_separator.join(ports_udp), "udp", status]))
            else:
                for port_spec in ports:
                    port = str(port_spec[0])
                    protocol = port_spec[1]
                    if port and protocol:
                        service = host.get_service(int(port), protocol=protocol)
                        service_name = service.banner or service.service or ""
                        data.append(np.array([host.address, port, protocol, status, service_name]))

        return data

    def __parse_nmap_xml_file(self, nmap_xml_file):
        data = []
        nmap_data = NmapParser.parse_fromfile(nmap_xml_file)
        for host in nmap_data.hosts:
            data += self.__parse_host(host)

        return data

    def __parse_nmap_xml_files(self, nmap_xml_files):
        for nmap_xml_file in nmap_xml_files:
            if not os.path.isfile(nmap_xml_file):
                raise Exception("No such file: {}".format(nmap_xml_file))

        data = []
        for nmap_xml_file in nmap_xml_files:
            data += self.__parse_nmap_xml_file(nmap_xml_file)
        return data

    def build(self, separator=None, filter_string=None):
        data_frame = pd.DataFrame(data=self._data, columns=self._data_columns)
        if filter_string:
            try:
                data_frame = data_frame.query(filter_string)
            except:
                raise("Invalid filter expression!")
        data_frame = data_frame[self._view_columns].drop_duplicates()
        separator = str('\t') if not separator else str(separator)
        return data_frame.to_csv(sep=separator, index=False, encoding='utf-8')


logger = init_logger(app_name)
parser = argparse.ArgumentParser(description=app_description)
parser.add_argument("-c", "--columns", dest="columns",
                    help="Columns to print (default='address,port,protocol,status,banner').")
parser.add_argument("-p", "--pack-ports", dest="pack_ports", action="store_true",
                    help="Pack ports into single string separated by character (default=',').")
parser.add_argument("-f", "--filter", dest="filter",
                    help="Filter results using pandas query language notation "
                         "(e.g. 'status=\"open\" and protocol=\"tcp\"').")
parser.add_argument("--pack-ports-separator", dest="pack_ports_separator", metavar="CHARACTER",
                    help="1-character string which is used to separate packed ports (default=,).")
parser.add_argument("--csv-separator", dest="csv_separator", metavar="CHARACTER",
                    help="1-character string which is used to separate columns in the resulting csv (default=\\t).")
parser.add_argument(dest="nmap_xml_files", metavar="NMAP_XML_FILE", nargs='+',
                    help="One or more nmap xml files to parse")
parser.add_argument('-d', '--debug', action="store_true",
                    dest='debug',
                    help="Prints additional debug information (e.g. stack traces).")

arguments = parser.parse_args()
if len(sys.argv) == 0 or not arguments.nmap_xml_files:
    parser.print_usage()
    exit(1)

if arguments.csv_separator and len(arguments.csv_separator != 1):
    logger.error("ERROR: --csv-separator must be a 1-character string!")
    exit(1)

if arguments.pack_ports_separator and len(arguments.pack_ports_separator != 1):
    logger.error("ERROR: --pack-ports-separator must be a 1-character string!")
    exit(1)

csv_separator = arguments.csv_separator if arguments.csv_separator else '\t'
pack_ports_separator = arguments.pack_ports_separator if arguments.pack_ports_separator else ','
if csv_separator == pack_ports_separator:
    logger.error("ERROR: --separator and --pack-ports separator can not be the same!")
    exit(1)

try:
    nview = NView(arguments.nmap_xml_files, arguments.columns, arguments.pack_ports, pack_ports_separator)
    print(nview.build(csv_separator, arguments.filter))
except Exception as err:
    logger.error("ERROR: {}".format(err))
    if arguments.debug:
        traceback.print_exc()
    exit(1)
