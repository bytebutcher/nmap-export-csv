# nmap-export-csv

export nmap xml results into csv format

## Usage

```
usage: nmap-export-csv.py [-h] [-c COLUMNS] [-p PACK_PORTS] [-f FILTER]
                          [-s SEPARATOR]
                          NMAP_XML_FILE [NMAP_XML_FILE ...]

Export nmap results into csv format

positional arguments:
  NMAP_XML_FILE         One or more nmap xml files to parse

optional arguments:
  -h, --help            show this help message and exit
  -c COLUMNS, --columns COLUMNS
                        Columns to print (default='address,port,protocol,status,banner').
  -p PACK_PORTS, --pack-ports [SEPARATOR]
                        Pack ports into single string separated by character (default=',').
  -f FILTER, --filter FILTER
                        Filter results using pandas query language notation
                        (e.g. 'status="open" and protocol="tcp"').
  -s SEPARATOR, --separator SEPARATOR
                        1-character string which is used to separate columns
                        in the resulting csv (default=\t).
```

## Installation

```
pip3 install requirements.txt
```