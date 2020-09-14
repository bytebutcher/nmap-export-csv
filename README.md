# nview

View and filter nmap results.

## Usage

```
usage: nview [-h] [-c COLUMNS] [-f FILTER] [--compact [CHARACTER]] [--column-separator CHARACTER] [-d]
             NMAP_XML_FILE [NMAP_XML_FILE ...]

View and filter nmap results.

positional arguments:
  NMAP_XML_FILE         One or more nmap xml files to parse

optional arguments:
  -h, --help            show this help message and exit
  -c COLUMNS, --columns COLUMNS
                        Columns to print (default='address,port,protocol,status,banner').
  -f FILTER, --filter FILTER
                        Filter results using pandas query language notation (e.g. 'status="open" and
                        protocol="tcp"').
  --compact [CHARACTER]
                        packs ports with same host and status using character as separator (default=,).
  --column-separator CHARACTER
                        1-character string which is used to separate columns (default=\t).
  -d, --debug           Prints additional debug information (e.g. stack traces).

```

## Installation

```
pip3 install -r requirements.txt
```
