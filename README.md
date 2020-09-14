# nview

View and filter nmap results.

## Usage

```
usage: nview.py [-h] [-c COLUMNS] [-p] [-f FILTER]
                          [--pack-ports-separator CHARACTER]
                          [--csv-separator CHARACTER]
                          NMAP_XML_FILE [NMAP_XML_FILE ...]

Export nmap results into csv format

positional arguments:
  NMAP_XML_FILE         One or more nmap xml files to parse

optional arguments:
  -h, --help            show this help message and exit
  -c COLUMNS, --columns COLUMNS
                        Columns to print
                        (default='address,port,protocol,status,banner').
  -p, --pack-ports      Pack ports into single string separated by character
                        (default=',').
  -f FILTER, --filter FILTER
                        Filter results using pandas query language notation
                        (e.g. 'status="open" and protocol="tcp"').
  --pack-ports-separator CHARACTER
                        1-character string which is used to separate packed
                        ports (default=,).
  --csv-separator CHARACTER
                        1-character string which is used to separate columns
                        in the resulting csv (default=\t).
```

## Installation

```
pip3 install -r requirements.txt
```
