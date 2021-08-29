# OUI

This module adds an OUI lookup to Zeek IDS. Additionally, it comes with a script to maintain a Zeek input file containing OUI data pulled from IEEE.

## Performing an OUI Lookup

```zeek
##! This script extends dhcp.log to include the manufacturer that a 
##! mac address is associated with as the client_vendor field.
module OUI;

export {
    ## DHCP::Info is owned by the DHCP module and is the record that
    ## is logged when the DHCP module logs
    redef record DHCP::Info += {
        ## client_vendor is the manufacturer identified by the OUI
        client_vendor:  string &log &optional;
    };
}

# DHCP::aggregate_msgs is used to distribute data around clusters.
# In this case, this event is used to extend the DHCP logs. 
event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, 
    is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    local vendor = lookup_oui(msg$chaddr);
    DHCP::log_info$client_vendor = vendor;
    }
```

## Updating the OUI Data File

To update the OUI data file, run the included `oui.py` script and specify the path of the existing `oui.dat` file.

```
usage: oui.py [-h] path

Download and parse a listing of Organizationally unique identifiers, then
export the listing as a Zeek input file. This can then be used with the OUI
module to allow for OUI lookups in Zeek.

positional arguments:
  path        Where to place the exported input file.

optional arguments:
  -h, --help  show this help message and exit
```

## A Note on oui.dat

Local modifications to oui.dat will be overwritten by updates of this plugin. Additionally, by running `oui.py`, the entire oui.dat file will be overwritten. This file is not meant to contain local modifications.