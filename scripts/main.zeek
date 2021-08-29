##! Build a table of OUI identifiers paired with the manufacturer
##! that the OUI identifies. 
module OUI;

export {
    ## Idx is used as an identifier to load an input file into 
    ## a table.
    type Idx: record {
        ## OUI is the unique identifier for an organization that
        ## manufactures hardware.
        oui:    string;
    };

    ## Val is the record that is read in from the input file
    type Val: record {
        ## vendor is the name of the vendor that created the device 
        ## marked with an OUI.
        vendor: string;
    };

    ## vendors is a table of OUI references paired with manufacturer
    ## names to be used to identify network devices.
    global vendors: table[string] of Val = table()
        &default=Val($vendor="unknown");

    ## lookup_oui is used to lookup a mac address and return the 
    ## name of an organization that has manufactured the device.
    global lookup_oui: function(l2_addr: string): string;
}

# lookup_oui is used to lookup a mac address and return the name
# of an organization that has manufactured the device.
# Args:
# l2_addr: string
#   the mac address to lookup the OUI for
# Returns:
# string:
#   the manufacturer/organization that the OUI for the device
#   identifies.
function lookup_oui(l2_addr: string): string 
    {
    local prefix = l2_addr[:8];
    return vendors[prefix]$vendor;
    }

event zeek_init()
    {
    # create an input file to be used to learn OUI data. This input
    # reads the data into the vendors table and will reread the 
    # table if the file is rewritten.
    Input::add_table([$source=fmt("%s/oui.dat", @DIR), 
        $name="vendors", 
        $idx=Idx, 
        $val=Val, 
        $destination=vendors,
        $mode=Input::REREAD]);
    }