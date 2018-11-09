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