do
   srx_null_loopback_protocol = Proto("srx_null_loopback",  "Juniper SRX loopback")
   
   -- don't decode any fields, these are unknown
   srx_null_loopback_protocol.fields = {}
  
   function srx_null_loopback_protocol.dissector(buffer, pinfo, tree)

      length = buffer:len()

      if length == 0 then return end
      
      --SRX null loopback packets start with 0x4d47 (19783 DEC)
      if buffer(0,2):uint() == 19783 then
        pinfo.cols.protocol = srx_null_loopback_protocol.name
        
        local subtree = tree:add(srx_null_loopback_protocol, buffer(), "Juniper SRX loopback IP payload")
        
        -- if reading from NULL works then 28 is the offset.
        -- IPv4, IPv4 packet starts with 0x45 (69 DEC)
        if buffer(32,1):uint() == 69 then
            original_ip_dissector:call(buffer(32,buffer:len()-32):tvb(),pinfo,tree)
        -- IPv6 (FIXME - not sure if this is a proper assumption)
        else
            original_ipv6_dissector:call(buffer(32, buffer:len()-32):tvb(),pinfo,tree)
        end
      -- IPv4 on NULL/Loopback
      elseif buffer(0,1):uint() == 2 then
        -- by default use original NULL loopback dissector on the whole buffer
        original_ip_dissector:call(buffer(4, buffer:len()-4):tvb(),pinfo,tree)
      -- IPv6 on NULL/Loopback
      elseif buffer(0,1):uint() == 24 or buffer(0,1):uint() == 28 or buffer(0,1):uint() == 30 then
        -- by default use original NULL loopback dissector on the whole buffer
        original_ipv6_dissector:call(buffer(4, buffer:len()-4):tvb(),pinfo,tree)
      end

   end

   -- FIXME: doesn't work, couldn't find a reason why
   -- bind it to null loopback (type 0x4387 == 17287 DEC as collected by monitor traffic)
   -- local null_dissector_table = DissectorTable.get("null.type")
   -- null_dissector_table:add('17287',srx_null_loopback_protocol)
   -- get original dissector for IP in NULL 
   -- original_ip_dissector = null_dissector_table:get_dissector(0x4)

   -- WORKAROUND - bind dissector to wiretap directly with a type Null/Loopback == 15
   local wiretap_dissector_table = DissectorTable.get("wtap_encap")
   wiretap_dissector_table:add('15',srx_null_loopback_protocol)
   -- get dissector for IP/IPv6 in WIRETAP (only for SRX null loopback)
   original_ip_dissector = wiretap_dissector_table:get_dissector('129')
   original_ipv6_dissector = wiretap_dissector_table:get_dissector('130')
end