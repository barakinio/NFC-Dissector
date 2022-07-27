nfc_protocol = Proto("NFC",  "NFC protocol")


--PN532 HCI fields
local hcipreamble = ProtoField.uint8("hci.preamble", "Preamble", base.DEC)
local hcistartcode = ProtoField.uint16("hci.startcode", "Start Code", base.HEX)
local hcilength = ProtoField.uint8("hci.length", "Length", base.DEC)
local hcilengthchecksum = ProtoField.uint8("hci.lengthchecksum", "Length Checksum", base.HEX)
local hcidatachecksum = ProtoField.uint8("hci.datachecksum", "Data Checksum", base.HEX)
local hcipostamble = ProtoField.uint8("hci.postamble", "Postamble", base.DEC)

--PN532 fields
local pn532direction = ProtoField.uint8 ("pn532.direction", "Direction", base.HEX)
local pn532command = ProtoField.uint8 ("pn532.command", "Command", base.HEX)

--NFC-DEP fields
local nfcdeplength = ProtoField.uint8("nfcdep.length", "Length", base.DEC)
local nfcdepcommand = ProtoField.uint16("nfcdep.command", "Command", base.HEX)
local nfcdeppfb = ProtoField.uint8("nfcdep.pfb", "PFB", base.DEC)

--LLCP fields
local nfcllcpdsap = ProtoField.uint8("nfcllcp.dsap", "DSAP", base.DEC)
local nfcllcpptype = ProtoField.uint8("nfcllcp.ptype", "PTYPE", base.DEC)
local nfcllcpssap = ProtoField.uint8("nfcllcp.ssap", "SSAP", base.DEC)
local nfcllcpseq = ProtoField.uint8("nfcllcp.seq", "Sequence", base.DEC)

--SNEP fields
local snepversion = ProtoField.uint8("snep.dsap", "Version", base.HEX)
local snepcommand = ProtoField.uint8("snep.command", "SNEP Command", base.HEX)
local sneplength = ProtoField.uint32("snep.length", "Length", base.DEC)

--NDEF fields
local ndef_flags = ProtoField.new("Flags", "ndef.flags", ftypes.UINT8, nil, base.HEX) --The switched order here is not a mistake, for some reason in this type it's the other way around 🤷‍♂️

local ndef_flags_mb = ProtoField.bool("ndef.flags.mb", "Message Begin", 8, nil, 0x80)
local ndef_flags_me = ProtoField.bool("ndef.flags.me", "Message End", 8, nil, 0x40)
local ndef_flags_cf = ProtoField.bool("ndef.flags.cf", "Chunk Flag", 8, nil, 0x20)
local ndef_flags_sr = ProtoField.bool("ndef.flags.sr", "Short Record", 8, nil, 0x10)
local ndef_flags_il = ProtoField.bool("ndef.flags.il", "ID Length", 8, nil, 0x08)
local ndef_flags_tnf = ProtoField.uint8("ndef.flags.tnf", "TNF", base.DEC, {[0] = "Empty", [1] = "Well-Known", [2] = "MIME", [3] = "URI", [4] = "External", [5] = "Unknown", [6] = "Unchanged", [7] = "Reserved"}, 0x07)

local ndef_type_length = ProtoField.uint8("ndef.type_length", "Type Length", base.DEC)
local ndef_payload_length = ProtoField.uint32("ndef.payload_length", "Payload Length", base.DEX)
local ndef_id_length = ProtoField.uint8("ndef.id_length", "ID Length", base.DEC)
local ndef_payload_type = ProtoField.new("Payload Type", "ndef.payload_type", ftypes.STRING)
local ndef_payload_id = ProtoField.uint8("ndef.payload_id", "Payload ID", base.DEC)
local ndef_payload = ProtoField.new("Payload", "ndef.payload", ftypes.STRING)
local ndef_text_language_code_length = ProtoField.uint8("ndef.text.language_code_length", "Language Code Length", base.DEC)
local ndef_text_language_code = ProtoField.new("Language Code", "ndef.text.language_code", ftypes.STRING)

--debugging purposes
local nfc_index = ProtoField.uint8("nfc.index", "Index", base.DEC)



nfc_protocol.fields = { hcipreamble, hcistartcode, hcilength, hcilengthchecksum, hcidatachecksum, hcipostamble, pn532direction, pn532command, nfcdeplength, nfcdepcommand, nfcdeppfb, nfcllcpdsap,
 nfcllcpptype, nfcllcpssap, nfcllcpseq, snepversion, snepcommand, sneplength, ndef_flags, ndef_flags_mb, ndef_flags_me, ndef_flags_cf, ndef_flags_sr, ndef_flags_il, ndef_flags_tnf,
 ndef_type_length, ndef_payload_length, ndef_id_length, ndef_payload_type, ndef_payload_id, ndef_payload, ndef_text_language_code_length, ndef_text_language_code, nfc_index}

function nfc_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  local index = 0

  pinfo.cols.protocol = nfc_protocol.name

  -- NXP PN532 HCI tree creation
  local hcisubtree = tree:add(nfc_protocol, buffer(), "NXP PN532 HCI")
  
  hcisubtree:add_le(hcipreamble, buffer(index,1))
  index = index + 1

  hcisubtree:add_le(hcistartcode, buffer(index,2))
  index = index + 2

  hcisubtree:add_le(hcilength, buffer(index,1))
  index = index + 1

  hcisubtree:add_le(hcilengthchecksum, buffer(index,1))
  index = index + 1

  --suffix
  hcisubtree:add_le(hcidatachecksum, buffer((length-2),1))
  hcisubtree:add_le(hcipostamble, buffer((length-1),1))

  if length == 6 then return end

  -- NXP PN532 tree creation
  local pn532_buffer = buffer:range(index, (length - index - 2))
  local pn532_length = pn532_buffer:len()
  if pn532_length == 0 then return end
  index = 0
  local pn532subtree = tree:add(nfc_protocol, pn532_buffer, "NXP PN532")
  
  local direction_value = pn532_buffer(index, 1):le_uint()
  local direction_string = get_direction_string(direction_value)
  pn532subtree:add_le(pn532direction, pn532_buffer(index,1)):append_text(" (" .. direction_string .. ")")
  index = index + 1

  local pn_532_command_value = pn532_buffer(index, 1):le_uint()
  local pn_532_command_string = get_pn532_command_string(pn_532_command_value)
  pn532subtree:add_le(pn532command, pn532_buffer(index,1)):append_text(" (" .. pn_532_command_string .. ")")
  index = index + 1

  if length == 9 then return end
  

  -- NFC-DEP tree creation
  local dep_buffer = pn532_buffer:range(index, (pn532_length - index))
  local dep_length = dep_buffer:len()
  if dep_length == 0 then return end
  index = 0
  local NFCDEPsubtree = tree:add(nfc_protocol, dep_buffer, "NFC-DEP")
  
  local nfc_dep_length_field = dep_buffer(index, 1):le_uint()
  if nfc_dep_length_field == 0
  then
    index = index + 1
    nfc_dep_length_field = dep_buffer(index, 1):le_uint()
  end

  NFCDEPsubtree:add_le(nfcdeplength, nfc_dep_length_field)
  index = index + 1

  local nfc_dep_command_direction = dep_buffer(index, 1):le_uint()
  local nfc_dep_command_opcode = dep_buffer(index + 1, 1):le_uint()
  local nfc_dep_command_string = get_nfc_dep_command_string(nfc_dep_command_direction, nfc_dep_command_opcode)
  NFCDEPsubtree:add(nfcdepcommand, dep_buffer(index,2)):append_text(" (" .. nfc_dep_command_string .. ")")
  index = index + 2


  NFCDEPsubtree:add_le(nfcdeppfb, dep_buffer(index,1))
  index = index + 1
  
-- NFC-LLCP tree creation
if (dep_length - index) == 0 then return end
  local llcp_buffer = dep_buffer:range(index, (dep_length - index))
  local llcp_length = llcp_buffer:len()
  if llcp_length == 0 then return end
  index = 0
  local llcpsubtree = tree:add(nfc_protocol, llcp_buffer(index, 3), "NFC LLCP")

  local nfc_llcp_byte_0 = llcp_buffer(index, 1):le_uint()
  local nfc_llcp_byte_1 = llcp_buffer(index + 1, 1):le_uint()

  local dsap = bit.band(nfc_llcp_byte_0, 0xfc)
  local ptype = bit.lshift(bit.band(nfc_llcp_byte_0, 0x3), 2) + bit.band(nfc_llcp_byte_1, 0xc0)
  local ssap = bit.band(nfc_llcp_byte_0, 0x3f)

  llcpsubtree:add_le(nfcllcpdsap, dsap)
  llcpsubtree:add_le(nfcllcpptype, ptype) --map to all the options
  llcpsubtree:add_le(nfcllcpssap, ssap)
  index = index + 2

  llcpsubtree:add_le(nfcllcpseq, llcp_buffer(index,1))
  index = index + 1

  -- NFC-SNEP tree creation
  if (llcp_length - index) == 0 then return end
  local snep_buffer = llcp_buffer:range(index, (llcp_length - index))
  local snep_length = snep_buffer:len()
  if snep_length == 0 then return end
  index = 0
  local snepsubtree = tree:add(nfc_protocol, snep_buffer(index, 6), "NFC SNEP")

  snepsubtree:add_le(snepversion, snep_buffer(index,1))
  index = index + 1

  local nfc_snep_command_opcode = snep_buffer(index, 1):le_uint()
  local nfc_snep_command_string = get_nfc_snep_command_string(nfc_snep_command_opcode)
  pinfo.cols.info:set(nfc_snep_command_string)
  snepsubtree:add_le(snepcommand, nfc_snep_command_opcode):append_text(" (" .. nfc_snep_command_string .. ")")
  index = index + 1

  snepsubtree:add(sneplength, snep_buffer(index,4))
  index = index + 4


  -- NFC-NDEF tree creation
  if (snep_length - index) == 0 then return end
  local ndef_buffer = snep_buffer:range(index, (snep_length - index))
  local ndef_length = ndef_buffer:len()
  if ndef_length == 0 then return end
  index = 0
  local remlen = 0
  local tempindex = 0
  local payload_length = 0
  local temppayload_length = 0
  local dump = 0
  local ndefsubtree = tree:add(nfc_protocol, ndef_buffer, "NFC NDEF")


  repeat
  local ndefrecord_one = ndefsubtree:add(nfc_protocol, ndef_buffer, "NDEF Record")
  tempindex, payload_length = dissect_ndef_record(ndefrecord_one, ndef_buffer)
  temppayload_length = payload_length
  index = index + tempindex
  remlen = ndef_length - index
  temppayload_length = payload_length - index
  
  ndef_buffer = ndef_buffer(index, ndef_length - index)
  ndef_length = ndef_buffer:len()
  index = 0
  
  while temppayload_length > 0 do
    

    local ndefrecord_two = ndefrecord_one:add(nfc_protocol, ndef_buffer, "NDEF Record")
    tempindex, dump = dissect_ndef_record(ndefrecord_two, ndef_buffer)
    index = index + tempindex
    temppayload_length = temppayload_length - index
    if (ndef_length - index) == 0 then break end
    ndef_buffer = ndef_buffer(index, ndef_length - index)
    ndef_length = ndef_buffer:len()
    index = 0
  end
  until (remlen == payload_length)


  
end


function dissect_ndef_record(subtree, buffer)
    local index = 0
    local ndef_id_length_value = 0
    local uri_abb = ""

    local ndef_flag_range = buffer:range(index, 1)
    local ndef_flag_tree = subtree:add(ndef_flags, ndef_flag_range)
        ndef_flag_tree:add(ndef_flags_mb, ndef_flag_range)
        ndef_flag_tree:add(ndef_flags_me, ndef_flag_range)
        ndef_flag_tree:add(ndef_flags_cf, ndef_flag_range)
        ndef_flag_tree:add(ndef_flags_sr, ndef_flag_range)
        ndef_flag_tree:add(ndef_flags_il, ndef_flag_range)
        ndef_flag_tree:add(ndef_flags_tnf, ndef_flag_range)
        local ndef_sr = bit.band(buffer(index, 1):le_uint(), 0x10)
        local ndef_il = bit.band(buffer(index, 1):le_uint(), 0x08)
    index = index + 1

    local ndef_type_length_value = buffer(index, 1):le_uint()
    subtree:add_le(ndef_type_length, ndef_type_length_value)
    index = index + 1

    local ndef_record_length = 1
    if ndef_sr == 0 then ndef_record_length = 4 end
  
    local ndef_payload_length_value = buffer(index, ndef_record_length):le_uint()
    subtree:add_le(ndef_payload_length, ndef_payload_length_value)
    index = index + ndef_record_length

    if ndef_il == 1
    then
        ndef_id_length_value = buffer(index, 1):le_uint()
        subtree:add_le(ndef_id_length, ndef_id_length_value)
        index = index + 1
    end
    
    local ndef_payload_type_value = buffer(index, ndef_type_length_value)
    subtree:add(ndef_payload_type, ndef_payload_type_value)
    index = index + ndef_type_length_value

    --Type specific fields
    if ndef_payload_type_value:le_uint() == 0x55 --"U"
    then
        uri_abb = get_ndef_uri_abb(buffer(index, 1):le_uint())
        index = index + 1

        local urn = buffer(index, ndef_payload_length_value - 1):string()
        subtree:add(ndef_payload, uri_abb):append_text(urn)
        index = index + ndef_payload_length_value - 1
    elseif ndef_payload_type_value:le_uint() == 0x54 --"T"
     then
        local ndef_text_language_code_length_value = buffer(index, 1):le_uint()
        subtree:add(ndef_text_language_code_length, ndef_text_language_code_length_value)
        index = index + 1

        subtree:add(ndef_text_language_code, buffer(index, ndef_text_language_code_length_value))
        index = index + ndef_text_language_code_length_value

        subtree:add(ndef_payload, buffer(index, ndef_payload_length_value - ndef_text_language_code_length_value - 1):string())
        index = index + ndef_payload_length_value - ndef_text_language_code_length_value - 1
    end

    if ndef_il == 1
    then
        subtree:add_le(ndef_payload_id, buffer(index, ndef_id_length_value))
        index = index + ndef_id_length_value
    end
    
    return index, ndef_payload_length_value

end


function get_direction_string(opcode)
    local opcode_name = "Unknown"
  
        if opcode == 0xd4 then opcode_name = "Host to PN532"
    elseif opcode == 0xd5 then opcode_name = "PN532 to Host" end
  
    return opcode_name
end

function get_pn532_command_string(opcode)
    local opcode_name = "Unknown"

        if opcode == 0x02 then opcode_name = "GetFirmwareVersion"
    elseif opcode == 0x03 then opcode_name = "GetFirmwareVersion (Response)"
    elseif opcode == 0x06 then opcode_name = "ReadRegister"
    elseif opcode == 0x07 then opcode_name = "ReadRegister (Response)"
    elseif opcode == 0x08 then opcode_name = "WriteRegister"
    elseif opcode == 0x09 then opcode_name = "WriteRegister (Response)"
    elseif opcode == 0x12 then opcode_name = "SetParameters"
    elseif opcode == 0x13 then opcode_name = "SetParameters (Response)"
    elseif opcode == 0x32 then opcode_name = "RFConfiguration"
    elseif opcode == 0x33 then opcode_name = "RFConfiguration (Response)"
    elseif opcode == 0x88 then opcode_name = "TgGetInitiatorCommand"
    elseif opcode == 0x89 then opcode_name = "TgGetInitiatorCommand (Response)"
    elseif opcode == 0x8c then opcode_name = "TgInitAsTarget"
    elseif opcode == 0x8d then opcode_name = "TgInitAsTarget (Response)"
    elseif opcode == 0x90 then opcode_name = "TgResponseToInitiator"
    elseif opcode == 0x91 then opcode_name = "TgResponseToInitiator (Response)"  end
  
    return opcode_name
end


function get_nfc_dep_command_string(command_direction, command_opcode)
    local command_name = "Unknown"

        if command_direction == 0xd4
            then
            if command_opcode == 0x00 then command_name = "ATR_REQ"
            elseif command_opcode == 0x04 then command_name = "PSL_REQ"
            elseif command_opcode == 0x06 then command_name = "DEP_REQ"
            elseif command_opcode == 0x08 then command_name = "DSL_REQ"
            elseif command_opcode == 0x0a then command_name = "RLS_REQ" end
        elseif command_direction == 0xd5
        then
            if command_opcode == 0x01 then command_name = "ATR_RES"
            elseif command_opcode == 0x05 then command_name = "PSL_RES"
            elseif command_opcode == 0x07 then command_name = "DEP_RES"
            elseif command_opcode == 0x09 then command_name = "DSL_RES"
            elseif command_opcode == 0x0b then command_name = "RLS_RES" end
    end
  
    return command_name
end

function get_nfc_snep_command_string(opcode)
    local opcode_name = "Unknown"
  
        if opcode == 0x00 then opcode_name = "SNEP REQUEST CONTINUE"
    elseif opcode == 0x01 then opcode_name = "SNEP REQUEST GET"
    elseif opcode == 0x02 then opcode_name = "SNEP REQUEST PUT"
    elseif opcode == 0x7f then opcode_name = "SNEP REQUEST REJECT"
    elseif opcode == 0x80 then opcode_name = "SNEP RESPONSE CONTINUE"
    elseif opcode == 0x81 then opcode_name = "SNEP RESPONSE SUCCESS"
    elseif opcode == 0xc0 then opcode_name = "SNEP RESPONSE NOT FOUND"
    elseif opcode == 0xc1 then opcode_name = "SNEP RESPONSE EXCESS DATA"
    elseif opcode == 0xc2 then opcode_name = "SNEP RESPONSE BAD REQUEST"
    elseif opcode == 0xe0 then opcode_name = "SNEP RESPONSE NOT IMPLEMENTED"
    elseif opcode == 0xe1 then opcode_name = "SNEP RESPONSE UNSUPPORTED"
    elseif opcode == 0xf then opcode_name = "SNEP RESPONSE REJECT" end
  
    return opcode_name
end


function get_ndef_uri_abb(opcode)
    if opcode == 0x01 then return "http://www."
    elseif opcode == 0x02 then return "https://www."
    elseif opcode == 0x03 then return "http://"
    elseif opcode == 0x04 then return "https://"
    elseif opcode == 0x05 then return "tel:"
    elseif opcode == 0x06 then return "mailto:"
    elseif opcode == 0x07 then return "ftp://anonymous:anonymous@"
    elseif opcode == 0x08 then return "ftp://ftp."
    elseif opcode == 0x09 then return "ftps:"
    elseif opcode == 0x0a then return "sftp://"
    elseif opcode == 0x0b then return "smb://"
    elseif opcode == 0x0c then return "nfs://"
    elseif opcode == 0x0d then return "ftp://"
    elseif opcode == 0x0e then return "dav://"
    elseif opcode == 0x0f then return "news:"
    elseif opcode == 0x10 then return "telnet://"
    elseif opcode == 0x11 then return "imap:"
    elseif opcode == 0x12 then return "rtsp:"
    elseif opcode == 0x13 then return "urn:"
    elseif opcode == 0x14 then return "pop:"
    elseif opcode == 0x15 then return "sip:"
    elseif opcode == 0x16 then return "sips:"
    elseif opcode == 0x17 then return "tftp:"
    elseif opcode == 0x18 then return "btspp://"
    elseif opcode == 0x19 then return "btl2cap://"
    elseif opcode == 0x1a then return "btgoep://"
    elseif opcode == 0x1b then return "tcpobex://"
    elseif opcode == 0x1c then return "irdaobex://"
    elseif opcode == 0x1d then return "file://"
    elseif opcode == 0x1e then return "urn:epc:id:"
    elseif opcode == 0x1f then return "urn:epc:tag:"
    elseif opcode == 0x20 then return "urn:epc:pat:"
    elseif opcode == 0x21 then return "urn:epc:raw:"
    elseif opcode == 0x22 then return "urn:epc:"
    elseif opcode == 0x23 then return "urn:nfc:"
    else return "" end

end

DissectorTable.get("usb.bulk"):add(0xff, nfc_protocol)