var Collector = require('node-sflow');
var pcap = require('pcap2');
Collector(function(flow) {
    if (flow && flow.flow.records && flow.flow.records.length>0) {
        flow.flow.records.forEach(function(n) {
            if (n.type == 'raw') {
                if (n.protocolText == 'ethernet') {
                    var pcapDummyHeader = new Buffer(16);
                    pcapDummyHeader.writeUInt32LE((new Date()).getTime()/1000,0); // Dummy time, you can take it from the sflow if you like
                    pcapDummyHeader.writeUInt32LE((new Date()).getTime()%1000,4);
                    pcapDummyHeader.writeUInt32LE(n.header.length,8);
                    pcapDummyHeader.writeUInt32LE(n.frameLen,12);
                    var pkt = pcap.decode.packet({
                       buf: n.header,
                       header: pcapDummyHeader,
                       link_type: 'LINKTYPE_ETHERNET'
                    });
                    if (pkt.payload.ethertype!=2048) return; // Check if it is IPV4 packet
                    console.log(pkt,'VLAN',pkt.payload.vlan,'IP Packet',pkt.payload.payload)
                }
            }
        });
    }
}).listen(6343);
