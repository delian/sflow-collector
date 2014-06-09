/**
 * Created by delian on 6/9/14.
 */

var Collector = require('node-sflow');
var pcap = require('pcap');

Collector(function(flow) {
    if (flow && flow.flow.records && flow.flow.records.length>0) {
        flow.flow.records.forEach(function(n) {
            console.log('process record',n);

            if (n.type == 'raw') {
                if (n.protocolText == 'ethernet') {
                    try {
                        var pkt = pcap.decode.ethernet(n.header, 0);
                        if (pkt.ethertype==2048) return;
                        console.log('VLAN',pkt.vlan?pkt.vlan.id:'none','Packet',pkt.ip.protocol_name,pkt.ip.saddr,':',pkt.ip.tcp?pkt.ip.tcp.sport:pkt.ip.udp.sport,'->',pkt.ip.daddr,':',pkt.ip.tcp?pkt.ip.tcp.dport:pkt.ip.udp.dport)
                    } catch(e) {}
                }
            }
        });
    }
}).listen(6344);
