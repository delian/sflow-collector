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
                    console.log(pcap.decode.ethernet(n.header,0));
                }
            }
        });
    }
}).listen(6344);
