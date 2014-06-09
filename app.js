/**
 * Created by delian on 6/9/14.
 */

var Collector = require('node-sflow');
var pcap = require('pcap');
var config = require('./config.json');
var exec = require('child_process').exec;

function startApp(n) {
    exec(n, function callback(error, stdout){
        console.log('Executed',n,stdout);
    });
}

function ip2num(ip) {
    var x = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)/);
    if (!x) return 0;
    return parseInt(x[4])+(parseInt(x[3])<<8)+(parseInt(x[2])<<16)+((parseInt(x[1])<<16)*256);
}

function ipMatch(net,ip) {
    var x = net.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
    if (!x) return 0;
    var netNum = ip2num(x[1]);
    var netCount = Math.pow(2,32-parseInt(x[2]));
    //var netMask = ((1<<30)*4)-netCount;
    var ipNum = ip2num(ip);
    return (ipNum>=netNum) && (ipNum<netNum+netCount);
}

function ipBelong(ip,nets) {
    for (var i = nets.length-1;i>=0;i--) {
        if (ipMatch(nets[i],ip)) return 1;
    }
    return 0;
}

if (config && config.rules instanceof Array) {
    config.rules.forEach(function(n) {
        var sampleInterval = 30;
        var pps = 100;
        var minInterval = 30;
        var maxInterval = 600;
        var multiplier = 2;
        var clearInterval = 600;

        if (n.thresholds) {
            sampleInterval = n.thresholds.sampleInterval || sampleInterval;
            pps = n.thresholds.pps || pps;
            minInterval = n.thresholds.minInterval || minInterval;
            maxInterval = n.thresholds.maxInterval || maxInterval;
            multiplier = n.thresholds.multiplier || multiplier;
            clearInterval = n.thresholds.clearInterval || clearInterval;
        }

        n.counters = {};

        setInterval(function() {
            Object.keys(n.counters).forEach(function(s) {
                var p = n.counters[s];
                if (p.packets>pps) {
                    if (!p.trigger) {
                        console.log('Trigger the startScript for',n,'execute', n.startScript);
                        startApp(n.startScript);
                        p.trigger = 1;
                        p.clearInterval = clearInterval;
                        setTimeout(function() {
                            console.log('Trigger the stopScript for',n,'execute', n.stopScript);
                            startApp(n.stopScript);
                            p.trigger = 0;
                        }, p.nextBlockInterval*1000);
                        p.nextBlockInterval *= multiplier;
                    }
                } else {
                    if (!p.trigger) {
                        p.clearInterval-=sampleInterval;
                        if (p.clearInterval<=0) p.nextBlockInterval = minInterval; // Next Time we will block for this time
                    }
                }
                s.packets = 0;
            });
        },sampleInterval*1000);
    });
}

Collector(function(flow) {
    if (flow && flow.flow.records && flow.flow.records.length>0) {
        flow.flow.records.forEach(function(n) {
            if (n.type == 'raw') {
                if (n.protocolText == 'ethernet') {
                    try {
                        var pkt = pcap.decode.ethernet(n.header, 0);
                    } catch(e) { console.log(e);return; }

                    if (pkt.ethertype!=2048) return;
                    console.log('VLAN',pkt.vlan?pkt.vlan.id:'none','Packet',pkt.ip.protocol_name,pkt.ip.saddr,':',pkt.ip.tcp?pkt.ip.tcp.sport:pkt.ip.udp.sport,'->',pkt.ip.daddr,':',pkt.ip.tcp?pkt.ip.tcp.dport:pkt.ip.udp.dport);
                    
                    config.rules.forEach(function(r) {
                        // Lets check if it belong to the correct VLAN
                        //console.log(r);
                        if (r.vlans instanceof Array) {
                            if (pkt.vlan.id) {
                                if (r.vlans.indexOf(pkt.vlan.id)<0) return;
                            } else return;
                        }
                        // Lets check if the destination IP address belong to a group of networks
                        if (r.networks instanceof Array) {
                            console.log('rrr', pkt.ip.daddr,r.networks,ipBelong(pkt.ip.daddr, r.networks));
                            if (!ipBelong(pkt.ip.daddr, r.networks)) return;
                        }
                        console.log('IP is ok');

                        // Now we have match both for VLANs and Networks
                        console.log('counters',r);
                        if (typeof r.counters[pkt.ip.daddr] == 'undefined') r.counters[pkt.ip.daddr] = {
                            trigger: 0,
                            packets: 0,
                            nextBlockInterval: (r.thresholds && r.thresholds.minInterval)? r.thresholds.minInterval:30,
                            clearInterval: 0
                        };

                        var p = r.counters[pkt.ip.daddr];
                        p.packets++;
                    });
                }
            }
        });
    }
}).listen(config.collectorPort||6344);
