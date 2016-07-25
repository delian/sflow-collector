/**
 * Created by delian on 6/9/14.
 */

var Collector = require('node-sflow');
var pcap = require('pcap2');
var config = require('./config.json');
var exec = require('child_process').exec;

var verbose = config.verbose || true;

function startApp(n,ip) {
    exec(n+' '+ip, function callback(error, stdout){
        if (verbose) console.log('Completed execution',n,stdout);
    });
}

function a2ip(a) {
    return a.addr[0]+'.'+a.addr[1]+'.'+a.addr[2]+'.'+a.addr[3];
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
        var unblockUnforced = true;

        if (n.thresholds) {
            sampleInterval = n.thresholds.sampleInterval || sampleInterval;
            pps = n.thresholds.pps || pps;
            minInterval = n.thresholds.minInterval || minInterval;
            maxInterval = n.thresholds.maxInterval || maxInterval;
            multiplier = n.thresholds.multiplier || multiplier;
            clearInterval = n.thresholds.clearInterval || clearInterval;
            unblockUnforced = !(n.thresholds.forcedStop);
        }

        n.counters = {};

        setInterval(function() {
            Object.keys(n.counters).forEach(function(ip) {
                var p = n.counters[ip];
                if (verbose) console.log('Counters for',ip, 'average pps:',p.packets/sampleInterval,'of',pps,p);

                function triggerStart(ip,p,n) {
                    if (!p.trigger) {
                        if (verbose) console.log('Trigger the startScript for',ip,'execute', n.startScript);
                        startApp(n.startScript,ip);
                        p.trigger = 1;
                        p.clearInterval = clearInterval;
                    }
                    if (verbose) console.log('Next unblock check in', p.nextBlockInterval);
                    setTimeout(function() {
                        if (unblockUnforced && p.packets>pps*sampleInterval) {
                            return triggerStart(ip,p,n);
                        } else {
                            if (verbose) console.log('Trigger the stopScript for',ip,'execute', n.stopScript);
                            startApp(n.stopScript,ip);
                            p.trigger = 0;
                        }
                    }, p.nextBlockInterval*1000-100); // Preseve the order
                    p.nextBlockInterval *= multiplier;
                    if (p.nextBlockInterval>maxInterval) p.nextBlockInterval=maxInterval; // Never block for more than maxInterval
                }

                if (p.packets>pps*sampleInterval) {
                    if (!p.trigger) triggerStart(ip,p,n);
                } else {
                    if (!p.trigger) {
                        p.clearInterval-=sampleInterval;
                        if (p.clearInterval<=0) p.nextBlockInterval = minInterval; // Next Time we will block for this time
                    }
                }
                p.packets = 0;
            });
        },sampleInterval*1000);
    });
}

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
                    //console.log('VLAN',pkt.vlan,'Packet',pkt.payload.IPv4)
                    if (pkt.payload.payload.protocol!=6 && pkt.payload.payload.protocol!=17) return;
                    if (verbose) console.log('VLAN',pkt.payload.vlan?pkt.payload.vlan.id:'none','Packet',pkt.payload.payload.protocol,a2ip(pkt.payload.payload.saddr),':',pkt.payload.payload.payload.sport,'->',a2ip(pkt.payload.payload.daddr),':',pkt.payload.payload.payload.dport);
                    
                    config.rules.forEach(function(r) {
                        // Lets check if it belong to the correct VLAN
                        if (r.vlans instanceof Array) {
                            if (pkt.payload.vlan.id) {
                                if (r.vlans.indexOf(pkt.payload.vlan.id)<0) return;
                            } else return;
                        }
                        // Lets check if the destination IP address belong to a group of networks
                        if (r.networks instanceof Array) {
                            if (!ipBelong(a2ip(pkt.payload.payload.daddr), r.networks)) return;
                        }

                        // Now we have match both for VLANs and Networks
                        if (typeof r.counters[a2ip(pkt.payload.payload.daddr)] == 'undefined') r.counters[a2ip(pkt.payload.payload.daddr)] = {
                            trigger: 0,
                            packets: 0,
                            nextBlockInterval: (r.thresholds && r.thresholds.minInterval)? r.thresholds.minInterval:30,
                            clearInterval: 0
                        };

                        var p = r.counters[a2ip(pkt.payload.payload.daddr)];
                        p.packets++;
                    });
                }
            }
        });
    }
}).listen(config.collectorPort||6344);
