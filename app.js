/**
 * Created by delian on 6/9/14.
 */

var Collector = require('node-sflow');

Collector(function(flow) {
    if (flow && flow.flow.records && flow.flow.records.length>0) {
        console.log(flow.flow);

        flow.flow.records.forEach(function(n) {
            console.log('process record',n);
        });
    }
}).listen(6344);
