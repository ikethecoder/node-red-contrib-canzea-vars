/**
 * Copyright JS Foundation and other contributors, http://js.foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

var request = require('request');
var async = require('async');
var nconf = require('nconf');


module.exports = function(RED) {
    "use strict";

    nconf.defaults({VAULT_URI: ""}).env();

    var operators = {
        'eq': function(a, b) { return a == b; },
        'neq': function(a, b) { return a != b; },
        'lt': function(a, b) { return a < b; },
        'lte': function(a, b) { return a <= b; },
        'gt': function(a, b) { return a > b; },
        'gte': function(a, b) { return a >= b; },
        'btwn': function(a, b, c) { return a >= b && a <= c; },
        'cont': function(a, b) { return (a + "").indexOf(b) != -1; },
        'regex': function(a, b, c, d) { return (a + "").match(new RegExp(b,d?'i':'')); },
        'true': function(a) { return a === true; },
        'false': function(a) { return a === false; },
        'null': function(a) { return (typeof a == "undefined" || a === null); },
        'nnull': function(a) { return (typeof a != "undefined" && a !== null); },
        'else': function(a) { return a === true; }
    };

    function doRequest (node, msg, url, tlsNode, callback) {

        var opts = {
            method: 'GET',
            timeout: node.reqTimeout,
            followRedirect: false,
            headers: {}
        };

        if (msg.req && msg.req.headers.hasOwnProperty('x-vault-token')) {
            opts.headers['X-Vault-Token'] = msg.req.headers['x-vault-token']
        }

        if (msg.req && msg.req.headers.hasOwnProperty('x-tenant-id')) {
            opts.headers['X-Tenant-ID'] = msg.req.headers['x-tenant-id']
        }
        
        var rule = url.rule;

        if (rule.t == "keyvalue") {
            opts['url'] = url.url + "/v1/kv/" + rule.v;
        } else if (rule.t == "service") {
            opts['url'] = url.url + "/v1/catalog/service/" + rule.v;
        } else {
            opts['url'] = url.url + "/v1/secret/" + rule.v;
        }

        node.debug("CALLING: " + opts['url']);

        if (tlsNode) {
            tlsNode.addTLSOptions(opts);
        }

        return request(opts, function (error, response, body) {
            node.status({});

            if (error) {
              if (error.code === 'ETIMEDOUT') {
                node.error(RED._("common.notification.errors.no-response"), msg);
                setTimeout(function () {
                  node.status({
                    fill: "red",
                    shape: "ring",
                    text: "common.notification.errors.no-response"
                  });
                }, 10);
              } else {
                node.error(error, msg);
                //msg.payload = error.toString() + " : " + url;
                //msg.statusCode = error.code;
                node.status({
                  fill: "red",
                  shape: "ring",
                  text: "Error - " + error.statusCode
                });
              }
            } else {

              if (node.metric()) {
                // Calculate request time
                var diff = process.hrtime(preRequestTimestamp);
                var ms = diff[0] * 1e3 + diff[1] * 1e-6;
                var metricRequestDurationMillis = ms.toFixed(3);
                node.metric("duration.millis", msg, metricRequestDurationMillis);
                if (response.connection && response.connection.bytesRead) {
                  node.metric("size.bytes", msg, response.connection.bytesRead);
                }
              }

              if (response.statusCode != 200) {
                  msg.missing.push(rule.cv + ':' + rule.v);
              } else {
                  if (rule.t == "keyvalue") {

                      var key = rule.v.toUpperCase();
                      key = key.replace(/\./g, '').replace(/-/g, '_').replace(/\//g, '_');
                      var data = JSON.parse(body)[0]['Value'];

                      var contents = new Buffer(data, 'base64').toString('utf8')

                      msg.envs[key] = contents;

                      node.debug("Result = "+contents);

                  } else if (rule.t == "service") {

                        var name = rule.v.toUpperCase();

                        var services = JSON.parse(body);

                        services.forEach(function (s) {

                            var key = "" + name + "_ADDRESS"
                            key = key.replace(/\./g, '').replace(/-/g, '_').replace(/\//g, '_');
                            node.debug("Setting: " + key + " : " + s["ServiceAddress"])
                            msg.envs[key] = s["ServiceAddress"];

                            key = "" + name + "_PORT"
                            key = key.replace(/\./g, '').replace(/-/g, '_').replace(/\//g, '_');
                            node.debug("Setting: " + key + " : " + String(s["ServicePort"]))
                            msg.envs[key] = "" + s["ServicePort"];

                            key = "" + name + "_URL"
                            key = key.replace(/\./g, '').replace(/-/g, '_').replace(/\//g, '_');
                            var val = "http://" + s["ServiceAddress"] + ":" + String(s["ServicePort"])
                            node.debug("Setting: " + key + " : " + val)
                            msg.envs[key] = val;
                        });

                  } else {
                      var data = JSON.parse(body)['data'];
                      var key = rule.v.toUpperCase();
                      key = key.replace(/\./g, '').replace(/-/g, '_').replace(/\//g, '_');

                      Object.keys(data).forEach(function (e) {
                          var fkey = e.toUpperCase().replace(/\./g, '').replace(/-/g, '_').replace(/\//g, '_');

                          msg.envs[key + "_" + fkey] = data[e];
                      });
                  }
              }
              //node.warn("Finished request for " + rule.v);
            }
            callback();
        });

    }

    function VarsNode(n) {
        RED.nodes.createNode(this, n);
        this.rules = n.rules || [];
        this.property = n.property;
        this.propertyType = n.propertyType || "msg";

        if (n.tls) {
          var tlsNode = RED.nodes.getNode(n.tls);
        }

        if (this.propertyType === 'jsonata') {
            try {
                this.property = RED.util.prepareJSONataExpression(this.property,this);
            } catch(err) {
                this.error(RED._("vars.errors.invalid-expr",{error:err.message}));
                return;
            }
        }

        this.checkall = n.checkall || "true";
        this.previousValue = null;
        var node = this;
        var valid = true;
        for (var i=0; i<this.rules.length; i+=1) {
            var rule = this.rules[i];
            if (!rule.vt) {
                if (!isNaN(Number(rule.v))) {
                    rule.vt = 'num';
                } else {
                    rule.vt = 'str';
                }
            }
            if (rule.vt === 'num') {
                if (!isNaN(Number(rule.v))) {
                    rule.v = Number(rule.v);
                }
            } else if (rule.vt === "jsonata") {
                try {
                    rule.v = RED.util.prepareJSONataExpression(rule.v,node);
                } catch(err) {
                    this.error(RED._("vars.errors.invalid-expr",{error:err.message}));
                    valid = false;
                }
            }
            if (typeof rule.v2 !== 'undefined') {
                if (!rule.v2t) {
                    if (!isNaN(Number(rule.v2))) {
                        rule.v2t = 'num';
                    } else {
                        rule.v2t = 'str';
                    }
                }
                if (rule.v2t === 'num') {
                    rule.v2 = Number(rule.v2);
                } else if (rule.v2t === 'jsonata') {
                    try {
                        rule.v2 = RED.util.prepareJSONataExpression(rule.v2,node);
                    } catch(err) {
                        this.error(RED._("vars.errors.invalid-expr",{error:err.message}));
                        valid = false;
                    }
                }
            }
        }

        if (!valid) {
            return;
        }

        this.on('input', function (msg) {
            node.status({
                fill: "blue",
                shape: "dot",
                text: "Requesting"
            });

            var promises = [];
            try {
                if (msg.hasOwnProperty('envs') == false) {
                    msg.envs = {};
                }
                if (msg.hasOwnProperty('missing') == false) {
                    msg.missing = [];
                }

                var baseUrl = (typeof n.url === "undefined" || n.url == "") ? nconf.get("VAULT_URI") : n.url;

                var urls = [];
                for (var i=0; i<node.rules.length; i+=1) {
                    var rule = node.rules[i];

                    var v = evalValue(node, rule, msg);
                    node.debug("vars : " + rule.v + " -> " + v + " : " + JSON.stringify(rule));

                    rule.cv = rule.v;
                    rule.v = v;
                    urls.push({"url":baseUrl, "rule":rule});
                }

                async.each(urls, function (url, callback) {
                    doRequest (node, msg, url, tlsNode, callback);
                }, function (err) {
                    node.send(msg);
                });
            } catch(err) {
                node.warn(err);
            }
        });



    }

    function evalValue (node, rule, msg) {
        var v1,v2;
        if (rule.vt === 'prev') {
            v1 = node.previousValue;
        } else if (rule.vt === 'jsonata') {
            try {
                v1 = RED.util.evaluateJSONataExpression(rule.v,msg);
            } catch(err) {
                node.error(RED._("switch.errors.invalid-expr",{error:err.message}));
                return;
            }
        } else {
            try {
                v1 = RED.util.evaluateNodeProperty(rule.v,rule.vt,node,msg);
            } catch(err) {
                node.error(RED._("switch.errors.invalid-property",{error:err.message}));
                v1 = undefined;
            }
        }
        return v1;
    }
    RED.nodes.registerType("vars", VarsNode);
}
