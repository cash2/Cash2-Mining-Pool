/**
 * Cryptonote Node.JS Pool
 * https://github.com/dvandal/cryptonote-nodejs-pool
 *
 * Pool TCP daemon
 **/

// var previousBlockHashGlobal;
// var coinbaseTransactionGlobal;
// var transactionHashesGlobal;
// var timestampGlobal;
var extraNonce1Global = 0;


// Load required modules
var fs = require('fs');
var net = require('net');
var tls = require('tls');
var async = require('async');
var bignum = require('bignum');

var apiInterfaces = require('./apiInterfaces.js')(config.daemon, config.wallet, config.api);
var notifications = require('./notifications.js');
var utils = require('./utils.js');

var cnHashing = require('cryptonight-hashing');
var blake2 = require('blake2');

// Set nonce pattern - must exactly be 16 hex chars
var noncePattern = new RegExp("^[0-9A-Fa-f]{16}$");

// Set redis database cleanup interval
var cleanupInterval = config.redis.cleanupInterval && config.redis.cleanupInterval > 0 ? config.redis.cleanupInterval : 15;

// Initialize log system
var logSystem = 'pool';
require('./exceptionWriter.js')(logSystem);

var threadId = '(Thread ' + process.env.forkId + ') ';
var log = function(severity, system, text, data){
    global.log(severity, system, threadId + text, data);
};

// Set cryptonight algorithm
var cnAlgorithm = config.cnAlgorithm || "cryptonight";
var cnVariant = config.cnVariant || 0;
var cnBlobType = config.cnBlobType || 0;

var cryptoNight;
if (!cnHashing || !cnHashing[cnAlgorithm]) {
    log('error', logSystem, 'Invalid cryptonight algorithm: %s', [cnAlgorithm]);
} else {
    cryptoNight = cnHashing[cnAlgorithm];
}

// Set instance id
var instanceId = utils.instanceId();

// Pool variables
var poolStarted = false;
var connectedMiners = {};

// Pool settings
var shareTrustEnabled = config.poolServer.shareTrust && config.poolServer.shareTrust.enabled;
var shareTrustStepFloat = shareTrustEnabled ? config.poolServer.shareTrust.stepDown / 100 : 0;
var shareTrustMinFloat = shareTrustEnabled ? config.poolServer.shareTrust.min / 100 : 0;

var banningEnabled = config.poolServer.banning && config.poolServer.banning.enabled;
var bannedIPs = {};
var perIPStats = {};

var slushMiningEnabled = config.poolServer.slushMining && config.poolServer.slushMining.enabled;

if (!config.poolServer.paymentId) config.poolServer.paymentId = {};
if (!config.poolServer.paymentId.addressSeparator) config.poolServer.paymentId.addressSeparator = "+";


// Block templates
var validBlockTemplates = [];
var currentBlockTemplate;

// Difficulty buffer
var diff1 = bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);

/**
 * Convert buffer to byte array
 **/
Buffer.prototype.toByteArray = function () {
    return Array.prototype.slice.call(this, 0);
};

/**
 * Periodical updaters
 **/
 
// Variable difficulty retarget
setInterval(function(){
    var now = Date.now() / 1000 | 0;
    for (var minerId in connectedMiners){
        var miner = connectedMiners[minerId];
        if(!miner.noRetarget) {
            miner.retarget(now);
        }
    }
}, config.poolServer.varDiff.retargetTime * 1000);

// Every 30 seconds clear out timed-out miners and old bans
setInterval(function(){
    var now = Date.now();
    var timeout = config.poolServer.minerTimeout * 1000;
    for (var minerId in connectedMiners){
        var miner = connectedMiners[minerId];
        if (now - miner.lastBeat > timeout){
            log('warn', logSystem, 'Miner timed out and disconnected %s@%s', [miner.login, miner.ip]);
            delete connectedMiners[minerId];
            removeConnectedWorker(miner, 'timeout');
        }
    }    

    if (banningEnabled){
        for (ip in bannedIPs){
            var banTime = bannedIPs[ip];
            if (now - banTime > config.poolServer.banning.time * 1000) {
                delete bannedIPs[ip];
                delete perIPStats[ip];
                log('info', logSystem, 'Ban dropped for %s', [ip]);
            }
        }
    }

}, 30000);

/**
 * Handle multi-thread messages
 **/ 
process.on('message', function(message) {
    switch (message.type) {
        case 'banIP':
            bannedIPs[message.ip] = Date.now();
            break;
    }
});

/**
 * Block template
 **/
function BlockTemplate(template){
    this.blob = template.blocktemplate_blob;
    this.difficulty = template.difficulty;
    this.height = template.height;
    this.reserveOffset = template.reserved_offset;
    this.buffer = new Buffer(this.blob, 'hex');
    // instanceId.copy(this.buffer, this.reserveOffset + 8, 0, 7);
    this.extraNonce = 0;
    this.previousBlockHash = template.blocktemplate_blob.substr(0, 64); // previous block hash is 32 bytes long or 64 hex characters
    this.timestamp = template.blocktemplate_blob.substr(80, 16); // timestamp is 8 bytes long or 16 hex characters

    // get the last 120 bytes (240 hex characters) of the coinbase transaction

    // console.log("coinbase transaction from substring = " + template.blocktemplate_blob.substr(160));
    // console.log("coinbase transaction from rpc = " + template.coinbase_tx);

    var coinbaseEnd = template.coinbase_tx.length;

    // this.coinbaseTransaction1 = template.blocktemplate_blob.substr(coinbaseEnd - 240 - 2, (2 * template.reserved_offset - (coinbaseEnd - 240))); // 160 is from 80 byte header size times 2, for some reason need to subtract 2 to get it to work
    this.coinbaseTransaction1 = template.coinbase_tx.substr(coinbaseEnd - 240, (2 * template.reserved_offset - 160 - (coinbaseEnd - 240 + 2))); // 160 is from 80 byte header size times 2, 240 is the number of hex characters we want for coinbase transaction 1 + extra nonce 1 + extra nonce 2 + coinbase transaction 2
    // this.coinbaseTransaction2 = template.blocktemplate_blob.substr(2 * template.reserved_offset + 16); // 16 is the size of extra nonce 1 plus extra nonce 2
    this.coinbaseTransaction2 = template.coinbase_tx.substr(2 * template.reserved_offset - 160 - 2 + 16); // 2 x reserve_offset - 160 - 2 gives the start of extra nonce 1.  16 is the size of extra nonce 1 plus extra nonce 2

    // console.log("coinbase transaction = " + template.coinbase_tx);
    // console.log("coinbase transaction 1 = " + this.coinbaseTransaction1);
    // console.log("coinbase transaction 2 = " + this.coinbaseTransaction2);

    this.transactionHashes = template.transaction_hashes;

    var h = blake2.createHash('blake2b', {digestLength: 32});
    var coinbaseTransactionBuffer = new Buffer(template.blocktemplate_blob.substr(160), "hex");
    h.update(coinbaseTransactionBuffer);
    
    // console.log("base transaction from substring hash = " + h.digest().toString("Hex"));
    // console.log("transactionHashes[0] = " + this.transactionHashes[0]);
    // console.log("transactionHashes[1] = " + this.transactionHashes[1]);
    // console.log("transactionHashes[2] = " + this.transactionHashes[2]);
    // console.log("transactionHashes[3] = " + this.transactionHashes[3]);

    //this.previous_hash = new Buffer(32);
    //this.buffer.copy(this.previous_hash,0,7,39);
}

BlockTemplate.prototype = {
    nextBlob: function(){
        this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
        return utils.cnUtil.convert_blob(this.buffer, cnBlobType).toString('hex');
    }
};

/**
 * Get block template
 **/
function getBlockTemplate(callback){
    apiInterfaces.rpcDaemon('getblocktemplate', {reserve_size: 16, wallet_address: config.poolServer.poolAddress}, callback);
}

/**
 * Process block template
 **/
function processBlockTemplate(template, socket){
    if (currentBlockTemplate)
        validBlockTemplates.push(currentBlockTemplate);

    if (validBlockTemplates.length > 3)
        validBlockTemplates.shift();

    currentBlockTemplate = new BlockTemplate(template);

    for (var minerId in connectedMiners){
      var miner = connectedMiners[minerId];
      var job = miner.getJob();
      miner.pushMessage('job', job);

      if (socket)
      {
        var sendData = JSON.stringify({
            params:
            [
              job.job_id, // job id
              job.previousBlockHash, // hash of previous block
              job.coinbaseTransaction1, // coinbase part 1
              job.coinbaseTransaction2, // coinbase part 2
              job.transactionHashes, // merkle branches
              "", // block version number
              job.target.toString(16), // network difficulty
              job.timestamp, // time
              false // clean jobs
            ],
            id : null,
            method: "mining.notify"
        }) + "\n";

        socket.write(sendData);
      }
    }
}

/**
 * Job refresh
 **/
function jobRefresh(loop, socket, callback){
    callback = callback || function(){};
    getBlockTemplate(function(error, result){
        if (loop)
            setTimeout(function(){
                jobRefresh(true);
            }, config.poolServer.blockRefreshInterval);
        if (error){
            log('error', logSystem, 'Error polling getblocktemplate %j', [error]);
            if (!poolStarted) log('error', logSystem, 'Could not start pool');
            callback(false);
            return;
        }

        //var buffer = new Buffer(result.blocktemplate_blob, 'hex');
        //var previous_hash = new Buffer(32);
        //buffer.copy(previous_hash,0,7,39);
        //if (!currentBlockTemplate || previous_hash.toString('hex') !== currentBlockTemplate.previous_hash.toString('hex')) {

        // console.log("block template blob = " + result.blocktemplate_blob);
        // console.log("block template reserved offset = " + result.reserved_offset);
        // console.log("coinbase transaction = " + result.blocktemplate_blob.substr(160));
        // console.log("coinbase transaction 1 = " + result.blocktemplate_blob.substr(160, (2* result.reserved_offset - 160 - 2)));
        // console.log("coinbase transaction 2 = " + result.blocktemplate_blob.substr(2 * result.reserved_offset + 16 - 2));

        // console.log("\nparse from block hash\n");

        // console.log("coinbase tx = " + result.coinbase_tx);
        // console.log("transaction hashes = " + result.transaction_hashes);

        // console.log("previous block hash = " + result.blocktemplate_blob.substr(0, 64));
        // console.log("nonce = " + result.blocktemplate_blob.substr(64, 16));
        // console.log("timestamp = " + result.blocktemplate_blob.substr(80, 16));
        // console.log("merkle root = " + result.blocktemplate_blob.substr(96, 64));
        // console.log("coinbase tx = " + result.blocktemplate_blob.substr(160));

        // console.log("get block template difficulty = " + result.difficulty);

        if (!currentBlockTemplate || result.height > currentBlockTemplate.height) {
            log('info', logSystem, 'New block to mine at height %d w/ difficulty of %d', [result.height, result.difficulty]);
            processBlockTemplate(result, socket);
        }
        if (!poolStarted) {
            startPoolServerTcp(function(successful){ poolStarted = true });
        }
        callback(true);
    })
}

/**
 * Variable difficulty
 **/
var VarDiff = (function(){
    var variance = config.poolServer.varDiff.variancePercent / 100 * config.poolServer.varDiff.targetTime;
    return {
        variance: variance,
        bufferSize: config.poolServer.varDiff.retargetTime / config.poolServer.varDiff.targetTime * 4,
        tMin: config.poolServer.varDiff.targetTime - variance,
        tMax: config.poolServer.varDiff.targetTime + variance,
        maxJump: config.poolServer.varDiff.maxJump
    };
})();

/**
 * Miner
 **/
function Miner(id, login, pass, ip, port, workerName, startingDiff, noRetarget, pushMessage, extraNonce1){
    this.id = id;
    this.login = login;
    this.pass = pass;
    this.ip = ip;
    this.port = port;
    this.workerName = workerName;
    this.pushMessage = pushMessage;
    this.heartbeat();
    this.noRetarget = noRetarget;
    this.difficulty = startingDiff;
    this.validJobs = [];
    this.extraNonce1 = extraNonce1;

    // Vardiff related variables
    this.shareTimeRing = utils.ringBuffer(16);
    this.lastShareTime = Date.now() / 1000 | 0;

    if (shareTrustEnabled) {
        this.trust = {
            threshold: config.poolServer.shareTrust.threshold,
            probability: 1,
            penalty: 0
        };
    }
}

Miner.prototype = {
    retarget: function(now){

        var options = config.poolServer.varDiff;

        var sinceLast = now - this.lastShareTime;
        var decreaser = sinceLast > VarDiff.tMax;

        var avg = this.shareTimeRing.avg(decreaser ? sinceLast : null);
        var newDiff;

        var direction;

        if (avg > VarDiff.tMax && this.difficulty > options.minDiff){
            newDiff = options.targetTime / avg * this.difficulty;
            newDiff = newDiff > options.minDiff ? newDiff : options.minDiff;
            direction = -1;
        }
        else if (avg < VarDiff.tMin && this.difficulty < options.maxDiff){
            newDiff = options.targetTime / avg * this.difficulty;
            newDiff = newDiff < options.maxDiff ? newDiff : options.maxDiff;
            direction = 1;
        }
        else{
            return;
        }

        if (Math.abs(newDiff - this.difficulty) / this.difficulty * 100 > options.maxJump){
            var change = options.maxJump / 100 * this.difficulty * direction;
            newDiff = this.difficulty + change;
        }

        this.setNewDiff(newDiff);
        this.shareTimeRing.clear();
        if (decreaser) this.lastShareTime = now;
    },
    setNewDiff: function(newDiff){
        newDiff = Math.round(newDiff);
        if (this.difficulty === newDiff) return;
        log('info', logSystem, 'Retargetting difficulty %d to %d for %s', [this.difficulty, newDiff, this.login]);
        this.pendingDifficulty = newDiff;
        this.pushMessage('job', this.getJob());
    },
    heartbeat: function(){
        this.lastBeat = Date.now();
    },
    getTargetHex: function(){
        if (this.pendingDifficulty){
            this.lastDifficulty = this.difficulty;
            this.difficulty = this.pendingDifficulty;
            this.pendingDifficulty = null;
        }

        var padded = new Buffer(32);
        padded.fill(0);

        var diffBuff = diff1.div(this.difficulty).toBuffer();
        diffBuff.copy(padded, 32 - diffBuff.length);

        var buff = padded.slice(0, 4);
        var buffArray = buff.toByteArray().reverse();
        var buffReversed = new Buffer(buffArray);
        this.target = buffReversed.readUInt32BE(0);
        var hex = buffReversed.toString('hex');
        return hex;
    },
    getJob: function(){
        if (this.lastBlockHeight === currentBlockTemplate.height && !this.pendingDifficulty) {
            return {
                blob: '',
                timestamp: '',
                previousBlockHash: '',
                transactionHashes: [],
                coinbaseTransaction1: '',
                coinbaseTransaction2: '',
                job_id: '',
                target: ''
            };
        }

        var blob = currentBlockTemplate.nextBlob();
        this.lastBlockHeight = currentBlockTemplate.height;
        var target = this.getTargetHex();

        var newJob = {
            id: utils.uid(),
            timestamp: currentBlockTemplate.timestamp,
            previousBlockHash: currentBlockTemplate.previousBlockHash,
            transactionHashes: currentBlockTemplate.transactionHashes,
            coinbaseTransaction1: currentBlockTemplate.coinbaseTransaction1,
            coinbaseTransaction2: currentBlockTemplate.coinbaseTransaction2,
            extraNonce: currentBlockTemplate.extraNonce,
            height: currentBlockTemplate.height,
            difficulty: this.difficulty,
            diffHex: this.diffHex,
            submissions: []
        };

        this.validJobs.push(newJob);

        if (this.validJobs.length > 4)
            this.validJobs.shift();

        // console.log("blob = " + blob);

        return {
            blob: blob,
            timestamp: currentBlockTemplate.timestamp,
            previousBlockHash: currentBlockTemplate.previousBlockHash,
            transactionHashes: currentBlockTemplate.transactionHashes,
            coinbaseTransaction1: currentBlockTemplate.coinbaseTransaction1,
            coinbaseTransaction2: currentBlockTemplate.coinbaseTransaction2,
            job_id: newJob.id,
            target: target,
            id: this.id
        };
    },
    checkBan: function(validShare){
        if (!banningEnabled) return;
    
        // Init global per-ip shares stats
        if (!perIPStats[this.ip]){
            perIPStats[this.ip] = { validShares: 0, invalidShares: 0 };
        }
    
        var stats = perIPStats[this.ip];
        validShare ? stats.validShares++ : stats.invalidShares++;
    
        if (stats.validShares + stats.invalidShares >= config.poolServer.banning.checkThreshold){
            if (stats.invalidShares / stats.validShares >= config.poolServer.banning.invalidPercent / 100){
                validShare ? this.validShares++ : this.invalidShares++;
                log('warn', logSystem, 'Banned %s@%s', [this.login, this.ip]);
                bannedIPs[this.ip] = Date.now();
                delete connectedMiners[this.id];
                process.send({type: 'banIP', ip: this.ip});
                removeConnectedWorker(this, 'banned');
            }
            else{
                stats.invalidShares = 0;
                stats.validShares = 0;
            }
        }
    }
};

/**
 * Handle miner method
 **/
function handleMinerMethod(method, params, socket, portData, sendReply, pushMessage, id){

    var ip = socket.remoteAddress;

    var miner = connectedMiners[params.id];

    // Check for ban here, so preconnected attackers can't continue to screw you
    if (IsBannedIp(ip)){
        sendReply('Your IP is banned');
        return;
    }

    switch(method){
        case "mining.subscribe" :

          // console.log("mining.subscribe");

          // Set up miner with temporary values for login, difficulty, and noRetarget
          // Call get job to get unique extra nonce 1 for the miner
          var minerId = utils.uid();
          var login = "";
          var pass = "";
          var port = "";
          var workerName = "worker_" + minerId;
          var difficulty = "";
          var noRetarget = false;
          var extraNonce1 = "" + extraNonce1Global++; // increment extra nonce 1 global and convert to string
          var extraNonce1and2Size = 4;
          while (extraNonce1.length < 2 * extraNonce1and2Size)
          {
            extraNonce1 = "0" + extraNonce1;
          }

          miner = new Miner(minerId, login, pass, ip, port, workerName, difficulty, noRetarget, pushMessage, extraNonce1);
          connectedMiners[params.id] = miner;

          // console.log("sent extraNonce1 = " + extraNonce1);

          var sendData = JSON.stringify({
            "id": id,
            "result": [ [ ["mining.set_difficulty", "b4b6693b72a50c7116db18d6497cac52"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"]], extraNonce1, extraNonce1and2Size],
            "error": null
          }) + "\n";

          socket.write(sendData);

          break;
        case 'mining.authorize':

            // console.log("mining.authorize");

            var login = params[0];

            if (!login){
                console.log("mining.authorize missing login");
                sendReply('Missing login');
                return;
            }

            var port = portData.port;

            var pass = params.pass;
            var difficulty = portData.difficulty;
            var noRetarget = false;
            if(config.poolServer.fixedDiff.enabled) {
                var fixedDiffCharPos = login.lastIndexOf(config.poolServer.fixedDiff.addressSeparator);
                if (fixedDiffCharPos !== -1 && (login.length - fixedDiffCharPos < 32)){
                    diffValue = login.substr(fixedDiffCharPos + 1);
                    difficulty = parseInt(diffValue);
                    login = login.substr(0, fixedDiffCharPos);
                    if (!difficulty || difficulty != diffValue) {
                        log('warn', logSystem, 'Invalid difficulty value "%s" for login: %s', [diffValue, login]);
                        difficulty = portData.difficulty;
                    } else {
                        noRetarget = true;
                        if (difficulty < config.poolServer.varDiff.minDiff) {
                            difficulty = config.poolServer.varDiff.minDiff;
                        }
                    }
                }
            }

            var addr = login.split(config.poolServer.paymentId.addressSeparator);
            var address = addr[0] || null;

            if (!address) {
                log('warn', logSystem, 'No address specified for login');
                sendReply('Invalid address used for login');
                console.log("mining.authorize invalid login address");
            }

            if (!utils.validateMinerAddress(address)) {
                var addressPrefix = utils.getAddressPrefix(address);
                if (!addressPrefix) addressPrefix = 'N/A';

                log('warn', logSystem, 'Invalid address used for login (prefix: %s): %s', [addressPrefix, address]);
                sendReply('Invalid address used for login');
                console.log("mining.authorize invalid login address");
                return;
            }

            if (!miner){
                // console.log("unauthenticated");
                sendReply('Unauthenticated');
                return;
            }

            // var minerId = utils.uid();

            miner.login = login;
            miner.pass = pass;
            miner.ip = ip;
            miner.port = port;
            miner.difficulty = difficulty;
            miner.noRetarget = noRetarget;

            // miner = new Miner(minerId, login, pass, ip, port, workerName, difficulty, noRetarget, pushMessage);
            // connectedMiners[minerId] = miner;
        
            var sendData1 = JSON.stringify({
                "error": null,
                "id": id,
                "result": true
            }) + "\n";

            socket.write(sendData1);

            newConnectedWorker(miner);

            var job = miner.getJob();

            var sendData2 = JSON.stringify({
                params:
                [
                  job.job_id, // job id
                  job.previousBlockHash, // hash of previous block
                  job.coinbaseTransaction1, // coinbase part 1
                  job.coinbaseTransaction2, // coinbase part 2
                  job.transactionHashes, // coinbase transaction hash + block transactions hashes
                  "", // block version number
                  job.target.toString(16), // network difficulty
                  job.timestamp, // time
                  false // clean jobs
                ],
                id : null,
                method: "mining.notify"
            }) + "\n";

            socket.write(sendData2);

            // set difficulty
            var sendData3 = JSON.stringify({
                "params": [1234],
                "id" : null,
                "method": "mining.set_difficulty"
            }) + "\n";

            socket.write(sendData3);

            break;
        case 'mining.submit':

            // console.log("mining.submit");

            // console.log("params = ");
            // console.log(params);

            if (!miner){
                // console.log("unauthenticated");
                sendReply('Unauthenticated');
                return;
            }

            miner.heartbeat();

            var jobId = params[1];

            var job = miner.validJobs.filter(function(job){
                // console.log("job.id = " + job.id);
                // console.log("jobId = " + jobId);
                return job.id === jobId;
            })[0];

            if (!job){
                // console.log("invalid job id");
                sendReply('Invalid job id');
                return;
            }

            var nonce = params[4];

            if (!nonce) {
                sendReply('Attack detected');
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Malformed miner share: ' + JSON.stringify(params) + ' from ' + minerText);
                return;
            }

            if (!noncePattern.test(nonce)) {
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Malformed nonce: ' + JSON.stringify(params) + ' from ' + minerText);
                // perIPStats[miner.ip] = { validShares: 0, invalidShares: 999999 };
                // miner.checkBan(false);
                sendReply('Duplicate share');
                return;
            }

            // Force lowercase for further comparison
            nonce = nonce.toLowerCase();

            if (job.submissions.indexOf(nonce) !== -1){
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Duplicate share: ' + JSON.stringify(params) + ' from ' + minerText);
                perIPStats[miner.ip] = { validShares: 0, invalidShares: 999999 };
                miner.checkBan(false);
                sendReply('Duplicate share');
                return;
            }

            job.submissions.push(nonce);

            var blockTemplate = currentBlockTemplate.height === job.height ? currentBlockTemplate : validBlockTemplates.filter(function(t){
                return t.height === job.height;
            })[0];

            if (!blockTemplate){
                sendReply('Block expired');
                return;
            }

            // console.log("mining.submit process share");

            var extraNonce2 = params[2];
            var timestamp = params[3];
            
            var shareAccepted = processShare(miner, job, blockTemplate, nonce, extraNonce2, timestamp, socket);
            miner.checkBan(shareAccepted);

            // console.log("shareAccepted = " + shareAccepted);
            
            if (shareTrustEnabled){
                if (shareAccepted){
                    miner.trust.probability -= shareTrustStepFloat;
                    if (miner.trust.probability < shareTrustMinFloat)
                        miner.trust.probability = shareTrustMinFloat;
                    miner.trust.penalty--;
                    miner.trust.threshold--;
                }
                else{
                    log('warn', logSystem, 'Share trust broken by %s@%s', [miner.login, miner.ip]);
                    miner.trust.probability = 1;
                    miner.trust.penalty = config.poolServer.shareTrust.penalty;
                }
            }
            
            if (!shareAccepted){
                sendReply('Rejected share: invalid result');
                return;
            }

            var now = Date.now() / 1000 | 0;
            miner.shareTimeRing.append(now - miner.lastShareTime);
            miner.lastShareTime = now;
            //miner.retarget(now);

            sendReply(null, {status: 'OK'});
            break;

        case 'login':
            var login = params.login;
            if (!login){
                sendReply('Missing login');
                return;
            }

            var port = portData.port;

            var pass = params.pass;
            var workerName = '';
            if (params.rigid) {
                workerName = params.rigid.trim();
            }
            else if (pass) {
                workerName = pass.trim();
                if (pass.indexOf(':') >= 0 && pass.indexOf('@') >= 0) {
                    passDelimiterPos = pass.lastIndexOf(':');
                    workerName = pass.substr(0, passDelimiterPos).trim();
                }
                workerName = workerName.replace(/:/g, '');
                workerName = workerName.replace(/\+/g, '');
                workerName = workerName.replace(/\s/g, '');
                if (workerName.toLowerCase() === 'x') {
                    workerName = '';
                }
            }
            if (!workerName || workerName === '') {
                workerName = 'undefined';
            }
            workerName = utils.cleanupSpecialChars(workerName);
        
            var difficulty = portData.difficulty;
            var noRetarget = false;
            if(config.poolServer.fixedDiff.enabled) {
                var fixedDiffCharPos = login.lastIndexOf(config.poolServer.fixedDiff.addressSeparator);
                if (fixedDiffCharPos !== -1 && (login.length - fixedDiffCharPos < 32)){
                    diffValue = login.substr(fixedDiffCharPos + 1);
                    difficulty = parseInt(diffValue);
                    login = login.substr(0, fixedDiffCharPos);
                    if (!difficulty || difficulty != diffValue) {
                        log('warn', logSystem, 'Invalid difficulty value "%s" for login: %s', [diffValue, login]);
                        difficulty = portData.difficulty;
                    } else {
                        noRetarget = true;
                        if (difficulty < config.poolServer.varDiff.minDiff) {
                            difficulty = config.poolServer.varDiff.minDiff;
                        }
                    }
                }
            }

            var addr = login.split(config.poolServer.paymentId.addressSeparator);
            var address = addr[0] || null;

            if (!address) {
                log('warn', logSystem, 'No address specified for login');
                sendReply('Invalid address used for login');
            }

            if (!utils.validateMinerAddress(address)) {
                var addressPrefix = utils.getAddressPrefix(address);
                if (!addressPrefix) addressPrefix = 'N/A';

                log('warn', logSystem, 'Invalid address used for login (prefix: %s): %s', [addressPrefix, address]);
                sendReply('Invalid address used for login');
                return;
            }

            var minerId = utils.uid();
            miner = new Miner(minerId, login, pass, ip, port, workerName, difficulty, noRetarget, pushMessage);
            connectedMiners[minerId] = miner;
        
            sendReply(null, {
                id: minerId,
                job: miner.getJob(),
                status: 'OK'
            });

            newConnectedWorker(miner);
            break;
        case 'getjob':
            if (!miner){
                sendReply('Unauthenticated');
                return;
            }
            miner.heartbeat();
            sendReply(null, miner.getJob());
            break;
        case 'submit':
            if (!miner){
                sendReply('Unauthenticated');
                return;
            }
            miner.heartbeat();

            var job = miner.validJobs.filter(function(job){
                return job.id === params.job_id;
            })[0];

            if (!job){
                sendReply('Invalid job id');
                return;
            }

            if (!params.nonce || !params.result) {
                sendReply('Attack detected');
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Malformed miner share: ' + JSON.stringify(params) + ' from ' + minerText);
                return;
            }

            // if (!noncePattern.test(params.nonce)) {
                // var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                // log('warn', logSystem, 'Malformed nonce: ' + JSON.stringify(params) + ' from ' + minerText);
                // perIPStats[miner.ip] = { validShares: 0, invalidShares: 999999 };
                // miner.checkBan(false);
                // sendReply('Duplicate share');
                // return;
            // }

            // Force lowercase for further comparison
            params.nonce = params.nonce.toLowerCase();

            if (job.submissions.indexOf(params.nonce) !== -1){
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Duplicate share: ' + JSON.stringify(params) + ' from ' + minerText);
                perIPStats[miner.ip] = { validShares: 0, invalidShares: 999999 };
                miner.checkBan(false);
                sendReply('Duplicate share');
                return;
            }

            job.submissions.push(params.nonce);

            var blockTemplate = currentBlockTemplate.height === job.height ? currentBlockTemplate : validBlockTemplates.filter(function(t){
                return t.height === job.height;
            })[0];

            if (!blockTemplate){
                sendReply('Block expired');
                return;
            }

            var shareAccepted = processShare(miner, job, blockTemplate, params.nonce, params.result);
            miner.checkBan(shareAccepted);
            
            if (shareTrustEnabled){
                if (shareAccepted){
                    miner.trust.probability -= shareTrustStepFloat;
                    if (miner.trust.probability < shareTrustMinFloat)
                        miner.trust.probability = shareTrustMinFloat;
                    miner.trust.penalty--;
                    miner.trust.threshold--;
                }
                else{
                    log('warn', logSystem, 'Share trust broken by %s@%s', [miner.login, miner.ip]);
                    miner.trust.probability = 1;
                    miner.trust.penalty = config.poolServer.shareTrust.penalty;
                }
            }
            
            if (!shareAccepted){
                sendReply('Rejected share: invalid result');
                return;
            }

            var now = Date.now() / 1000 | 0;
            miner.shareTimeRing.append(now - miner.lastShareTime);
            miner.lastShareTime = now;
            //miner.retarget(now);

            sendReply(null, {status: 'OK'});
            break;
        case 'keepalived' :
            if (!miner){
                sendReply('Unauthenticated');
                return;
            }
            miner.heartbeat();
            sendReply(null, { status:'KEEPALIVED' });
            break;
        default:
            sendReply('Invalid method');
            var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
            log('warn', logSystem, 'Invalid method: %s (%j) from %s', [method, params, minerText]);
            break;
    }
}

/**
 * New connected worker
 **/
function newConnectedWorker(miner){
    log('info', logSystem, 'Miner connected %s@%s on port', [miner.login, miner.ip, miner.port]);
    if (miner.workerName !== 'undefined') log('info', logSystem, 'Worker Name: %s', [miner.workerName]);
    if (miner.difficulty) log('info', logSystem, 'Miner difficulty fixed to %s', [miner.difficulty]);

    // console.log("newConnectedWorker");

    redisClient.sadd(config.coin + ':workers_ip:' + miner.login, miner.ip);
    redisClient.hincrby(config.coin + ':ports:'+miner.port, 'users', 1);

    redisClient.hincrby(config.coin + ':active_connections', miner.login + '~' + miner.workerName, 1, function(error, connectedWorkers) {
        if (connectedWorkers === 1) {
            notifications.sendToMiner(miner.login, 'workerConnected', {
                'LOGIN' : miner.login,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
                'IP': miner.ip.replace('::ffff:', ''),
                'PORT': miner.port,
                'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : ''
            });
        }
    });
}

/**
 * Remove connected worker
 **/
function removeConnectedWorker(miner, reason){
    redisClient.hincrby(config.coin + ':ports:'+miner.port, 'users', '-1');

    redisClient.hincrby(config.coin + ':active_connections', miner.login + '~' + miner.workerName, -1, function(error, connectedWorkers) {
        if (reason === 'banned') {
            notifications.sendToMiner(miner.login, 'workerBanned', {
                'LOGIN' : miner.login,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
                'IP': miner.ip.replace('::ffff:', ''),
                'PORT': miner.port,
                'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : ''
            });
        } else if (!connectedWorkers || connectedWorkers <= 0) {
            notifications.sendToMiner(miner.login, 'workerTimeout', {
                'LOGIN' : miner.login,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
                'IP': miner.ip.replace('::ffff:', ''),
                'PORT': miner.port,
                'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : '',
                'LAST_HASH': utils.dateFormat(new Date(miner.lastBeat), 'yyyy-mm-dd HH:MM:ss Z')
            });
       }
    });
}

/**
 * Return if IP has been banned
 **/
function IsBannedIp(ip){
    if (!banningEnabled || !bannedIPs[ip]) return false;

    var bannedTime = bannedIPs[ip];
    var bannedTimeAgo = Date.now() - bannedTime;
    var timeLeft = config.poolServer.banning.time * 1000 - bannedTimeAgo;
    if (timeLeft > 0){
        return true;
    }
    else {
        delete bannedIPs[ip];
        log('info', logSystem, 'Ban dropped for %s', [ip]);
        return false;
    }
}

/**
 * Record miner share data
 **/
function recordShareData(miner, job, shareDiff, blockCandidate, hashHex, shareType, blockTemplate){

    // console.log("\x1b[36m", "\nrecordShareData", "\x1b[0m");

    var dateNow = Date.now();
    var dateNowSeconds = dateNow / 1000 | 0;

    var updateScore;
    // Weighting older shares lower than newer ones to prevent pool hopping
    if (slushMiningEnabled) {
        // We need to do this via an eval script because we need fetching the last block time and
        // calculating the score to run in a single transaction (otherwise we could have a race
        // condition where a block gets discovered between the time we look up lastBlockFound and
        // insert the score, which would give the miner an erroneously huge proportion on the new block)
        updateScore = ['eval', `
            local age = (ARGV[3] - redis.call('hget', KEYS[2], 'lastBlockFound')) / 1000
            local score = string.format('%.17g', ARGV[2] * math.exp(age / ARGV[4]))
            redis.call('hincrbyfloat', KEYS[1], ARGV[1], score)
            return {score, tostring(age)}
            `,
            2 /*keys*/, config.coin + ':scores:roundCurrent', config.coin + ':stats',
            /* args */ miner.login, job.difficulty, Date.now(), config.poolServer.slushMining.weight];
    }
    else {
        job.score = job.difficulty;
        updateScore = ['hincrbyfloat', config.coin + ':scores:roundCurrent', miner.login, job.score]
    }

    var redisCommands = [
        updateScore,
        ['hincrby', config.coin + ':shares_actual:roundCurrent', miner.login, job.difficulty],
        ['zadd', config.coin + ':hashrate', dateNowSeconds, [job.difficulty, miner.login, dateNow].join(':')],
        ['hincrby', config.coin + ':workers:' + miner.login, 'hashes', job.difficulty],
        ['hset', config.coin + ':workers:' + miner.login, 'lastShare', dateNowSeconds],
        ['expire', config.coin + ':workers:' + miner.login, (86400 * cleanupInterval)],
        ['expire', config.coin + ':payments:' + miner.login, (86400 * cleanupInterval)]
    ];

    // console.log("\x1b[36m", "\nWorker name = " + miner.workerName + "\n", "\x1b[0m");

    if (miner.workerName) {
        redisCommands.push(['zadd', config.coin + ':hashrate', dateNowSeconds, [job.difficulty, miner.login + '~' + miner.workerName, dateNow].join(':')]);
        redisCommands.push(['hincrby', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, 'hashes', job.difficulty]);
        redisCommands.push(['hset', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, 'lastShare', dateNowSeconds]);
        redisCommands.push(['expire', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, (86400 * cleanupInterval)]);
    }
    
    if (blockCandidate){
        redisCommands.push(['hset', config.coin + ':stats', 'lastBlockFound', Date.now()]);
        redisCommands.push(['rename', config.coin + ':scores:roundCurrent', config.coin + ':scores:round' + job.height]);
        redisCommands.push(['rename', config.coin + ':shares_actual:roundCurrent', config.coin + ':shares_actual:round' + job.height]);
        redisCommands.push(['hgetall', config.coin + ':scores:round' + job.height]);
        redisCommands.push(['hgetall', config.coin + ':shares_actual:round' + job.height]);
    }

    redisClient.multi(redisCommands).exec(function(err, replies){

        // console.log("\x1b[36m", "\nredis exec errors = " + err, "\x1b[0m");
        // console.log("\x1b[36m", "\nredis exec replies = " + replies, "\x1b[0m");

        if (err){
            log('error', logSystem, 'Failed to insert share data into redis %j \n %j', [err, redisCommands]);
            return;
        }

        if (slushMiningEnabled) {
            job.score = parseFloat(replies[0][0]);
            var age = parseFloat(replies[0][1]);
            log('info', logSystem, 'Submitted score ' + job.score + ' for difficulty ' + job.difficulty + ' and round age ' + age + 's');
        }

        if (blockCandidate){
            var workerScores = replies[replies.length - 2];
            var workerShares = replies[replies.length - 1];
            var totalScore = Object.keys(workerScores).reduce(function(p, c){
                return p + parseFloat(workerScores[c])
            }, 0);
            var totalShares = Object.keys(workerShares).reduce(function(p, c){
                return p + parseInt(workerShares[c])
            }, 0);
            redisClient.zadd(config.coin + ':blocks:candidates', job.height, [
                hashHex,
                Date.now() / 1000 | 0,
                blockTemplate.difficulty,
                totalShares,
                totalScore
            ].join(':'), function(err, result){
                if (err){
                    log('error', logSystem, 'Failed inserting block candidate %s \n %j', [hashHex, err]);
                }
            });

            notifications.sendToAll('blockFound', {
                'HEIGHT': job.height,
                'HASH': hashHex,
                'DIFFICULTY': blockTemplate.difficulty,
                'SHARES': totalShares,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7)
            });
        }

    });

    log('info', logSystem, 'Accepted %s share at difficulty %d/%d from %s@%s', [shareType, job.difficulty, shareDiff, miner.login, miner.ip]);
}

/**
 * Process miner share data
 **/
function processShare(miner, job, blockTemplate, nonce, extraNonce2, timestamp, socket)
{
    var template = new Buffer(blockTemplate.buffer.length);
    blockTemplate.buffer.copy(template);

    // console.log("confirm extra nonce 1 = " + miner.extraNonce1);

    var extraNonce1And2 = "" + miner.extraNonce1 + extraNonce2;

    // console.log("extraNonce1And2 = " + extraNonce1And2);

    template.write(extraNonce1And2, blockTemplate.reserveOffset - 1, 16, "hex");
    
    // console.log("confirm nonce = " + nonce);
    // console.log("confirm coinbaseTransaction1 = " + job.coinbaseTransaction1);
    // console.log("confirm coinbaseTransaction2 = " + job.coinbaseTransaction2);
    // console.log("confirm previousBlockHash = " + job.previousBlockHash);
    // console.log("confirm timestamp = " + job.timestamp);
    // console.log("confirm transactionHashes[0] = " + job.transactionHashes[0]);
    // console.log("confirm transactionHashes[1] = " + job.transactionHashes[1]);
    // console.log("confirm transactionHashes[2] = " + job.transactionHashes[2]);
    // console.log("confirm transactionHashes[3] = " + job.transactionHashes[3]);

    // NEED TO DO: Need to also hash all transactions in the block
    // var merkleRoot = new Buffer("0000000000000000000000000000000000000000000000000000000000000000", "hex");
    var h = blake2.createHash('blake2b', {digestLength: 32});
    var arbitraryTransactionBuffer = new Buffer("00" + job.coinbaseTransaction1 + extraNonce1And2 + job.coinbaseTransaction2, "hex");
    
    // console.log("arbitrary transaction to be hashed = " + arbitraryTransactionBuffer.toString("hex"));
    
    h.update(arbitraryTransactionBuffer);

    var merkleRoot = h.digest();

    // console.log("0x00 + base tail transaction = " + arbitraryTransactionBuffer.toString("hex"));
    // console.log("base tail transaction hash = " + merkleRoot.toString("hex"));

    if (job.transactionHashes)
    {
      for (var i = 0; i < job.transactionHashes.length; i++)
      {
        var transactionBuffer = new Buffer("01" + job.transactionHashes[i] + merkleRoot.toString("hex"), "hex");
        var hash = blake2.createHash('blake2b', {digestLength: 32});
        hash.update(transactionBuffer);
        merkleRoot = hash.digest();
      
        // console.log("0x01 + h + merkleRoot) = " + transactionBuffer.toString("hex"));
        // console.log("hash(0x01 + h + merkleRoot) = " + merkleRoot.toString("hex"));
      }
    }

    // console.log("confirm merkle root = " + merkleRoot.toString("hex"));

    // console.log("template = " + template.toString("hex"));

    var shareBuffer = utils.cnUtil.construct_block_blob(template, new Buffer(nonce, 'hex'), new Buffer(merkleRoot, 'hex'), cnBlobType);

    // console.log("shareBuffer = " + shareBuffer.toString('hex'));

    var convertedBlob;
    var hash;
    var shareType;

    if (shareTrustEnabled && miner.trust.threshold <= 0 && miner.trust.penalty <= 0 && Math.random() > miner.trust.probability){
        hash = new Buffer(resultHash, 'hex');
        shareType = 'trusted';
    }
    else {
        convertedBlob = utils.cnUtil.convert_blob(shareBuffer, cnBlobType);

        // console.log("convertedBlob = " + convertedBlob.toString('hex'));

        var hard_fork_version = convertedBlob[0];
        if (config.daemonType === "cash2") {
          var h = blake2.createHash('blake2b', {digestLength: 32});
          var blockHeaderBuffer = new Buffer(job.previousBlockHash + nonce + timestamp + merkleRoot.toString("hex"), "hex");
          
          // console.log("block header to be hashed = " + blockHeaderBuffer.toString("hex"));

          h.update(blockHeaderBuffer);
          hash = h.digest();
          log('info', logSystem, 'Mining pool algorithm: Blake2b', []);
        } else {
          hash = cryptoNight(convertedBlob, cnVariant);
          log('info', logSystem, 'Mining pool algorithm: %s variant %d, Hard fork version: %d', [cnAlgorithm, cnVariant, hard_fork_version]);
        }

        shareType = 'valid';
    }

    // console.log("confirmed hash = " + hash.toString('hex'));
    // console.log("hashFromA3 = " + resultHash);

    // if (hash.toString('hex') !== resultHash) {
        // log('warn', logSystem, 'Bad hash from miner %s@%s', [miner.login, miner.ip]);
        // return false;
    // }

    // var hashArray = hash.toByteArray().reverse();
    var hashArray = hash.toByteArray();
    var hashNum = bignum.fromBuffer(new Buffer(hashArray));
    var hashDiff = diff1.div(hashNum);

    // console.log("hashDiff = " + hashDiff);
    // console.log("blockTemplate.difficulty = " + blockTemplate.difficulty);

    if (hashDiff.ge(blockTemplate.difficulty)){

      // console.log("Ready to be submitted!!!!!!");
      apiInterfaces.rpcDaemon('submitblock', [shareBuffer.toString('hex')], function(error, result){
        if (error){
          log('error', logSystem, 'Error submitting block at height %d from %s@%s, share type: "%s" - %j', [job.height, miner.login, miner.ip, shareType, error]);
          recordShareData(miner, job, hashDiff.toString(), false, null, shareType);
          jobRefresh(false, socket);
        }
        else{
          var blockFastHash = utils.cnUtil.get_block_id(shareBuffer, cnBlobType).toString('hex');
          log('info', logSystem,
            'Block %s found at height %d by miner %s@%s - submit result: %j',
            [blockFastHash, job.height, miner.login, miner.ip, result]
          );
          recordShareData(miner, job, hashDiff.toString(), true, blockFastHash, shareType, blockTemplate);
          jobRefresh(false, socket);
        }
      });
    }

    else if (hashDiff.lt(job.difficulty)){
        log('warn', logSystem, 'Rejected low difficulty share of %s from %s@%s', [hashDiff.toString(), miner.login, miner.ip]);
        return false;
    }
    else{
        recordShareData(miner, job, hashDiff.toString(), false, null, shareType);
    }

    return true;
}

/**
 * Start pool server on TCP ports
 **/
var httpResponse = ' 200 OK\nContent-Type: text/plain\nContent-Length: 20\n\nMining server online';

function startPoolServerTcp(callback){
    log('info', logSystem, 'Clear values for connected workers in redis database.');
    redisClient.del(config.coin + ':active_connections');

    async.each(config.poolServer.ports, function(portData, cback){
        var handleMessage = function(socket, jsonData, pushMessage){

            // if (jsonData.method == "mining.submit")
            // {
              // console.log(jsonData);
            // }

            if (portData.port != "5555" && !jsonData.id) {
                log('warn', logSystem, 'Miner RPC request missing RPC id');
                return;
            }
            else if (portData.port != "5555" && !jsonData.method) {
                log('warn', logSystem, 'Miner RPC request missing RPC method');
                return;
            } 
            else if (portData.port != "5555" && !jsonData.params) {
                log('warn', logSystem, 'Miner RPC request missing RPC params');
                return;
            }

            var sendReply = function(error, result){
                if(!socket.writable) return;
                var sendData = JSON.stringify({
                    id: jsonData.id,
                    jsonrpc: "2.0",
                    error: error ? {code: -1, message: error} : null,
                    result: result
                }) + "\n";
                socket.write(sendData);
            };

            // console.log(jsonData);

            handleMinerMethod(jsonData.method, jsonData.params, socket, portData, sendReply, pushMessage, jsonData.id);
        };

        var socketResponder = function(socket){
            socket.setKeepAlive(true);
            socket.setEncoding('utf8');

            var dataBuffer = '';

            var pushMessage = function(method, params){
                if(!socket.writable) return;
                var sendData = JSON.stringify({
                    jsonrpc: "2.0",
                    method: method,
                    params: params
                }) + "\n";
                socket.write(sendData);
            };

            socket.on('data', function(d){
                dataBuffer += d;
                if (Buffer.byteLength(dataBuffer, 'utf8') > 10240){ //10KB
                    dataBuffer = null;
                    log('warn', logSystem, 'Socket flooding detected and prevented from %s', [socket.remoteAddress]);
                    socket.destroy();
                    return;
                }
                if (dataBuffer.indexOf('\n') !== -1){
                    var messages = dataBuffer.split('\n');
                    var incomplete = dataBuffer.slice(-1) === '\n' ? '' : messages.pop();
                    for (var i = 0; i < messages.length; i++){
                        var message = messages[i];
                        if (message.trim() === '') continue;
                        var jsonData;
                        try{
                            jsonData = JSON.parse(message);
                        }
                        catch(e){
                            if (message.indexOf('GET /') === 0) {
                                if (message.indexOf('HTTP/1.1') !== -1) {
                                    socket.end('HTTP/1.1' + httpResponse);
                                    break;
                                }
                                else if (message.indexOf('HTTP/1.0') !== -1) {
                                    socket.end('HTTP/1.0' + httpResponse);
                                    break;
                                }
                            }

                            log('warn', logSystem, 'Malformed message from %s: %s', [socket.remoteAddress, message]);
                            socket.destroy();

                            break;
                        }
                        try {
                            handleMessage(socket, jsonData, pushMessage);
                        } catch (e) {
                            log('warn', logSystem, 'Malformed message from ' + socket.remoteAddress + ' generated an exception. Message: ' + message);
                            if (e.message) log('warn', logSystem, 'Exception: ' + e.message);
                        }
                     }
                    dataBuffer = incomplete;
                }
            }).on('error', function(err){
                if (err.code !== 'ECONNRESET')
                    log('warn', logSystem, 'Socket error from %s %j', [socket.remoteAddress, err]);
            }).on('close', function(){
                pushMessage = function(){};
            });
        };

        if (portData.ssl) {
            if (!config.poolServer.sslCert) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate not configured', [portData.port]);
                cback(true);
            } else if (!config.poolServer.sslKey) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL key not configured', [portData.port]);
                cback(true);
            } else if (!config.poolServer.sslCA) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate authority not configured', [portData.port]);
                cback(true);
            } else if (!fs.existsSync(config.poolServer.sslCert)) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate file not found (configuration error)', [portData.port]);
                cback(true);
            } else if (!fs.existsSync(config.poolServer.sslKey)) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL key file not found (configuration error)', [portData.port]);
                cback(true);
            } else if (!fs.existsSync(config.poolServer.sslCA)) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate authority file not found (configuration error)', [portData.port]);
                cback(true);
            } else {
                var options = {
                    key: fs.readFileSync(config.poolServer.sslKey),
                    cert: fs.readFileSync(config.poolServer.sslCert),
                    ca: fs.readFileSync(config.poolServer.sslCA)
                };
                tls.createServer(options, socketResponder).listen(portData.port, function (error, result) {
                    if (error) {
                        log('error', logSystem, 'Could not start server listening on port %d (SSL), error: $j', [portData.port, error]);
                        cback(true);
                        return;
                    }

                    log('info', logSystem, 'Clear values for SSL port %d in redis database.', [portData.port]);
                    redisClient.del(config.coin + ':ports:'+portData.port);
                    redisClient.hset(config.coin + ':ports:'+portData.port, 'port', portData.port);

                    log('info', logSystem, 'Started server listening on port %d (SSL)', [portData.port]);
                    cback();
                });
            }
        } 
        else {
            net.createServer(socketResponder).listen(portData.port, function (error, result) {
                if (error) {
                    log('error', logSystem, 'Could not start server listening on port %d, error: $j', [portData.port, error]);
                    cback(true);
                    return;
                }

                log('info', logSystem, 'Clear values for port %d in redis database.', [portData.port]);
                redisClient.del(config.coin + ':ports:'+portData.port);
                redisClient.hset(config.coin + ':ports:'+portData.port, 'port', portData.port);

                log('info', logSystem, 'Started server listening on port %d', [portData.port]);
                cback();
            });
        }
    }, function(err){
        if (err)
            callback(false);
        else
            callback(true);
    });
}

/**
 * Initialize pool server
 **/
 
(function init(){
    jobRefresh(true, null, function(sucessful){ });
})();
