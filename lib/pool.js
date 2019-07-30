/**
 * Cryptonote Node.JS Pool
 * https://github.com/dvandal/cryptonote-nodejs-pool
 *
 * Pool TCP daemon
 **/

var extraNonce1Global = 0;

redisClient.set("currentBlockHeight", -1);
redisClient.set("currentBlockHeight2", -1);

// Load required modules
var fs = require('fs');
var net = require('net');
var tls = require('tls');
var async = require('async');
var bignum = require('bignum');

var apiInterfaces = require('./apiInterfaces.js')(config.daemon, config.wallet, config.api);
var notifications = require('./notifications.js');
var utils = require('./utils.js');

var blake2 = require('blake2');

var CASH2_HARD_FORK_HEIGHT_2 = 420016;

// extraNonce1 + extraNonce2 must be 16 hex characters
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

// Set cash2 algorithm
var algorithm = "cash2";
var blobType = 0;

// Pool variables
var poolStarted = false;
var connectedMiners = {};

// Pool settings
var shareTrustEnabled = config.poolServer.shareTrust && config.poolServer.shareTrust.enabled;
var shareTrustStepFloat = shareTrustEnabled ? config.poolServer.shareTrust.stepDown / 100 : 0;
var shareTrustMinFloat = shareTrustEnabled ? config.poolServer.shareTrust.min / 100 : 0;

var banningEnabled = config.poolServer.banning && config.poolServer.banning.enabled;
var bannedIPs = {};
var bannedIPAddresses = {};
var perIPStats = {};

var slushMiningEnabled = config.poolServer.slushMining && config.poolServer.slushMining.enabled;

if (!config.poolServer.paymentId)
{
  config.poolServer.paymentId = {};
}

if (!config.poolServer.paymentId.addressSeparator)
{
  config.poolServer.paymentId.addressSeparator = "+";
}

// Block templates
var validBlockTemplates = [];
var currentBlockTemplate;

// Difficulty buffer
var diff1 = bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);

// Convert buffer to byte array
Buffer.prototype.toByteArray = function () {
  return Array.prototype.slice.call(this, 0);
};


// Periodical updaters

 
// Variable difficulty retarget
setInterval(function(){
  var now = Date.now() / 1000 | 0;
  for (var minerId in connectedMiners)
  {
    var miner = connectedMiners[minerId];
    
    if(!miner.noRetarget)
    {
      miner.retarget(now);
    }
  }
}, config.poolServer.varDiff.retargetTime * 1000);

// Every 30 seconds clear out timed-out miners and old bans
setInterval(function(){
  var now = Date.now();
  var timeout = config.poolServer.minerTimeout * 1000;
  for (var minerId in connectedMiners)
  {
    var miner = connectedMiners[minerId];

    // remove inactive miners
    if (now - miner.lastBeat > timeout)
    {
      log('warn', logSystem, 'Miner timed out and disconnected %s@%s', [miner.login, miner.ip]);
      delete connectedMiners[minerId];
      removeConnectedWorker(miner, 'timeout');
    }
  }    

  if (banningEnabled)
  {
    // unban ips that were previously banned
    for (ip in bannedIPs)
    {
      var banTime = bannedIPs[ip];
      if (now - banTime > config.poolServer.banning.time * 1000)
      {
        delete bannedIPs[ip];
        delete perIPStats[ip];
        log('info', logSystem, 'Ban dropped for %s', [ip]);
      }
    }

    // unban addresses that were previously banned
    for (address in bannedIPAddresses)
    {
      var banTime = bannedIPAddresses[address];
      if (now - banTime > config.poolServer.banning.time * 1000)
      {
        delete bannedIPAddresses[address];
        log('info', logSystem, 'Ban dropped for %s', [address]);
      }
    }
  }
}, 30000);

/**
 * Handle multi-thread messages
 **/ 
process.on('message', function(message) {
  switch (message.type)
  {
    case 'banIP':
      bannedIPs[message.ip] = Date.now();
      break;
  }
});


// Block template
// Used in processShare() function
function BlockTemplate(template){
  this.blob = template.block_template_blob;

  var difficulty = template.difficulty;

  // Cash2 hard fork 2 reduces the block difficulty by a factor of 16^10 = 1,099,511,627,776
  // So we need to multiply the difficulty obtained from the Cash2 daemon by 1,099,511,627,776
  if (template.height >= CASH2_HARD_FORK_HEIGHT_2)
  {
    difficulty = bignum('1099511627776').mul(template.difficulty);
  }

  this.difficulty = difficulty;
  this.height = template.height;
  this.reserveOffset = template.reserved_offset;
  this.buffer = new Buffer(this.blob, 'hex');

  // previous block hash is 32 bytes long or 64 hex characters
  this.previousBlockHash = template.block_template_blob.substr(0, 64);

  // timestamp is 8 bytes long or 16 hex characters
  this.timestamp = template.block_template_blob.substr(80, 16);

  var coinbaseEnd = template.coinbase_transaction.length;

  // 160 is from 80 byte header size times 2, 240 is the number of hex characters we want
  // for coinbase transaction 1 + extra nonce 1 + extra nonce 2 + coinbase transaction 2
  this.coinbaseTransaction1 = template.coinbase_transaction.substr(coinbaseEnd - 240, (2 * template.reserved_offset - 160 - (coinbaseEnd - 240 + 2)));
  
  // 2 x reserve_offset - 160 - 2 gives the start of extra nonce 1.
  // 16 is the size of extra nonce 1 plus extra nonce 2
  this.coinbaseTransaction2 = template.coinbase_transaction.substr(2 * template.reserved_offset - 160 - 2 + 16);

  // hashes of transactions included in the block
  this.transactionHashes = template.transaction_hashes;
}

BlockTemplate.prototype = {
  nextBlob: function(){
    return utils.cnUtil.convert_blob(this.buffer, blobType).toString('hex');
  }
};


// Gets a new block template from the Cash2 daemon using an rpc call
// Called by function jobRefresh()
function getBlockTemplate(callback){
  apiInterfaces.rpcDaemon('get_block_template', {reserve_size: 16, wallet_address: config.poolServer.poolAddress}, callback);
}

// Gets the current blockchain height from the Cash2 daemon using an rpc call
// Called by function jobRefresh()
function getBlockCount(callback){
  apiInterfaces.rpcDaemon('get_block_count', {}, callback);
}

// Process block template
// Called by function jobRefresh() to process the new block template received from the Cash2 daemon
// Saves the new block template into currentBlockTemplate
// Saves the new block template into each miner object
// Broadcasts the new block template to each miner for them to work on
function processBlockTemplate(template) {

  // save the current block template into validBlockTemplates
  if (currentBlockTemplate)
  {
    validBlockTemplates.push(currentBlockTemplate);
  }

  // resize validBlockTemplates so that it saves only the previous 3 block templates
  if (validBlockTemplates.length > 3)
  {
    validBlockTemplates.shift();
  }

  // replace the current block template with the new block template we got from the Cash2 daemon 
  currentBlockTemplate = new BlockTemplate(template);

  // broadcast the new block template to all connected miners
  for (var minerId in connectedMiners){

    var miner = connectedMiners[minerId];
    
    // getJob() saves the currentBlockTemplate into each Miner object
    var job = miner.getJob();

    // need to check if a new valid job was returned by the function getJob() and 
    // if the miner's communication socket exists and is open
    if (job && miner.socket && miner.socket.readyState == "open")
    {

      // send the new job data to the miner 
      var sendData = JSON.stringify({
        params:
        [
          job.job_id,
          job.previousBlockHash,
          job.coinbaseTransaction1,
          job.coinbaseTransaction2,
          job.transactionHashes,
          "", // block version number
          job.target.toString(16), // network difficulty
          job.timestamp,
          true // Clean jobs. When true, server indicates that submitting shares from previous jobs don't have a sense and such shares will be rejected. When this flag is set, miner should also drop all previous jobs
        ],
        id : null,
        method: "mining.notify"
      }) + "\n";

      miner.socket.write(sendData);
    }
  }
}


// Job refresh
// Gets a new block template from the Cash2 daemon by calling getBlockTemplate() and
// Stores the new block template into currentBlockTemplate by calling processBlockTemplate()
function jobRefresh(loop , callback)
{
  callback = callback || function(){};

  // console.log('\x1b[36m', 'jobRefresh','\x1b[0m');

  getBlockCount(function(error0, result0) {

    // get a new block template from the Cash2 daemon every n seconds
    if (loop)
    {
      // wait n number of seconds before calling jobRefresh() again
      var blockRefreshInterval = config.poolServer.blockRefreshInterval;
      setTimeout(function(){ jobRefresh(true); }, config.poolServer.blockRefreshInterval);
    }

    // Rpc call to Cash2 daemon requesting a new block template returned an error
    if (error0)
    {
      log('error', logSystem, 'Error calling get_block_count %j', [error]);
      
      if (!poolStarted)
      {
        log('error', logSystem, 'Could not start pool');
      }

      callback(false);
      return;
    }

    // Successfully recieved the current blockchain height from the Cash2 daemon
    // console.log('\x1b[36m', 'blockchain height = ' + result0.count,'\x1b[0m');

    if (!currentBlockTemplate || result0.count > currentBlockTemplate.height)
    {
      // gets a new block template from the Cash2 daemon using an rpc call
      getBlockTemplate(function(error, result) {

        // Rpc call to Cash2 daemon requesting a new block template returned an error
        if (error)
        {
          log('error', logSystem, 'Error calling get_block_template %j', [error]);
          
          if (!poolStarted)
          {
            log('error', logSystem, 'Could not start pool');
          }

          callback(false);
          return;
        }

        // Successfully recieved a new block template from the Cash2 daemon
        // console.log('\x1b[36m', 'New block template','\x1b[0m');

        // New block template is different than the current block template we are working on or
        // We just started the pool server and do not yet have a current block template we are working on
        if (!currentBlockTemplate || result.height > currentBlockTemplate.height)
        {

          // Save new block height into redis
          // Used as a mutex by processShare() to prevent multiple threads from submitting duplicate shares
          var saveCurrentBlockHeight = [
            ['set', "currentBlockHeight", result.height],
            ['set', "currentBlockHeight2", result.height],
          ];

          redisClient.multi(saveCurrentBlockHeight).exec(function(redisError) {
            // redis command returns an error and command was not successfully executed
            if (redisError)
            {
              log('error', logSystem, 'Error saving current block height into redis');
              callback(false);
              return;
            }

            // Adjust the difficulty that was returned by the Cash2 daemon
            var difficulty = result.difficulty;
            if (result.height >= CASH2_HARD_FORK_HEIGHT_2)
            {
              difficulty = bignum('1099511627776').mul(result.difficulty);
            }

            log('info', logSystem, 'New block to mine at height %d w/ network difficulty of %d', [result.height, difficulty]);

            // Broadcast new block template to all miners so they can begin working on it
            processBlockTemplate(result);
          });
        }

        // Start the pool
        if (!poolStarted)
        {
          startPoolServerTcp(function(successful){ poolStarted = true });
        }

        callback(true);
      })
    }
  })
}


// Variable difficulty
// Used by miner.retartget() function
// A little too complicated for me to understand completely at the moment
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

// Miner
// Called by handleMinerMethod() to create a new miner object when a new miner connects to the pool
// using "mining.subscribe"
function Miner(id, login, pass, ip, port, workerName, startingDiff, noRetarget, extraNonce1, socket){
  this.id = id;
  this.login = login;
  this.pass = pass;
  this.ip = ip;
  this.port = port;
  this.workerName = workerName;
  this.heartbeat();
  this.noRetarget = noRetarget;
  this.difficulty = startingDiff;
  this.validJobs = [];
  this.extraNonce1 = extraNonce1;
  this.socket = socket;

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


// Each miner object inherits the following methods :
//  - retarget()
//  - setNewDiff()
//  - heartbeat()
//  - getTargetHex()
//  - getJob()
//  - checkBan()
//  - ban()
Miner.prototype = {
  retarget: function(now){
    var options = config.poolServer.varDiff;

    var sinceLast = now - this.lastShareTime;
    var decreaser = sinceLast > VarDiff.tMax;

    var avg = this.shareTimeRing.avg(decreaser ? sinceLast : null);
    var newDiff;

    var direction;

    if (avg > VarDiff.tMax && this.difficulty > options.minDiff)
    {
      newDiff = options.targetTime / avg * this.difficulty;
      newDiff = newDiff > options.minDiff ? newDiff : options.minDiff;
      direction = -1;
    }
    else if (avg < VarDiff.tMin && this.difficulty < options.maxDiff)
    {
      newDiff = options.targetTime / avg * this.difficulty;
      newDiff = newDiff < options.maxDiff ? newDiff : options.maxDiff;
      direction = 1;
    }
    else
    {
      return;
    }

    if (Math.abs(newDiff - this.difficulty) / this.difficulty * 100 > options.maxJump){
      var change = options.maxJump / 100 * this.difficulty * direction;
      newDiff = this.difficulty + change;
    }

    this.setNewDiff(newDiff);
    this.shareTimeRing.clear();
    if (decreaser)
    {
      this.lastShareTime = now;
    }
  },
  setNewDiff: function(newDiff){
    newDiff = Math.round(newDiff);
    if (this.difficulty === newDiff)
    {
      return;
    }
    log('info', logSystem, 'Retargetting difficulty %d to %d for %s', [this.difficulty, newDiff, this.login]);
    this.pendingDifficulty = newDiff;
    this.getJob(false);
  },
  heartbeat: function(){
    this.lastBeat = Date.now();
  },
  getTargetHex: function(){
    if (this.pendingDifficulty)
    {
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
  getJob: function(forced){
    // Returns block information for the miner to work on
    // The block information retrieved from the currentBlockTemplate
    // If the new block information was already sent to the miner before, getJob() returns false
    // Forced means to return a job even if it has already been recorded by the miner object, this is an attemp to fix the "job not found for ip" errors
    if (!forced && this.lastBlockHeight === currentBlockTemplate.height && !this.pendingDifficulty)
    {
      return false;
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
    {
      this.validJobs.shift();
    }

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
    if (!banningEnabled)
    {
      return;
    }

    // Init global per-ip shares stats
    if (!perIPStats[this.ip])
    {
      perIPStats[this.ip] = { validShares: 0, invalidShares: 0 };
    }

    var stats = perIPStats[this.ip];
    validShare ? stats.validShares++ : stats.invalidShares++;

    if (stats.validShares + stats.invalidShares >= config.poolServer.banning.checkThreshold)
    {
      if (stats.invalidShares / stats.validShares >= config.poolServer.banning.invalidPercent / 100)
      {
        validShare ? this.validShares++ : this.invalidShares++;
        log('warn', logSystem, 'Banned %s@%s', [this.login, this.ip]);
        bannedIPs[this.ip] = Date.now();
        delete connectedMiners[this.id];
        process.send({type: 'banIP', ip: this.ip});
        removeConnectedWorker(this, 'banned');
      }
      else
      {
        stats.invalidShares = 0;
        stats.validShares = 0;
      }
    }
  },
  ban: function(){
    // ban socket and port
    log('warn', logSystem, 'Banned %s@%s', [this.login, this.ip]);
    bannedIPs[this.ip] = Date.now();
    delete connectedMiners[this.id];
    process.send({type: 'banIP', ip: this.ip});
    removeConnectedWorker(this, 'banned');

    // ban socket
    var ipStringArray = this.ip.split(':');
    bannedIPs[ipStringArray[0]] = Date.now();
  }
};

function checkFunctionParameterExists(parameter)
{
  if (typeof parameter !== 'undefined')
  {
    return true;
  }
  else
  {
    return false;
  }
}

// Handle miner method
// Processes the information the miners sends to the pool server
// Miner send information to the pool using 3 methods:
//  - mining.subscribe
//  - mining.authorize
//  - mining.submit
function handleMinerMethod(method, params, socket, portData, id)
{

  if (!checkFunctionParameterExists(method) ||
      !checkFunctionParameterExists(params) ||
      !checkFunctionParameterExists(socket) ||
      !checkFunctionParameterExists(portData) ||
      !checkFunctionParameterExists(id))
  {
    console.log('\x1b[36m', 'Miner sending data with missing parameters','\x1b[0m');
    return false;
  }


  var ip = socket.remoteAddress + ":" + socket.remotePort;

  // Check for ban here, so preconnected attackers can't continue to screw you
  if (
    IsBannedIp(ip) ||
    IsBannedIPAddress(socket.remoteAddress) ||
    socket.remoteAddress == "::ffff:85.135.134.104" ||
    socket.remoteAddress == "::ffff:118.174.80.93" ||
    socket.remoteAddress == "::ffff:77.48.221.3" ||
    socket.remoteAddress == "::ffff:182.132.139.23" ||
    // socket.remoteAddress == "::ffff:125.27.102.127" ||
    socket.remoteAddress == "::ffff:190.73.242.13"
    )
  {
    console.log('\x1b[36m', "ip " + ip + " is banned" ,'\x1b[0m');
    return false;
  }

  var miner = connectedMiners[ip];

  if (miner)
  {
    miner.socket = socket;
  }

  switch(method){
    // Miner is connecting to the pool for the first time or is reconnecting to the pool after being disconnected
    case "mining.subscribe" :

      // Set up miner with temporary values for login, password, difficulty, and noRetarget
      // Call getJob() to get unique extra nonce 1 for the miner
      // Return extra nonce 1 to miner
      // var minerId = utils.uid();
      var minerId = ip;
      var login = "";
      var pass = "";
      var port = "";
      var workerName = "worker_" + minerId;
      var difficulty = "";
      var noRetarget = false;
      var extraNonce1 = "" + extraNonce1Global;
      
      extraNonce1Global++;

      var extraNonce1Size = 4; // size in bytes
      var extraNonce2Size = 4; // size in bytes

      // left pad extra nonce 1 with zeros until 8 characters long
      while (extraNonce1.length < 2 * extraNonce1Size)
      {
        extraNonce1 = "0" + extraNonce1;
      }

      // create a new miner object
      var miner = new Miner(minerId, login, pass, ip, port, workerName, difficulty, noRetarget, extraNonce1, socket);
      
      connectedMiners[ip] = miner;

      var sendData = JSON.stringify({
        "id": id,
        "result": [ [ ["mining.set_difficulty", minerId], ["mining.notify", minerId]], extraNonce1, extraNonce2Size],
        "error": null
      }) + "\n";

      socket.write(sendData);

      break;
    case 'mining.authorize':

      if (!miner)
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (24, "Unauthorized worker", null)
        // }) + "\n";

        // socket.write(sendData);

        return false;
      }

      var login = params[0];

      // Check that Cash2 address is not empty
      if (!login)
      {
        log('warn', logSystem, 'Worker Cash2 address is empty');

        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (24, "Unauthorized worker", null)
        // }) + "\n";
        // socket.write(sendData);

        return false;
      }

      // Check that Cash2 address is exactly 95 characters
      if (login.length != 95)
      {
        log('warn', logSystem, 'Worker Cash2 address is not 95 characters long %s', [login]);

        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (24, "Unauthorized worker", null)
        // }) + "\n";
        // socket.write(sendData);

        return false;
      }

      var port = portData.port;
      var pass = params.pass;
      var difficulty = portData.difficulty;
      var noRetarget = false;

      // if(config.poolServer.fixedDiff.enabled)
      // {
        // var fixedDiffCharPos = login.lastIndexOf(config.poolServer.fixedDiff.addressSeparator);
        // if (fixedDiffCharPos !== -1 && (login.length - fixedDiffCharPos < 32))
        // {
          // diffValue = login.substr(fixedDiffCharPos + 1);
          // difficulty = parseInt(diffValue);
          // if (!difficulty || difficulty != diffValue)
          // {
            // log('warn', logSystem, 'Invalid difficulty value "%s" for login: %s', [diffValue, login.substr(0, fixedDiffCharPos)]);
            // difficulty = portData.difficulty;
          // }
          // else
          // {
            // noRetarget = true;
            // if (difficulty < config.poolServer.varDiff.minDiff)
            // {
              // difficulty = config.poolServer.varDiff.minDiff;
            // }
          // }
        // }
      // }

      // // check that parsed address is not empty
      // var addr = login.split(config.poolServer.paymentId.addressSeparator);
      // var address = addr[0] || null;

      // if (!address) {
        // log('warn', logSystem, 'No address specified for login');

        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (24, "Unauthorized worker", null)
        // }) + "\n";
        // socket.write(sendData);
      // }

      var address = login;

      // check for valid address
      if (!utils.validateMinerAddress(address)) {
        var addressPrefix = utils.getAddressPrefix(address);
        if (!addressPrefix) addressPrefix = 'N/A';

        log('warn', logSystem, 'Invalid address used for login (prefix: %s): %s', [addressPrefix, address]);
        
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (24, "Unauthorized worker", null)
        // }) + "\n";
        // socket.write(sendData);

        miner.ban(socket.remoteAddress);

        return false;
      }

      miner.login = login;
      miner.pass = pass;
      miner.ip = ip;
      miner.port = port;
      miner.difficulty = difficulty;
      miner.noRetarget = noRetarget;

      var sendData1 = JSON.stringify({
        "error": null,
        "id": id,
        "result": true
      }) + "\n";

      socket.write(sendData1);

      var job = miner.getJob(false);

      if (job)
      {
        var sendData2 = JSON.stringify({
          params:
          [
            job.job_id,
            job.previousBlockHash,
            job.coinbaseTransaction1,
            job.coinbaseTransaction2,
            job.transactionHashes,
            "", // block version number
            job.target.toString(16), // network difficulty
            job.timestamp,
            false // clean jobs
          ],
          id : id,
          method: "mining.notify"
        }) + "\n";

        socket.write(sendData2);

        // set difficulty
        var sendData3 = JSON.stringify({
            "params": [4096],
            "id" : null,
            "method": "mining.set_difficulty"
        }) + "\n";

        socket.write(sendData3);
      }
      else
      {
        log('warn', logSystem, 'Error getting job for miner %s', [miner.ip]);
        return false;
      }

      newConnectedWorker(miner);

      break;
    case 'mining.submit':
      if (!miner)
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (24, "Unauthorized worker", null)
        // }) + "\n";
        // socket.write(sendData);

        return false;
      }

      console.log('\x1b[36m', 'mining.submit ip = ' + miner.ip ,'\x1b[0m');

      miner.heartbeat();

      var jobId = params[1];

      var job = miner.validJobs.filter(function(job){
        return job.id === jobId;
      })[0];

      if (!job)
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (21, "Job not found", null)
        // }) + "\n";
        // socket.write(sendData);

        console.log('\x1b[36m', 'job id ' + jobId + ' is not valid, ip = ' + miner.op ,'\x1b[0m');
        console.log('\x1b[36m', 'miner.validJobs = ' + miner.validJobs,'\x1b[0m');

        // should we remove the connected worker here or reset their connection?

        // jobRefresh(false);

        // send out a new job the the miner
        var job = miner.getJob(true);

        if (job)
        {
          var sendData = JSON.stringify({
            params:
            [
              job.job_id,
              job.previousBlockHash,
              job.coinbaseTransaction1,
              job.coinbaseTransaction2,
              job.transactionHashes,
              "", // block version number
              job.target.toString(16), // network difficulty
              job.timestamp,
              true // Clean jobs. When true, server indicates that submitting shares from previous jobs don't have a sense and such shares will be rejected. When this flag is set, miner should also drop all previous jobs
            ],
            id : null,
            method: "mining.notify"
          }) + "\n";

          socket.write(sendData);
        }

        return false;
      }

      var nonce = params[4];

      if (!nonce)
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (20, "Other/Unknown", null)
        // }) + "\n";
        // socket.write(sendData);

        console.log('\x1b[36m', 'nonce not found for ip = ' + miner.ip ,'\x1b[0m');

        var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
        log('warn', logSystem, 'Malformed miner share: ' + JSON.stringify(params) + ' from ' + minerText);
        return false;
      }

      if (!noncePattern.test(nonce))
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (20, "Other/Unknown", null)
        // }) + "\n";
        // socket.write(sendData);

        console.log('\x1b[36m', 'nonce pattern invalid for ip = ' + miner.ip ,'\x1b[0m');

        var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
        log('warn', logSystem, 'Malformed nonce: ' + JSON.stringify(params) + ' from ' + minerText);
        return false;
      }

      nonce = nonce.toLowerCase();

      if (job.submissions.indexOf(nonce) !== -1)
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (22, "Duplicate share", null)
        // }) + "\n";
        // socket.write(sendData);

        console.log('\x1b[36m', 'index of nonce invalid for ip = ' + miner.ip ,'\x1b[0m');

        var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
        log('warn', logSystem, 'Duplicate share: ' + JSON.stringify(params) + ' from ' + minerText);
        perIPStats[miner.ip] = { validShares: 0, invalidShares: 999999 };
        miner.checkBan(false);
        return false;
      }

      job.submissions.push(nonce);

      var blockTemplate = currentBlockTemplate.height === job.height ? currentBlockTemplate : validBlockTemplates.filter(function(t){
        return t.height === job.height;
      })[0];

      if (!blockTemplate)
      {
        // var sendData = JSON.stringify({
          // "id": id,
          // "result": null,
          // "error": (20, "Other/Unknown", null)
        // }) + "\n";
        // socket.write(sendData);

        console.log('\x1b[36m', 'block template not found for ip = ' + miner.ip ,'\x1b[0m');

        return false;
      }

      var extraNonce2 = params[2];
      var timestamp = params[3];
      
      var shareAccepted = processShare(miner, job, blockTemplate, nonce, extraNonce2, timestamp, socket, id);
      miner.checkBan(shareAccepted);

      if (shareTrustEnabled)
      {
        if (shareAccepted)
        {
          miner.trust.probability -= shareTrustStepFloat;
          if (miner.trust.probability < shareTrustMinFloat)
          {
            miner.trust.probability = shareTrustMinFloat;
          }
          miner.trust.penalty--;
          miner.trust.threshold--;
        }
        else
        {
          log('warn', logSystem, 'Share trust broken by %s@%s', [miner.login, miner.ip]);
          miner.trust.probability = 1;
          miner.trust.penalty = config.poolServer.shareTrust.penalty;
        }
      }
      
      if (!shareAccepted){
        var sendData = JSON.stringify({
          "id": id,
          "result": null,
          "error": (23, "Low difficulty share", null)
        }) + "\n";
        socket.write(sendData);

        console.log('\x1b[36m', 'share not accepted for ip = ' + miner.ip ,'\x1b[0m');

        return false;
      }

      var now = Date.now() / 1000 | 0;
      miner.shareTimeRing.append(now - miner.lastShareTime);
      miner.lastShareTime = now;

      // notify miner that share has been accepted
      var sendData = JSON.stringify({
        "id": id,
        "result": true,
        "error": null
      }) + "\n";
      socket.write(sendData);

      break;

    default:
      // var sendData = JSON.stringify({
        // "id": id,
        // "result": null,
        // "error": (20, "Other/Unknown", null)
      // }) + "\n";
      // socket.write(sendData);

      var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
      log('warn', logSystem, 'Invalid method: %s (%j) from %s', [method, params, minerText]);
      break;
  }

  return true;
}

/**
 * New connected worker
 **/
function newConnectedWorker(miner){
  log('info', logSystem, 'Miner connected %s@%s on port', [miner.login, miner.ip, miner.port]);
  
  if (miner.workerName !== 'undefined')
  {
    log('info', logSystem, 'Worker Name: %s', [miner.workerName]);
  }

  if (miner.difficulty)
  {
    log('info', logSystem, 'Miner difficulty fixed to %s', [miner.difficulty]);
  }

  redisClient.sadd(config.coin + ':workers_ip:' + miner.login, miner.ip);
  redisClient.hincrby(config.coin + ':ports:'+miner.port, 'users', 1);

  redisClient.hincrby(config.coin + ':active_connections', miner.login + '~' + miner.workerName, 1, function(error, connectedWorkers) {
    if (connectedWorkers === 1)
    {
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
    if (reason === 'banned')
    {
      notifications.sendToMiner(miner.login, 'workerBanned', {
        'LOGIN' : miner.login,
        'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
        'IP': miner.ip.replace('::ffff:', ''),
        'PORT': miner.port,
        'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : ''
      });
    }
    else if (!connectedWorkers || connectedWorkers <= 0)
    {
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


// Checks if ip (socket and port) has been banned
function IsBannedIp(ip){
  if (!banningEnabled || !bannedIPs[ip])
  {
    return false;
  }

  var bannedTime = bannedIPs[ip];
  var bannedTimeAgo = Date.now() - bannedTime;
  var timeLeft = config.poolServer.banning.time * 1000 - bannedTimeAgo;
  if (timeLeft > 0)
  {
    return true;
  }
  else
  {
    delete bannedIPs[ip];
    log('info', logSystem, 'Ban dropped for ip %s', [ip]);
    return false;
  }
}

// Checks if ip address (no port included) has been banned
function IsBannedIPAddress(address){
  if (!banningEnabled || !bannedIPAddresses[address])
  {
    return false;
  }

  var bannedTime = bannedIPAddresses[address];
  var bannedTimeAgo = Date.now() - bannedTime;
  var timeLeft = config.poolServer.banning.time * 1000 - bannedTimeAgo;
  if (timeLeft > 0)
  {
    return true;
  }
  else
  {
    delete bannedIPAddresses[address];
    log('info', logSystem, 'Ban dropped for address %s', [address]);
    return false;
  }
}

/**
 * Record miner share data
 **/
function recordShareData(miner, job, shareDiff, blockCandidate, hashHex, shareType, blockTemplate){

  var dateNow = Date.now();
  var dateNowSeconds = dateNow / 1000 | 0;

  var updateScore;
  // Weighting older shares lower than newer ones to prevent pool hopping
  if (slushMiningEnabled)
  {
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
  else
  {
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

  if (miner.workerName)
  {
    redisCommands.push(['zadd', config.coin + ':hashrate', dateNowSeconds, [job.difficulty, miner.login + '~' + miner.workerName, dateNow].join(':')]);
    redisCommands.push(['hincrby', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, 'hashes', job.difficulty]);
    redisCommands.push(['hset', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, 'lastShare', dateNowSeconds]);
    redisCommands.push(['expire', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, (86400 * cleanupInterval)]);
  }
  
  if (blockCandidate)
  {
    redisCommands.push(['hset', config.coin + ':stats', 'lastBlockFound', Date.now()]);
    redisCommands.push(['rename', config.coin + ':scores:roundCurrent', config.coin + ':scores:round' + job.height]);
    redisCommands.push(['rename', config.coin + ':shares_actual:roundCurrent', config.coin + ':shares_actual:round' + job.height]);
    redisCommands.push(['hgetall', config.coin + ':scores:round' + job.height]);
    redisCommands.push(['hgetall', config.coin + ':shares_actual:round' + job.height]);
  }

  redisClient.multi(redisCommands).exec(function(err, replies){
    if (err)
    {
      log('error', logSystem, 'Failed to insert share data into redis %j \n %j', [err, redisCommands]);
      return;
    }

    if (slushMiningEnabled)
    {
      job.score = parseFloat(replies[0][0]);
      var age = parseFloat(replies[0][1]);
      log('info', logSystem, 'Submitted score ' + job.score + ' for difficulty ' + job.difficulty + ' and round age ' + age + 's');
    }

    if (blockCandidate)
    {
      var workerScores = replies[replies.length - 2];
      var workerShares = replies[replies.length - 1];
      if (workerScores)
      {
        var totalScore = Object.keys(workerScores).reduce(function(p, c){
            return p + parseFloat(workerScores[c])
        }, 0);
      }
      if (workerShares)
      {
        var totalShares = Object.keys(workerShares).reduce(function(p, c){
            return p + parseInt(workerShares[c])
        }, 0);
      }
      redisClient.zadd(config.coin + ':blocks:candidates', job.height, [
        hashHex,
        Date.now() / 1000 | 0,
        blockTemplate.difficulty,
        totalShares,
        totalScore
      ].join(':'), function(err, result){
        if (err)
        {
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

// This function has a potential bug
// We should not be returning true at the end of this function but only inside the if else statements
// This is because in the last redis call we do not want the function to immediately return
// true but wait for the current block height to be set back to the original value in redis before
// exiting the function
function processShare(miner, job, blockTemplate, nonce, extraNonce2, timestamp, socket, id)
{
  var template = new Buffer(blockTemplate.buffer.length);
  blockTemplate.buffer.copy(template);

  var extraNonce1And2 = "" + miner.extraNonce1 + extraNonce2;

  // write extra nonce 1 and extra nonce 2 to the block template
  template.write(extraNonce1And2, blockTemplate.reserveOffset - 1, 16, "hex");
  
  // Get hash list root
  
  // Coinbase transaction hash
  var h = blake2.createHash('blake2b', {digestLength: 32});
  var arbitraryTransactionBuffer = new Buffer("00" + job.coinbaseTransaction1 + extraNonce1And2 + job.coinbaseTransaction2, "hex");
  h.update(arbitraryTransactionBuffer);
  var merkleRoot = h.digest();

  // Hash all transactions in the block
  if (job.transactionHashes)
  {
    for (var i = 0; i < job.transactionHashes.length; i++)
    {
      var transactionBuffer = new Buffer("01" + job.transactionHashes[i] + merkleRoot.toString("hex"), "hex");
      var hash = blake2.createHash('blake2b', {digestLength: 32});
      hash.update(transactionBuffer);
      merkleRoot = hash.digest();
    }
  }

  // write nonce and merkle root to block blob
  var shareBuffer = utils.cnUtil.construct_block_blob(template, new Buffer(nonce, 'hex'), new Buffer(merkleRoot, 'hex'), blobType);

  var convertedBlob = utils.cnUtil.convert_blob(shareBuffer, blobType);

  // Check the nonce and extra nonce 2 returned by the miner
  // Check that the block hash meets the difficulty requirements
  var h = blake2.createHash('blake2b', {digestLength: 32});
  var blockHeaderBuffer = new Buffer(job.previousBlockHash + nonce + timestamp + merkleRoot.toString("hex"), "hex");
  h.update(blockHeaderBuffer);
  var hash = h.digest();

  var hashArray = hash.toByteArray();
  var hashNum = bignum.fromBuffer(new Buffer(hashArray));
  var hashDiff = diff1.div(hashNum);

  var shareType;

  if (shareTrustEnabled && miner.trust.threshold <= 0 && miner.trust.penalty <= 0 && Math.random() > miner.trust.probability)
  {
    shareType = 'trusted';
  }
  else {
    shareType = 'valid';
  }

  var blockFastHash = utils.cnUtil.get_block_id(shareBuffer, blobType).toString('hex');

  // console.log('\x1b[32m', 'blockTemplate.difficulty = ' + blockTemplate.difficulty,'\x1b[0m');
  console.log('\x1b[32m', 'hashDiff = ' + hashDiff.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","),'\x1b[0m');
  // console.log('\x1b[32m', 'blockHeight = ' + job.height.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","),'\x1b[0m');

  // block hash meets the difficulty requirements
  if (hashDiff.ge(blockTemplate.difficulty))
  {

    // We have to use redis to store the current block height to prevent multiple threads
    // from submitting blocks at the same height.
    // We were getting many "Error submitting block" errors due to submitting multiple blocks for the
    // same height by the different threads, and clogging up the network.
    // We use redis as kind of like a mutex where the current block height can only be accessed by one
    // thread at a time.

    // get the value of the current block height from redis and store it in the variable currentBlockHeight
    redisClient.get("currentBlockHeight", function (redisError1, currentBlockHeight) {
      if (redisError1)
      {
        log('error', logSystem, 'Error getting block height from redis');
        return false;
      }

      var currentBlockHeightSave = currentBlockHeight;
    
      if (currentBlockHeight == job.height)
      {
        var redisCommands1 = [
          ['set', "currentBlockHeight", -1],
          ['set', "currentBlockHeight2", -1],
        ];

        // set the value of the current block height in redis to -1 then call submitblock
        redisClient.multi(redisCommands1).exec(function(redisError2) {
        
        // redisClient.set("currentBlockHeight", -1, function (redisError2) {
        
          if (redisError2)
          {
            log('error', logSystem, 'Error setting block height in redis');
            return false;
          }

          // currentBlockHeightGlobal = -1;

          apiInterfaces.rpcDaemon('submit_block', [shareBuffer.toString('hex')], function(error, result){
            if (error)
            {
              var redisCommands2 = [
                ['set', "currentBlockHeight", currentBlockHeightSave],
                ['set', "currentBlockHeight2", currentBlockHeightSave],
              ];

              // set the value of the current block height in redis back to the original value then send error response to the miner

              // redisClient.set("currentBlockHeight", currentBlockHeightSave, function (redisError3) {
              redisClient.multi(redisCommands2).exec(function(redisError3) {

                if (redisError3)
                {
                  log('error', logSystem, 'Error setting block height in redis');
                }

                // currentBlockHeightGlobal = job.height;

                log('error', logSystem, 'Error submitting block %s at height %d from %s@%s, share type: "%s" - %j', [blockFastHash, job.height, miner.login, miner.ip, shareType, error]);
                
                recordShareData(miner, job, hashDiff.toString(), false, null, shareType);

                // // send error response to miner
                // var sendData = JSON.stringify({
                  // "id": id,
                  // "result": null,
                  // "error": (20, "Other/Unknown", null)
                // }) + "\n";
                // socket.write(sendData);

                jobRefresh(false);
              });
            }
            else
            {
              console.log('\x1b[32m', 'Block found ' + job.height + ' hash ' + hash.toString('hex'),'\x1b[0m');
              log('info', logSystem,
                'Block %s found at height %d by miner %s@%s - submit result: %j',
                [blockFastHash, job.height, miner.login, miner.ip, result]
              );

              // send success response to miner
              var sendData = JSON.stringify({
                "id": id,
                "result": true,
                "error": null
              }) + "\n";
              socket.write(sendData);

              recordShareData(miner, job, hashDiff.toString(), true, blockFastHash, shareType, blockTemplate);
              
              jobRefresh(false);
            }
          });
        });
      }
      // else
      // {
        // recordShareData(miner, job, hashDiff.toString(), false, null, shareType);
      // }
    });
  }
  else if (hashDiff.lt(job.difficulty))
  {
    log('warn', logSystem, 'Rejected low difficulty share of %s from %s@%s', [hashDiff.toString(), miner.login, miner.ip]);
    return false;
  }
  else
  {
    redisClient.get("currentBlockHeight2", function (redisError, currentBlockHeight) {
      if (redisError)
      {
        log('error', logSystem, 'Error getting block height from redis');
        return false;
      }

      if (currentBlockHeight == job.height)
      {
        recordShareData(miner, job, hashDiff.toString(), false, null, shareType);
      }
      
    });
  }

  return true;
}

/**
 * Start pool server on TCP ports
 **/
var httpResponse = ' 200 OK\nContent-Type: text/plain\nContent-Length: 20\n\nMining server online';

// var socketsGlobal = new Set();

function startPoolServerTcp(callback)
{
  log('info', logSystem, 'Clear values for connected workers in redis database.');
  redisClient.del(config.coin + ':active_connections');

  async.each(config.poolServer.ports, function(portData, cback) {
    var handleMessage = function(socket, jsonData) {
      if (portData.port != "5555" && !jsonData.id)
      {
        log('warn', logSystem, 'Miner RPC request missing RPC id');
        return;
      }
      else if (portData.port != "5555" && !jsonData.method)
      {
        log('warn', logSystem, 'Miner RPC request missing RPC method');
        return;
      } 
      else if (portData.port != "5555" && !jsonData.params)
      {
        log('warn', logSystem, 'Miner RPC request missing RPC params');
        return;
      }

      var handleMinerMethodSuccess = handleMinerMethod(jsonData.method, jsonData.params, socket, portData, jsonData.id);

      if (!handleMinerMethodSuccess)
      {
        log('warn', logSystem, 'Error handling information received by miner');
        return;
      }
    };

    var socketResponder = function(socket){
      socket.setKeepAlive(true);
      socket.setEncoding('utf8');

      var dataBuffer = '';

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
          for (var i = 0; i < messages.length; i++)
          {
            var message = messages[i];
            if (message.trim() === '')
            {
              continue;
            }

            var jsonData;
            try
            {
              jsonData = JSON.parse(message);
            }
            catch(e)
            {
              if (message.indexOf('GET /') === 0)
              {
                if (message.indexOf('HTTP/1.1') !== -1)
                {
                  socket.end('HTTP/1.1' + httpResponse);
                  break;
                }
                else if (message.indexOf('HTTP/1.0') !== -1)
                {
                  socket.end('HTTP/1.0' + httpResponse);
                  break;
                }
              }

              log('warn', logSystem, 'Malformed message from %s: %s', [socket.remoteAddress, message]);
              socket.destroy();

              break;
            }

            try {
              handleMessage(socket, jsonData);
            } catch (e) {
              log('warn', logSystem, 'Malformed message from ' + socket.remoteAddress + ' generated an exception. Message: ' + message);
              if (e.message)
              {
                log('warn', logSystem, 'Exception: ' + e.message);
              }
            }
          }
          dataBuffer = incomplete;
        }
      }).on('error', function(err){
        if (err.code !== 'ECONNRESET')
        {
          log('warn', logSystem, 'Socket error from %s %j', [socket.remoteAddress, err]);
        }
      });
    };

    if (portData.ssl)
    {
      if (!config.poolServer.sslCert)
      {
        log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate not configured', [portData.port]);
        cback(true);
      }
      else if (!config.poolServer.sslKey)
      {
        log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL key not configured', [portData.port]);
        cback(true);
      }
      else if (!config.poolServer.sslCA)
      {
        log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate authority not configured', [portData.port]);
        cback(true);
      }
      else if (!fs.existsSync(config.poolServer.sslCert))
      {
        log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate file not found (configuration error)', [portData.port]);
        cback(true);
      }
      else if (!fs.existsSync(config.poolServer.sslKey))
      {
        log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL key file not found (configuration error)', [portData.port]);
        cback(true);
      }
      else if (!fs.existsSync(config.poolServer.sslCA))
      {
        log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate authority file not found (configuration error)', [portData.port]);
        cback(true);
      }
      else
      {
        var options = {
          key: fs.readFileSync(config.poolServer.sslKey),
          cert: fs.readFileSync(config.poolServer.sslCert),
          ca: fs.readFileSync(config.poolServer.sslCA)
        };
        tls.createServer(options, socketResponder).listen(portData.port, function (error, result) {
          if (error)
          {
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
    else
    {
      net.createServer(socketResponder).listen(portData.port, function (error, result) {
        if (error)
        {
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
    {
      callback(false);
    }
    else
    {
      callback(true);
    }
  });
}

/**
 * Initialize pool server
 **/
 
(function init(){
    jobRefresh(true, function(sucessful){ });
})();
