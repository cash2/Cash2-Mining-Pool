/**
 * Cryptonote Node.JS Pool
 * https://github.com/dvandal/cryptonote-nodejs-pool
 *
 * Block unlocker
 **/

// Load required modules
var async = require('async');
var bignum = require('bignum');

var apiInterfaces = require('./apiInterfaces.js')(config.daemon, config.wallet, config.api);
var notifications = require('./notifications.js');
var utils = require('./utils.js');
var slushMiningEnabled = config.poolServer.slushMining && config.poolServer.slushMining.enabled;

var CASH2_HARD_FORK_HEIGHT_2 = 420016;
// Initialize log system
var logSystem = 'unlocker';
require('./exceptionWriter.js')(logSystem);

/**
 * Run block unlocker
 **/
log('info', logSystem, 'Started');

function runInterval(){

    // console.log("\x1b[36m", "block unlocker", "\x1b[0m");

    async.waterfall([
        // Get all block candidates in redis
        function(callback){

            // console.log("\x1b[36m", "get all block candidates in redis", "\x1b[0m");

            redisClient.zrange(config.coin + ':blocks:candidates', 0, -1, 'WITHSCORES', function(error, results){
                if (error){
                    log('error', logSystem, 'Error trying to get pending blocks from redis %j', [error]);
                    callback(true);
                    return;
                }

                // console.log("\x1b[36m", "number of block candidates in redis = " + results.length, "\x1b[0m");

                if (results.length === 0){

                    // console.log("\x1b[36m", "results.length = 0", "\x1b[0m");

                    log('info', logSystem, 'No blocks candidates in redis');
                    callback(true);
                    return;
                }

                var blocks = [];

                for (var i = 0; i < results.length; i += 2){

                    // console.log("\x1b[36m", "results["+ i +"] = " + results[i], "\x1b[0m");

                    var parts = results[i].split(':');
                    blocks.push({
                        serialized: results[i],
                        height: parseInt(results[i + 1]),
                        hash: parts[0],
                        time: parts[1],
                        difficulty: parts[2],
                        shares: parts[3],
                        score: parts.length >= 5 ? parts[4] : parts[3]
                    });
                }

                // console.log("\x1b[36m", "blocks.length = " + blocks.length, "\x1b[0m");

                callback(null, blocks);
            });
        },

        // Check if blocks are orphaned
        function(blocks, callback){

            // console.log("\x1b[36m", "check if blocks are orphaned", "\x1b[0m");

            // console.log("\x1b[36m", "orphaned blocks = " + blocks.length, "\x1b[0m");

            async.filter(blocks, function(block, mapCback){
                var daemonType = config.daemonType ? config.daemonType.toLowerCase() : "default";
                var blockHeight = (daemonType === "forknote" || daemonType === "bytecoin" || config.blockUnlocker.fixBlockHeightRPC) ? block.height + 1 : block.height;
                
                // console.log("\x1b[36m", "blockHeight = " + blockHeight, "\x1b[0m");

                apiInterfaces.rpcDaemon('getblockheaderbyheight', {height: blockHeight}, function(error, result){
                    
                    // console.log("\x1b[36m", "getblockheaderbyheight", "\x1b[0m");
                    // console.log("\x1b[36m", "getblockheaderbyheight error = " + error, "\x1b[0m");
                    // console.log("\x1b[36m", "getblockheaderbyheight result = " + result, "\x1b[0m");

                    if (error){
                        log('error', logSystem, 'Error with getblockheaderbyheight RPC request for block %s - %j', [block.serialized, error]);
                        block.unlocked = false;
                        mapCback();
                        return;
                    }
                    if (!result.block_header){
                        log('error', logSystem, 'Error with getblockheaderbyheight, no details returned for %s - %j', [block.serialized, result]);
                        block.unlocked = false;
                        mapCback();
                        return;
                    }
                    var blockHeader = result.block_header;

                    var difficulty = blockHeader.difficulty;

                    if (blockHeader.height >= CASH2_HARD_FORK_HEIGHT_2)
                    {
                      blockHeader.difficulty = bignum('1099511627776').mul(difficulty);
                    }     
                                   
                    // console.log("\x1b[36m", "blockHeader keys = " + Object.keys(blockHeader), "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.height = " + blockHeader.height, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.depth = " + blockHeader.depth, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.difficulty = " + blockHeader.difficulty, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.hash = " + blockHeader.hash, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.merkle_root = " + blockHeader.merkle_root, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.nonce = " + blockHeader.nonce, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.orphan_status = " + blockHeader.orphan_status, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.prev_hash = " + blockHeader.prev_hash, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.reward = " + blockHeader.reward, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.timestamp = " + blockHeader.timestamp, "\x1b[0m");

                    block.orphaned = blockHeader.hash === block.hash ? 0 : 1;

                    // console.log("\x1b[36m", "block.orphaned = " + block.orphaned, "\x1b[0m");
                    
                    // console.log("\x1b[36m", "block.height = " + block.height, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.height = " + blockHeader.height, "\x1b[0m");
                    // console.log("\x1b[36m", "block.hash = " + block.hash, "\x1b[0m");
                    // console.log("\x1b[36m", "blockHeader.hash = " + blockHeader.hash, "\x1b[0m");
                    // console.log("\n");

                    block.unlocked = blockHeader.depth >= config.blockUnlocker.depth;

                    // console.log("\x1b[36m", "config.blockUnlocker.depth = " + config.blockUnlocker.depth, "\x1b[0m");

                    // console.log("\x1b[36m", "block.unlocked = " + block.unlocked, "\x1b[0m");

                    block.reward = blockHeader.reward;
                    if (config.blockUnlocker.networkFee) {
                        var networkFeePercent = config.blockUnlocker.networkFee / 100;
                        block.reward = block.reward - (block.reward * networkFeePercent);
                    }
                    mapCback(block.unlocked);
                });
            }, function(unlockedBlocks){

                // console.log("\x1b[36m", "check unlocked blocks", "\x1b[0m");

                if (unlockedBlocks.length === 0){
                    log('info', logSystem, 'No pending blocks are unlocked yet (%d pending)', [blocks.length]);
                    callback(true);
                    return;
                }

                callback(null, unlockedBlocks)
            })
        },

        // Get worker shares for each unlocked block
        function(blocks, callback){

            // console.log("\x1b[36m", "get worker shares for each unlocked block", "\x1b[0m");

            var redisCommands = blocks.map(function(block){
                return ['hgetall', config.coin + ':scores:round' + block.height];
            });


            redisClient.multi(redisCommands).exec(function(error, replies){
                if (error){
                    log('error', logSystem, 'Error with getting round shares from redis %j', [error]);
                    callback(true);
                    return;
                }
                for (var i = 0; i < replies.length; i++){
                    var workerScores = replies[i];
                    blocks[i].workerScores = workerScores;
                }
                callback(null, blocks);
            });
        },

        // Handle orphaned blocks
        function(blocks, callback){

            // console.log("\x1b[36m", "handle orphaned blocks", "\x1b[0m");

            var orphanCommands = [];

            blocks.forEach(function(block){
                if (!block.orphaned) return;

                orphanCommands.push(['del', config.coin + ':scores:round' + block.height]);
                orphanCommands.push(['del', config.coin + ':shares_actual:round' + block.height]);

                orphanCommands.push(['zrem', config.coin + ':blocks:candidates', block.serialized]);
                orphanCommands.push(['zadd', config.coin + ':blocks:matured', block.height, [
                    block.hash,
                    block.time,
                    block.difficulty,
                    block.shares,
                    block.orphaned
                ].join(':')]);

                if (block.workerScores && !slushMiningEnabled) {
                    var workerScores = block.workerScores;
                    Object.keys(workerScores).forEach(function (worker) {
                        orphanCommands.push(['hincrby', config.coin + ':scores:roundCurrent', worker, workerScores[worker]]);
                    });
                }

                notifications.sendToAll('blockOrphaned', {
                    'HEIGHT': block.height,
                    'BLOCKTIME': utils.dateFormat(new Date(parseInt(block.time) * 1000), 'yyyy-mm-dd HH:MM:ss Z'),
                    'HASH': block.hash,
                    'DIFFICULTY': block.difficulty,
                    'SHARES': block.shares,
                    'EFFORT': Math.round(block.shares / block.difficulty * 100) + '%'
                });
            });

            if (orphanCommands.length > 0){
                redisClient.multi(orphanCommands).exec(function(error, replies){
                    if (error){
                        log('error', logSystem, 'Error with cleaning up data in redis for orphan block(s) %j', [error]);
                        callback(true);
                        return;
                    }
                    callback(null, blocks);
                });
            }
            else{
                callback(null, blocks);
            }
        },

        // Handle unlocked blocks
        function(blocks, callback){

            // console.log("\x1b[36m", "handle unlocked blocks", "\x1b[0m");

            var unlockedBlocksCommands = [];
            var payments = {};
            var totalBlocksUnlocked = 0;

            // console.log("\x1b[36m", "handle unlocked blocks : num blocks = " + blocks.length, "\x1b[0m");

            blocks.forEach(function(block){

                // console.log("\x1b[36m", "handle unlocked blocks : block orphaned = " + block.orphaned, "\x1b[0m");

                if (block.orphaned) return;
                totalBlocksUnlocked++;

                unlockedBlocksCommands.push(['del', config.coin + ':scores:round' + block.height]);
                unlockedBlocksCommands.push(['del', config.coin + ':shares_actual:round' + block.height]);
                unlockedBlocksCommands.push(['zrem', config.coin + ':blocks:candidates', block.serialized]);
                unlockedBlocksCommands.push(['zadd', config.coin + ':blocks:matured', block.height, [
                    block.hash,
                    block.time,
                    block.difficulty,
                    block.shares,
                    block.orphaned,
                    block.reward
                ].join(':')]);

                var feePercent = config.blockUnlocker.poolFee / 100;

                if (Object.keys(donations).length) {
                    for(var wallet in donations) {
                        var percent = donations[wallet] / 100;
                        feePercent += percent;
                        payments[wallet] = Math.round(block.reward * percent);
                        log('info', logSystem, 'Block %d donation to %s as %d percent of reward: %d', [block.height, wallet, percent, payments[wallet]]);
                    }
                }

                var reward = Math.round(block.reward - (block.reward * feePercent));

                // console.log("\x1b[36m", "handle unlocked blocks : reward = " + reward, "\x1b[0m");

                log('info', logSystem, 'Unlocked %d block with reward %d and donation fee %d. Miners reward: %d', [block.height, block.reward, feePercent, reward]);

                if (block.workerScores) {
                    var totalScore = parseFloat(block.score);
                    Object.keys(block.workerScores).forEach(function (worker) {
                        var percent = block.workerScores[worker] / totalScore;
                        var workerReward = Math.round(reward * percent);
                        payments[worker] = (payments[worker] || 0) + workerReward;
                        log('info', logSystem, 'Block %d payment to %s for %d%% of total block score: %d', [block.height, worker, percent*100, payments[worker]]);
                    });
                }

                notifications.sendToAll('blockUnlocked', {
                    'HEIGHT': block.height,
                    'BLOCKTIME': utils.dateFormat(new Date(parseInt(block.time) * 1000), 'yyyy-mm-dd HH:MM:ss Z'),
                    'HASH': block.hash,
                    'REWARD': utils.getReadableCoins(block.reward),
                    'DIFFICULTY': block.difficulty,
                    'SHARES': block.shares,
                    'EFFORT': Math.round(block.shares / block.difficulty * 100) + '%'
                });
            });

            for (var worker in payments) {
                var amount = parseInt(payments[worker]);

                // console.log("\x1b[36m", "handle unlocked blocks : amount = " + amount, "\x1b[0m");

                if (amount <= 0){
                    delete payments[worker];
                    continue;
                }
                unlockedBlocksCommands.push(['hincrby', config.coin + ':workers:' + worker, 'balance', amount]);
            }

            if (unlockedBlocksCommands.length === 0){
                log('info', logSystem, 'No unlocked blocks yet (%d pending)', [blocks.length]);
                callback(true);
                return;
            }

            redisClient.multi(unlockedBlocksCommands).exec(function(error, replies){
                if (error){
                    log('error', logSystem, 'Error with unlocking blocks %j', [error]);
                    callback(true);
                    return;
                }
                log('info', logSystem, 'Unlocked %d blocks and update balances for %d workers', [totalBlocksUnlocked, Object.keys(payments).length]);
                callback(null);
            });
        }
    ], function(error, result){
        setTimeout(runInterval, config.blockUnlocker.interval * 1000);
    })
}

runInterval();

