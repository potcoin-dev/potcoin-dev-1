// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "streams.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion,const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp,(const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Banks Aren't Accepting Legal Marijuana Money. Here's Why";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nMajorityEnforceBlockUpgrade = 700;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000091bc0f9d1578c7979142b2ff70e6bf8ff7c388cf3dcb486cf19a7518949");
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7056; // 70% of 10080
        consensus.nMinerConfirmationWindow = 10080; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1514764800; // Jan 1st 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1546300800; // Jan 1st 2019

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1514764800; // Jan 1st 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1546300800; // Jan 1st 2019

        consensus.powLimit = ArithToUint256(~arith_uint256(0) >> 20);
	consensus.nBitcoinStartingHeight = 0;
	consensus.nBitcoinTargetTimespan = 108 * 40;
	consensus.nBitcoinTargetSpacing = 40;

	consensus.nDigiShieldStartingHeight = 280000;
	consensus.nDigiShieldTargetTimespan = 40;
	consensus.nDigiShieldTargetSpacing = 40;

	consensus.nKimotoGravityWellV1StartingHeight = 61798;
	consensus.nKimotoGravityWellV1TargetTimespan = 108 * 40;
	consensus.nKimotoGravityWellV1TargetSpacing = 40;

        consensus.nKimotoGravityWellV2StartingHeight = 158000;
        consensus.nKimotoGravityWellV2TargetTimespan = 108 * 40;
        consensus.nKimotoGravityWellV2TargetSpacing = 40;

        consensus.nPOSStartingHeight = 974999;
        consensus.nPOSTargetTimespan = 40;
        consensus.nPOSTargetSpacing = 40;

        consensus.posLimit = ArithToUint256(~arith_uint256(0) >> 20);
	consensus.nLastPOWBlock = 974999;
	consensus.nInterestRate = 5 * CENT;
	consensus.nStakeMinAge = 8 * 60 * 60;
	consensus.nStakeMaxAge = 365 * 24 * 60 * 60;
	consensus.nStakeModifierInterval = 13 * 60;
	consensus.nCoinbaseMaturityV1 = 5;
	consensus.nCoinbaseMaturityV2 = 6 * 40;
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 4200;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1389688315, 471993, 0x1e0ffff0, 1, 420 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(genesis.hashMerkleRoot == uint256S("0xd5a08606e06eea7eae8a889dbcdcdd84917c10fc8e177ec013a9005305afe53d"));
        assert(consensus.hashGenesisBlock == uint256S("0xde36b0cb2a9c7d1d7ac0174d0a89918f874fabcf5f9741dd52cd6d04ee1335ec"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,55);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,183);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x03)(0x77)(0xD4)(0x4D).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0x77)(0xEE)(0xE1).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds.clear();
      	vSeeds.clear();

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("dnsseedz.potcoin.info", "dnsseedz.potcoin.info"));
        vSeeds.push_back(CDNSSeedData("dns1.potcoin.info", "dns1.potcoin.info"));
        vSeeds.push_back(CDNSSeedData("98.214.180.203", "98.214.180.203"));
        vSeeds.push_back(CDNSSeedData("95.130.37.130", "95.130.37.130"));
        vSeeds.push_back(CDNSSeedData("93.23.129.54", "93.23.129.54"));

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (     10, uint256S("0xc2818dc9bf6fd7fb692cc0886d39a724bb4e86fad095a62266bd015b9fbae04f"))
            (     17, uint256S("0x6c8818dd77bcaee6c3c775a34c0a84f349cc4db99e2c8b40ed7adb83b0184606"))
            (     22, uint256S("0x592cc1502043365de34d8c806fa2355e8f2ca47bfd568812c77547b4b72df744"))
            (     27, uint256S("0x49fc54fa7fe3939e57b83a468cb40333177b8e1ae1648a641ccc79d47ca68834"))
            (     35, uint256S("0x697905a9b6822eb09a6e3eecb82133cde24f15e5c400368b65bdc9b2cc7943c7"))
            (     50, uint256S("0x6a5411cbcbe8d69dd3cc85af05ad7439fc2c02acd8d5861471ea32a1b59ce271"))
            (  80000, uint256S("0x0def72391fd1db25297478048a8b1b5feca86061d614146ea8e875d27be1f41f"))
            ( 120000, uint256S("0xa6d147731bb021c5365ba44264e7faffd47aaf806861278a4227deac33f78207"))
            ( 258805, uint256S("0x74133722e84132005691a21a8092f0c590da7ab5744f3bdf8113089cc6d55051"))
            ( 564890, uint256S("0x1230d31d9b93651e02c877776e01158496fbac59dd3d898d9b86b76a8e6beb83")),
            1420681312, // * UNIX timestamp of last checkpoint block
            93726,          // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            2260         // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nMajorityEnforceBlockUpgrade = 700;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 900000;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 84; // 70% of 120
        consensus.nMinerConfirmationWindow = 120; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1514764800; // Jan 1st 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1546300800; // Jan 1st 2019

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1514764800; // Jan 1st 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1546300800; // Jan 1st 2019

        consensus.powLimit = ArithToUint256(~arith_uint256(0) >> 20);
        consensus.nBitcoinStartingHeight = 0;
        consensus.nBitcoinTargetTimespan = 108 * 40;
        consensus.nBitcoinTargetSpacing = 40;

        consensus.nDigiShieldStartingHeight = 280000;
        consensus.nDigiShieldTargetTimespan = 40;
        consensus.nDigiShieldTargetSpacing = 40;

        consensus.nKimotoGravityWellV1StartingHeight = 61798;
        consensus.nKimotoGravityWellV1TargetTimespan = 108 * 40;
        consensus.nKimotoGravityWellV1TargetSpacing = 40;

        consensus.nKimotoGravityWellV2StartingHeight = 158000;
        consensus.nKimotoGravityWellV2TargetTimespan = 108 * 40;
        consensus.nKimotoGravityWellV2TargetSpacing = 40;

        consensus.nPOSStartingHeight = 974999;
        consensus.nPOSTargetTimespan = 40;
        consensus.nPOSTargetSpacing = 40;
        consensus.posLimit = ArithToUint256(~arith_uint256(0) >> 20);

        consensus.nLastPOWBlock = 974999;
        consensus.nInterestRate = 5 * CENT;
        consensus.nStakeMinAge = 8 * 60 * 60;
        consensus.nStakeMaxAge = 365 * 24 * 60 * 60;
        consensus.nStakeModifierInterval = 13 * 60;
        consensus.nCoinbaseMaturityV1 = 5;
        consensus.nCoinbaseMaturityV2 = 6 * 40;


        pchMessageStart[0] = 0x55;
        pchMessageStart[1] = 0x66;
        pchMessageStart[2] = 0x77;
        pchMessageStart[3] = 0x88;
        nDefaultPort = 13777;
        nPruneAfterHeight = 1000;
        bnProofOfWorkLimit = arith_uint256(~arith_uint256() >> 16);

        genesis = CreateGenesisBlock(1498944188, 18717, 0x1f00ffff, 1, 420 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        //assert(consensus.hashGenesisBlock == uint256S("0x0000c7b67a057053c5043fad3ae7896f3d3172361ba4a850abb24f6dd80df5dc"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.push_back(CDNSSeedData("209.250.246.85", "209.250.246.85"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x0000c7b67a057053c5043fad3ae7896f3d3172361ba4a850abb24f6dd80df5dc")),
	    0,
            0,
            0,
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        consensus.powLimit = ArithToUint256(~arith_uint256(0) >> 20);
        consensus.nBitcoinStartingHeight = 0;
        consensus.nBitcoinTargetTimespan = 108 * 40;
        consensus.nBitcoinTargetSpacing = 40;

        consensus.nDigiShieldStartingHeight = 280000;
        consensus.nDigiShieldTargetTimespan = 40;
        consensus.nDigiShieldTargetSpacing = 40;

        consensus.nKimotoGravityWellV1StartingHeight = 61798;
        consensus.nKimotoGravityWellV1TargetTimespan = 108 * 40;
        consensus.nKimotoGravityWellV1TargetSpacing = 40;

        consensus.nKimotoGravityWellV2StartingHeight = 158000;
        consensus.nKimotoGravityWellV2TargetTimespan = 108 * 40;
        consensus.nKimotoGravityWellV2TargetSpacing = 40;

        consensus.nPOSStartingHeight = 974999;
        consensus.nPOSTargetTimespan = 40;
        consensus.nPOSTargetSpacing = 40;

        consensus.posLimit = ArithToUint256(~arith_uint256(0) >> 20);
        consensus.nLastPOWBlock = 974999;
        consensus.nInterestRate = 5 * CENT;
        consensus.nStakeMinAge = 8 * 60 * 60;
        consensus.nStakeMaxAge = 365 * 24 * 60 * 60;
        consensus.nStakeModifierInterval = 13 * 60;
        consensus.nCoinbaseMaturityV1 = 5;
        consensus.nCoinbaseMaturityV2 = 6 * 40;

        pchMessageStart[0] = 0x99;
        pchMessageStart[1] = 0x98;
        pchMessageStart[2] = 0x97;
        pchMessageStart[3] = 0x96;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1411111111, 0, 0x1e0fffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0000000013cb675cc890cf8c7a22f1f3948684b297ccd2553d6e203e00198ae0")),
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,20);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,96);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,39);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x05)(0x38)(0x34)(0x76).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x06)(0x37)(0x64)(0x13).convert_to_container<std::vector<unsigned char> >();
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
