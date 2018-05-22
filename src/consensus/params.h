// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KEKCOIN_CONSENSUS_PARAMS_H
#define KEKCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141 and BIP143
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    double nYesCount;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargetting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];

    /** Proof of work parameters */
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;

    /**
     * Difficulty Related Parameters
     */
    uint256 powLimit;

    int64_t nBitcoinStartingHeight;
    int64_t nBitcoinTargetTimespan;
    int64_t nBitcoinTargetSpacing;
    int64_t BitcoinDifficultyAdjustmentInterval() const { return nBitcoinTargetTimespan / nBitcoinTargetSpacing; }

    int64_t nDigiShieldStartingHeight;
    int64_t nDigiShieldTargetTimespan;
    int64_t nDigiShieldTargetSpacing;
    int64_t DigiShieldDifficultyAdjustmentInterval() const { return nDigiShieldTargetTimespan / nDigiShieldTargetSpacing; }

    int64_t nKimotoGravityWellV1StartingHeight;
    int64_t nKimotoGravityWellV1TargetTimespan;
    int64_t nKimotoGravityWellV1TargetSpacing;
    int64_t KimotoGravityWellV1DifficltyAdjusmentInterval() const { return nKimotoGravityWellV1TargetTimespan / nKimotoGravityWellV1TargetSpacing; }

    int64_t nKimotoGravityWellV2StartingHeight;
    int64_t nKimotoGravityWellV2TargetTimespan;
    int64_t nKimotoGravityWellV2TargetSpacing;
    int64_t KimotoGravityWellDifficultyAdjusmentInterval() const { return nKimotoGravityWellV2TargetTimespan / nKimotoGravityWellV2TargetSpacing; }

    uint256 posLimit;
    int64_t nPOSStartingHeight;
    int64_t nPOSTargetTimespan;
    int64_t nPOSTargetSpacing;
    int64_t POSDifficultyAdjustmentInterval() const { return nPOSTargetTimespan / nPOSTargetSpacing; }

    /**
     * POS Related Settings
     */
    int64_t nLastPOWBlock;
    int64_t nInterestRate;
    int64_t nStakeMinAge;
    int64_t nStakeMaxAge;
    unsigned int nStakeModifierInterval;

    /**
     * Coinbase Spending Settings
     */
    int64_t nCoinbaseMaturityV1;
    int64_t nCoinbaseMaturityV2;

};
} // namespace Consensus

#endif // KEKCOIN_CONSENSUS_PARAMS_H
