// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "uint256.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    int currentHeight = pindexLast->nHeight + 1;

    if (currentHeight > params.nBitcoinStartingHeight && currentHeight < params.nKimotoGravityWellV1StartingHeight) {
        LogPrintf("Using Bitcoin Retarget Algorithm\n");
        return GetNextWorkRequiredBitcoin(pindexLast, pblock, params);
    } else if (currentHeight >= params.nKimotoGravityWellV1StartingHeight && currentHeight < params.nKimotoGravityWellV2StartingHeight) {
        LogPrintf("Using Kimoto Gravity Well V1 Retarget Algorithm\n");
        return GetNextWorkRequiredKGWV1(pindexLast, pblock, params);
    } else if (currentHeight >= params.nKimotoGravityWellV2StartingHeight && currentHeight < params.nDigiShieldStartingHeight) {
	LogPrintf("Using Kimoto Gravity Well V2 Retarget Algorithm\n");
	return GetNextWorkRequiredKGWV2(pindexLast, pblock, params);
    } else if (currentHeight >= params.nDigiShieldStartingHeight && currentHeight < params.nPOSStartingHeight) {
        LogPrintf("Using DigiShield Retarget Algorithm\n");
        return GetNextWorkRequiredDigiShield(pindexLast, pblock, params);
    } else {
        LogPrintf("Using PPCoin Retarget Algorithm\n");
        return GetNextWorkRequiredPOS(pindexLast, pblock, params);
    }

}
unsigned int GetNextWorkRequiredBitcoin(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.BitcoinDifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nBitcoinTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.BitcoinDifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.BitcoinDifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.BitcoinDifficultyAdjustmentInterval())
        blockstogoback = params.BitcoinDifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetNextWorkRequiredDigiShield(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % params.DigiShieldDifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* nTargetSpacing minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nDigiShieldTargetSpacing * 2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DigiShieldDifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DigiShieldDifficultyAdjustmentInterval() - 1;
    if ((pindexLast->nHeight+1) != params.DigiShieldDifficultyAdjustmentInterval())
        blockstogoback = params.DigiShieldDifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    nActualTimespan = params.nDigiShieldTargetTimespan + (nActualTimespan - params.nDigiShieldTargetTimespan)/8;

    if (nActualTimespan < (params.nDigiShieldTargetTimespan - (params.nDigiShieldTargetTimespan/4)))
        nActualTimespan = (params.nDigiShieldTargetTimespan - (params.nDigiShieldTargetTimespan/4));

    if (nActualTimespan > (params.nDigiShieldTargetTimespan + (params.nDigiShieldTargetTimespan/2)))
        nActualTimespan = (params.nDigiShieldTargetTimespan + (params.nDigiShieldTargetTimespan/2));

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= params.nDigiShieldTargetTimespan;
    arith_uint256 bnProofOfWorkLimit = UintToArith256(params.powLimit);
    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredKGWV1(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    static CBigNum bnProofOfWorkLimit(~uint256_old(0) >> 20);
    unsigned int TimeDaySeconds = 60 * 60 * 24;
    int64_t PastSecondsMin = TimeDaySeconds * 0.01;
    int64_t PastSecondsMax = TimeDaySeconds * 0.14;
    uint64_t PastBlocksMin = PastSecondsMin / params.nKimotoGravityWellV1TargetSpacing;
    uint64_t PastBlocksMax = PastSecondsMax / params.nKimotoGravityWellV1TargetSpacing;
    const CBlockIndex *BlockLastSolved  = pindexLast;
    const CBlockIndex *BlockReading     = pindexLast;
    uint64_t PastBlocksMass             = 0;
    int64_t  PastRateActualSeconds      = 0;
    int64_t  PastRateTargetSeconds      = 0;
    double   PastRateAdjustmentRatio    = double(1);
    CBigNum  PastDifficultyAverage;
    CBigNum  PastDifficultyAveragePrev;
    double   EventHorizonDeviation;
    double   EventHorizonDeviationFast;
    double   EventHorizonDeviationSlow;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) { return UintToArith256(params.powLimit).GetCompact(); }

    int64_t LatestBlockTime = BlockLastSolved->GetBlockTime();
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {

         if (PastBlocksMax > 0 && i > PastBlocksMax) {
             break;
         }
         PastBlocksMass++;

         if (i == 1) {
             PastDifficultyAverage.SetCompact(BlockReading->nBits);
         } else {
             PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
         }
         PastDifficultyAveragePrev = PastDifficultyAverage;
         PastRateActualSeconds   = LatestBlockTime - BlockReading->GetBlockTime();
         PastRateTargetSeconds   = params.nKimotoGravityWellV1TargetSpacing * PastBlocksMass;
         PastRateAdjustmentRatio = double(1);

         if (PastRateActualSeconds < 0) {
             PastRateActualSeconds = 0;
         }

         if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
             PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
         }
         EventHorizonDeviation     = 1 + (0.7084 * std::pow((double(PastBlocksMass)/double(144)), -1.228));
         EventHorizonDeviationFast = EventHorizonDeviation;
         EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

         if (PastBlocksMass >= PastBlocksMin) {
             if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
                 assert(BlockReading);
                 break;
             }
         }
         if (BlockReading->pprev == NULL) {
             assert(BlockReading);
             break;
         }
         BlockReading = BlockReading->pprev;
     }
     CBigNum bnNew(PastDifficultyAverage);
     if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
         bnNew *= PastRateActualSeconds;
         bnNew /= PastRateTargetSeconds;
     }

     if (bnNew > bnProofOfWorkLimit) {
         bnNew = bnProofOfWorkLimit;
     }

    return bnNew.GetCompact();
}


unsigned int GetNextWorkRequiredKGWV2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    static CBigNum bnProofOfWorkLimit(~uint256_old(0) >> 20);
    unsigned int TimeDaySeconds = 60 * 60 * 24;
    int64_t PastSecondsMin = TimeDaySeconds * 0.01;
    int64_t PastSecondsMax = TimeDaySeconds * 0.14;
    uint64_t PastBlocksMin = PastSecondsMin / params.nKimotoGravityWellV2TargetSpacing;
    uint64_t PastBlocksMax = PastSecondsMax / params.nKimotoGravityWellV2TargetSpacing;
    const CBlockIndex *BlockLastSolved  = pindexLast;
    const CBlockIndex *BlockReading     = pindexLast;
    uint64_t PastBlocksMass             = 0;
    int64_t  PastRateActualSeconds      = 0;
    int64_t  PastRateTargetSeconds      = 0;
    double   PastRateAdjustmentRatio    = double(1);
    CBigNum  PastDifficultyAverage;
    CBigNum  PastDifficultyAveragePrev;
    double   EventHorizonDeviation;
    double   EventHorizonDeviationFast;
    double   EventHorizonDeviationSlow;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) { return UintToArith256(params.powLimit).GetCompact(); }

    int64_t LatestBlockTime = BlockLastSolved->GetBlockTime();
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {

         if (PastBlocksMax > 0 && i > PastBlocksMax) {
             break;
         }
         PastBlocksMass++;

         if (i == 1) {
             PastDifficultyAverage.SetCompact(BlockReading->nBits);
         } else {
             PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
         }
         PastDifficultyAveragePrev = PastDifficultyAverage;

         if (LatestBlockTime < BlockReading->GetBlockTime()) {
             LatestBlockTime = BlockReading->GetBlockTime();
         }
         PastRateActualSeconds   = LatestBlockTime - BlockReading->GetBlockTime();
         PastRateTargetSeconds   = params.nKimotoGravityWellV2TargetSpacing * PastBlocksMass;
         PastRateAdjustmentRatio = double(1);

         if (PastRateActualSeconds < 1) {
             PastRateActualSeconds = 1;
         }

         if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
             PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
         }
         EventHorizonDeviation     = 1 + (0.7084 * std::pow((double(PastBlocksMass)/double(144)), -1.228));
         EventHorizonDeviationFast = EventHorizonDeviation;
         EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

         if (PastBlocksMass >= PastBlocksMin) {
             if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
                 assert(BlockReading);
                 break;
             }
         }
         if (BlockReading->pprev == NULL) {
             assert(BlockReading);
             break;
         }
         BlockReading = BlockReading->pprev;
     }
     CBigNum bnNew(PastDifficultyAverage);
     if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
         bnNew *= PastRateActualSeconds;
         bnNew /= PastRateTargetSeconds;
     }

     if (bnNew > bnProofOfWorkLimit) {
         bnNew = bnProofOfWorkLimit;
     }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredPOS(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    arith_uint256 nProofOfWorkLimit = UintToArith256(params.posLimit);
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, true);
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, true);

    // Reset difficulty for PoS switchover
    if (pindexLast->nHeight < params.nLastPOWBlock + 50) {
	LogPrintf("Resetting POS Difficulty \n");
        return nProofOfWorkLimit.GetCompact();
    }

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // Normalize extreme values
    if (nActualSpacing < 1)
        nActualSpacing = 1;
    if (nActualSpacing > 2200)
        nActualSpacing = 2200;

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    bnNew *= ((params.POSDifficultyAdjustmentInterval() - 1) * params.nPOSTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((params.POSDifficultyAdjustmentInterval() + 1) * params.nPOSTargetSpacing);

    if (bnNew > nProofOfWorkLimit)
        bnNew = nProofOfWorkLimit;

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nBitcoinTargetTimespan/4)
        nActualTimespan = params.nBitcoinTargetTimespan/4;
    if (nActualTimespan > params.nBitcoinTargetTimespan*4)
        nActualTimespan = params.nBitcoinTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nBitcoinTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    return true;
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

