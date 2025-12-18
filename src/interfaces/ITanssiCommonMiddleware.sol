//SPDX-License-Identifier: GPL-3.0-or-later

// Copyright (C) Moondance Labs Ltd.
// This file is part of Tanssi.
// Tanssi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// Tanssi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with Tanssi.  If not, see <http://www.gnu.org/licenses/>
pragma solidity ^0.8.0;

import {ITanssiMetaMiddleware} from "./ITanssiMetaMiddleware.sol";

/**
 * @title ITanssiCommonMiddleware
 * @notice Interface for common middleware functionality that all Tanssi middlewares must implement
 * @dev This interface defines the standard operations that middlewares must support for rewards distribution, slashing and operator management
 */
interface ITanssiCommonMiddleware {
    /**
     * @notice Prepares rewards distribution data for a specific era
     * @param eraIndex The era index for which to prepare rewards distribution data
     * @param rewardsToken The address of the token to distribute as rewards
     * @return rewardsDistributionData Encoded data containing the rewards distribution information
     * @dev This function should calculate and encode all necessary data for distributing rewards to operators
     */
    function prepareRewardsDistributionData(
        uint48 eraIndex,
        address rewardsToken
    ) external view returns (bytes memory rewardsDistributionData);

    /**
     * @notice Prepares rewards distribution data from a list of operator rewards
     * @param eraIndex The era index for which to prepare rewards distribution data
     * @param rewardsToken The address of the token to distribute as rewards
     * @param operatorRewards Array of operator rewards to include in the distribution
     * @return rewardsDistributionData Encoded data containing the rewards distribution information
     * @dev This function allows preparing distribution data from pre-calculated operator rewards
     * @dev The output of this function is then passed to the distributeRewards call.
     */
    function prepareRewardsDistributionDataFromOperatorRewards(
        uint48 eraIndex,
        address rewardsToken,
        ITanssiMetaMiddleware.OperatorReward[] memory operatorRewards
    ) external view returns (bytes memory rewardsDistributionData);

    /**
     * @notice Distributes rewards to operators based on the provided distribution data
     * @param eraIndex The era index for which rewards are being distributed
     * @param tokenAddress The address of the token being distributed
     * @param rewardsDistributionData Encoded data containing the rewards distribution information
     * @return distributionComplete True if all rewards were distributed in this call, false if distribution needs to continue
     * @dev This function may need to be called multiple times if the distribution is too large for a single transaction
     */
    function distributeRewards(
        uint48 eraIndex,
        address tokenAddress,
        bytes memory rewardsDistributionData
    ) external returns (bool distributionComplete);

    /**
     * @notice Slashes an operator's stake by a specified percentage
     * @param epoch The epoch number for which the slash applies
     * @param operator The address of the operator to slash
     * @param percentage The percentage to slash, represented as parts per billion
     */
    function slash(
        uint48 epoch,
        address operator,
        uint256 percentage
    ) external;

    /**
     * @notice Returns the list of active operators at a specific epoch
     * @param epoch The epoch number to query
     * @return Array of operator addresses that were active during the specified epoch
     */
    function activeOperatorsAtEpoch(
        uint48 epoch
    ) external view returns (address[] memory);

    /**
     * @notice Transfers rewards tokens to the middleware for distribution
     * @param eraIndex The era index for which rewards are being transferred
     * @param tokenAddress The address of the token being transferred
     * @param totalRewards The total amount of rewards to transfer
     * @dev This function is called by the meta middleware to transfer rewards before distribution
     * @dev This function is called only once per era and middleware
     */
    function transferRewards(
        uint48 eraIndex,
        address tokenAddress,
        uint256 totalRewards
    ) external;
}
