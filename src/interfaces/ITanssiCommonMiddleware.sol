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

interface ITanssiCommonMiddleware {
    function prepareRewardsDistributionData(
        uint48 eraIndex,
        address rewardsToken
    ) external view returns (bytes memory rewardsDistributionData);

    function prepareRewardsDistributionDataFromOperatorRewards(
        uint48 eraIndex,
        address rewardsToken,
        ITanssiMetaMiddleware.OperatorReward[] memory operatorRewards
    ) external view returns (bytes memory rewardsDistributionData);

    function distributeRewards(
        uint48 eraIndex,
        address tokenAddress,
        bytes memory rewardsDistributionData
    ) external returns (bool distributionComplete);

    /**
     * @notice Slashes an operator's stake
     * @dev Only the gateway can call this function
     * @dev This function slashes the operator's stake for the target epoch
     * @param epoch The epoch number
     * @param operator The address of the operator to slash
     * @param percentage Percentage to slash, represented as parts per billion.
     */
    function slash(uint48 epoch, address operator, uint256 percentage) external;

    function activeOperatorsAtEpoch(
        uint48 epoch
    ) external view returns (address[] memory);

    function transferRewards(uint48 eraIndex, address tokenAddress, uint256 totalRewards) external;
}
