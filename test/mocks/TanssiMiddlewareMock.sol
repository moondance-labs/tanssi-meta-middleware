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
pragma solidity ^0.8.25;

import {ITanssiCommonMiddleware} from "src/interfaces/ITanssiCommonMiddleware.sol";
import {ITanssiMetaMiddleware} from "src/interfaces/ITanssiMetaMiddleware.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TanssiMiddlewareMock {
    /*is ITanssiCommonMiddleware*/
    ITanssiMetaMiddleware public immutable metaMiddleware;
    address[] activeOperators;
    mapping(address => bytes32) operatorKeys;
    bool public distributionCompleteReponse;

    mapping(uint48 eraIndex => uint256 distributionCalls) public distributionCallsPerEraIndex;
    mapping(uint48 eraIndex => uint256 rewards) public transferredRewardsPerEraIndex;
    mapping(uint48 epoch => mapping(address operator => uint256 percentage)) public slashedOperators;

    constructor(
        address metaMiddleware_
    ) {
        metaMiddleware = ITanssiMetaMiddleware(metaMiddleware_);
    }

    function prepareRewardsDistributionData(
        uint48 eraIndex,
        address rewardsToken
    ) public view returns (bytes memory rewardsDistributionData) {}

    function prepareRewardsDistributionDataFromOperatorRewards(
        uint48 eraIndex,
        address rewardsToken,
        ITanssiMetaMiddleware.OperatorReward[] memory operatorRewards
    ) public view returns (bytes memory rewardsDistributionData) {
        return abi.encode(operatorRewards);
    }

    function distributeRewards(
        uint48 eraIndex,
        address,
        bytes memory
    ) external returns (bool distributionComplete) {
        distributionCallsPerEraIndex[eraIndex]++;

        distributionComplete = distributionCompleteReponse;
    }

    function slash(
        uint48 epoch,
        address operator,
        uint256 percentage
    ) external {
        slashedOperators[epoch][operator] = percentage;
    }

    function transferRewards(
        uint48 eraIndex,
        address tokenAddress,
        uint256 totalRewards
    ) external {
        transferredRewardsPerEraIndex[eraIndex] += totalRewards;
        IERC20(tokenAddress).transferFrom(msg.sender, address(this), totalRewards);
    }

    function setDistributionCompleteResponse(
        bool distributionComplete
    ) external {
        distributionCompleteReponse = distributionComplete;
    }

    function registerOperator(
        address operator,
        bytes32 key
    ) external {
        operatorKeys[operator] = key;
        activeOperators.push(operator);
        metaMiddleware.registerOperator(operator, key);
    }
}
