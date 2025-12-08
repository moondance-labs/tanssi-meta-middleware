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

interface ITanssiMetaMiddleware {
    event RewardsTransferred(address indexed middleware, uint48 indexed eraIndex, uint256 totalRewards);

    event RewardsDistributed(address indexed middleware, uint48 indexed eraIndex, bool allDistributed);

    // Whether tokens were transferred yet is not tracked here, it is tracked per era only
    enum DistributionStatus {
        PENDING,
        IN_PROGRESS,
        DISTRIBUTED
    }

    /**
     * @notice Data about a token
     * @param price The price of the token
     * @param priceDecimals The number of decimals of the price
     * @param tokenDecimals The number of decimals of the token
     */
    struct TokenData {
        int256 price;
        uint8 priceDecimals;
        uint8 tokenDecimals;
    }

    /* @notice Struct to store the data related to rewards distribution per era.
     * @param epoch network epoch of the middleware
     * @param amount amount of tokens received per eraIndex
     * @param totalPoints total amount of points for the reward distribution
     * @param totalAmount total amount of tokens for the reward distribution
     * @param root Merkle root of the rewards distribution
     * @param tokenAddress address of the reward token
     */
    struct EraRoot {
        uint48 epoch;
        uint256 totalAmount;
        uint256 totalPoints;
        bytes32 root;
        address tokenAddress;
    }

    /**
     * @notice Struct to store the data related to rewards distribution per operator.
     * @param operatorKey operator key of the rewards' recipient
     * @param totalPoints total amount of points that can be claimed
     * @param proof Merkle proof of the rewards distribution
     */
    struct OperatorRewardWithProof {
        bytes32 operatorKey;
        uint32 totalPoints;
        bytes32[] proof;
    }

    /**
     * @notice Struct to store the data related to rewards distribution per operator.
     * @param operator The address of the operator
     * @param rewardAmount The amount of reward tokens for the operator and its stakers
     */
    struct OperatorReward {
        address operator;
        uint256 rewardAmount;
    }

    error TanssiMetaMiddleware__CollateralAlreadyRegistered();
    error TanssiMetaMiddleware__CouldNotDistributeRewardsInASingleCall();
    error TanssiMetaMiddleware__EraRootNotSet();
    error TanssiMetaMiddleware__InsufficientRewardsReceived();
    error TanssiMetaMiddleware__InvalidProof();
    error TanssiMetaMiddleware__KeyAlreadyUsed();
    error TanssiMetaMiddleware__MiddlewareAlreadyRegistered();
    error TanssiMetaMiddleware__UnexpectedEraIndex();
    error TanssiMetaMiddleware__UnexpectedDistributionStatus();
    error TanssiMetaMiddleware__UnexpectedMiddleware();
    error TanssiMetaMiddleware__UnknownMiddleware();

    event CollateralRegistered(address indexed collateral, address indexed oracle);
    event OperatorRegistered(address indexed operator, address indexed middleware);
    event OperatorKeySet(address indexed operator, bytes32 newKey);

    function registerMiddleware(
        address middleware
    ) external;

    function registerCollateral(
        address collateral,
        address oracle
    ) external;

    function registerOperator(
        address operator,
        bytes32 key
    ) external;

    function updateOperatorKey(
        address operator,
        bytes32 newKey
    ) external;

    /**
     * @notice Distribute rewards for a specific era contained in an epoch by providing a Merkle root, total points, total amount of tokens and the token address of the rewards.
     * @param epoch network epoch of the middleware
     * @param eraIndex era index of Starlight's rewards distribution
     * @param totalPoints total amount of points for the reward distribution
     * @param totalAmount total amount of tokens to distribute
     * @param root Merkle root of the reward distribution
     * @param tokenAddress The token address of the rewards
     * @dev This function is called by the gateway only
     * @dev Emit DistributeRewards event.
     */
    function distributeRewards(
        uint48 epoch,
        uint48 eraIndex,
        uint256 totalPoints,
        uint256 totalAmount,
        bytes32 root,
        address tokenAddress
    ) external;

    /**
     * @notice Slashes an operator's stake
     * @dev Only the gateway can call this function
     * @dev This function slashes the operator's stake for the target epoch
     * @param epoch The epoch number
     * @param operatorKey The operator key to slash
     * @param percentage Percentage to slash, represented as parts per billion.
     */
    function slash(
        uint48 epoch,
        bytes32 operatorKey,
        uint256 percentage
    ) external;

    function isValidCollateral(
        address collateral
    ) external view returns (bool);

    function getTokensData(
        address[] memory collaterals
    ) external view returns (TokenData[] memory);

    function getOperatorsRewards(
        uint48 eraIndex,
        address middleware,
        address[] memory operators
    ) external view returns (uint256[] memory);

    function getEraRoot(
        uint48 eraIndex
    ) external view returns (EraRoot memory);
}
