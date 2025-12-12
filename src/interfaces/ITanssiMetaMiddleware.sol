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

/**
 * @title ITanssiMetaMiddleware
 * @notice Interface for the Tanssi Meta Middleware contract that aggregates multiple middleware instances
 * @dev This interface defines the operations for managing middlewares, operators, collaterals, and rewards distribution
 */
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

    /**
     * @notice Struct to store the data related to rewards distribution per era
     * @param epoch Network epoch of the middleware
     * @param totalAmount Total amount of tokens for the reward distribution
     * @param totalPoints Total amount of points for the reward distribution
     * @param root Merkle root of the rewards distribution
     * @param tokenAddress Address of the reward token
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

    /**
     * @notice Registers a new middleware with the meta middleware
     * @param middleware The address of the middleware contract to register
     * @dev Only callable by the admin role
     * @dev Emits an event when a middleware is registered
     */
    function registerMiddleware(
        address middleware
    ) external;

    /**
     * @notice Registers a collateral token with its associated price oracle
     * @param collateral The address of the collateral token
     * @param oracle The address of the Chainlink price oracle for the collateral
     * @dev Only callable by the admin role
     * @dev Emits CollateralRegistered event
     */
    function registerCollateral(address collateral, address oracle) external;

    /**
     * @notice Registers an operator with a unique key
     * @param operator The address of the operator
     * @param key The unique key associated with the operator
     * @dev Only callable by registered middlewares
     * @dev Emits OperatorRegistered event
     */
    function registerOperator(address operator, bytes32 key) external;

    /**
     * @notice Updates the key associated with an operator
     * @param operator The address of the operator
     * @param newKey The new unique key to associate with the operator
     * @dev Only callable by the middleware that registered the operator
     * @dev Emits OperatorKeySet event
     */
    function updateOperatorKey(address operator, bytes32 newKey) external;

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
    function slash(uint48 epoch, bytes32 operatorKey, uint256 percentage) external;

    /**
     * @notice Checks if a collateral token is registered and valid
     * @param collateral The address of the collateral token to check
     * @return True if the collateral is registered with a valid oracle, false otherwise
     */
    function isValidCollateral(
        address collateral
    ) external view returns (bool);

    /**
     * @notice Retrieves token data including price and decimals for multiple collaterals
     * @param collaterals Array of collateral token addresses to query
     * @return Array of TokenData structs containing price, price decimals, and token decimals for each collateral
     * @dev This function queries Chainlink oracles for price data
     */
    function getTokensData(
        address[] memory collaterals
    ) external view returns (TokenData[] memory);

    /**
     * @notice Retrieves the reward amounts for specific operators in a given era and middleware
     * @param eraIndex The era index to query
     * @param middleware The middleware address to query
     * @param operators Array of operator addresses to get rewards for
     * @return Array of reward amounts corresponding to each operator
     */
    function getOperatorsRewards(
        uint48 eraIndex,
        address middleware,
        address[] memory operators
    ) external view returns (uint256[] memory);

    /**
     * @notice Retrieves the era root data for a specific era index
     * @param eraIndex The era index to query
     * @return EraRoot struct containing epoch, total amount, total points, root, and token address
     */
    function getEraRoot(
        uint48 eraIndex
    ) external view returns (EraRoot memory);
}
