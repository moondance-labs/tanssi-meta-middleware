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

    /// @notice Thrown when attempting to register a collateral that is already registered
    error TanssiMetaMiddleware__CollateralAlreadyRegistered();
    /// @notice Thrown when rewards distribution cannot be completed in a single transaction
    error TanssiMetaMiddleware__CouldNotDistributeRewardsInASingleCall();
    /// @notice Thrown when attempting to set an era root that has already been set
    error TanssiMetaMiddleware__EraRootAlreadySet();
    /// @notice Thrown when attempting to access an era root that has not been set
    error TanssiMetaMiddleware__EraRootNotSet();
    /// @notice Thrown when the total rewards received does not match the expected balance
    error TanssiMetaMiddleware__InsufficientRewardsReceived();
    /// @notice Thrown when a Merkle proof verification fails
    error TanssiMetaMiddleware__InvalidProof();
    /// @notice Thrown when attempting to use an operator key that has already been used
    error TanssiMetaMiddleware__KeyAlreadyUsed();
    /// @notice Thrown when attempting to store rewards for an operator that already has rewards stored
    error TanssiMetaMiddleware__OperatorRewardAlreadyStored(uint48 eraIndex, address operator);
    /// @notice Thrown when attempting to register a middleware that is already registered
    error TanssiMetaMiddleware__MiddlewareAlreadyRegistered();
    /// @notice Thrown when the distribution status is not in the expected state for the operation
    error TanssiMetaMiddleware__UnexpectedDistributionStatus();
    /// @notice Thrown when the era index does not match the expected sequential order
    error TanssiMetaMiddleware__UnexpectedEraIndex();
    /// @notice Thrown when an operator is associated with a different middleware than expected
    error TanssiMetaMiddleware__UnexpectedMiddleware();
    /// @notice Thrown when attempting to use a middleware that is not registered
    error TanssiMetaMiddleware__UnknownMiddleware();

    event CollateralRegistered(address indexed collateral, address indexed oracle);
    event OperatorRegistered(address indexed operator, address indexed middleware);
    event OperatorKeySet(address indexed operator, bytes32 newKey);

    // ---------------------- External ----------------------

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
     * @param oracle The address of the price oracle for the collateral
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
     * @notice Stores operator rewards by verifying Merkle proofs for a specific era
     * @param eraIndex The era index for which to store rewards
     * @param operatorRewardsAndProofs Array of operator rewards with their Merkle proofs
     * @dev This function verifies Merkle proofs and stores the rewards. If all points are stored,
     *      it automatically transfers rewards to middlewares
     */
    function storeRewards(uint48 eraIndex, OperatorRewardWithProof[] memory operatorRewardsAndProofs) external;

    /**
     * @notice Trustlessly distributes rewards to a middleware for a specific era.
     * @param eraIndex    The era index for which to distribute rewards.
     * @param middleware  The middleware address to distribute rewards to.
     * @dev Only callable for a known middleware.
     * @dev Requires that distribution status is PENDING.
     * @dev Reverts if distribution cannot be completed in a single call.
     * @dev This operation is significantly more expensive than trustingly distributed rewards,
     *      since it requires all rewards for each operator to be stored beforehand and prepares
     *      distribution data within this call.
     */
    function distributeRewardsToMiddlewareTrustlessly(uint48 eraIndex, address middleware) external;

    /**
     * @notice Trustingly distributes rewards to a middleware, used by automation systems
     * @param eraIndex The era index for which to distribute rewards
     * @param middleware The middleware address to distribute rewards to
     * @param totalAmount The total amount of rewards to distribute
     * @param rewardsDistributionData Encoded data containing the rewards distribution information
     * @dev Only callable by addresses with AUTOMATION_ROLE on known middlewares
     * @dev This function trusts the provided data and does not verify Merkle proofs
     * @dev Transfers rewards to middleware if not already transferred
     */
    function distributeRewardsToMiddlewareTrustingly(
        uint48 eraIndex,
        address middleware,
        uint256 totalAmount,
        bytes memory rewardsDistributionData
    ) external;

    // ---------------------- External View ----------------------

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
     * @dev The rewards are only cached via storeRewards method, which is not used on the trustingly distributed rewards.
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

    /**
     * @notice Retrieves the operator address associated with a given key
     * @param key The operator key to look up
     * @return operator The address of the operator associated with the key, or address(0) if not found
     */
    function keyToOperator(
        bytes32 key
    ) external view returns (address operator);

    /**
     * @notice Checks if a middleware is registered with the meta middleware
     * @param middleware The middleware address to check
     * @return True if the middleware is registered, false otherwise
     */
    function isMiddlewareRegistered(
        address middleware
    ) external view returns (bool);

    /**
     * @notice Retrieves all era indices associated with a specific epoch
     * @param epoch The epoch number to query
     * @return eraIndexes Array of era indices that belong to the specified epoch
     */
    function getEraIndexesPerEpoch(
        uint48 epoch
    ) external view returns (uint48[] memory eraIndexes);

    /**
     * @notice Checks if rewards for a specific era have been transferred to middlewares
     * @param eraIndex The era index to check
     * @return eraTransferred True if rewards have been transferred, false otherwise
     */
    function getEraTransferred(
        uint48 eraIndex
    ) external view returns (bool eraTransferred);

    /**
     * @notice Retrieves the most recent era index for which rewards were received from the gateway
     * @return lastReceivedEraIndex The last received era index
     */
    function getLastReceivedEraIndex() external view returns (uint48 lastReceivedEraIndex);

    /**
     * @notice Retrieves the most recent era index for which all rewards have been distributed
     * @return lastDistributedEraIndex The last distributed era index
     */
    function getLastDistributedEraIndex() external view returns (uint48 lastDistributedEraIndex);

    /**
     * @notice Retrieves the distribution status for a specific era and middleware
     * @param eraIndex The era index to query
     * @param middleware The middleware address to query
     * @return status The current distribution status (PENDING, IN_PROGRESS, or DISTRIBUTED)
     */
    function getDistributionStatusPerEraIndexPerMiddleware(
        uint48 eraIndex,
        address middleware
    ) external view returns (DistributionStatus status);

    /**
     * @notice Retrieves the total points stored for a specific era and middleware
     * @param eraIndex The era index to query
     * @param middleware The middleware address to query
     * @return pointsStored The total points stored for the era and middleware combination
     * @dev The points are only stored via storeRewards method, which is not used on the trustingly distributed rewards.
     */
    function getPointsStoredPerEraIndexPerMiddleware(
        uint48 eraIndex,
        address middleware
    ) external view returns (uint256 pointsStored);

    /**
     * @notice Prepares rewards distribution data for a middleware based on operator rewards with proofs
     * @param eraIndex The era index for which to prepare distribution data
     * @param middleware The middleware address to prepare distribution data for
     * @param operatorRewardsAndProofs Array of operator rewards with their Merkle proofs
     * @return rewardsDistributionData Encoded data containing the rewards distribution information
     * @return totalAmount The total amount of rewards to be distributed
     * @dev This function verifies proofs and prepares distribution data without storing rewards
     * @dev The actual rewards distribution data is prepared by each middleware itself, in an arbitrary encoding that it is then passed to the distributeRewardsToMiddlewareTrustingly call.
     */
    function prepareRewardsDistributionData(
        uint48 eraIndex,
        address middleware,
        OperatorRewardWithProof[] memory operatorRewardsAndProofs
    ) external view returns (bytes memory rewardsDistributionData, uint256 totalAmount);
}
