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

/// ----------------------------- OPENZEPPELIN -----------------------------
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// ----------------------------- CHAINLINK -----------------------------
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV3Interface.sol";

/// ----------------------------- TANSSI -----------------------------
import {ITanssiCommonMiddleware} from "../interfaces/ITanssiCommonMiddleware.sol";
import {ITanssiMetaMiddleware} from "../interfaces/ITanssiMetaMiddleware.sol";

/**
 * @title TanssiMetaMiddleware
 * @notice Middleware for aggregating multiple middleware instances and managing rewards distribution, slashing and sorting operators by power
 * @dev This contract acts as a meta middleware that coordinates between multiple middleware instances,
 *      manages operator registration, collateral oracles, and handles rewards distribution across eras
 */
contract TanssiMetaMiddleware is AccessControlUpgradeable, UUPSUpgradeable, ITanssiMetaMiddleware {
    using Math for uint256;

    /// @notice Role that allows calling gateway functions like distributeRewards and slash
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    /// @notice Role that allows automation systems to distribute rewards trustingly
    bytes32 public constant AUTOMATION_ROLE = keccak256("AUTOMATION_ROLE");

    /// @custom:storage-location erc7201:tanssi-meta-middleware.storage.TanssiMetaMiddlewareStorage.v1
    /// @notice Storage structure for middleware, operator, and collateral management
    /// @param usedKeys Mapping of operator keys to whether they have been used
    /// @param keyToOperator Mapping of operator keys to operator addresses
    /// @param operatorToMiddleware Mapping of operator addresses to their associated middleware
    /// @param collateralToOracle Mapping of collateral token addresses to their price oracle addresses
    /// @param knownMiddlewares Mapping of middleware addresses to whether they are registered
    /// @param middlewares Array of all registered middleware addresses
    struct TanssiMetaMiddlewareStorage {
        mapping(bytes32 key => bool used) usedKeys;
        mapping(bytes32 key => address operator) keyToOperator;
        mapping(address operator => address middleware) operatorToMiddleware;
        mapping(address collateral => address oracle) collateralToOracle;
        mapping(address middleware => bool known) knownMiddlewares;
        address[] middlewares;
    }

    /// @custom:storage-location erc7201:tanssi-meta-middleware.storage.TanssiMetaMiddlewareRewardsStorage.v1
    /// @notice Storage structure for rewards distribution tracking
    /// @param lastReceivedEraIndex The most recent era index for which rewards were received from the gateway
    /// @param lastDistributedEraIndex The most recent era index for which all rewards have been distributed
    /// @param eraRoot Mapping of era indices to their era root data
    /// @param eraIndexesPerEpoch Mapping of epochs to arrays of era indices within that epoch
    /// @param operatorRewardsPerIndexPerMiddlewarePerOperator Mapping of era index -> middleware -> operator -> reward amount
    /// @param distributionStatusPerEraIndexPerMiddleware Mapping of era index -> middleware -> distribution status
    /// @param pointsStoredPerEraIndexPerMiddleware Mapping of era index -> middleware -> total points stored
    /// @param eraTransferred Mapping of era indices to whether rewards have been transferred to middlewares
    /// @param totalRewardsReceived Total amount of rewards received from the gateway across all eras
    /// @param totalRewardsTransferred Total amount of rewards distributed to the middlewares across all eras
    struct TanssiMetaMiddlewareRewardsStorage {
        uint48 lastReceivedEraIndex;
        uint48 lastDistributedEraIndex;
        mapping(uint48 eraIndex => EraRoot eraRoot) eraRoot;
        mapping(uint48 epoch => uint48[] eraIndexes) eraIndexesPerEpoch;
        mapping(uint48 eraIndex => mapping(address middleware => mapping(address operator => uint256 rewardAmount)))
            operatorRewardsPerIndexPerMiddlewarePerOperator;
        mapping(uint48 eraIndex => mapping(address middleware => DistributionStatus status))
            distributionStatusPerEraIndexPerMiddleware;
        mapping(uint48 eraIndex => mapping(address middleware => uint256 rewards)) pointsStoredPerEraIndexPerMiddleware;
        mapping(uint48 eraIndex => bool eraTransferred) eraTransferred;
        uint256 totalRewardsReceived; // Total amount of rewards received from the gateway
        uint256 totalRewardsTransferred; // Total amount of rewards distributed to the middlewares
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi-meta-middleware.storage.TanssiMetaMiddlewareStorage.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TanssiMetaMiddlewareStorageLocation =
        0xba564c59da0b4154dce76e3aea90aa62b630a2789bd79824e75960236433fd00;

    // keccak256(abi.encode(uint256(keccak256("tanssi-meta-middleware.storage.TanssiMetaMiddlewareRewardsStorage.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TanssiMetaMiddlewareRewardsStorageLocation =
        0x54a3f29c5fa45fe2d6fd3fc47f629c8d05757edae5a867d838093af1389d7500;

    /**
     * @notice Modifier that ensures the middleware address is registered
     * @param middleware The middleware address to check
     * @dev Reverts if the middleware is not registered
     */
    modifier onlyKnownMiddleware(
        address middleware
    ) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require($.knownMiddlewares[middleware], TanssiMetaMiddleware__UnknownMiddleware());
        _;
    }

    /**
     * @notice Constructor that disables initializers to prevent initialization of the implementation contract
     * @dev This ensures the implementation contract cannot be initialized directly
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with an admin address
     * @param admin The address that will receive the DEFAULT_ADMIN_ROLE
     * @dev This function should be called during proxy deployment
     */
    function initialize(
        address admin
    ) external initializer {
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function registerMiddleware(
        address middleware
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require(!$.knownMiddlewares[middleware], TanssiMetaMiddleware__MiddlewareAlreadyRegistered());

        $.knownMiddlewares[middleware] = true;
        $.middlewares.push(middleware);
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function registerOperator(address operator, bytes32 key) external onlyKnownMiddleware(msg.sender) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();

        $.operatorToMiddleware[operator] = msg.sender;
        _setOperatorKey(operator, key);

        emit OperatorRegistered(operator, msg.sender);
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function updateOperatorKey(address operator, bytes32 newKey) external onlyKnownMiddleware(msg.sender) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require($.operatorToMiddleware[operator] == msg.sender, TanssiMetaMiddleware__UnexpectedMiddleware());

        _setOperatorKey(operator, newKey);
    }

    /**
     * @notice Retrieves the operator address associated with a given key
     * @param key The operator key to look up
     * @return operator The address of the operator associated with the key, or address(0) if not found
     */
    function keyToOperator(
        bytes32 key
    ) external view returns (address operator) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        operator = $.keyToOperator[key];
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function registerCollateral(address collateral, address oracle) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require($.collateralToOracle[collateral] == address(0), TanssiMetaMiddleware__CollateralAlreadyRegistered());

        $.collateralToOracle[collateral] = oracle;
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function distributeRewards(
        uint48 epoch,
        uint48 eraIndex,
        uint256 totalPoints,
        uint256 totalAmount,
        bytes32 root,
        address tokenAddress
    ) external onlyRole(GATEWAY_ROLE) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        require($r.lastReceivedEraIndex + 1 == eraIndex, TanssiMetaMiddleware__UnexpectedEraIndex());

        require(
            totalAmount + $r.totalRewardsReceived
                == IERC20(tokenAddress).balanceOf(address(this)) + $r.totalRewardsTransferred,
            TanssiMetaMiddleware__InsufficientRewardsReceived()
        );

        EraRoot memory eraRoot = EraRoot({
            epoch: epoch,
            totalAmount: totalAmount,
            // We need to calculate how much each point is worth in tokens
            totalPoints: totalPoints,
            root: root,
            tokenAddress: tokenAddress
        });
        $r.eraRoot[eraIndex] = eraRoot;
        $r.eraIndexesPerEpoch[epoch].push(eraIndex);

        $r.lastReceivedEraIndex = eraIndex;
        $r.totalRewardsReceived += totalAmount;
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function isValidCollateral(
        address collateral
    ) external view returns (bool) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        return $.collateralToOracle[collateral] != address(0);
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function getTokensData(
        address[] memory collaterals
    ) external view returns (TokenData[] memory) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();

        TokenData[] memory tokensData = new TokenData[](collaterals.length);
        for (uint256 i; i < collaterals.length;) {
            AggregatorV3Interface oracle = AggregatorV3Interface($.collateralToOracle[collaterals[i]]);
            (, int256 price,,,) = oracle.latestRoundData();
            uint8 priceDecimals = oracle.decimals();
            IERC20Metadata token = IERC20Metadata(collaterals[i]);
            uint8 tokenDecimals = token.decimals();

            tokensData[i] = TokenData({price: price, priceDecimals: priceDecimals, tokenDecimals: tokenDecimals});
            unchecked {
                ++i;
            }
        }
        return tokensData;
    }

    /**
     * @notice Checks if a middleware is registered with the meta middleware
     * @param middleware The middleware address to check
     * @return True if the middleware is registered, false otherwise
     */
    function isMiddlewareRegistered(
        address middleware
    ) external view returns (bool) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        return $.knownMiddlewares[middleware];
    }

    /**
     * @notice Retrieves the cached reward amounts for specific operators in a given era and middleware
     * @param eraIndex The era index to query
     * @param middleware The middleware address to query
     * @param operators Array of operator addresses to get rewards for
     * @return operatorRewards Array of reward amounts corresponding to each operator
     * @dev The rewards are only cached via storeRewards method, which is no used on the trustingly distributed rewards.
     */
    function getOperatorsRewards(
        uint48 eraIndex,
        address middleware,
        address[] memory operators
    ) external view returns (uint256[] memory operatorRewards) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();

        uint256 totalOperators = operators.length;
        operatorRewards = new uint256[](totalOperators);
        for (uint256 i; i < totalOperators;) {
            operatorRewards[i] = $r.operatorRewardsPerIndexPerMiddlewarePerOperator[eraIndex][middleware][operators[i]];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Retrieves the era root data for a specific era index
     * @param eraIndex The era index to query
     * @return eraRoot EraRoot struct containing epoch, total amount, total points, root, and token address
     */
    function getEraRoot(
        uint48 eraIndex
    ) external view returns (EraRoot memory eraRoot) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        eraRoot = $r.eraRoot[eraIndex];
    }

    /**
     * @notice Retrieves all era indices associated with a specific epoch
     * @param epoch The epoch number to query
     * @return eraIndexes Array of era indices that belong to the specified epoch
     */
    function getEraIndexesPerEpoch(
        uint48 epoch
    ) external view returns (uint48[] memory eraIndexes) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        eraIndexes = $r.eraIndexesPerEpoch[epoch];
    }

    /**
     * @notice Checks if rewards for a specific era have been transferred to middlewares
     * @param eraIndex The era index to check
     * @return eraTransferred True if rewards have been transferred, false otherwise
     */
    function getEraTransferred(
        uint48 eraIndex
    ) external view returns (bool eraTransferred) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        eraTransferred = $r.eraTransferred[eraIndex];
    }

    /**
     * @notice Retrieves the most recent era index for which rewards were received from the gateway
     * @return lastReceivedEraIndex The last received era index
     */
    function getLastReceivedEraIndex() external view returns (uint48 lastReceivedEraIndex) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        lastReceivedEraIndex = $r.lastReceivedEraIndex;
    }

    /**
     * @notice Retrieves the most recent era index for which all rewards have been distributed
     * @return lastDistributedEraIndex The last distributed era index
     */
    function getLastDistributedEraIndex() external view returns (uint48 lastDistributedEraIndex) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        lastDistributedEraIndex = $r.lastDistributedEraIndex;
    }

    /**
     * @notice Retrieves the distribution status for a specific era and middleware
     * @param eraIndex The era index to query
     * @param middleware The middleware address to query
     * @return status The current distribution status (PENDING, IN_PROGRESS, or DISTRIBUTED)
     */
    function getDistributionStatusPerEraIndexPerMiddleware(
        uint48 eraIndex,
        address middleware
    ) external view returns (DistributionStatus status) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        status = $r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware];
    }

    /**
     * @notice Retrieves the total points stored for a specific era and middleware
     * @param eraIndex The era index to query
     * @param middleware The middleware address to query
     * @return pointsStored The total points stored for the era and middleware combination
     */
    function getPointsStoredPerEraIndexPerMiddleware(
        uint48 eraIndex,
        address middleware
    ) external view returns (uint256 pointsStored) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        pointsStored = $r.pointsStoredPerEraIndexPerMiddleware[eraIndex][middleware];
    }

    /**
     * @notice Stores operator rewards by verifying Merkle proofs for a specific era
     * @param eraIndex The era index for which to store rewards
     * @param operatorRewardsAndProofs Array of operator rewards with their Merkle proofs
     * @dev This function verifies Merkle proofs and stores the rewards. If all points are stored,
     *      it automatically transfers rewards to middlewares
     */
    function storeRewards(uint48 eraIndex, OperatorRewardWithProof[] memory operatorRewardsAndProofs) external {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        EraRoot memory eraRoot = _loadAndVerifyEraRoot($r, eraIndex);

        _storeRewards($r, eraIndex, eraRoot, operatorRewardsAndProofs);
        _transferRewardsIfAllStored($r, eraIndex, eraRoot);
    }

    /**
     * @notice Prepares rewards distribution data for a middleware based on operator rewards with proofs
     * @param eraIndex The era index for which to prepare distribution data
     * @param middleware The middleware address to prepare distribution data for
     * @param operatorRewardsAndProofs Array of operator rewards with their Merkle proofs
     * @return rewardsDistributionData Encoded data containing the rewards distribution information
     * @return totalAmount The total amount of rewards to be distributed
     * @dev This function verifies proofs and prepares distribution data without storing rewards
     * @dev The actual rewards distribution data is prepared by the middleware itself, in an arbitrary encoding that it can use on   the distributeRewardsToMiddlewareTrustingly call.
     */
    function prepareRewardsDistributionData(
        uint48 eraIndex,
        address middleware,
        OperatorRewardWithProof[] memory operatorRewardsAndProofs
    ) external view returns (bytes memory rewardsDistributionData, uint256 totalAmount) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        EraRoot memory eraRoot = _loadAndVerifyEraRoot($r, eraIndex);

        uint256 totalOperators = operatorRewardsAndProofs.length;
        ITanssiMetaMiddleware.OperatorReward[] memory operatorRewards =
            new ITanssiMetaMiddleware.OperatorReward[](totalOperators);
        for (uint256 i; i < totalOperators;) {
            OperatorRewardWithProof memory operatorRewardAndProof = operatorRewardsAndProofs[i];
            operatorRewards[i] = _verifyProofAndGetOperatorRewards(eraRoot, operatorRewardAndProof);
            require(
                $.operatorToMiddleware[operatorRewards[i].operator] == middleware,
                TanssiMetaMiddleware__UnexpectedMiddleware()
            );
            totalAmount += operatorRewards[i].rewardAmount;
            unchecked {
                ++i;
            }
        }

        rewardsDistributionData = ITanssiCommonMiddleware(middleware).prepareRewardsDistributionDataFromOperatorRewards(
            eraIndex, eraRoot.tokenAddress, operatorRewards
        );
    }

    /**
     * @notice Manually distributes rewards to a middleware for a specific era
     * @param eraIndex The era index for which to distribute rewards
     * @param middleware The middleware address to distribute rewards to
     * @dev Only callable for a known middleware
     * @dev Requires that distribution status is PENDING
     * @dev Reverts if distribution cannot be completed in a single call
     */
    function distributeRewardsToMiddlewareManually(
        uint48 eraIndex,
        address middleware
    ) external onlyKnownMiddleware(middleware) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        EraRoot memory eraRoot = _loadAndVerifyEraRoot($r, eraIndex);

        DistributionStatus currentStatus = $r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware];

        // Cannot distribute if distrubution is in progress (by automation in batches) or already distributed
        require(currentStatus == DistributionStatus.PENDING, TanssiMetaMiddleware__UnexpectedDistributionStatus());

        bytes memory rewardsDistributionData =
            ITanssiCommonMiddleware(middleware).prepareRewardsDistributionData(eraIndex, eraRoot.tokenAddress);

        bool distributionComplete =
            _distributeRewardsToMiddleware(eraIndex, middleware, eraRoot, currentStatus, rewardsDistributionData);

        if (!distributionComplete) {
            revert TanssiMetaMiddleware__CouldNotDistributeRewardsInASingleCall();
        }
    }

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
    ) external onlyKnownMiddleware(middleware) onlyRole(AUTOMATION_ROLE) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        EraRoot memory eraRoot = _loadAndVerifyEraRoot($r, eraIndex);

        DistributionStatus currentStatus = $r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware];

        require(currentStatus != DistributionStatus.DISTRIBUTED, TanssiMetaMiddleware__UnexpectedDistributionStatus());

        if (!$r.eraTransferred[eraIndex]) {
            IERC20(eraRoot.tokenAddress).approve(middleware, totalAmount);
            ITanssiCommonMiddleware(middleware).transferRewards(eraIndex, eraRoot.tokenAddress, totalAmount);
            $r.eraTransferred[eraIndex] = true;
        }

        _distributeRewardsToMiddleware(eraIndex, middleware, eraRoot, currentStatus, rewardsDistributionData);
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function slash(uint48 epoch, bytes32 operatorKey, uint256 percentage) external onlyRole(GATEWAY_ROLE) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        address operator = $.keyToOperator[operatorKey];
        address middleware = $.operatorToMiddleware[operator];
        require(middleware != address(0), TanssiMetaMiddleware__UnexpectedMiddleware());

        ITanssiCommonMiddleware(middleware).slash(epoch, operator, percentage);
    }

    /**
     * @notice Internal function to distribute rewards to a middleware
     * @param eraIndex The era index for which to distribute rewards
     * @param middleware The middleware address to distribute rewards to
     * @param eraRoot The era root data containing reward information
     * @param currentStatus The current distribution status before this call
     * @param rewardsDistributionData Encoded data containing the rewards distribution information
     * @return distributionComplete True if all rewards were distributed, false if distribution needs to continue
     * @dev Updates distribution status and emits RewardsDistributed event
     */
    function _distributeRewardsToMiddleware(
        uint48 eraIndex,
        address middleware,
        EraRoot memory eraRoot,
        DistributionStatus currentStatus,
        bytes memory rewardsDistributionData
    ) internal returns (bool distributionComplete) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();

        distributionComplete = ITanssiCommonMiddleware(middleware).distributeRewards(
            eraIndex, eraRoot.tokenAddress, rewardsDistributionData
        );

        if (distributionComplete) {
            $r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware] = DistributionStatus.DISTRIBUTED;
        } else if (currentStatus == DistributionStatus.PENDING) {
            $r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware] = DistributionStatus.IN_PROGRESS;
        }

        _updateLastDistributedEraIndex($r, eraIndex);
        emit RewardsDistributed(middleware, eraIndex, distributionComplete);
    }

    /**
     * @notice Loads and verifies that an era root exists for the given era index
     * @param $r Reference to the rewards storage
     * @param eraIndex The era index to load
     * @return eraRoot The era root data
     * @dev Reverts if the era root has not been set
     */
    function _loadAndVerifyEraRoot(
        TanssiMetaMiddlewareRewardsStorage storage $r,
        uint48 eraIndex
    ) internal view returns (EraRoot memory eraRoot) {
        eraRoot = $r.eraRoot[eraIndex];

        require(eraRoot.epoch != 0, TanssiMetaMiddleware__EraRootNotSet());
    }

    /**
     * @notice Stores operator rewards after verifying Merkle proofs
     * @param $r Reference to the rewards storage
     * @param eraIndex The era index for which to store rewards
     * @param eraRoot The era root data containing the Merkle root
     * @param operatorRewardsAndProofs Array of operator rewards with their Merkle proofs
     * @dev Verifies each proof and stores the reward amounts per operator per middleware
     * @dev Reverts if the era has already been transferred (distribution in progress)
     */
    function _storeRewards(
        TanssiMetaMiddlewareRewardsStorage storage $r,
        uint48 eraIndex,
        EraRoot memory eraRoot,
        OperatorRewardWithProof[] memory operatorRewardsAndProofs
    ) internal {
        // If the era has already been transferred, distribution is in progress and we cannot know if it was already partially distributed so we need to revert.
        require(!$r.eraTransferred[eraIndex], TanssiMetaMiddleware__UnexpectedDistributionStatus());

        uint256 totalOperators = operatorRewardsAndProofs.length;
        uint256 totalPointsProcessed;
        for (uint256 i; i < totalOperators;) {
            OperatorRewardWithProof memory operatorRewardAndProof = operatorRewardsAndProofs[i];
            _verifyProofAndStoreReward($r, eraIndex, eraRoot, operatorRewardAndProof);
            totalPointsProcessed += operatorRewardAndProof.totalPoints;
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Verifies a Merkle proof and stores the operator reward
     * @param $r Reference to the rewards storage
     * @param eraIndex The era index for which to store the reward
     * @param eraRoot The era root data containing the Merkle root
     * @param operatorRewardAndProof The operator reward with its Merkle proof
     * @dev Skips storage if totalPoints is zero
     * @dev Updates operator rewards and points stored per middleware
     */
    function _verifyProofAndStoreReward(
        TanssiMetaMiddlewareRewardsStorage storage $r,
        uint48 eraIndex,
        EraRoot memory eraRoot,
        OperatorRewardWithProof memory operatorRewardAndProof
    ) internal {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();

        uint32 totalPoints = operatorRewardAndProof.totalPoints;
        if (totalPoints == 0) {
            return;
        }

        OperatorReward memory operatorReward = _verifyProofAndGetOperatorRewards(eraRoot, operatorRewardAndProof);
        address middleware = $.operatorToMiddleware[operatorReward.operator];

        $r.operatorRewardsPerIndexPerMiddlewarePerOperator[eraIndex][middleware][operatorReward.operator] =
            operatorReward.rewardAmount;
        $r.pointsStoredPerEraIndexPerMiddleware[eraIndex][middleware] += totalPoints;
    }

    /**
     * @notice Verifies a Merkle proof and calculates the operator reward amount
     * @param eraRoot The era root data containing the Merkle root and total amounts
     * @param operatorRewardAndProof The operator reward with its Merkle proof
     * @return operatorReward The calculated operator reward with operator address and amount
     * @dev Reverts if the Merkle proof is invalid
     * @dev Calculates reward amount based on operator's points relative to total points
     */
    function _verifyProofAndGetOperatorRewards(
        EraRoot memory eraRoot,
        OperatorRewardWithProof memory operatorRewardAndProof
    ) internal view returns (OperatorReward memory operatorReward) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();

        bytes32 operatorKey = operatorRewardAndProof.operatorKey;
        uint32 totalPoints = operatorRewardAndProof.totalPoints;

        require(
            MerkleProof.verify(
                operatorRewardAndProof.proof,
                eraRoot.root,
                keccak256(abi.encodePacked(operatorKey, _encodeU32(totalPoints)))
            ),
            TanssiMetaMiddleware__InvalidProof()
        );

        operatorReward = OperatorReward({
            operator: $.keyToOperator[operatorKey],
            rewardAmount: eraRoot.totalAmount.mulDiv(totalPoints, eraRoot.totalPoints)
        });
    }

    /**
     * @notice Transfers rewards to middlewares if all points for an era have been stored
     * @param $r Reference to the rewards storage
     * @param eraIndex The era index to check and transfer rewards for
     * @param eraRoot The era root data containing total points and token address
     * @dev Checks if total stored points equals total points, then transfers proportional rewards to each middleware
     * @dev Emits RewardsTransferred event for each middleware
     */
    function _transferRewardsIfAllStored(
        TanssiMetaMiddlewareRewardsStorage storage $r,
        uint48 eraIndex,
        EraRoot memory eraRoot
    ) internal {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();

        address[] memory middlewares = $.middlewares;
        uint256 totalStoredPoints;
        for (uint256 i; i < middlewares.length;) {
            address middleware = middlewares[i];
            totalStoredPoints += $r.pointsStoredPerEraIndexPerMiddleware[eraIndex][middleware];
            unchecked {
                ++i;
            }
        }
        if (totalStoredPoints == eraRoot.totalPoints) {
            for (uint256 i; i < middlewares.length;) {
                address middleware = middlewares[i];
                uint256 totalPointsForEraAndMiddleware = $r.pointsStoredPerEraIndexPerMiddleware[eraIndex][middleware];
                uint256 totalRewardsForEraAndMiddleware =
                    eraRoot.totalAmount.mulDiv(totalPointsForEraAndMiddleware, eraRoot.totalPoints);

                IERC20(eraRoot.tokenAddress).approve(middleware, totalRewardsForEraAndMiddleware);
                ITanssiCommonMiddleware(middleware).transferRewards(
                    eraIndex, eraRoot.tokenAddress, totalRewardsForEraAndMiddleware
                );

                unchecked {
                    $r.totalRewardsTransferred += totalRewardsForEraAndMiddleware;
                    ++i;
                }

                emit RewardsTransferred(middleware, eraIndex, totalRewardsForEraAndMiddleware);
            }

            $r.eraTransferred[eraIndex] = true;
        }
    }

    /**
     * @notice Updates the last distributed era index if all middlewares have completed distribution
     * @param $r Reference to the rewards storage
     * @param eraIndex The era index that was just processed
     * @dev Checks if all middlewares have DISTRIBUTED status for this era, then updates lastDistributedEraIndex
     */
    function _updateLastDistributedEraIndex(TanssiMetaMiddlewareRewardsStorage storage $r, uint48 eraIndex) internal {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        address[] memory middlewares = $.middlewares;
        bool allDistributed = true;
        for (uint256 i; i < middlewares.length;) {
            address middleware = middlewares[i];
            if ($r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware] != DistributionStatus.DISTRIBUTED) {
                allDistributed = false;
                break;
            }
            unchecked {
                ++i;
            }
        }
        if (allDistributed) {
            $r.lastDistributedEraIndex = eraIndex;
        }
    }

    /**
     * @notice Sets a new operator key for an operator
     * @param operator The operator address
     * @param newKey The new unique key to associate with the operator
     * @dev Reverts if the key has already been used
     * @dev Emits OperatorKeySet event
     */
    function _setOperatorKey(address operator, bytes32 newKey) internal {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require(!$.usedKeys[newKey], TanssiMetaMiddleware__KeyAlreadyUsed());

        $.usedKeys[newKey] = true;
        $.keyToOperator[newKey] = operator;

        emit OperatorKeySet(operator, newKey);
    }

    /**
     * @notice Retrieves the storage slot for TanssiMetaMiddlewareStorage
     * @return $ Reference to the storage struct at the ERC-7201 storage location
     * @dev Uses assembly to access the storage slot defined by ERC-7201
     */
    function _getTanssiMetaMiddlewareStorage() internal pure returns (TanssiMetaMiddlewareStorage storage $) {
        assembly {
            $.slot := TanssiMetaMiddlewareStorageLocation
        }
    }

    /**
     * @notice Retrieves the storage slot for TanssiMetaMiddlewareRewardsStorage
     * @return $ Reference to the rewards storage struct at the ERC-7201 storage location
     * @dev Uses assembly to access the storage slot defined by ERC-7201
     */
    function _getTanssiMetaMiddlewareRewardsStorage()
        internal
        pure
        returns (TanssiMetaMiddlewareRewardsStorage storage $)
    {
        assembly {
            $.slot := TanssiMetaMiddlewareRewardsStorageLocation
        }
    }

    /**
     * @notice Reverses the byte order of a 32-bit unsigned integer
     * @param input The 32-bit value to reverse
     * @return v The reversed 32-bit value
     * @dev Taken from Snowbridge's ScaleCodec.sol. Used for encoding SCALE-encoded data.
     */
    // Taken from Snowbridge's ScaleCodec.sol. The original solidity version is not compatible with this project.
    function _reverse32(
        uint32 input
    ) internal pure returns (uint32 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);

        // swap 2-byte long pairs
        v = (v >> 16) | (v << 16);
    }

    /**
     * @notice Encodes a 32-bit unsigned integer as SCALE-encoded bytes
     * @param input The 32-bit value to encode
     * @return The SCALE-encoded bytes4 representation
     * @dev Taken from Snowbridge's ScaleCodec.sol. Used for Merkle proof verification.
     */
    // Taken from Snowbridge's ScaleCodec.sol. The original solidity version is not compatible with this project.
    function _encodeU32(
        uint32 input
    ) internal pure returns (bytes4) {
        return bytes4(_reverse32(input));
    }

    /**
     * @notice Authorizes an upgrade to a new implementation
     * @param newImplementation The address of the new implementation contract
     * @dev Only callable by addresses with DEFAULT_ADMIN_ROLE
     * @dev Required by UUPSUpgradeable pattern
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
