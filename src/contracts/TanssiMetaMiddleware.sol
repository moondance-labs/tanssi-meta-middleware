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
 * @notice Middleware for aggregating multiple middleware
 */
contract TanssiMetaMiddleware is AccessControlUpgradeable, UUPSUpgradeable, ITanssiMetaMiddleware {
    using Math for uint256;

    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    bytes32 public constant AUTOMATION_ROLE = keccak256("AUTOMATION_ROLE");

    /// @custom:storage-location erc7201:tanssi-meta-middleware.storage.TanssiMetaMiddlewareStorage.v1
    struct TanssiMetaMiddlewareStorage {
        mapping(bytes32 key => bool used) usedKeys;
        mapping(bytes32 key => address operator) keyToOperator;
        mapping(address operator => address middleware) operatorToMiddleware;
        mapping(address collateral => address oracle) collateralToOracle;
        mapping(address middleware => bool known) knownMiddlewares;
        address[] middlewares;
    }

    /// @custom:storage-location erc7201:tanssi-meta-middleware.storage.TanssiMetaMiddlewareRewardsStorage.v1
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

    modifier onlyKnownMiddleware(
        address middleware
    ) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require($.knownMiddlewares[middleware], TanssiMetaMiddleware__UnknownMiddleware());
        _;
    }

    constructor() {
        _disableInitializers();
    }

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

        _registerOperator($, operator, key, msg.sender);
    }

    /**
     * @dev Method to migrate operators which already belong to a middleware when metamiddelware is introduced.
     * @dev It can be removed once the migration is complete.
     * @param operators The addresses of the operators to migrate
     * @param keys The keys of the operators to migrate
     * @param middleware The middleware to migrate the operators to
     */
    function migrateOperators(
        address[] calldata operators,
        bytes32[] memory keys,
        address middleware
    ) external onlyRole(DEFAULT_ADMIN_ROLE) onlyKnownMiddleware(middleware) {
        uint256 totalOperators = operators.length;
        require(keys.length == totalOperators, TanssiMetaMiddleware__InvalidKeysLength());

        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        for (uint256 i; i < totalOperators;) {
            _registerOperator($, operators[i], keys[i], middleware);
            unchecked {
                ++i;
            }
        }
    }

    function _registerOperator(
        TanssiMetaMiddlewareStorage storage $,
        address operator,
        bytes32 key,
        address middleware
    ) private {
        $.operatorToMiddleware[operator] = middleware;
        _setOperatorKey(operator, key);

        emit OperatorRegistered(operator, middleware);
    }

    /**
     * @inheritdoc ITanssiMetaMiddleware
     */
    function updateOperatorKey(address operator, bytes32 newKey) external onlyKnownMiddleware(msg.sender) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require($.operatorToMiddleware[operator] == msg.sender, TanssiMetaMiddleware__UnexpectedMiddleware());

        _setOperatorKey(operator, newKey);
    }

    function keyToOperator(
        bytes32 key
    ) external view returns (address operator) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        operator = $.keyToOperator[key];
    }

    function operatorToMiddleware(
        address operator
    ) external view returns (address middleware) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        middleware = $.operatorToMiddleware[operator];
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

    function isMiddlewareRegistered(
        address middleware
    ) external view returns (bool) {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        return $.knownMiddlewares[middleware];
    }

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

    function getEraRoot(
        uint48 eraIndex
    ) external view returns (EraRoot memory eraRoot) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        eraRoot = $r.eraRoot[eraIndex];
    }

    function getEraIndexesPerEpoch(
        uint48 epoch
    ) external view returns (uint48[] memory eraIndexes) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        eraIndexes = $r.eraIndexesPerEpoch[epoch];
    }

    function getEraTransferred(
        uint48 eraIndex
    ) external view returns (bool eraTransferred) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        eraTransferred = $r.eraTransferred[eraIndex];
    }

    function getLastReceivedEraIndex() external view returns (uint48 lastReceivedEraIndex) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        lastReceivedEraIndex = $r.lastReceivedEraIndex;
    }

    function getLastDistributedEraIndex() external view returns (uint48 lastDistributedEraIndex) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        lastDistributedEraIndex = $r.lastDistributedEraIndex;
    }

    function getDistributionStatusPerEraIndexPerMiddleware(
        uint48 eraIndex,
        address middleware
    ) external view returns (DistributionStatus status) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        status = $r.distributionStatusPerEraIndexPerMiddleware[eraIndex][middleware];
    }

    function getPointsStoredPerEraIndexPerMiddleware(
        uint48 eraIndex,
        address middleware
    ) external view returns (uint256 pointsStored) {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        pointsStored = $r.pointsStoredPerEraIndexPerMiddleware[eraIndex][middleware];
    }

    function storeRewards(uint48 eraIndex, OperatorRewardWithProof[] memory operatorRewardsAndProofs) external {
        TanssiMetaMiddlewareRewardsStorage storage $r = _getTanssiMetaMiddlewareRewardsStorage();
        EraRoot memory eraRoot = _loadAndVerifyEraRoot($r, eraIndex);

        _storeRewards($r, eraIndex, eraRoot, operatorRewardsAndProofs);
        _transferRewardsIfAllStored($r, eraIndex, eraRoot);
    }

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

    function _loadAndVerifyEraRoot(
        TanssiMetaMiddlewareRewardsStorage storage $r,
        uint48 eraIndex
    ) internal view returns (EraRoot memory eraRoot) {
        eraRoot = $r.eraRoot[eraIndex];

        require(eraRoot.epoch != 0, TanssiMetaMiddleware__EraRootNotSet());
    }

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

    function _setOperatorKey(address operator, bytes32 newKey) internal {
        TanssiMetaMiddlewareStorage storage $ = _getTanssiMetaMiddlewareStorage();
        require(!$.usedKeys[newKey], TanssiMetaMiddleware__KeyAlreadyUsed());

        $.usedKeys[newKey] = true;
        $.keyToOperator[newKey] = operator;

        emit OperatorKeySet(operator, newKey);
    }

    function _getTanssiMetaMiddlewareStorage() internal pure returns (TanssiMetaMiddlewareStorage storage $) {
        assembly {
            $.slot := TanssiMetaMiddlewareStorageLocation
        }
    }

    function _getTanssiMetaMiddlewareRewardsStorage()
        internal
        pure
        returns (TanssiMetaMiddlewareRewardsStorage storage $)
    {
        assembly {
            $.slot := TanssiMetaMiddlewareRewardsStorageLocation
        }
    }

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

    // Taken from Snowbridge's ScaleCodec.sol. The original solidity version is not compatible with this project.
    function _encodeU32(
        uint32 input
    ) internal pure returns (bytes4) {
        return bytes4(_reverse32(input));
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
