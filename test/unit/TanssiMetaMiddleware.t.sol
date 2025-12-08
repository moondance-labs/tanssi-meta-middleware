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

import {Test, console2} from "forge-std/Test.sol";

// ---------------------- CHAINLINK ----------------------
import {MockV3Aggregator} from "lib/chainlink-brownie-contracts/contracts/src/v0.8/tests/MockV3Aggregator.sol";

// ---------------------- OPENZEPPELIN ----------------------
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

// ---------------------- TANSSI CONTRACTS ----------------------
import {TanssiMetaMiddleware} from "src/contracts/TanssiMetaMiddleware.sol";
import {ITanssiMetaMiddleware} from "src/interfaces/ITanssiMetaMiddleware.sol";

// ---------------------- TESTS ----------------------
import {TanssiMiddlewareMock} from "test/mocks/TanssiMiddlewareMock.sol";
import {ERC20Mock} from "test/mocks/ERC20Mock.sol";
import {Utils} from "test/utils/Utils.sol";

contract TanssiMetaMiddlewareTest is Utils {
    using Strings for address;
    using Strings for uint256;
    using Strings for uint48;
    using Math for uint256;

    TanssiMetaMiddleware public tanssiMetaMiddleware;

    IERC20 public eth;
    IERC20 public usdc;
    ERC20Mock public rewardsToken;
    address public admin = makeAddr("admin");
    address public gateway = makeAddr("gateway");
    address public automationPerformer = makeAddr("automationPerformer");

    function setUp() public {
        TanssiMetaMiddleware tanssiMetaMiddlewareImpl = new TanssiMetaMiddleware();
        tanssiMetaMiddleware = TanssiMetaMiddleware(address(new ERC1967Proxy(address(tanssiMetaMiddlewareImpl), "")));
        tanssiMetaMiddleware.initialize(admin);

        vm.startPrank(admin);
        tanssiMetaMiddleware.grantRole(tanssiMetaMiddleware.GATEWAY_ROLE(), gateway);
        tanssiMetaMiddleware.grantRole(tanssiMetaMiddleware.AUTOMATION_ROLE(), automationPerformer);
        vm.stopPrank();

        eth = IERC20(address(new ERC20Mock("Ether", 18)));
        usdc = IERC20(address(new ERC20Mock("USDC", 6)));
        rewardsToken = new ERC20Mock("TANSSI", 12);
    }

    function testCanRegisterMiddleware() public {
        vm.startPrank(admin);
        address middleware = makeAddr("middleware");
        tanssiMetaMiddleware.registerMiddleware(middleware);
        vm.stopPrank();
        assertEq(tanssiMetaMiddleware.isMiddlewareRegistered(middleware), true);
    }

    function testCannotRegisterMiddlewareIfAlreadyRegistered() public {
        vm.startPrank(admin);
        address middleware = makeAddr("middleware");
        tanssiMetaMiddleware.registerMiddleware(middleware);
        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__MiddlewareAlreadyRegistered.selector)
        );
        tanssiMetaMiddleware.registerMiddleware(middleware);
        vm.stopPrank();
    }

    function testCannotRegisterMiddlewareIfNotAdmin() public {
        address middleware = makeAddr("middleware");
        address notAdmin = makeAddr("notAdmin");
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                notAdmin,
                tanssiMetaMiddleware.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(notAdmin);
        tanssiMetaMiddleware.registerMiddleware(middleware);
    }

    // ---------------------- Collateral Registration ----------------------

    function testCanRegisterCollateral() public {
        vm.startPrank(admin);
        address collateral = makeAddr("collateral");
        address oracle = makeAddr("oracle");
        tanssiMetaMiddleware.registerCollateral(collateral, oracle);
        vm.stopPrank();
        assertEq(tanssiMetaMiddleware.isValidCollateral(collateral), true);
    }

    function testCannotRegisterCollateralIfNotAdmin() public {
        address collateral = makeAddr("collateral");
        address oracle = makeAddr("oracle");
        address notAdmin = makeAddr("notAdmin");
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                notAdmin,
                tanssiMetaMiddleware.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(notAdmin);
        tanssiMetaMiddleware.registerCollateral(collateral, oracle);
    }

    function testCannotRegisterCollateralIfAlreadyRegistered() public {
        vm.startPrank(admin);
        address collateral = makeAddr("collateral");
        address oracle = makeAddr("oracle");
        tanssiMetaMiddleware.registerCollateral(collateral, oracle);
        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__CollateralAlreadyRegistered.selector)
        );
        tanssiMetaMiddleware.registerCollateral(collateral, oracle);
        vm.stopPrank();
    }

    function testCanGetTokensData() public {
        ERC20Mock collateralA = new ERC20Mock("WETH", 18);
        ERC20Mock collateralB = new ERC20Mock("USDC", 6);
        MockV3Aggregator oracleA = new MockV3Aggregator(6, 3_000_000_000); // 3k usd with 6 decimals
        MockV3Aggregator oracleB = new MockV3Aggregator(4, 10_000); // 1 usdc with 4 decimals

        vm.startPrank(admin);
        tanssiMetaMiddleware.registerCollateral(address(collateralA), address(oracleA));
        tanssiMetaMiddleware.registerCollateral(address(collateralB), address(oracleB));
        vm.stopPrank();

        address[] memory collaterals = new address[](2);
        collaterals[0] = address(collateralA);
        collaterals[1] = address(collateralB);
        ITanssiMetaMiddleware.TokenData[] memory tokensData = tanssiMetaMiddleware.getTokensData(collaterals);
        assertEq(tokensData[0].price, 3_000_000_000);
        assertEq(tokensData[0].priceDecimals, 6);
        assertEq(tokensData[0].tokenDecimals, 18);
        assertEq(tokensData[1].price, 10_000);
        assertEq(tokensData[1].priceDecimals, 4);
        assertEq(tokensData[1].tokenDecimals, 6);
    }

    // ---------------------- Operator Registration ----------------------

    function testCanRegisterOperator() public {
        bytes32 operatorKey = keccak256(abi.encodePacked("operatorKey"));
        address middleware = makeAddr("middleware");
        vm.prank(admin);
        tanssiMetaMiddleware.registerMiddleware(middleware);

        vm.prank(middleware);
        tanssiMetaMiddleware.registerOperator(operator1, operatorKey);

        assertEq(tanssiMetaMiddleware.keyToOperator(operatorKey), operator1);
    }

    function testCannotRegisterSameKeyTwiceForDifferentOperators() public {
        bytes32 operatorKey = keccak256(abi.encodePacked("operatorKey"));
        address middleware = makeAddr("middleware");
        vm.prank(admin);
        tanssiMetaMiddleware.registerMiddleware(middleware);

        vm.startPrank(middleware);
        tanssiMetaMiddleware.registerOperator(operator1, operatorKey);

        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__KeyAlreadyUsed.selector));
        tanssiMetaMiddleware.registerOperator(operator2, operatorKey);
    }

    function testCannotUpdateAnOperatorKeyToAnAlreadyUsedKey() public {
        bytes32 operatorKey = keccak256(abi.encodePacked("operatorKey"));
        bytes32 operatorKey2 = keccak256(abi.encodePacked("operatorKey2"));
        address middleware = makeAddr("middleware");
        vm.prank(admin);
        tanssiMetaMiddleware.registerMiddleware(middleware);

        vm.startPrank(middleware);
        tanssiMetaMiddleware.registerOperator(operator1, operatorKey);
        tanssiMetaMiddleware.registerOperator(operator2, operatorKey2);

        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__KeyAlreadyUsed.selector));
        tanssiMetaMiddleware.updateOperatorKey(operator2, operatorKey);
    }

    function testCannotUpdateOperatorKeyIfNotMiddleware() public {
        address middleware = makeAddr("middleware");
        address middleware2 = makeAddr("middleware2");
        vm.startPrank(admin);
        tanssiMetaMiddleware.registerMiddleware(middleware);
        tanssiMetaMiddleware.registerMiddleware(middleware2);

        vm.startPrank(middleware);
        tanssiMetaMiddleware.registerOperator(operator1, OPERATOR1_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedMiddleware.selector)
        );
        vm.startPrank(middleware2);
        tanssiMetaMiddleware.updateOperatorKey(operator1, OPERATOR1_KEY);
    }

    function testCannotRegisterOperatorIfUnknownMiddleware() public {
        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnknownMiddleware.selector));

        vm.prank(makeAddr("unknownMiddleware"));
        tanssiMetaMiddleware.registerOperator(operator1, OPERATOR1_KEY);
    }

    function testCannotUpdateOperatorIfUnknownMiddleware() public {
        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnknownMiddleware.selector));

        vm.prank(makeAddr("unknownMiddleware"));
        tanssiMetaMiddleware.updateOperatorKey(operator1, OPERATOR1_KEY);
    }

    function testCannotRegisterSameKeyTwiceFromDifferentMiddlewares() public {
        address middleware = makeAddr("middleware");
        address middleware2 = makeAddr("middleware2");
        vm.startPrank(admin);
        tanssiMetaMiddleware.registerMiddleware(middleware);
        tanssiMetaMiddleware.registerMiddleware(middleware2);

        vm.startPrank(middleware);
        tanssiMetaMiddleware.registerOperator(operator1, OPERATOR1_KEY);

        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__KeyAlreadyUsed.selector));
        vm.startPrank(middleware2);
        tanssiMetaMiddleware.registerOperator(operator2, OPERATOR1_KEY);
    }

    // ---------------------- Rewards Distribution ----------------------

    function testCannotDistributeRewardsIfNotGateway() public {
        address notGateway = makeAddr("notGateway");
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                notGateway,
                tanssiMetaMiddleware.GATEWAY_ROLE()
            )
        );
        vm.prank(notGateway);
        tanssiMetaMiddleware.distributeRewards(1, 1, 100, 100, bytes32(0), address(rewardsToken));
    }

    function testCannotDistributeRewardsIfNotEnoughTokens() public {
        uint256 totalTokens = 50;
        rewardsToken.mint(address(tanssiMetaMiddleware), totalTokens - 1);

        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__InsufficientRewardsReceived.selector)
        );
        vm.prank(gateway);
        tanssiMetaMiddleware.distributeRewards(1, 1, 100, totalTokens, bytes32(0), address(rewardsToken));
    }

    function testCannotDistributeRewardsIfUnexpectedEraIndex() public {
        rewardsToken.mint(address(tanssiMetaMiddleware), 100);

        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedEraIndex.selector));
        vm.prank(gateway);
        uint48 eraIndex = 5; // Should be 1
        tanssiMetaMiddleware.distributeRewards(1, eraIndex, 100, 100, bytes32(0), address(rewardsToken));
    }

    function testCanDistributeRewards() public {
        uint48 eraIndex = 1;
        (, uint256 totalTokens, uint256 totalPoints, uint48 epoch, bytes32 root) = _setupAndDistributeRewards(eraIndex);

        ITanssiMetaMiddleware.EraRoot memory eraRoot = tanssiMetaMiddleware.getEraRoot(eraIndex);
        assertEq(eraRoot.epoch, epoch);
        assertEq(eraRoot.totalAmount, totalTokens);
        assertEq(eraRoot.totalPoints, totalPoints);
        assertEq(eraRoot.root, root);
        assertEq(eraRoot.tokenAddress, address(rewardsToken));

        uint48[] memory eraIndexes = tanssiMetaMiddleware.getEraIndexesPerEpoch(epoch);
        assertEq(eraIndexes.length, 1);
        assertEq(eraIndexes[0], eraIndex);

        assertEq(tanssiMetaMiddleware.getLastReceivedEraIndex(), eraIndex);
        assertEq(tanssiMetaMiddleware.getLastDistributedEraIndex(), 0);
    }

    function _registerMiddlewaresAndOperators() public returns (TanssiMiddlewareMock[] memory middlewares) {
        middlewares = _registerMiddlewares();
        _registerOperators(middlewares);
    }

    function _registerMiddlewares() public returns (TanssiMiddlewareMock[] memory middlewares) {
        middlewares = new TanssiMiddlewareMock[](2);
        middlewares[0] = new TanssiMiddlewareMock(address(tanssiMetaMiddleware));
        middlewares[1] = new TanssiMiddlewareMock(address(tanssiMetaMiddleware));

        vm.startPrank(admin);
        tanssiMetaMiddleware.registerMiddleware(address(middlewares[0]));
        tanssiMetaMiddleware.registerMiddleware(address(middlewares[1]));
        vm.stopPrank();
    }

    function _registerOperators(
        TanssiMiddlewareMock[] memory middlewares
    ) public {
        vm.startPrank(admin);
        middlewares[0].registerOperator(operator1, OPERATOR1_KEY);
        middlewares[0].registerOperator(operator2, OPERATOR2_KEY);
        middlewares[0].registerOperator(operator3, OPERATOR3_KEY);
        middlewares[0].registerOperator(operator4, OPERATOR4_KEY);

        middlewares[1].registerOperator(operator5, OPERATOR5_KEY);
        middlewares[1].registerOperator(operator6, OPERATOR6_KEY);
        middlewares[1].registerOperator(operator7, OPERATOR7_KEY);
        vm.stopPrank();
    }

    // ---------------------- Slashing ----------------------

    function testCannotSlashOperatorIfNotGateway() public {
        uint48 eraIndex = 1;
        address notGateway = makeAddr("notGateway");
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                notGateway,
                tanssiMetaMiddleware.GATEWAY_ROLE()
            )
        );
        vm.prank(notGateway);
        tanssiMetaMiddleware.slash(eraIndex, OPERATOR1_KEY, 50);
    }

    function testCannotSlashOperatorIfOperatorDoesNotBelongToAMiddleware() public {
        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedMiddleware.selector)
        );
        vm.prank(gateway);
        tanssiMetaMiddleware.slash(1, OPERATOR1_KEY, 50);
    }

    function testCanSlashOperator() public {
        TanssiMiddlewareMock[] memory middlewares = _registerMiddlewaresAndOperators();
        vm.startPrank(gateway);
        tanssiMetaMiddleware.slash(1, OPERATOR1_KEY, 50);
        assertEq(middlewares[0].slashedOperators(1, operator1), 50);
    }

    // ---------------------- GAS COSTS ----------------------

    function testCostProofResponseLengths() public {
        vm.skip(skipCostTests);

        for (uint256 o = 30; o <= 200; o += 10) {
            // The proof lenght grows logarithmically with the number of operators
            uint256 proofLength = 1;
            uint256 maxLeafsWithproof = 2 ** proofLength;
            while (maxLeafsWithproof < o) {
                proofLength++;
                maxLeafsWithproof = 2 ** proofLength;
            }
            console2.log("--------------------------------");
            console2.log("Max proof length for", o, "operators:", proofLength);

            bytes32[] memory proof = new bytes32[](proofLength);
            ITanssiMetaMiddleware.OperatorRewardWithProof memory mockRewardsWithProof =
                ITanssiMetaMiddleware.OperatorRewardWithProof({
                    operatorKey: OPERATOR1_KEY, totalPoints: 1, proof: proof
                });

            for (uint256 i = 1; i <= 40; i += 1) {
                ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs =
                    new ITanssiMetaMiddleware.OperatorRewardWithProof[](i);

                for (uint256 j = 0; j < i; j++) {
                    operatorRewardsAndProofs[j] = mockRewardsWithProof;
                }
                bytes memory encodedResponse = abi.encode(operatorRewardsAndProofs);

                if (encodedResponse.length > 10_000) {
                    console2.log("Response length for", i, "operators:", encodedResponse.length);
                    console2.log("Total calls needed:", getTotalCallsNeeded(i, o, encodedResponse.length));
                    break;
                }
            }
        }
    }

    function testCostDistributeRewardsOnMetaMiddleware() public {
        vm.skip(skipCostTests);

        uint48 eraIndex = 1;
        uint256 totalTokens = 1000 * 10 ** 12;
        (uint48 epoch, bytes32 root,,, uint256 totalPoints) = _loadRewardsRootAndProof(eraIndex, 1);

        rewardsToken.mint(address(tanssiMetaMiddleware), totalTokens);
        _registerMiddlewaresAndOperators();

        uint256 gasBefore = gasleft();
        vm.prank(gateway);
        tanssiMetaMiddleware.distributeRewards(epoch, eraIndex, totalPoints, totalTokens, root, address(rewardsToken));
        uint256 gasAfter = gasleft();
        console2.log("Gas used on MetaMiddleware.distributeRewards:", gasBefore - gasAfter);
    }

    // ---------------------- Rewards Distribution to Middleware ----------------------

    function testCannotPrepareDistributionDataIfMiddlewareDoesNotMatch() public {
        uint48 eraIndex = 1;
        (ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,,,) =
            _prepare50OperatorsWithRewardsAndProofs(eraIndex);

        address notMiddleware = makeAddr("notMiddleware");
        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedMiddleware.selector)
        );
        tanssiMetaMiddleware.prepareRewardsDistributionData(eraIndex, notMiddleware, operatorRewardsAndProofs);
    }

    function testCanPrepareRewardsDistributionDataFromOperatorRewards() public {
        uint48 eraIndex = 1;
        (
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,
            address middleware,
            uint256 totalTokens,
            uint256 totalPoints
        ) = _prepare50OperatorsWithRewardsAndProofs(eraIndex);
        tanssiMetaMiddleware.storeRewards(eraIndex, operatorRewardsAndProofs);

        // This should prepare an OperatorReward array and call the middleware with it. The mock will simply encode it and return it so we can easily verify it.
        (bytes memory rewardsDistributionData, uint256 totalAmount) =
            tanssiMetaMiddleware.prepareRewardsDistributionData(eraIndex, middleware, operatorRewardsAndProofs);

        ITanssiMetaMiddleware.OperatorReward[] memory operatorRewards =
            abi.decode(rewardsDistributionData, (ITanssiMetaMiddleware.OperatorReward[]));
        assertEq(operatorRewards.length, 50);

        uint256 totalDistributedAmount;
        for (uint256 i; i < 50; i++) {
            assertEq(
                operatorRewards[i].operator, tanssiMetaMiddleware.keyToOperator(operatorRewardsAndProofs[i].operatorKey)
            );
            uint256 rewardAmount = totalTokens.mulDiv(operatorRewardsAndProofs[i].totalPoints, totalPoints);
            totalDistributedAmount += rewardAmount;
            assertEq(operatorRewards[i].rewardAmount, rewardAmount);
        }

        assertEq(totalAmount, totalDistributedAmount);
    }

    function testStoreAndTransferRewards() public {
        vm.skip(skipCostTests);

        uint48 eraIndex = 1;
        (
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,
            address middleware,
            uint256 totalTokens,
            uint256 totalPoints
        ) = _prepare50OperatorsWithRewardsAndProofs(eraIndex);

        uint256 gasBefore = gasleft();
        tanssiMetaMiddleware.storeRewards(eraIndex, operatorRewardsAndProofs);
        console2.log("Gas used on MetaMiddleware.storeRewards (50 operators):", gasBefore - gasleft());

        assertEq(tanssiMetaMiddleware.getEraTransferred(eraIndex), true);

        address[] memory operators = new address[](50);
        for (uint256 i; i < 50;) {
            operators[i] = tanssiMetaMiddleware.keyToOperator(operatorRewardsAndProofs[i].operatorKey);
            unchecked {
                ++i;
            }
        }
        uint256[] memory operatorRewards = tanssiMetaMiddleware.getOperatorsRewards(eraIndex, middleware, operators);
        for (uint256 i; i < 50;) {
            uint256 reward = totalTokens.mulDiv(operatorRewardsAndProofs[i].totalPoints, totalPoints);
            assertEq(operatorRewards[i], reward);
            unchecked {
                ++i;
            }
        }
    }

    function testRewardsWithZeroPointsAreIgnored() public {
        uint48 eraIndex = 1;
        (
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,
            address middleware,,
            uint256 totalPoints
        ) = _prepare50OperatorsWithRewardsAndProofs(eraIndex);
        uint256 removedPoints = operatorRewardsAndProofs[0].totalPoints;
        operatorRewardsAndProofs[0].totalPoints = 0;
        operatorRewardsAndProofs[0].proof = new bytes32[](0);
        tanssiMetaMiddleware.storeRewards(eraIndex, operatorRewardsAndProofs);

        assertEq(
            tanssiMetaMiddleware.getPointsStoredPerEraIndexPerMiddleware(eraIndex, middleware),
            totalPoints - removedPoints
        );
    }

    function testCannotStoreRewardsWithInvalidProof() public {
        uint48 eraIndex = 1;
        (
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,
            address middleware,,
            uint256 totalPoints
        ) = _prepare50OperatorsWithRewardsAndProofs(eraIndex);
        operatorRewardsAndProofs[0].proof = new bytes32[](0);

        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__InvalidProof.selector));
        tanssiMetaMiddleware.storeRewards(eraIndex, operatorRewardsAndProofs);
    }

    function testCanDistributeRewardsTrustingly() public {
        (uint48 eraIndex, address middleware,, bytes memory rewardsDistributionData, uint256 totalAmount) =
            _distributeRewardsTrustingly();

        assertEq(TanssiMiddlewareMock(middleware).distributionCallsPerEraIndex(eraIndex), 1);
        assertEq(TanssiMiddlewareMock(middleware).transferredRewardsPerEraIndex(eraIndex), totalAmount);
        assertEq(
            uint8(tanssiMetaMiddleware.getDistributionStatusPerEraIndexPerMiddleware(eraIndex, middleware)),
            uint8(ITanssiMetaMiddleware.DistributionStatus.DISTRIBUTED)
        );
    }

    function testCannotDistributeRewardsTrustinglyIfAlreadyDistributed() public {
        (uint48 eraIndex, address middleware,, bytes memory rewardsDistributionData, uint256 totalAmount) =
            _distributeRewardsTrustingly();

        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedDistributionStatus.selector)
        );
        vm.prank(automationPerformer);
        tanssiMetaMiddleware.distributeRewardsToMiddlewareTrustingly(
            eraIndex, middleware, totalAmount, rewardsDistributionData
        );
    }

    function testCannotStoreRewardsTrustinglyIfAlreadyDistributed() public {
        (
            uint48 eraIndex,
            address middleware,
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,,
        ) = _distributeRewardsTrustingly();

        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedDistributionStatus.selector)
        );
        tanssiMetaMiddleware.storeRewards(eraIndex, operatorRewardsAndProofs);
    }

    function testEraIsMarkedAsDistributedWhenAllMiddlewaresHaveDistributed() public {
        uint48 eraIndex = 1;
        (
            TanssiMiddlewareMock[] memory middlewares,
            uint256 totalTokens,
            uint256 totalPoints,
            uint48 epoch,
            bytes32 root
        ) = _setupAndDistributeRewards(eraIndex);

        for (uint256 i; i < middlewares.length;) {
            TanssiMiddlewareMock(middlewares[i]).setDistributionCompleteResponse(true);
            unchecked {
                ++i;
            }
        }

        for (uint256 i; i < middlewares.length;) {
            vm.prank(automationPerformer);
            tanssiMetaMiddleware.distributeRewardsToMiddlewareTrustingly(
                eraIndex, address(middlewares[i]), 100, new bytes(0)
            );
            unchecked {
                ++i;
            }
        }

        assertEq(tanssiMetaMiddleware.getLastDistributedEraIndex(), eraIndex);
    }

    function _distributeRewardsTrustingly()
        private
        returns (
            uint48 eraIndex,
            address middleware,
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,
            bytes memory rewardsDistributionData,
            uint256 totalAmount
        )
    {
        eraIndex = 1;

        (operatorRewardsAndProofs, middleware,,) = _prepare50OperatorsWithRewardsAndProofs(eraIndex);

        TanssiMiddlewareMock(middleware).setDistributionCompleteResponse(true);

        (rewardsDistributionData, totalAmount) =
            tanssiMetaMiddleware.prepareRewardsDistributionData(eraIndex, middleware, operatorRewardsAndProofs);

        vm.prank(automationPerformer);
        tanssiMetaMiddleware.distributeRewardsToMiddlewareTrustingly(
            eraIndex, middleware, totalAmount, rewardsDistributionData
        );
    }

    function testCannotDistributeManuallyIfAlreadyTransferred() public {
        // TODO: We need to mark it somehow that distribition started, because both manual and automated will call store rewards first.
        vm.skip(skipCostTests);
        uint48 eraIndex = 1;

        (ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs, address middleware,,) =
            _prepare50OperatorsWithRewardsAndProofs(eraIndex);
        tanssiMetaMiddleware.storeRewards(eraIndex, operatorRewardsAndProofs);

        // We add 30 more operators so they don't all fit in the first batch, even though they will have no rewards, they must be iterated over by the middleware
        for (uint256 i = 50; i < 80;) {
            bytes32 operatorKey = bytes32(uint256(i + 1));
            TanssiMiddlewareMock(middleware)
                .registerOperator(makeAddr(string.concat("operator", vm.toString(i + 1))), operatorKey);
            unchecked {
                ++i;
            }
        }

        // Automation starts
        (bytes memory rewardsDistributionData, uint256 totalAmount) =
            tanssiMetaMiddleware.prepareRewardsDistributionData(eraIndex, middleware, operatorRewardsAndProofs);

        vm.prank(automationPerformer);
        tanssiMetaMiddleware.distributeRewardsToMiddlewareTrustingly(
            eraIndex, middleware, totalAmount, rewardsDistributionData
        );

        // Manual can no longer start
        vm.expectRevert(
            abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__UnexpectedDistributionStatus.selector)
        );
        tanssiMetaMiddleware.distributeRewardsToMiddlewareManually(eraIndex, middleware);
    }

    function testCannotDistributeManuallyIfDistributionIsNotCompleteInASingleCall() public {
        vm.skip(skipCostTests);

        uint48 eraIndex = 1;
        (, address middleware,,) = _prepare50OperatorsWithRewardsAndProofs(eraIndex);

        TanssiMiddlewareMock(middleware).setDistributionCompleteResponse(false);

        // Current state for the middleware/era is transferred, so we should not be able to transfer again
        vm.prank(automationPerformer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITanssiMetaMiddleware.TanssiMetaMiddleware__CouldNotDistributeRewardsInASingleCall.selector
            )
        );
        tanssiMetaMiddleware.distributeRewardsToMiddlewareManually(eraIndex, middleware);
    }

    function testCannotDistributeManuallyForANotDistributedEra() public {
        uint48 eraIndex = 1;
        TanssiMiddlewareMock[] memory middlewares = _registerMiddlewares();

        address middleware = address(middlewares[0]);

        // Current state for the middleware/era is transferred, so we should not be able to transfer again
        vm.prank(automationPerformer);
        vm.expectRevert(abi.encodeWithSelector(ITanssiMetaMiddleware.TanssiMetaMiddleware__EraRootNotSet.selector));
        tanssiMetaMiddleware.distributeRewardsToMiddlewareManually(eraIndex, middleware);
    }

    function _prepare50OperatorsWithRewardsAndProofs(
        uint48 eraIndex
    )
        private
        returns (
            ITanssiMetaMiddleware.OperatorRewardWithProof[] memory operatorRewardsAndProofs,
            address middleware,
            uint256 totalTokens,
            uint256 totalPoints
        )
    {
        uint48 rewardsKey = 3; // Key "3" has 50 operators

        totalTokens = 1000 * 10 ** 12;
        uint48 epoch;
        bytes32 root;
        (epoch, root,,, totalPoints) = _loadRewardsRootAndProof(rewardsKey, 1);

        rewardsToken.mint(address(tanssiMetaMiddleware), totalTokens);
        TanssiMiddlewareMock[] memory middlewares = _registerMiddlewares();

        middleware = address(middlewares[0]);

        operatorRewardsAndProofs = new ITanssiMetaMiddleware.OperatorRewardWithProof[](50); // All 50 operators
        for (uint256 i; i < 50;) {
            bytes32 operatorKey = bytes32(uint256(i + 1));
            // All 50 operators are registered on the first middleware
            middlewares[0].registerOperator(makeAddr(string.concat("operator", vm.toString(i + 1))), operatorKey);

            // Prepare the proof
            operatorRewardsAndProofs[i] = _getOperatorRewardWithProof(operatorKey, uint48(i + 1), rewardsKey);
            unchecked {
                ++i;
            }
        }

        vm.prank(gateway);
        tanssiMetaMiddleware.distributeRewards(epoch, eraIndex, totalPoints, totalTokens, root, address(rewardsToken));
    }

    function _setupAndDistributeRewards(
        uint48 eraIndex
    )
        public
        returns (
            TanssiMiddlewareMock[] memory middlewares,
            uint256 totalTokens,
            uint256 totalPoints,
            uint48 epoch,
            bytes32 root
        )
    {
        totalTokens = 1000 * 10 ** 12;
        (epoch, root,,, totalPoints) = _loadRewardsRootAndProof(eraIndex, 1);

        rewardsToken.mint(address(tanssiMetaMiddleware), totalTokens);
        middlewares = _registerMiddlewaresAndOperators();

        vm.prank(gateway);
        tanssiMetaMiddleware.distributeRewards(epoch, eraIndex, totalPoints, totalTokens, root, address(rewardsToken));
    }

    function _getOperatorRewardWithProof(
        bytes32 operatorKey,
        uint48 operator,
        uint48 eraIndex
    ) private view returns (ITanssiMetaMiddleware.OperatorRewardWithProof memory operatorRewardAndProof) {
        (,, bytes32[] memory proof, uint32 points,) = _loadRewardsRootAndProof(eraIndex, operator);
        operatorRewardAndProof = ITanssiMetaMiddleware.OperatorRewardWithProof({
            operatorKey: operatorKey, totalPoints: points, proof: proof
        });
    }

    function _getExpectedRewardsAmounts(
        uint48 eraIndex,
        uint256 totalTokens,
        uint256 totalOperators
    ) private view returns (uint256[] memory rewardsAmounts) {
        rewardsAmounts = new uint256[](totalOperators);
        for (uint256 i; i < totalOperators;) {
            (,,, uint32 points, uint32 totalPoints) = _loadRewardsRootAndProof(eraIndex, uint8(i + 1));
            rewardsAmounts[i] = totalTokens.mulDiv(points, totalPoints);
            unchecked {
                ++i;
            }
        }
    }

    function _loadRewardsRootAndProof(
        uint48 eraIndex,
        uint48 operator
    ) private view returns (uint48 epoch, bytes32 root, bytes32[] memory proof, uint32 points, uint32 totalPoints) {
        (epoch, root, proof, points, totalPoints) =
            loadRewardsRootAndProof(eraIndex, uint8(operator), "/test/unit/rewards_data.json");
    }

    // ---------------------- Upgrading ----------------------

    function testCanUpgradeIfAdmin() public {
        TanssiMetaMiddleware newTanssiMetaMiddleware = new TanssiMetaMiddleware();

        vm.prank(admin);
        tanssiMetaMiddleware.upgradeToAndCall(address(newTanssiMetaMiddleware), "");
    }

    function testCannotUpgradeIfNotAdmin() public {
        TanssiMetaMiddleware newTanssiMetaMiddleware = new TanssiMetaMiddleware();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(this),
                tanssiMetaMiddleware.DEFAULT_ADMIN_ROLE()
            )
        );
        tanssiMetaMiddleware.upgradeToAndCall(address(newTanssiMetaMiddleware), "");
    }
}
