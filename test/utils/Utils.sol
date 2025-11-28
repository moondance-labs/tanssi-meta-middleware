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

contract Utils is Test {
    bytes32 public constant OPERATOR1_KEY = 0x0101010101010101010101010101010101010101010101010101010101010101;
    bytes32 public constant OPERATOR2_KEY = 0x0202020202020202020202020202020202020202020202020202020202020202;
    bytes32 public constant OPERATOR3_KEY = 0x0303030303030303030303030303030303030303030303030303030303030303;
    bytes32 public constant OPERATOR4_KEY = 0x0404040404040404040404040404040404040404040404040404040404040404;
    bytes32 public constant OPERATOR5_KEY = 0x0505050505050505050505050505050505050505050505050505050505050505;
    bytes32 public constant OPERATOR6_KEY = 0x0606060606060606060606060606060606060606060606060606060606060606;
    bytes32 public constant OPERATOR7_KEY = 0x0707070707070707070707070707070707070707070707070707070707070707;
    bytes32 public constant OPERATOR8_KEY = 0x0808080808080808080808080808080808080808080808080808080808080808;
    bytes32 public constant OPERATOR9_KEY = 0x0909090909090909090909090909090909090909090909090909090909090909;

    bool skipCostTests = vm.envOr("SKIP_COST_TESTS", false);

    address public operator1 = makeAddr("operator1");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");
    address public operator4 = makeAddr("operator4");
    address public operator5 = makeAddr("operator5");
    address public operator6 = makeAddr("operator6");
    address public operator7 = makeAddr("operator7");

    function loadRewardsRootAndProof(
        uint48 rewardsKey,
        uint48 operator,
        string memory rewardsDataPath
    )
        internal
        view
        returns (uint48 epoch, bytes32 rewardsRoot, bytes32[] memory proof, uint32 points, uint32 totalPoints)
    {
        string memory path = string.concat(vm.projectRoot(), rewardsDataPath);
        string memory json = vm.readFile(path);

        string memory key = string.concat("$.", vm.toString(rewardsKey), ".root");
        rewardsRoot = vm.parseJsonBytes32(json, key);

        key = string.concat("$.", vm.toString(rewardsKey), ".epoch");
        epoch = uint48(vm.parseJsonUint(json, key));

        key = string.concat("$.", vm.toString(rewardsKey), ".operator", vm.toString(operator), "_proof");
        proof = vm.parseJsonBytes32Array(json, key);

        key = string.concat("$.", vm.toString(rewardsKey), ".operator", vm.toString(operator), "_points");
        points = uint32(vm.parseJsonUint(json, key));

        key = string.concat("$.", vm.toString(rewardsKey), ".total_points");
        totalPoints = uint32(vm.parseJsonUint(json, key));
    }

    function getTotalCallsNeeded(
        uint256 batchSize,
        uint256 totalOperators,
        uint256 responseLength
    ) internal pure returns (uint256) {
        if (responseLength > 10_240) {
            batchSize--;
        }
        uint256 totalCallsNeeded = 1;
        while (totalCallsNeeded * batchSize < totalOperators) {
            totalCallsNeeded++;
        }
        return totalCallsNeeded;
    }
}
