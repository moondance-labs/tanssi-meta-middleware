import { decodeAbiParameters } from "viem";
import { PerformData } from "./types";

export const CACHE_DATA_COMMAND = 1;
export const SEND_DATA_COMMAND = 2;

// Utility function to safely stringify objects with bigints
export const safeJsonStringify = (obj: any): string =>
  JSON.stringify(
    obj,
    (_, value) => (typeof value === "bigint" ? value.toString() : value),
    2
  );

export function decodePerformData(performData: `0x${string}`): PerformData {
  const [command] = decodeAbiParameters([{ type: "uint8" }], performData);

  if (command === CACHE_DATA_COMMAND) {
    const [_, epoch, validators] = decodeAbiParameters(
      [
        { type: "uint8" },
        { type: "uint256" },
        {
          type: "tuple[]",
          components: [
            { name: "power", type: "uint256" },
            { name: "key", type: "bytes32" },
          ],
        },
      ],
      performData
    );

    return {
      command,
      epoch,
      validatorsData: validators,
    };
  } else if (command === SEND_DATA_COMMAND) {
    const [_, epoch, sortedKeys] = decodeAbiParameters(
      [{ type: "uint8" }, { type: "uint256" }, { type: "bytes32[]" }],
      performData
    );

    return {
      command,
      epoch,
      sortedKeys,
    };
  }

  throw new Error("Unknown command in performData");
}
