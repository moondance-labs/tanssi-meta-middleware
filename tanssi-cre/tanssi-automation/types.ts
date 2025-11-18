export type CheckUpkeepTuple = [boolean, `0x${string}`];

export type ValidatorData = {
  power: bigint;
  key: `0x${string}`;
};

// COMMAND = 1 => CACHE_DATA_COMMAND
export type CacheDataPerform = {
  command: 1;
  epoch: bigint;
  validatorsData: readonly ValidatorData[];
};

// COMMAND = 2 => SEND_DATA_COMMAND
export type SendDataPerform = {
  command: 2;
  epoch: bigint;
  sortedKeys: readonly `0x${string}`[];
};

export type PerformData = CacheDataPerform | SendDataPerform;
