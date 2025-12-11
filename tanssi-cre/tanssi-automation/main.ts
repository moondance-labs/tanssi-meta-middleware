import {
  type CronPayload,
  cre,
  getNetwork,
  Runner,
  type Runtime,
  encodeCallMsg,
  LAST_FINALIZED_BLOCK_NUMBER,
  TxStatus,
  hexToBase64,
} from "@chainlink/cre-sdk";
import { Config, configSchema } from "./config";
import {
  Address,
  bytesToHex,
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  parseAbiParameters,
  zeroAddress,
} from "viem";
import { Middleware } from "../contracts/abi";
import {
  decodePerformData,
  SEND_DATA_COMMAND,
  safeJsonStringify,
  CRE_AUTOMATION_CODE,
} from "./utils";
import { CheckUpkeepTuple } from "./types";

const cacheAndSendOperatorsToGateway = (
  runtime: Runtime<Config>,
  evmConfig: Config["evms"][0]
): void => {
  runtime.log(`fetching por url ${runtime.config.url}`);

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: evmConfig.chainSelectorName,
    isTestnet: true,
  });

  if (!network) {
    throw new Error(
      `Network not found for chain selector name: ${evmConfig.chainSelectorName}`
    );
  }

  const evmClient = new cre.capabilities.EVMClient(
    network.chainSelector.selector
  );

  while (true) {
    // Encode the contract call data for getLastMessage
    const checkUpKeepcallData = encodeFunctionData({
      abi: Middleware,
      functionName: "checkUpkeep",
      args: [""],
    });

    runtime.log(`Encoded checkUpkeep call data: ${checkUpKeepcallData}`);

    const contractCall = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: evmConfig.middleware as Address,
          data: checkUpKeepcallData,
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();

    runtime.log(`Contract call result data: ${bytesToHex(contractCall.data)}`);

    // Decode the result
    const [upkeepNeeded, performData] = decodeFunctionResult({
      abi: Middleware,
      functionName: "checkUpkeep",
      data: bytesToHex(contractCall.data),
    }) as CheckUpkeepTuple;

    if (!upkeepNeeded) {
      runtime.log("No upkeep needed at this time. Exiting loop.");
      return;
    }

    runtime.log(
      `Decoded checkUpkeep result: upkeepNeeded=${upkeepNeeded}, performData=${performData}`
    );

    const decodedData = decodePerformData(performData);

    runtime.log(`Decoded performData: ${safeJsonStringify(decodedData)}`);

    const reportData = encodeAbiParameters(
      parseAbiParameters("uint8 executionCode, bytes performData"),
      [CRE_AUTOMATION_CODE, performData]
    );

    const reportResponse = runtime
      .report({
        encodedPayload: hexToBase64(reportData),
        encoderName: "evm",
        signingAlgo: "ecdsa",
        hashingAlgo: "keccak256",
      })
      .result();

    const writeResult = evmClient
      .writeReport(runtime, {
        receiver: evmConfig.middleware,
        report: reportResponse,
        gasConfig: {
          gasLimit: evmConfig.gasLimit,
        },
      })
      .result();

    runtime.log(
      `Transaction fee: ${safeJsonStringify(writeResult.transactionFee)}`
    );
    runtime.log(`Transaction status: ${TxStatus[writeResult.txStatus]}`);

    if (decodedData.command === SEND_DATA_COMMAND) {
      return;
    }
  }
};

const onCronTrigger = (
  runtime: Runtime<Config>,
  payload: CronPayload
): string => {
  if (!payload.scheduledExecutionTime) {
    throw new Error("Scheduled execution time is required");
  }

  runtime.log("Running CronTrigger");

  cacheAndSendOperatorsToGateway(runtime, runtime.config.evms[0]);
  return "CronTrigger completed";
};

const initWorkflow = (config: Config) => {
  const cronTrigger = new cre.capabilities.CronCapability();
  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: config.evms[0].chainSelectorName,
    isTestnet: true,
  });

  if (!network) {
    throw new Error(
      `Network not found for chain selector name: ${config.evms[0].chainSelectorName}`
    );
  }

  //   const evmClient = new cre.capabilities.EVMClient(
  //     network.chainSelector.selector
  //   );

  return [
    cre.handler(
      cronTrigger.trigger({
        schedule: config.schedule,
      }),
      onCronTrigger
    ),
    // cre.handler(
    //   evmClient.logTrigger({
    //     addresses: [config.evms[0].messageEmitterAddress],
    //   }),
    //   onLogTrigger
    // ),
  ];
};

export async function main() {
  const runner = await Runner.newRunner<Config>({
    configSchema,
  });
  await runner.run(initWorkflow);
}

main();
