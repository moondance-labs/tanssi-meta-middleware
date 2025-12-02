-include .env

.PHONY: all test clean clean-all deploy install snapshot format anvil

DEFAULT_ANVIL_KEY := 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6


all: clean remove install update build

clean  :; forge clean

clean-all :; forge clean && rm -rf broadcast && rm -rf cache

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules

install :; 	git submodule update --init --recursive

update:; forge update

build:; forge build

test :; forge test

testv :; forge test -vvvv

coverage :; forge coverage

hcoverage:; forge coverage  --report lcov && genhtml lcov.info -o report --branch-coverage

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

RPC_URL ?= http://localhost:8545
PRIVATE_KEY ?= ${DEFAULT_ANVIL_KEY}
GAS_PRICE = 2000000000 # 2 Gwei
ADDITIONAL_ARGS_BASE = --account mainnetDeployer --sender 0x008f37a7307aba7d5d9bca771c4a56f853755d1f --with-gas-price $(GAS_PRICE)

# Flag: set to 1 to use private key, 0 to use base args
USE_PRIVATE_KEY ?= 1

ifeq ($(USE_PRIVATE_KEY),1)
  ADDITIONAL_ARGS = --private-key $(PRIVATE_KEY)
else
  ADDITIONAL_ARGS = $(ADDITIONAL_ARGS_BASE)
endif
NETWORK_ARGS := --rpc-url ${RPC_URL} --broadcast --verify --etherscan-api-key ${ETHERSCAN_API_KEY} ${ADDITIONAL_ARGS}
