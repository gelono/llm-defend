module.exports = {
    apps: [
        {
            "name"                  : "miner",
            "script"                : "/root/llm-defender-subnet/llm_defender/neurons/miner.py",
            "interpreter"           : "/root/llm-defender-subnet/.venv/bin/python",
            "args"                  : "--netuid 1 --wallet.name miner --wallet.hotkey default --subtensor.chain_endpoint ws://127.0.0.1:9946 --subtensor.network local --validator_min_stake 0",
            "max_memory_restart"    : "7G"
        }
    ]
}
