module.exports = {
    apps: [
        {
            "name"                  : "miner",
            "script"                : "/root/llm-defender-subnet/llm_defender/neurons/miner.py",
            "interpreter"           : "/root/llm-defender-subnet/.venv/bin/python",
            "args"                  : "--netuid 38 --wallet.name validator --wallet.hotkey default --subtensor.network test --axon.port 15000 --miner_set_weights True --validator_min_stake 0",
            "max_memory_restart"    : "10G"
        }
    ]
}
