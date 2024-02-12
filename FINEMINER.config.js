module.exports = {
    apps: [
        {
            "name"                  : "FINEMINER",
            "script"                : "/root/llm-defender-subnet/llm_defender/neurons/miner.py",
            "interpreter"           : "/root/llm-defender-subnet/.venv/bin/python",
            "args"                  : "--netuid 38 --wallet.name miner --wallet.hotkey default --subtensor.network test --validator_min_stake 0",
            "max_memory_restart"    : "7G"
        }
    ]
}
