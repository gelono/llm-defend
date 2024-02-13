module.exports = {
    apps: [
        {
            "name"                  : "MINER_YARA_1TeST",
            "script"                : "/root/llm-defender-subnet/llm_defender/neurons/miner.py",
            "interpreter"           : "/root/llm-defender-subnet/.venv/bin/python",
            "args"                  : "--netuid 38 --wallet.name miner --wallet.hotkey default --subtensor.network test --axon.port 15010 --miner_set_weights True --validator_min_stake -1",
            "max_memory_restart"    : "10G"
        }
    ]
}
