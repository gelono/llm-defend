module.exports = {
    apps: [
        {
            "name"                  : "validator",
            "script"                : "/root/llm-defender-subnet/llm_defender/neurons/validator.py",
            "interpreter"           : "/root/llm-defender-subnet/.venv/bin/python",
            "args"                  : "--netuid 38 --wallet.name validator --wallet.hotkey default --subtensor.network test --logging.debug",
            "max_memory_restart"    : "10G"
        }
    ]
}
