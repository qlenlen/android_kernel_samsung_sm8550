config = {
    "header": {
        "uuid": "dd9c76cb-0993-427d-b46d-7ab8b5029fcc",
        "type": "SECURITY",
        "vendor": "SAMSUNG",
        "product": "mz_tee_driver",
        "variant": "mz_tee_driver",
        "name": "mz_tee_driver",
    },
    "build": {
        "path": "security/mz_tee_driver",
        "file": "security_mz_tee_driver.py",
        "location": [
            {
                "src": "*.c Makefile:update Kconfig:update",
                "dst": "security/samsung/mz_tee_driver/",
            },
       ],
    },
    "features": [
        {
            "label": "BUILD TYPE",
            "configs": {
                "not set": [
                    "# CONFIG_MZ_TEE_DRIVER is not set"
                ],
                "module": [
                    "CONFIG_MZ_TEE_DRIVER=m"
                ],
                "built-in": [
                    "CONFIG_MZ_TEE_DRIVER=y"
                ],
            },
             "list_value": [
                "not set",
                "module",
                "built-in",
            ],
            "type": "list",
            "value": "not set",
        }
    ],
}


def load():
    return config

if __name__ == '__main__':
    print(load())
