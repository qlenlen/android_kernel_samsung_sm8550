config = {
    "header": {
        "uuid": "283df57d-cc04-4f9f-ae5a-9c8140dd1e53",
        "type": "SECURITY",
        "vendor": "SAMSUNG",
        "product": "proca",
        "variant": "proca",
        "name": "proca",
    },
    "build": {
        "path": "security/proca",
        "file": "security_proca.py",
        "location": [
            {
                "src": "*.c *.h *.asn1 Makefile Kconfig",
                "dst": "security/samsung/proca/",
            },
            {
                "src": "gaf/*",
                "dst": "security/samsung/proca/gaf/",
            },
            {
                "src": "s_os/*.c s_os/*.h",
                "dst": "security/samsung/proca/s_os/",
            },
        ],
    },
    "features": [
        {
            "label": "General",
            "type": "boolean",
            "configs": {
                "True": [],
                "False": [],
            },
            "value": True,
        },
    ],
    "kunit_test": {
        "build": {
            "location": [
                {
                    "src": "../five/kunit_test/test_helpers.h kunit_test/*.c kunit_test/*.h kunit_test/Makefile:cp",
                    "dst": "security/samsung/proca/kunit_test/",
                },
                {
                    "src": "../five/*.c ../five/*.h ../five/*.S ../five/*.der ../five/Kconfig kunit_test/five/Makefile",
                    "dst": "security/samsung/five/",
                },
                {
                    "src": "../five/s_os/*.c",
                    "dst": "security/samsung/five/s_os/",
                },
            ],
        },
        "features": [
            {
                "label": "default",
                "configs": {
                    "True": [
                        "CONFIG_PROCA=y",
                        "CONFIG_PROCA_DEBUG=y",
                        "CONFIG_PROCA_S_OS=y",
                        "CONFIG_GAF_V6=y",
                        "CONFIG_FIVE=y",
                        "CONFIG_FIVE_GKI_10=y",
                        "CONFIG_CRC16=y",
                        "CONFIG_SECURITY=y",
                        "CONFIG_NET=y",
                        "CONFIG_AUDIT=y",
                        "CONFIG_AUDITSYSCALL=y",
                        "CONFIG_MD=y",
                        "CONFIG_BLK_DEV_DM=y",
                        "CONFIG_BLK_DEV_LOOP=y",
                        "CONFIG_DM_VERITY=y",
                        "CONFIG_CRYPTO_SHA256=y",
                        "CONFIG_DEBUG_KERNEL=y",
                        "CONFIG_DEBUG_INFO=y",
                        "CONFIG_GCOV=y"
                    ],
                    "False": [],
                },
                "type": "boolean",
           },
        ]
    },
}


def load():
    return config


if __name__ == "__main__":
    print(load())
