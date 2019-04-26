{
  "targets": [{
    "target_name": "secp256k1-zkp",
    "variables": {
      "conditions": [
        [
          "OS=='win'", {
            "with_gmp%": "false"
          }, {
            "with_gmp%": "<!(src/build-tools/has_lib.sh gmpxx && src/build-tools/has_lib.sh gmp)"
          }
        ]
      ]
    },
    "sources": [
      "./src/addon.cc",
      "./src/secp256k1-zkp/src/secp256k1.c",
    ],
    "include_dirs": [
      "./src/secp256k1-zkp",
      "./src/secp256k1-zkp/contrib",
      "./src/secp256k1-zkp/include",
      "./src/secp256k1-zkp/src",
      "<!(node -e \"require('nan')\")",
      "/usr/local/include",
    ],
    "defines": [
      "USE_NUM_NONE=1",
      "USE_FIELD_INV_BUILTIN=1",
      "USE_SCALAR_INV_BUILTIN=1",
      "USE_FIELD_10X26=1",
      "USE_SCALAR_8X32=1",
      "USE_ENDOMORPHISM=1",
      "ENABLE_MODULE_RECOVERY=1",
      "ENABLE_MODULE_GENERATOR=1",
      "ENABLE_MODULE_COMMITMENT=1",
      "ENABLE_MODULE_RANGEPROOF=1",
      "ENABLE_MODULE_BULLETPROOF=1",
      "ENABLE_MODULE_AGGSIG=1"
    ],
    "cflags": [
      "-Wall",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra"
    ],
    "cflags_cc+": [
      "-std=c++0x"
    ],
    "conditions": [
      [
        "with_gmp=='true'", {
          "defines": [
            "HAVE_LIBGMP=1",
            "USE_NUM_GMP=1",
            "USE_FIELD_INV_NUM=1",
            "USE_SCALAR_INV_NUM=1"
          ],
          "libraries": [
            "-lgmpxx",
            "-lgmp"
          ]
        }, {
          "defines": [
            "USE_NUM_NONE=1",
            "USE_FIELD_INV_BUILTIN=1",
            "USE_SCALAR_INV_BUILTIN=1"
          ]
        }
      ],
      [
        "target_arch=='x64' and OS!='win'", {
          "defines": [
            "HAVE___INT128=1",
            "USE_ASM_X86_64=1",
            "USE_FIELD_5X52=1",
            "USE_FIELD_5X52_INT128=1",
            "USE_SCALAR_4X64=1"
          ]
        }, {
          "defines": [
            "USE_FIELD_10X26=1",
            "USE_SCALAR_8X32=1"
          ]
        }
      ],
      [
        "OS=='mac'", {
          "libraries": [
            "-L/usr/local/lib"
          ],
          "xcode_settings": {
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "OTHER_CPLUSPLUSFLAGS": [
              "-stdlib=libc++",
              "-Wno-unused-function",
              "-Wno-unused-const-variable",
              "-Wno-undefined-internal",
              "-Wno-unused-result"
            ],
            "OTHER_CFLAGS": [
              "-Wno-unused-function",
              "-Wno-unused-const-variable",
              "-Wno-undefined-internal",
              "-Wno-unused-result"
            ]
          }
        }
      ]
    ]
  }]
}
