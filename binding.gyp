{
  "targets": [
    {
      "target_name": "darwin_process_evidence",
      "defines": [
        "NAPI_VERSION=8"
      ],
      "conditions": [
        [
          "OS==\"mac\"",
          {
            "sources": [
              "native/darwin-process-evidence.cc"
            ],
            "xcode_settings": {
              "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
              "CLANG_CXX_LIBRARY": "libc++",
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "MACOSX_DEPLOYMENT_TARGET": "12.0",
              "WARNING_CFLAGS": [
                "-Wall",
                "-Wextra"
              ]
            }
          }
        ],
        [
          "OS!=\"mac\"",
          {
            "sources": [
              "native/darwin-process-evidence-unavailable.cc"
            ]
          }
        ]
      ]
    }
  ]
}
