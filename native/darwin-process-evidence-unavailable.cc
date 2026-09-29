#include <node_api.h>

namespace {

napi_value Unavailable(napi_env environment, napi_callback_info information) {
  (void)information;
  napi_throw_error(environment, "ENOSYS", "Darwin process evidence is unavailable on this platform");
  return nullptr;
}

}

NAPI_MODULE_INIT() {
  napi_value capture = nullptr;
  napi_value list = nullptr;
  if (napi_create_function(env, "captureProcess", NAPI_AUTO_LENGTH, Unavailable, nullptr, &capture) != napi_ok ||
      napi_create_function(env, "listProcesses", NAPI_AUTO_LENGTH, Unavailable, nullptr, &list) != napi_ok ||
      napi_set_named_property(env, exports, "captureProcess", capture) != napi_ok ||
      napi_set_named_property(env, exports, "listProcesses", list) != napi_ok) {
    return nullptr;
  }
  return exports;
}
