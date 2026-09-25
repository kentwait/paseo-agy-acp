#include <node_api.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include <libproc.h>

namespace {

constexpr int kMaximumPid = 2'147'483'647;
constexpr int kInventoryAttempts = 5;
constexpr uint64_t kMicrosecondsPerSecond = 1'000'000;
constexpr uint64_t kNanosecondsPerSecond = 1'000'000'000;

struct ProcessRecord {
  uint64_t boot_session_token;
  int pid;
  uint64_t process_start_micros;
  int ppid;
  int pgrp;
  int session;
};

uint64_t CombineTime(uint64_t seconds, uint64_t fraction, uint64_t fraction_limit, uint64_t scale,
                     const char* subject) {
  if (fraction >= fraction_limit || seconds == 0 || seconds > (UINT64_MAX - fraction) / scale) {
    throw std::runtime_error(std::string(subject) + " is out of range");
  }
  return seconds * scale + fraction * (scale / fraction_limit);
}

uint64_t ReadBootSessionToken() {
  struct timeval boot_time {};
  size_t size = sizeof(boot_time);
  if (sysctlbyname("kern.boottime", &boot_time, &size, nullptr, 0) != 0 || size != sizeof(boot_time) ||
      boot_time.tv_sec < 0 || boot_time.tv_usec < 0) {
    throw std::runtime_error("boot session evidence is unavailable");
  }
  return CombineTime(static_cast<uint64_t>(boot_time.tv_sec), static_cast<uint64_t>(boot_time.tv_usec),
                     kMicrosecondsPerSecond, kNanosecondsPerSecond, "boot session");
}

bool ReadBsdInfo(int pid, struct proc_bsdinfo* info, bool* gone) {
  errno = 0;
  const int bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, PROC_PIDTBSDINFO_SIZE);
  if (bytes == PROC_PIDTBSDINFO_SIZE) return true;
  if (bytes <= 0 && errno == ESRCH) {
    *gone = true;
    return false;
  }
  throw std::runtime_error("native process information is unavailable");
}

bool ReadProcessRecord(int pid, uint64_t boot_session_token, ProcessRecord* record, bool* gone) {
  struct proc_bsdinfo first {};
  if (!ReadBsdInfo(pid, &first, gone)) return false;

  errno = 0;
  const pid_t session = getsid(pid);
  if (session < 0) {
    if (errno == ESRCH) {
      *gone = true;
      return false;
    }
    throw std::runtime_error("native session evidence is unavailable");
  }

  struct proc_bsdinfo second {};
  if (!ReadBsdInfo(pid, &second, gone)) return false;
  if (first.pbi_pid != second.pbi_pid || first.pbi_ppid != second.pbi_ppid || first.pbi_pgid != second.pbi_pgid ||
      first.pbi_start_tvsec != second.pbi_start_tvsec || first.pbi_start_tvusec != second.pbi_start_tvusec) {
    throw std::runtime_error("native process information is inconsistent");
  }
  if (first.pbi_pid != static_cast<uint32_t>(pid) || first.pbi_ppid > static_cast<uint32_t>(kMaximumPid) ||
      first.pbi_pgid > static_cast<uint32_t>(kMaximumPid) || session > kMaximumPid ||
      first.pbi_start_tvusec >= kMicrosecondsPerSecond) {
    throw std::runtime_error("native process information is malformed");
  }

  record->boot_session_token = boot_session_token;
  record->pid = pid;
  record->process_start_micros =
      CombineTime(first.pbi_start_tvsec, first.pbi_start_tvusec, kMicrosecondsPerSecond,
                  kMicrosecondsPerSecond, "process start");
  record->ppid = static_cast<int>(first.pbi_ppid);
  record->pgrp = static_cast<int>(first.pbi_pgid);
  record->session = static_cast<int>(session);
  return true;
}

bool ReadProcessIds(int process_group, std::vector<int>* pids) {
  errno = 0;
  const int required_count = proc_listpgrppids(process_group, nullptr, 0);
  if (required_count < 0) throw std::runtime_error("native process inventory is unavailable");

  if (required_count > INT_MAX - 16 || required_count + 16 > INT_MAX / static_cast<int>(sizeof(pid_t))) {
    throw std::runtime_error("native process inventory is too large");
  }
  const int capacity_count = required_count + 16;
  const int capacity_bytes = capacity_count * static_cast<int>(sizeof(pid_t));
  std::vector<pid_t> buffer(static_cast<size_t>(capacity_count));
  errno = 0;
  const int filled_count = proc_listpgrppids(process_group, buffer.data(), capacity_bytes);
  if (filled_count < 0) throw std::runtime_error("native process inventory is malformed");
  if (filled_count >= capacity_count) return false;

  pids->clear();
  pids->reserve(static_cast<size_t>(filled_count));
  for (int index = 0; index < filled_count; ++index) {
    const pid_t pid = buffer[static_cast<size_t>(index)];
    if (pid <= 0 || pid > kMaximumPid) throw std::runtime_error("native process inventory is malformed");
    pids->push_back(static_cast<int>(pid));
  }
  std::sort(pids->begin(), pids->end());
  if (std::adjacent_find(pids->begin(), pids->end()) != pids->end()) {
    throw std::runtime_error("native process inventory is malformed");
  }
  return true;
}

std::vector<ProcessRecord> ReadStableInventory(int process_group, int session) {
  for (int attempt = 0; attempt < kInventoryAttempts; ++attempt) {
    std::vector<int> pids;
    if (!ReadProcessIds(process_group, &pids)) continue;

    const uint64_t boot_session_token = ReadBootSessionToken();
    std::vector<ProcessRecord> records;
    records.reserve(pids.size());
    bool incomplete = false;
    for (const int pid : pids) {
      ProcessRecord record {};
      bool gone = false;
      if (!ReadProcessRecord(pid, boot_session_token, &record, &gone)) {
        if (gone) {
          incomplete = true;
          break;
        }
        throw std::runtime_error("native process inventory is incomplete");
      }
      if (record.pgrp != process_group || record.session != session) continue;
      records.push_back(record);
    }
    if (incomplete) continue;
    std::vector<int> after;
    if (!ReadProcessIds(process_group, &after)) continue;
    if (pids != after || ReadBootSessionToken() != boot_session_token) continue;

    std::sort(records.begin(), records.end(),
              [](const ProcessRecord& left, const ProcessRecord& right) { return left.pid < right.pid; });
    return records;
  }
  throw std::runtime_error("native process inventory did not stabilize");
}

napi_value CreateString(napi_env environment, const std::string& value) {
  napi_value result = nullptr;
  if (napi_create_string_utf8(environment, value.data(), value.size(), &result) != napi_ok) {
    throw std::runtime_error("native string allocation failed");
  }
  return result;
}

std::string ToDecimal(uint64_t value) {
  return std::to_string(value);
}

void SetNamed(napi_env environment, napi_value object, const char* name, napi_value value) {
  if (napi_set_named_property(environment, object, name, value) != napi_ok) {
    throw std::runtime_error("native object construction failed");
  }
}

napi_value CreateDouble(napi_env environment, int value);

napi_value CreateProcessRecord(napi_env environment, const ProcessRecord& record) {
  napi_value result = nullptr;
  if (napi_create_object(environment, &result) != napi_ok) throw std::runtime_error("native object allocation failed");
  SetNamed(environment, result, "bootSessionToken",
           CreateString(environment, ToDecimal(record.boot_session_token)));
  SetNamed(environment, result, "pid", CreateDouble(environment, record.pid));
  SetNamed(environment, result, "processStartMicros",
           CreateString(environment, ToDecimal(record.process_start_micros)));
  SetNamed(environment, result, "ppid", CreateDouble(environment, record.ppid));
  SetNamed(environment, result, "pgrp", CreateDouble(environment, record.pgrp));
  SetNamed(environment, result, "session", CreateDouble(environment, record.session));
  return result;
}

napi_value CreateDouble(napi_env environment, int value) {
  napi_value result = nullptr;
  if (napi_create_double(environment, static_cast<double>(value), &result) != napi_ok) {
    throw std::runtime_error("native number allocation failed");
  }
  return result;
}

napi_value CreateGone(napi_env environment) {
  napi_value result = nullptr;
  napi_value status = CreateString(environment, "gone");
  if (napi_create_object(environment, &result) != napi_ok) throw std::runtime_error("native object allocation failed");
  SetNamed(environment, result, "status", status);
  return result;
}

napi_value CreateCapture(napi_env environment, const ProcessRecord& record) {
  napi_value result = nullptr;
  napi_value process = CreateProcessRecord(environment, record);
  if (napi_create_object(environment, &result) != napi_ok) throw std::runtime_error("native object allocation failed");
  SetNamed(environment, result, "status", CreateString(environment, "ok"));
  SetNamed(environment, result, "process", process);
  return result;
}

napi_value CreateInventory(napi_env environment, const std::vector<ProcessRecord>& records) {
  napi_value result = nullptr;
  napi_value complete = nullptr;
  napi_value processes = nullptr;
  if (napi_create_object(environment, &result) != napi_ok ||
      napi_get_boolean(environment, true, &complete) != napi_ok ||
      napi_create_array_with_length(environment, records.size(), &processes) != napi_ok) {
    throw std::runtime_error("native inventory allocation failed");
  }
  for (size_t index = 0; index < records.size(); ++index) {
    if (napi_set_element(environment, processes, static_cast<uint32_t>(index),
                         CreateProcessRecord(environment, records[index])) != napi_ok) {
      throw std::runtime_error("native inventory construction failed");
    }
  }
  SetNamed(environment, result, "status", CreateString(environment, "ok"));
  SetNamed(environment, result, "complete", complete);
  SetNamed(environment, result, "processes", processes);
  return result;
}

napi_value ThrowUnavailable(napi_env environment, const std::string& message) {
  napi_throw_error(environment, "EPROCESS_EVIDENCE", message.c_str());
  return nullptr;
}

napi_value CaptureProcess(napi_env environment, napi_callback_info information) {
  size_t argument_count = 1;
  napi_value arguments[1] = {nullptr};
  if (napi_get_cb_info(environment, information, &argument_count, arguments, nullptr, nullptr) != napi_ok ||
      argument_count != 1) {
    return ThrowUnavailable(environment, "native process capture arguments are invalid");
  }

  napi_valuetype type = napi_undefined;
  double pid_number = 0;
  if (napi_typeof(environment, arguments[0], &type) != napi_ok || type != napi_number ||
      napi_get_value_double(environment, arguments[0], &pid_number) != napi_ok || !std::isfinite(pid_number) ||
      pid_number < 1 ||
      pid_number > kMaximumPid || static_cast<double>(static_cast<int>(pid_number)) != pid_number) {
    return ThrowUnavailable(environment, "native process capture arguments are invalid");
  }

  const int pid = static_cast<int>(pid_number);
  try {
    const uint64_t boot_session_token = ReadBootSessionToken();
    ProcessRecord record {};
    bool gone = false;
    if (!ReadProcessRecord(pid, boot_session_token, &record, &gone)) {
      if (gone) return CreateGone(environment);
      throw std::runtime_error("native process information is incomplete");
    }
    if (ReadBootSessionToken() != boot_session_token) {
      throw std::runtime_error("boot session evidence changed during capture");
    }
    return CreateCapture(environment, record);
  } catch (const std::exception& error) {
    return ThrowUnavailable(environment, error.what());
  }
}

napi_value ListProcesses(napi_env environment, napi_callback_info information) {
  size_t argument_count = 2;
  napi_value arguments[2] = {nullptr, nullptr};
  if (napi_get_cb_info(environment, information, &argument_count, arguments, nullptr, nullptr) != napi_ok ||
      argument_count != 2) {
    return ThrowUnavailable(environment, "native process inventory arguments are invalid");
  }

  napi_valuetype process_group_type = napi_undefined;
  napi_valuetype session_type = napi_undefined;
  double process_group_number = 0;
  double session_number = 0;
  if (napi_typeof(environment, arguments[0], &process_group_type) != napi_ok ||
      napi_typeof(environment, arguments[1], &session_type) != napi_ok ||
      process_group_type != napi_number || session_type != napi_number ||
      napi_get_value_double(environment, arguments[0], &process_group_number) != napi_ok ||
      napi_get_value_double(environment, arguments[1], &session_number) != napi_ok ||
      !std::isfinite(process_group_number) || !std::isfinite(session_number) || process_group_number < 0 ||
      session_number < 0 || process_group_number > kMaximumPid || session_number > kMaximumPid ||
      static_cast<double>(static_cast<int>(process_group_number)) != process_group_number ||
      static_cast<double>(static_cast<int>(session_number)) != session_number) {
    return ThrowUnavailable(environment, "native process inventory arguments are invalid");
  }

  try {
    return CreateInventory(
        environment, ReadStableInventory(static_cast<int>(process_group_number), static_cast<int>(session_number)));
  } catch (const std::exception& error) {
    return ThrowUnavailable(environment, error.what());
  }
}

}

NAPI_MODULE_INIT() {
  napi_env environment = env;
  napi_value capture = nullptr;
  napi_value list = nullptr;
  if (napi_create_function(environment, "captureProcess", NAPI_AUTO_LENGTH, CaptureProcess, nullptr, &capture) !=
          napi_ok ||
      napi_create_function(environment, "listProcesses", NAPI_AUTO_LENGTH, ListProcesses, nullptr, &list) != napi_ok ||
      napi_set_named_property(environment, exports, "captureProcess", capture) != napi_ok ||
      napi_set_named_property(environment, exports, "listProcesses", list) != napi_ok) {
    return ThrowUnavailable(environment, "native process evidence initialization failed");
  }
  return exports;
}
