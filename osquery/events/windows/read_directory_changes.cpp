#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/events/windows/read_directory_changes.h"

namespace fs = boost::filesystem;

namespace osquery {

std::map<int, std::string> kMaskActions = {
    {FILE_ACTION_ADDED, "CREATED"},
    {FILE_ACTION_REMOVED, "DELETED"},
    {FILE_ACTION_MODIFIED, "UPDATED"},
    {FILE_ACTION_RENAMED_OLD_NAME, "MOVED_FROM"},
    {FILE_ACTION_RENAMED_NEW_NAME, "MOVED_TO"},
};

REGISTER(RDChangesEventPublisher, "event_publisher", "rdchanges");

Status RDChangesEventPublisher::setUp() {
  thread = NULL;
  thread_id = 0;
  server = new rdcp::CReadChangesServer(&queue);
  return Status(0, "OK");
}

void RDChangesEventPublisher::tearDown() {
  if (thread) {
    ::QueueUserAPC(rdcp::CReadChangesServer::TerminateProc,
                   thread,
                   (ULONG_PTR)server);
    ::WaitForSingleObjectEx(thread, 10000, true);
    ::CloseHandle(thread);

    thread = NULL;
    thread_id = 0;
  }
  if (server) {
    delete server;
  }
}

void RDChangesEventPublisher::configure() {
  buildExcludePathsSet();

  paths_.clear();
  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    auto paths = monitorSubscription(sc);
    paths_.insert(paths.begin(), paths.end());
  }
}

std::set<std::string> RDChangesEventPublisher::monitorSubscription(
    RDChangesSubscriptionContextRef& sc) {
  std::set<std::string> rpaths;
  std::string discovered = sc->path;
  if (sc->path.find("**") != std::string::npos) {
    sc->recursive = true;
    discovered = sc->path.substr(0, sc->path.find("**"));
    sc->path = discovered;
  }
  if (sc->path.find('*') != std::string::npos) {
    // If the wildcard exists within the file (leaf), remove and monitor the
    // directory instead. Apply a fnmatch on fired events to filter leafs.
    auto fullpath = fs::path(sc->path);
    if (fullpath.filename().string().find('*') != std::string::npos) {
      discovered = fullpath.parent_path().string() + '/';
    }

    if (discovered.find('*') != std::string::npos) {
      // If a wildcard exists within the tree (stem), resolve at configure
      // time and monitor each path.
      std::vector<std::string> paths;
      resolveFilePattern(discovered, paths);
      sc->recursive_match = sc->recursive;
      for (const auto& _path : paths) {
        rpaths.insert(_path);
        addMonitor(_path, sc, sc->recursive);
      }
      return rpaths;
    }
  }

  if (isDirectory(discovered) && discovered.back() != '/') {
    sc->path += '/';
    discovered += '/';
  }

  addMonitor(discovered, sc, sc->recursive);
  rpaths.insert(discovered);
  return rpaths;
}

void RDChangesEventPublisher::buildExcludePathsSet() {
  auto parser = Config::getParser("file_paths");

  WriteLock lock(subscription_lock_);
  exclude_paths_.clear();
  for (const auto& excl_category :
       parser->getData().get_child("exclude_paths")) {
    for (const auto& excl_path : excl_category.second) {
      auto pattern = excl_path.second.get_value<std::string>("");
      if (pattern.empty()) {
        continue;
      }
      exclude_paths_.insert(pattern);
    }
  }
}

bool RDChangesEventPublisher::addMonitor(const std::string& path,
                                       RDChangesSubscriptionContextRef& sc,
                                       bool recursive) {
  {
    rdcp::CReadChangesRequest* request;
    const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME
                         | FILE_NOTIFY_CHANGE_DIR_NAME
                         | FILE_NOTIFY_CHANGE_ATTRIBUTES
                         | FILE_NOTIFY_CHANGE_SIZE
                         | FILE_NOTIFY_CHANGE_LAST_WRITE
                         | FILE_NOTIFY_CHANGE_SECURITY;
    if (!thread)
      thread = (HANDLE)_beginthreadex(NULL, 0, rdcp::CReadChangesServer::ThreadStartProc,
                                      server, 0, &thread_id);
    request = new rdcp::CReadChangesRequest(server, path.c_str(), recursive, filter, 16384);
    QueueUserAPC(rdcp::CReadChangesServer::AddDirectoryProc, thread, (ULONG_PTR)request);
  }
  return true;
}

Status RDChangesEventPublisher::run() {
  const HANDLE handles[] = { queue.GetWaitHandle() };
  DWORD rc = ::WaitForMultipleObjectsEx(_countof(handles), handles, false, INFINITE, true);
  switch (rc) {
    case WAIT_OBJECT_0 + 0:
      {
        DWORD action;
        CStringW filename;
        if (queue.overflow()) {
          VLOG(1) << "Read Directory Changes queue was overflown";
          queue.clear();
        } else {
          this->Pop(action, filename);
          auto ec = createEventContext();
          ec->path = CStringA(filename);
          for (const auto& item: kMaskActions) {
            if (action & item.first) {
              ec->action = item.second;
              break;
            }
          }
          if (!ec->action.empty()) {
            VLOG(1) << "Fire: " << ec->action << ": " << ec->path;
            fire(ec);
          }
        }
      }
      break;
  }
  return Status(0, "OK");
}

bool RDChangesEventPublisher::shouldFire(const RDChangesSubscriptionContextRef& sc,
                                         const RDChangesEventContextRef& ec) const {
  // exclude paths should be applied at last
  auto path = ec->path.substr(0, ec->path.rfind('/'));
  // Need to have two finds,
  // what if somebody excluded an individual file inside a directory
  if (!exclude_paths_.empty() &&
      (exclude_paths_.find(path) || exclude_paths_.find(ec->path))) {
    return false;
  }
  return true;
}

size_t RDChangesEventPublisher::numSubscriptionedPaths() const {
  return paths_.size();
}

bool RDChangesEventPublisher::Pop(DWORD& action, CStringW& filename) {
  Message pair;
  if (!queue.pop(pair))
    return false;
  action = pair.first;
  filename = pair.second;
  return true;
}
}
