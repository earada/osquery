#pragma once

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <atlstr.h>
#include <winevt.h>

#include <map>
#include <vector>

#include <osquery/events.h>
#include "osquery/events/pathset.h"

#include "ReadDirectoryChangesPrivate.h"

namespace rdcp = ReadDirectoryChangesPrivate;

namespace osquery {

struct RDChangesSubscriptionContext : public SubscriptionContext {
 public:
  /// Subscription the following filesystem path.
  std::string path;

  /// A pattern with a recursive match was provided.
  bool recursive{false};

  /// Save the category this path originated form within the config.
  std::string category;

 private:
  /// Handle to the monitored folder
  HANDLE handle;

  /// Required parameter for ReadDirectoryChangesW().
  OVERLAPPED overlapped;

  /// A configure-time pattern was expanded to match absolute paths.
  bool recursive_match{false};

 private:
  friend class RDChangesEventPublisher;
};


struct RDChangesEventContext : public EventContext {
 public:
  /// A string path parsed from the event.
  std::string path;

  /// A string action representing the event action.
  std::string action;
};


// Message container
typedef std::pair<DWORD,CStringW> Message;

using RDChangesEventContextRef = std::shared_ptr<RDChangesEventContext>;
using RDChangesSubscriptionContextRef = std::shared_ptr<RDChangesSubscriptionContext>;

using ExcludePathSet = PathSet<patternedPath>;


/**
 * @brief An osquery EventPublisher for the Windows ReadDirectoryChanges API.
 *
 */
class RDChangesEventPublisher
    : public EventPublisher<RDChangesSubscriptionContext, RDChangesEventContext> {
  DECLARE_PUBLISHER("rdchanges");

 public:
  RDChangesEventPublisher() : queue(1000) {}

  virtual ~RDChangesEventPublisher() {
    tearDown();
  }

  /// Create a new thread for `Completion Routines`
  Status setUp() override;

  /// Called when configuration is loaded or updates occur.
  void configure() override;

  /// Another alias for `::end` or `::stop`.
  void tearDown() override;

  /// Entrypoint to the run loop
  Status run() override;

  /// Given a SubscriptionContext and EventContext match path and action.
  bool shouldFire(const RDChangesSubscriptionContextRef& sc,
                  const RDChangesEventContextRef& ec) const override;

 private:
  /// Build the set of excluded paths for which events are not to be propogated.
  void buildExcludePathsSet();

  /// Helper method to parse a subscription and add an equivalent monitor.
  std::set<std::string> monitorSubscription(RDChangesSubscriptionContextRef& sc);

  /**
   * @brief Add a monitor on this path.
   *
   * A recursive flag will tell addMonitor to enumerate all subdirectories
   * recursively and add monitors to them.
   *
   * @param path complete (non-glob) canonical path to monitor.
   * @param subscription context tracking the path.
   * @param recursive perform a single recursive search of subdirectories.
   * @param add_watch (testing only) should an inotify watch be created.
   * @return success if the monitor was created.
   */
  bool addMonitor(const std::string& path,
                  RDChangesSubscriptionContextRef& sc,
                  bool recursive);

  /// Count the number of subscriptioned paths.
  size_t numSubscriptionedPaths() const;

  /// Helper method to get a message from queue.
  bool Pop(DWORD& action, CStringW& filename);

 private:
  /// Set of paths to monitor, determined by a configure step.
  std::set<std::string> paths_;

  /// Events pertaining to these paths not to be propagated.
  ExcludePathSet exclude_paths_;

  /// Class to handle monitoring notifications.
  rdcp::CReadChangesServer* server{NULL};

  /// The CReadChangesServer executes in a dedicated thread.
  HANDLE thread;

  /// Thread identifier.
  unsigned int thread_id;

  /// Thread-safe queue to communicate with CReadChangesServer.
  rdcp::CThreadSafeQueue<Message> queue;

 public:
  friend class ReadDirectoryChangesTests;
  FRIEND_TEST(ReadDirectoryChangesTests, test_register_event_pub);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_match_subscription);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_recursion);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_embedded_wildcards);
};
}
