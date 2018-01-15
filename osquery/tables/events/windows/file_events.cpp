/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <future>
#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/windows/read_directory_changes.h"
#include "osquery/tables/events/event_utils.h"

namespace osquery {

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class FileEventSubscriber : public EventSubscriber<RDChangesEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  /// Walk the configuration's file paths, create subscriptions.
  void configure() override;

  /**
   * @brief This exports a single Callback for RDChangesEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the RDChangesEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const ECRef& ec, const SCRef& sc);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers FileEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(FileEventSubscriber, "event_subscriber", "file_events");

void FileEventSubscriber::configure() {
  removeSubscriptions();

  Config::get().files([this](const std::string& category,
                             const std::vector<std::string>& files) {
    for (const auto& file : files) {
      VLOG(1) << "Added file event listener to: " << file;
      auto sc = createSubscriptionContext();
      sc->path = file;
      sc->category = category;
      subscribe(&FileEventSubscriber::Callback, sc);
    }
  });
}

Status FileEventSubscriber::Callback(const ECRef& ec,
                                     const SCRef& sc) {
  if (ec->action.empty()) {
    return Status(0);
  }

  Row r;
  r["action"] = ec->action;
  r["target_path"] = ec->path;
  r["category"] = sc->category;
  r["transaction_id"] = INTEGER(0);

  // Add hashing and 'join' against the file table for stat-information.
  decorateFileEvent(
      ec->path, (ec->action == "CREATED" || ec->action == "UPDATED"), r);

  add(r);
  return Status(0, "OK");
}
}
