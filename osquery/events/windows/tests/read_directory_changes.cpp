#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/events/windows/read_directory_changes.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

const int kMaxEventLatency = 3000;

class ReadDirectoryChangesTests : public testing::Test {
 protected:
  void SetUp() override {
    // ReadDirectoryChanges will use data from the config and config parsers.
    Registry::get().registry("config_parser")->setUp();

    // Create a basic path trigger, this is a file path.
    real_test_path = kTestWorkingDirectory + "rdchanges-trigger" +
                     std::to_string(rand() % 10000 + 10000);
    // Create a similar directory for embedded paths and directories.
    real_test_dir = kTestWorkingDirectory + "rdchanges-triggers" +
                    std::to_string(rand() % 10000 + 10000);

    // Create the embedded paths.
    real_test_dir_path = real_test_dir + "/1";
    real_test_sub_dir = real_test_dir + "/2";
    real_test_sub_dir_path = real_test_sub_dir + "/1";
  }

  void TearDown() override {
    // End the event loops, and join on the threads.
    removePath(real_test_dir);
  }

  void StartEventLoop() {
    event_pub_ = std::make_shared<RDChangesEventPublisher>();
    auto status = EventFactory::registerEventPublisher(event_pub_);
    FILE* fd = fopen(real_test_path.c_str(), "w");
    fclose(fd);
    temp_thread_ = std::thread(EventFactory::run, "rdchanges");
  }

  void StopEventLoop() {
    while (!event_pub_->hasStarted()) {
	  std::this_thread::sleep_for(std::chrono::microseconds(20));
    }

    EventFactory::end(true);
    temp_thread_.join();
  }

  void SubscriptionAction(const std::string& path,
                          EventCallback ec = nullptr) {
    auto sc = std::make_shared<RDChangesSubscriptionContext>();
    sc->path = path;

    EventFactory::addSubscription("rdchanges", "TestSubscriber", sc, ec);
    event_pub_->configure();
  }

  bool WaitForEvents(size_t max, size_t num_events = 0) {
    size_t delay = 0;
    while (delay <= max * 1000) {
      if (num_events > 0 && event_pub_->numEvents() >= num_events) {
        return true;
      } else if (num_events == 0 && event_pub_->numEvents() > 0) {
        return true;
      }
      delay += 50;
	  std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    return false;
  }

  void TriggerEvent(const std::string& path) {
    FILE* fd = fopen(path.c_str(), "w");
    fputs("rdchanges", fd);
    fclose(fd);
  }

  void RemoveAll(std::shared_ptr<RDChangesEventPublisher>& pub) {
    pub->subscriptions_.clear();
  }

 protected:
  /// Internal state managers: publisher reference.
  std::shared_ptr<RDChangesEventPublisher> event_pub_{nullptr};

  /// Internal state managers: event publisher thread.
  std::thread temp_thread_;

  /// Transient paths ./rdchanges-trigger.
  std::string real_test_path;

  /// Transient paths ./rdchanges-triggers/.
  std::string real_test_dir;

  /// Transient paths ./rdchanges-triggers/1.
  std::string real_test_dir_path;

  /// Transient paths ./rdchanges-triggers/2/.
  std::string real_test_sub_dir;

  /// Transient paths ./rdchanges-triggers/2/1.
  std::string real_test_sub_dir_path;
};

TEST_F(ReadDirectoryChangesTests, test_register_event_pub) {
  auto pub = std::make_shared<RDChangesEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventPublishers(), 1U);
  // And deregister
  status = EventFactory::deregisterEventPublisher("rdchanges");
  EXPECT_TRUE(status.ok());
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_add_subscription_missing_path) {
  auto pub = std::make_shared<RDChangesEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  // This subscription path is fake, and will succeed.
  auto mc = std::make_shared<RDChangesSubscriptionContext>();
  mc->path = "/this/path/is/fake";

  auto subscription = Subscription::create("TestSubscriber", mc);
  auto status = EventFactory::addSubscription("rdchanges", subscription);
  EXPECT_TRUE(status.ok());
  EventFactory::deregisterEventPublisher("rdchanges");
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_add_subscription_success) {
  auto pub = std::make_shared<RDChangesEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  // This subscription path *should* be real.
  auto mc = std::make_shared<RDChangesSubscriptionContext>();

  auto subscription = Subscription::create("TestSubscriber", mc);
  auto status = EventFactory::addSubscription("rdchanges", subscription);
  EXPECT_TRUE(status.ok());
  EventFactory::deregisterEventPublisher("rdchanges");
}


TEST_F(ReadDirectoryChangesTests, test_rdchanges_match_subscription) {
  auto event_pub = std::make_shared<RDChangesEventPublisher>();
  EventFactory::registerEventPublisher(event_pub);

  auto sc = event_pub->createSubscriptionContext();
  sc->path = "C:\\Windows\\%%";
  replaceGlobWildcards(sc->path);
  auto subscription = Subscription::create("TestSubscriber", sc);
  auto status = EventFactory::addSubscription("rdchanges", subscription);
  EXPECT_TRUE(status.ok());
  event_pub->configure();

  std::vector<std::string> exclude_paths = {"C:\\Windows\\System\\%%",
                                            "C:\\Windows\\",
                                            "C:\\Windows\\System32\\calc.exe",
                                            "C:\\"};
  for (const auto& path : exclude_paths) {
    event_pub->exclude_paths_.insert(path);
  }

  {
    auto ec = event_pub->createEventContext();
    ec->path = "C:\\";
    EXPECT_FALSE(event_pub->shouldFire(sc, ec));
    ec->path = "C:\\Windows";
    EXPECT_FALSE(event_pub->shouldFire(sc, ec));
    ec->path = "C:\\Windows\\System";
    EXPECT_FALSE(event_pub->shouldFire(sc, ec));
    ec->path = "C:\\Windows\\System32\\calc.exe";
    EXPECT_FALSE(event_pub->shouldFire(sc, ec));
    ec->path = "C:\\Windows\\System32\\cmd.exe";
    EXPECT_TRUE(event_pub->shouldFire(sc, ec));
  }
  EventFactory::deregisterEventPublisher("fsevents");
}

class TestRDChangesEventSubscriber
    : public EventSubscriber<RDChangesEventPublisher> {
 public:
  TestRDChangesEventSubscriber() {
    setName("TestRDChangesEventSubscriber");
  }

  Status init() override {
    callback_count_ = 0;
    return Status(0, "OK");
  }

  Status SimpleCallback(const ECRef& ec, const SCRef& sc) {
    callback_count_ += 1;
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc) {
    // The following comments are an example Callback routine.
    // Row r;
    // r["action"] = ec->action;
    // r["path"] = ec->path;

    // Normally would call Add here.
    callback_count_++;

    WriteLock lock(actions_lock_);
    actions_.push_back(ec->action);
    return Status(0, "OK");
  }

  SCRef GetSubscription(const std::string& path) {
    auto mc = createSubscriptionContext();
    mc->path = path;
    return mc;
  }

  void WaitForEvents(int max, int num_events = 1) {
    int delay = 0;
    while (delay < max * 1000) {
      if (callback_count_ >= num_events) {
        return;
      }
	  std::this_thread::sleep_for(std::chrono::microseconds(50));
      delay += 50;
    }
  }

  std::vector<std::string> actions() {
    WriteLock lock(actions_lock_);
    return actions_;
  }

  int count() {
    return callback_count_;
  }

 public:
  std::atomic<int> callback_count_{0};
  std::vector<std::string> actions_;

 private:
  Mutex actions_lock_;

 private:
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_run);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_fire_event);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_event_action);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_directory_watch);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_recursion);
  FRIEND_TEST(ReadDirectoryChangesTests, test_rdchanges_embedded_wildcards);
};

TEST_F(ReadDirectoryChangesTests, test_rdchanges_run) {
  // Assume event type is registered.
  event_pub_ = std::make_shared<RDChangesEventPublisher>();
  auto status = EventFactory::registerEventPublisher(event_pub_);
  EXPECT_TRUE(status.ok());

  // Create a temporary file to watch, open writeable
  FILE* fd = fopen(real_test_path.c_str(), "w");

  // Create a subscriber.
  auto sub = std::make_shared<TestRDChangesEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Create a subscription context
  auto mc = std::make_shared<RDChangesSubscriptionContext>();
  mc->path = real_test_path;
  status = EventFactory::addSubscription("rdchanges",
      Subscription::create("TestRDChangesEventSubscriber", mc));
  EXPECT_TRUE(status.ok());
  event_pub_->configure();

  // Create an event loop thread (similar to main)
  std::thread temp_thread(EventFactory::run, "rdchanges");
  EXPECT_TRUE(event_pub_->numEvents() == 0);

  // Cause an rdchanges event by writing to the watched path.
  fputs("rdchanges", fd);
  fclose(fd);

  // Wait for the thread's run loop to select.
  WaitForEvents(kMaxEventLatency);
  EXPECT_TRUE(event_pub_->numEvents() > 0);
  EventFactory::end();
  temp_thread.join();
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_fire_event) {
  // Assume event type is registered.
  StartEventLoop();
  auto sub = std::make_shared<TestRDChangesEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Create a subscriptioning context, note the added Event to the symbol
  auto sc = sub->GetSubscription(real_test_path);
  sub->subscribe(&TestRDChangesEventSubscriber::SimpleCallback, sc);
  event_pub_->configure();

  TriggerEvent(real_test_path);
  sub->WaitForEvents(kMaxEventLatency);

  // Make sure our expected event fired (aka subscription callback was called).
  EXPECT_TRUE(sub->count() > 0);
  StopEventLoop();
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_event_action) {
  // Assume event type is registered.
  StartEventLoop();
  auto sub = std::make_shared<TestRDChangesEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  auto sc = sub->GetSubscription(real_test_path);
  sub->subscribe(&TestRDChangesEventSubscriber::Callback, sc);
  event_pub_->configure();

  TriggerEvent(real_test_path);
  sub->WaitForEvents(kMaxEventLatency, 2);

  // Make sure the rdchanges action was expected.
  EXPECT_GT(sub->actions().size(), 0U);
  if (sub->actions().size() >= 2) {
    EXPECT_EQ(sub->actions()[0], "UPDATED");
  }
  StopEventLoop();
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_directory_watch) {
  StartEventLoop();

  auto sub = std::make_shared<TestRDChangesEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  fs::create_directory(real_test_dir);
  fs::create_directory(real_test_sub_dir);

  // Subscribe to the directory inode
  auto mc = sub->createSubscriptionContext();
  mc->path = real_test_dir;
  mc->recursive = true;
  sub->subscribe(&TestRDChangesEventSubscriber::Callback, mc);
  event_pub_->configure();

  // Trigger on a subdirectory's file.
  TriggerEvent(real_test_sub_dir_path);

  sub->WaitForEvents(kMaxEventLatency, 1);
  EXPECT_TRUE(sub->count() > 0);
  StopEventLoop();
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_recursion) {
  // Create a non-registered publisher and subscriber.
  auto pub = std::make_shared<RDChangesEventPublisher>();
  EventFactory::registerEventPublisher(pub);
  auto sub = std::make_shared<TestRDChangesEventSubscriber>();

  // Create a mock directory structure.
  createMockFileStructure();

  // Create and test several subscriptions.
  auto sc = sub->createSubscriptionContext();

  sc->path = kFakeDirectory + "/*";
  sub->subscribe(&TestRDChangesEventSubscriber::Callback, sc);
  // Trigger a configure step manually.
  pub->configure();

  // Expect a single monitor on the root of the fake tree.
  EXPECT_EQ(event_pub_->numSubscriptionedPaths(), 1U);
  EXPECT_EQ(event_pub_->paths_.count(kFakeDirectory + "/"), 1U);
  RemoveAll(pub);

  // Make sure monitors are empty.
  EXPECT_EQ(event_pub_->numSubscriptionedPaths(), 1U);

  auto sc2 = sub->createSubscriptionContext();
  sc2->path = kFakeDirectory + "/**";
  sub->subscribe(&TestRDChangesEventSubscriber::Callback, sc2);
  pub->configure();

  // Expect only the directories to be monitored.
  EXPECT_EQ(event_pub_->numSubscriptionedPaths(), 11U);
  RemoveAll(pub);

  // Use a directory structure that includes a loop.
  boost::system::error_code ec;
  fs::create_symlink(kFakeDirectory, kFakeDirectory + "/link", ec);

  auto sc3 = sub->createSubscriptionContext();
  sc3->path = kFakeDirectory + "/**";
  sub->subscribe(&TestRDChangesEventSubscriber::Callback, sc3);
  pub->configure();

  // Also expect canonicalized resolution (to prevent loops).
  EXPECT_EQ(event_pub_->numSubscriptionedPaths(), 11U);
  RemoveAll(pub);

  // Remove mock directory structure.
  tearDownMockFileStructure();
  EventFactory::deregisterEventPublisher("rdchanges");
}

TEST_F(ReadDirectoryChangesTests, test_rdchanges_embedded_wildcards) {
  // Assume event type is not registered.
  event_pub_ = std::make_shared<RDChangesEventPublisher>();
  EventFactory::registerEventPublisher(event_pub_);

  auto sub = std::make_shared<TestRDChangesEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Create ./rdchanges-triggers/2/1/.
  fs::create_directories(real_test_dir + "/2/1");

  // Create a subscription to match an embedded wildcard: "*"
  // The assumption is a watch will be created on the 'most-specific' directory
  // before the wildcard request.
  auto mc = sub->createSubscriptionContext();
  mc->path = real_test_dir + "/*/1";
  mc->recursive = true;
  sub->subscribe(&TestRDChangesEventSubscriber::Callback, mc);

  // Now the publisher must be configured.
  event_pub_->configure();

  // Assume there is one watched path: real_test_dir.
  ASSERT_EQ(event_pub_->numSubscriptionedPaths(), 1U);
  EXPECT_EQ(event_pub_->paths_.count(real_test_dir + "/2/1/"), 1U);
}
}
