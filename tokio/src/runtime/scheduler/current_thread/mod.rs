use crate::loom::sync::atomic::AtomicBool;
use crate::loom::sync::Arc;
use crate::runtime::driver::{self, Driver};
use crate::runtime::scheduler::{self, Defer, Inject};
use crate::runtime::task::{
    self, JoinHandle, OwnedTasks, Schedule, Task, TaskHarnessScheduleHooks,
};
use crate::runtime::{
    blocking, context, Config, MetricsBatch, SchedulerMetrics, TaskHooks, TaskMeta, WorkerMetrics,
};
use crate::sync::notify::Notify;
use crate::util::atomic_cell::AtomicCell;
use crate::util::{waker_ref, RngSeedGenerator, Wake, WakerRef};

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::sync::atomic::Ordering::{AcqRel, Release};
use std::task::Poll::{Pending, Ready};
use std::task::Waker;
use std::thread::ThreadId;
use std::time::Duration;
use std::{fmt, thread};
use fstack::*;
use std::ptr::addr_of_mut;
use std::mem::MaybeUninit;
use std::os::raw::c_void;

/// Executes tasks on the current thread
pub(crate) struct CurrentThread {
    /// Core scheduler data is acquired by a thread entering `block_on`.
    core: AtomicCell<Core>,

    /// Notifier for waking up other threads to steal the
    /// driver.
    notify: Notify,
}

/// Handle to the current thread scheduler
pub(crate) struct Handle {
    /// Scheduler state shared across threads
    shared: Shared,

    /// Resource driver handles
    pub(crate) driver: driver::Handle,

    /// Blocking pool spawner
    pub(crate) blocking_spawner: blocking::Spawner,

    /// Current random number generator seed
    pub(crate) seed_generator: RngSeedGenerator,

    /// User-supplied hooks to invoke for things
    pub(crate) task_hooks: TaskHooks,

    /// If this is a `LocalRuntime`, flags the owning thread ID.
    pub(crate) local_tid: Option<ThreadId>,
}

/// Data required for executing the scheduler. The struct is passed around to
/// a function that will perform the scheduling work and acts as a capability token.
struct Core {
    /// Scheduler run queue
    tasks: VecDeque<Notified>,

    /// Current tick
    tick: u32,

    /// Runtime driver
    ///
    /// The driver is removed before starting to park the thread
    driver: Option<Driver>,

    /// Metrics batch
    metrics: MetricsBatch,

    /// How often to check the global queue
    global_queue_interval: u32,

    /// True if a task panicked without being handled and the runtime is
    /// configured to shutdown on unhandled panic.
    unhandled_panic: bool,
}

/// Scheduler state shared between threads.
struct Shared {
    /// Remote run queue
    inject: Inject<Arc<Handle>>,

    /// Collection of all active tasks spawned onto this executor.
    owned: OwnedTasks<Arc<Handle>>,

    /// Indicates whether the blocked on thread was woken.
    woken: AtomicBool,

    /// Scheduler configuration options
    config: Config,

    /// Keeps track of various runtime metrics.
    scheduler_metrics: SchedulerMetrics,

    /// This scheduler only has one worker.
    worker_metrics: WorkerMetrics,
}

/// Thread-local context.
///
/// pub(crate) to store in `runtime::context`.
pub(crate) struct Context {
    /// Scheduler handle
    handle: Arc<Handle>,

    /// Scheduler core, enabling the holder of `Context` to execute the
    /// scheduler.
    core: RefCell<Option<Box<Core>>>,

    /// Deferred tasks, usually ones that called `task::yield_now()`.
    pub(crate) defer: Defer,
}

type Notified = task::Notified<Arc<Handle>>;

/// Initial queue capacity.
const INITIAL_CAPACITY: usize = 64;

/// Used if none is specified. This is a temporary constant and will be removed
/// as we unify tuning logic between the multi-thread and current-thread
/// schedulers.
const DEFAULT_GLOBAL_QUEUE_INTERVAL: u32 = 31;

impl CurrentThread {
    pub(crate) fn new(
        driver: Driver,
        driver_handle: driver::Handle,
        blocking_spawner: blocking::Spawner,
        seed_generator: RngSeedGenerator,
        config: Config,
        local_tid: Option<ThreadId>,
    ) -> (CurrentThread, Arc<Handle>) {
        let worker_metrics = WorkerMetrics::from_config(&config);
        worker_metrics.set_thread_id(thread::current().id());

        // Get the configured global queue interval, or use the default.
        let global_queue_interval = config
            .global_queue_interval
            .unwrap_or(DEFAULT_GLOBAL_QUEUE_INTERVAL);

        let handle = Arc::new(Handle {
            task_hooks: TaskHooks {
                task_spawn_callback: config.before_spawn.clone(),
                task_terminate_callback: config.after_termination.clone(),
                #[cfg(tokio_unstable)]
                before_poll_callback: config.before_poll.clone(),
                #[cfg(tokio_unstable)]
                after_poll_callback: config.after_poll.clone(),
            },
            shared: Shared {
                inject: Inject::new(),
                owned: OwnedTasks::new(1),
                woken: AtomicBool::new(false),
                config,
                scheduler_metrics: SchedulerMetrics::new(),
                worker_metrics,
            },
            driver: driver_handle,
            blocking_spawner,
            seed_generator,
            local_tid,
        });

        let core = AtomicCell::new(Some(Box::new(Core {
            tasks: VecDeque::with_capacity(INITIAL_CAPACITY),
            tick: 0,
            driver: Some(driver),
            metrics: MetricsBatch::new(&handle.shared.worker_metrics),
            global_queue_interval,
            unhandled_panic: false,
        })));

        let scheduler = CurrentThread {
            core,
            notify: Notify::new(),
        };

        (scheduler, handle)
    }

    #[track_caller]
    pub(crate) fn block_on<F: Future>(&self, handle: &scheduler::Handle, future: F) -> F::Output {
        pin!(future);

        crate::runtime::context::enter_runtime(handle, false, |blocking| {
            let handle = handle.as_current_thread();

            // Attempt to steal the scheduler core and block_on the future if we can
            // there, otherwise, lets select on a notification that the core is
            // available or the future is complete.
            loop {
                if let Some(core) = self.take_core(handle) {
                    handle
                        .shared
                        .worker_metrics
                        .set_thread_id(thread::current().id());
                    return core.block_on(future);
                } else {
                    let notified = self.notify.notified();
                    pin!(notified);

                    if let Some(out) = blocking
                        .block_on(poll_fn(|cx| {
                            if notified.as_mut().poll(cx).is_ready() {
                                return Ready(None);
                            }

                            if let Ready(out) = future.as_mut().poll(cx) {
                                return Ready(Some(out));
                            }

                            Pending
                        }))
                        .expect("Failed to `Enter::block_on`")
                    {
                        return out;
                    }
                }
            }
        })
    }

    fn take_core(&self, handle: &Arc<Handle>) -> Option<CoreGuard<'_>> {
        let core = self.core.take()?;

        Some(CoreGuard {
            context: scheduler::Context::CurrentThread(Context {
                handle: handle.clone(),
                core: RefCell::new(Some(core)),
                defer: Defer::new(),
            }),
            scheduler: self,
        })
    }

    pub(crate) fn shutdown(&mut self, handle: &scheduler::Handle) {
        let handle = handle.as_current_thread();

        // Avoid a double panic if we are currently panicking and
        // the lock may be poisoned.

        let core = match self.take_core(handle) {
            Some(core) => core,
            None if std::thread::panicking() => return,
            None => panic!("Oh no! We never placed the Core back, this is a bug!"),
        };

        // Check that the thread-local is not being destroyed
        let tls_available = context::with_current(|_| ()).is_ok();

        if tls_available {
            core.enter(|core, _context| {
                let core = shutdown2(core, handle);
                (core, ())
            });
        } else {
            // Shutdown without setting the context. `tokio::spawn` calls will
            // fail, but those will fail either way because the thread-local is
            // not available anymore.
            let context = core.context.expect_current_thread();
            let core = context.core.borrow_mut().take().unwrap();

            let core = shutdown2(core, handle);
            *context.core.borrow_mut() = Some(core);
        }
    }
}

fn shutdown2(mut core: Box<Core>, handle: &Handle) -> Box<Core> {
    // Drain the OwnedTasks collection. This call also closes the
    // collection, ensuring that no tasks are ever pushed after this
    // call returns.
    handle.shared.owned.close_and_shutdown_all(0);

    // Drain local queue
    // We already shut down every task, so we just need to drop the task.
    while let Some(task) = core.next_local_task(handle) {
        drop(task);
    }

    // Close the injection queue
    handle.shared.inject.close();

    // Drain remote queue
    while let Some(task) = handle.shared.inject.pop() {
        drop(task);
    }

    assert!(handle.shared.owned.is_empty());

    // Submit metrics
    core.submit_metrics(handle);

    // Shutdown the resource drivers
    if let Some(driver) = core.driver.as_mut() {
        driver.shutdown(&handle.driver);
    }

    core
}

impl fmt::Debug for CurrentThread {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("CurrentThread").finish()
    }
}

// ===== impl Core =====

impl Core {
    /// Get and increment the current tick
    fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    fn next_task(&mut self, handle: &Handle) -> Option<Notified> {
        if self.tick % self.global_queue_interval == 0 {
            handle
                .next_remote_task()
                .or_else(|| self.next_local_task(handle))
        } else {
            self.next_local_task(handle)
                .or_else(|| handle.next_remote_task())
        }
    }

    fn next_local_task(&mut self, handle: &Handle) -> Option<Notified> {
        let ret = self.tasks.pop_front();
        handle
            .shared
            .worker_metrics
            .set_queue_depth(self.tasks.len());
        ret
    }

    fn push_task(&mut self, handle: &Handle, task: Notified) {
        self.tasks.push_back(task);
        self.metrics.inc_local_schedule_count();
        handle
            .shared
            .worker_metrics
            .set_queue_depth(self.tasks.len());
    }

    fn submit_metrics(&mut self, handle: &Handle) {
        self.metrics.submit(&handle.shared.worker_metrics, 0);
    }
}

#[cfg(tokio_taskdump)]
fn wake_deferred_tasks_and_free(context: &Context) {
    let wakers = context.defer.take_deferred();
    for waker in wakers {
        waker.wake();
    }
}

// ===== impl Context =====

impl Context {
    /// Execute the closure with the given scheduler core stored in the
    /// thread-local context.
    fn run_task<R>(&self, mut core: Box<Core>, f: impl FnOnce() -> R) -> (Box<Core>, R) {
        core.metrics.start_poll();
        let mut ret = self.enter(core, || crate::task::coop::budget(f));
        ret.0.metrics.end_poll();
        ret
    }

    /// Blocks the current thread until an event is received by the driver,
    /// including I/O events, timer events, ...
    fn park(&self, mut core: Box<Core>, handle: &Handle) -> Box<Core> {
        let mut driver = core.driver.take().expect("driver missing");

        if let Some(f) = &handle.shared.config.before_park {
            let (c, ()) = self.enter(core, || f());
            core = c;
        }

        // This check will fail if `before_park` spawns a task for us to run
        // instead of parking the thread
        if core.tasks.is_empty() {
            // Park until the thread is signaled
            core.metrics.about_to_park();
            core.submit_metrics(handle);

            let (c, ()) = self.enter(core, || {
                driver.park(&handle.driver);
                self.defer.wake();
            });

            core = c;

            core.metrics.unparked();
            core.submit_metrics(handle);
        }

        if let Some(f) = &handle.shared.config.after_unpark {
            let (c, ()) = self.enter(core, || f());
            core = c;
        }

        core.driver = Some(driver);
        core
    }

    /// Checks the driver for new events without blocking the thread.
    fn park_yield(&self, mut core: Box<Core>, handle: &Handle) -> Box<Core> {
        let mut driver = core.driver.take().expect("driver missing");

        core.submit_metrics(handle);

        let (mut core, ()) = self.enter(core, || {
            driver.park_timeout(&handle.driver, Duration::from_millis(0));
            self.defer.wake();
        });

        core.driver = Some(driver);
        core
    }

    fn enter<R>(&self, core: Box<Core>, f: impl FnOnce() -> R) -> (Box<Core>, R) {
        // Store the scheduler core in the thread-local context
        //
        // A drop-guard is employed at a higher level.
        *self.core.borrow_mut() = Some(core);

        // Execute the closure while tracking the execution budget
        let ret = f();

        // Take the scheduler core back
        let core = self.core.borrow_mut().take().expect("core missing");
        (core, ret)
    }

    pub(crate) fn defer(&self, waker: &Waker) {
        self.defer.defer(waker);
    }
}

// ===== impl Handle =====

impl Handle {
    /// Spawns a future onto the `CurrentThread` scheduler
    pub(crate) fn spawn<F>(
        me: &Arc<Self>,
        future: F,
        id: crate::runtime::task::Id,
    ) -> JoinHandle<F::Output>
    where
        F: crate::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (handle, notified) = me.shared.owned.bind(future, me.clone(), id);

        me.task_hooks.spawn(&TaskMeta {
            id,
            _phantom: Default::default(),
        });

        if let Some(notified) = notified {
            me.schedule(notified);
        }

        handle
    }

    /// Spawn a task which isn't safe to send across thread boundaries onto the runtime.
    ///
    /// # Safety
    /// This should only be used when this is a `LocalRuntime` or in another case where the runtime
    /// provably cannot be driven from or moved to different threads from the one on which the task
    /// is spawned.
    pub(crate) unsafe fn spawn_local<F>(
        me: &Arc<Self>,
        future: F,
        id: crate::runtime::task::Id,
    ) -> JoinHandle<F::Output>
    where
        F: crate::future::Future + 'static,
        F::Output: 'static,
    {
        let (handle, notified) = me.shared.owned.bind_local(future, me.clone(), id);

        me.task_hooks.spawn(&TaskMeta {
            id,
            _phantom: Default::default(),
        });

        if let Some(notified) = notified {
            me.schedule(notified);
        }

        handle
    }

    /// Capture a snapshot of this runtime's state.
    #[cfg(all(
        tokio_unstable,
        tokio_taskdump,
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
    ))]
    pub(crate) fn dump(&self) -> crate::runtime::Dump {
        use crate::runtime::dump;
        use task::trace::trace_current_thread;

        let mut traces = vec![];

        // todo: how to make this work outside of a runtime context?
        context::with_scheduler(|maybe_context| {
            // drain the local queue
            let context = if let Some(context) = maybe_context {
                context.expect_current_thread()
            } else {
                return;
            };
            let mut maybe_core = context.core.borrow_mut();
            let core = if let Some(core) = maybe_core.as_mut() {
                core
            } else {
                return;
            };
            let local = &mut core.tasks;

            if self.shared.inject.is_closed() {
                return;
            }

            traces = trace_current_thread(&self.shared.owned, local, &self.shared.inject)
                .into_iter()
                .map(|(id, trace)| dump::Task::new(id, trace))
                .collect();

            // Avoid double borrow panic
            drop(maybe_core);

            // Taking a taskdump could wakes every task, but we probably don't want
            // the `yield_now` vector to be that large under normal circumstances.
            // Therefore, we free its allocation.
            wake_deferred_tasks_and_free(context);
        });

        dump::Dump::new(traces)
    }

    fn next_remote_task(&self) -> Option<Notified> {
        self.shared.inject.pop()
    }

    fn waker_ref(me: &Arc<Self>) -> WakerRef<'_> {
        // Set woken to true when enter block_on, ensure outer future
        // be polled for the first time when enter loop
        me.shared.woken.store(true, Release);
        waker_ref(me)
    }

    // reset woken to false and return original value
    pub(crate) fn reset_woken(&self) -> bool {
        self.shared.woken.swap(false, AcqRel)
    }

    pub(crate) fn num_alive_tasks(&self) -> usize {
        self.shared.owned.num_alive_tasks()
    }

    pub(crate) fn injection_queue_depth(&self) -> usize {
        self.shared.inject.len()
    }

    pub(crate) fn worker_metrics(&self, worker: usize) -> &WorkerMetrics {
        assert_eq!(0, worker);
        &self.shared.worker_metrics
    }
}

cfg_unstable_metrics! {
    impl Handle {
        pub(crate) fn scheduler_metrics(&self) -> &SchedulerMetrics {
            &self.shared.scheduler_metrics
        }

        pub(crate) fn worker_local_queue_depth(&self, worker: usize) -> usize {
            self.worker_metrics(worker).queue_depth()
        }

        pub(crate) fn num_blocking_threads(&self) -> usize {
            self.blocking_spawner.num_threads()
        }

        pub(crate) fn num_idle_blocking_threads(&self) -> usize {
            self.blocking_spawner.num_idle_threads()
        }

        pub(crate) fn blocking_queue_depth(&self) -> usize {
            self.blocking_spawner.queue_depth()
        }

        cfg_64bit_metrics! {
            pub(crate) fn spawned_tasks_count(&self) -> u64 {
                self.shared.owned.spawned_tasks_count()
            }
        }
    }
}

cfg_unstable! {
    use std::num::NonZeroU64;

    impl Handle {
        pub(crate) fn owned_id(&self) -> NonZeroU64 {
            self.shared.owned.id
        }
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("current_thread::Handle { ... }").finish()
    }
}

// ===== impl Shared =====

impl Schedule for Arc<Handle> {
    fn release(&self, task: &Task<Self>) -> Option<Task<Self>> {
        self.shared.owned.remove(task)
    }

    fn schedule(&self, task: task::Notified<Self>) {
        use scheduler::Context::CurrentThread;

        context::with_scheduler(|maybe_cx| match maybe_cx {
            Some(CurrentThread(cx)) if Arc::ptr_eq(self, &cx.handle) => {
                let mut core = cx.core.borrow_mut();

                // If `None`, the runtime is shutting down, so there is no need
                // to schedule the task.
                if let Some(core) = core.as_mut() {
                    core.push_task(self, task);
                }
            }
            _ => {
                // Track that a task was scheduled from **outside** of the runtime.
                self.shared.scheduler_metrics.inc_remote_schedule_count();

                // Schedule the task
                self.shared.inject.push(task);
                self.driver.unpark();
            }
        });
    }

    fn hooks(&self) -> TaskHarnessScheduleHooks {
        TaskHarnessScheduleHooks {
            task_terminate_callback: self.task_hooks.task_terminate_callback.clone(),
        }
    }

    cfg_unstable! {
        fn unhandled_panic(&self) {
            use crate::runtime::UnhandledPanic;

            match self.shared.config.unhandled_panic {
                UnhandledPanic::Ignore => {
                    // Do nothing
                }
                UnhandledPanic::ShutdownRuntime => {
                    use scheduler::Context::CurrentThread;

                    // This hook is only called from within the runtime, so
                    // `context::with_scheduler` should match with `&self`, i.e.
                    // there is no opportunity for a nested scheduler to be
                    // called.
                    context::with_scheduler(|maybe_cx| match maybe_cx {
                        Some(CurrentThread(cx)) if Arc::ptr_eq(self, &cx.handle) => {
                            let mut core = cx.core.borrow_mut();

                            // If `None`, the runtime is shutting down, so there is no need to signal shutdown
                            if let Some(core) = core.as_mut() {
                                core.unhandled_panic = true;
                                self.shared.owned.close_and_shutdown_all(0);
                            }
                        }
                        _ => unreachable!("runtime core not set in CURRENT thread-local"),
                    })
                }
            }
        }
    }
}

impl Wake for Handle {
    fn wake(arc_self: Arc<Self>) {
        Wake::wake_by_ref(&arc_self);
    }

    /// Wake by reference
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.shared.woken.store(true, Release);
        arc_self.driver.unpark();
    }
}

// ===== CoreGuard =====

struct ContextArgs {
    // handle: &'a Arc<Handle>,
    core: *mut Core,
    context: *mut Context,
    cx: *mut std::task::Context<'static>,
    future: *mut (),
    output: *mut (),
}

static mut CONTEXT_ARGS: MaybeUninit<ContextArgs> = MaybeUninit::uninit();

/// [`fstack_task_loop`] 由dpdk的lcore调用, 用于执行future
unsafe extern "C" fn fstack_task_loop<'a, F: Future + 'a>(arg: *mut c_void) -> i32 {
    // print into loop
    // println!("[YQ DEBUG]: into fstack_task_loop");
    
    let args = unsafe { &mut *CONTEXT_ARGS.as_mut_ptr() };
    let context = unsafe { &mut *args.context };

    let mut core = unsafe { Box::from_raw(args.core) }; // 将core指针还原为Box<Core>
    let future = unsafe { &mut *(args.future as *mut std::pin::Pin<&mut F>) };
    let cx = unsafe { &mut *args.cx };

    let handle = &context.handle;

    if handle.reset_woken() {
        let (c, res) = context.enter(core, || {
            crate::task::coop::budget(|| future.as_mut().poll(cx))
        });

        core = c;

        if let Ready(v) = res {
            // on_block的future已经执行完成, 将结果放入output中
            args.output = Box::into_raw(Box::new(v)) as *mut _;
            // 停止fstack无限循环
            fstack::fstack_stop_run();
            // 取出Box<core>的所有权,避免出现二次释放的问题
            unsafe { args.core = Box::into_raw(core) };
            return 0;
        }
    }

    for _ in 0..handle.shared.config.event_interval {
        // Make sure we didn't hit an unhandled_panic
        if core.unhandled_panic {
            args.output = std::ptr::null_mut();
            // return (core, None);
        }

        core.tick();

        let entry = core.next_task(handle);

        let task = match entry {
            Some(entry) => entry,
            None => {
                core.metrics.end_processing_scheduled_tasks();

                core = if !context.defer.is_empty() {
                    context.park_yield(core, handle)
                } else {
                    context.park(core, handle)
                };

                core.metrics.start_processing_scheduled_tasks();

                // Try polling the `block_on` future next
                // spawn所产生的future已经执行完成, 将Box<core>所有权移出用于下次loop,否则下次loop时core是野指针
                args.core = Box::into_raw(core);
                return 0;
            }
        };

        let task = context.handle.shared.owned.assert_owner(task);

        let (c, ()) = context.run_task(core, || {
            task.run();
        });

        core = c;
    }

    core.metrics.end_processing_scheduled_tasks();

    // Yield to the driver, this drives the timer and pulls any
    // pending I/O events.
    core = context.park_yield(core, handle);

    core.metrics.start_processing_scheduled_tasks();

    // 本次loop完成, 取出Box<core>的所有权, 避免Box离开作用域释放core导致下次loop时core是野指针
    args.core = Box::into_raw(core);
    
    // println!("[YQ DEBUG]: out fstack_task_loop");
    0
}

/// Used to ensure we always place the `Core` value back into its slot in
/// `CurrentThread`, even if the future panics.
struct CoreGuard<'a> {
    context: scheduler::Context,
    scheduler: &'a CurrentThread,
}

impl CoreGuard<'_> {
    /// 该函数运行逻辑与原有运行逻辑不一致,该函数展开了[`CoreGuard::enter`]函数的逻辑, 并将loop逻辑抽取到了[`fstack_task_loop`]函数中
    #[track_caller]
    fn block_on<F: Future>(self, future: F) -> F::Output {
        let context_ptr = std::ptr::addr_of!(self.context) as *mut scheduler::Context;

        let context = unsafe { (&*context_ptr).expect_current_thread() };

        let mut core = context.core.borrow_mut().take().expect("core missing");
        let core_ptr = std::ptr::addr_of_mut!(*core);

        let scheduler_context = unsafe { &*context_ptr };
        context::set_scheduler(scheduler_context, || {
            let waker = Handle::waker_ref(&context.handle);
            let waker: &'static Waker =
                unsafe { std::mem::transmute::<&Waker, &'static Waker>(&waker) };
            let mut cx = std::task::Context::from_waker(&waker);
            pin!(future);

            let future = addr_of_mut!(future);

            core.metrics.start_processing_scheduled_tasks();
            let context = context as *const Context as *mut _;
            let args = ContextArgs {
                core: core_ptr,
                context,
                cx: &mut cx,
                future: future as *mut _,
                output: std::ptr::null_mut(),
            };

            unsafe {
                let context_args = &mut *addr_of_mut!(CONTEXT_ARGS);
                context_args.write(args);
            }

            fstack::run(fstack_task_loop::<F>, std::ptr::null_mut() as *mut c_void);
        });

        *context.core.borrow_mut() = Some(core);

        unsafe {
            let context_args = &mut *addr_of_mut!(CONTEXT_ARGS);
            let args = context_args.assume_init_mut();

            if !args.output.is_null() {
                let output = args.output as *mut F::Output;
                let output = Box::from_raw(output);
                *output
            } else {
                panic!("a spawned task panicked and the runtime is configured to shut down on unhandled panic");
            }
        }
    }

    /// Enters the scheduler context. This sets the queue and other necessary
    /// scheduler state in the thread-local.
    fn enter<F, R>(self, f: F) -> R
    where
        F: FnOnce(Box<Core>, &Context) -> (Box<Core>, R),
    {
        let context = self.context.expect_current_thread();

        // Remove `core` from `context` to pass into the closure.
        let core = context.core.borrow_mut().take().expect("core missing");

        // Call the closure and place `core` back
        let (core, ret) = context::set_scheduler(&self.context, || f(core, context));

        *context.core.borrow_mut() = Some(core);

        ret
    }
}

impl Drop for CoreGuard<'_> {
    fn drop(&mut self) {
        let context = self.context.expect_current_thread();

        if let Some(core) = context.core.borrow_mut().take() {
            // Replace old scheduler back into the state to allow
            // other threads to pick it up and drive it.
            self.scheduler.core.set(core);

            // Wake up other possible threads that could steal the driver.
            self.scheduler.notify.notify_one();
        }
    }
}
