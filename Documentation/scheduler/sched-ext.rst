==========================
Extensible Scheduler Class
==========================

sched_ext is a scheduler class whose behavior can be defined by a set of BPF
programs - the BPF scheduler.

* sched_ext exports full scheduling interface so that any scheduling
  algorithm can be implemented on top.

* The BPF scheduler can group CPUs however it sees fit and schedule them
  together as tasks aren't tied to specific CPUs at the time of wakeup.

* sched_ext and the BPF scheduler can be turned on and off dynamically
  anytime.

* The system integrity is maintained no matter what the BPF scheduler does.
  The default scheduling behavior can be restored anytime an error is
  detected or on sysrq-S.

Switching to and from sched_ext
===============================

``CONFIG_SCHED_CLASS_EXT`` includes sched_ext into the kernel and
``CONFIG_SCHED_CLASS_EXT_DEFAULT`` determines whether sched_ext would be the
default on boot.

When enabled, sched_ext replaces sched_fair as the normal scheduler class
and schedules all ``SCHED_NORMAL``, ``SCHED_BATCH`` and ``SCHED_IDLE``
tasks. The sysctl ``kernel.sched_available_normal_classes`` lists all
available normal scheduling classes and ``kernel.sched_normal_class`` shows
and selects the currently active one.

        # sysctl kernel.sched_available_normal_classes
        kernel.sched_available_normal_classes = fair ext
        # sysctl kernel.sched_normal_class
        kernel.sched_normal_class = fair
        # sysctl kernel.sched_normal_class=ext
        kernel.sched_normal_class = ext

The Basics
==========

By default, sched_ext implements a simple global FIFO scheduling which
ignores scheduling classes and priorities. However, userspace can implement
an arbitrary BPF scheduler by loading a set of BPF programs that implement
``struct sched_ext_ops``.

The only mandatory field in ``sched_ext_ops`` is ``.name`` which must be a
valid BPF object name. All operations are optional. The following excerpt is
from ``tools/sched/scx_example_dummy.bpf.c`` showing a minimal global FIFO
scheduler using a custom dq (dispatch queue).

        s32 BPF_STRUCT_OPS(dummy_select_cpu, struct task_struct *p,
                           s32 prev_cpu, u64 wake_flags)
        {
                return prev_cpu;
        }

        s64 BPF_STRUCT_OPS(dummy_enqueue, struct task_struct *p, u64 enq_flags)
        {
                __sync_fetch_and_add(&nr_enqueued, 1);
                return DUMMY_DQ_ID;
        }

        void BPF_STRUCT_OPS(dummy_consume, s32 cpu)
        {
                scx_bpf_consume(DUMMY_DQ_ID);
        }

        int BPF_STRUCT_OPS(dummy_init)
        {
                return scx_bpf_create_dq(DUMMY_DQ_ID, -1);
        }

        void BPF_STRUCT_OPS(dummy_exit, struct scx_ops_exit_info *ei)
        {
                exited = true;
        }

        SEC(".struct_ops")
        struct sched_ext_ops dummy_ops = {
                .select_cpu             = (void *)dummy_select_cpu,
                .enqueue                = (void *)dummy_enqueue,
                .consume                = (void *)dummy_consume,
                .init                   = (void *)dummy_init,
                .exit                   = (void *)dummy_exit,
                .name                   = "dummy",
        };

Dispatch Queues
---------------

To match the impedance between the scheduler core and the BPF scheduler,
sched_ext uses simple FIFOs called dq's (dispatch queues). By default, there
is one global FIFO (`SCX_DQ_GLOBAL`), and one local dq per CPU
(`SCX_DQ_LOCAL`). The BPF scheduler can manage an arbitrary number of dq's
using `scx_bpf_create_dq()` and `scx_bpf_destroy_dq()`.

A task is always *dispatched to a dq for execution. The task starts
execution when a CPU *consume*s the task from the dq.

Internally, a CPU can only execute tasks which are on its local dq and tasks
from other dq's are bounced through the local dq for execution. A CPU only
looks at other dq's when its local dq is empty. As such, dispatching a task
to one of the local dq's means that the task will be executed before tasks
from other dq's.

Scheduling Cycle
----------------

The following briefly shows how a waking task is scheduled and executed.

1. When a task is waking up, ``.select_cpu()`` is the first operation
   invoked. This serves two purposes. First, CPU selection optimization
   hint. Second, waking up the selected CPU if idle.

   The CPU selected by ``.select_cpu()`` is an optimization hint and not
   binding. The actual decision is made at the last step of scheduling.
   However, there is a small performance gain if the CPU ``.select_cpu()``
   returns matches the eventual CPU the task eventually runs on.

   A side-effect of selecting a CPU is waking it up from idle. While a BPF
   scheduler can wake up any cpu using the ``scx_bpf_kick_cpu()`` helper,
   using ``.select_cpu()`` judiciously can be simpler and more efficient.

   Note that the scheduler core will ignore an invalid CPU selection, for
   example, if it's outside the allowed cpumask of the task.

2. Once the target CPU is selected, ``.enqueue()`` is invoked. It can make
   one of the following decisions:

   * Immediately dispatch the task to either the global or local dq
     (dispatch queue) by returning ``SCX_DQ_GLOBAL`` or ``SCX_DQ_LOCAL``,
     respectively.

   * Immediately dispatch the task to a user-created dq by returning the
     dq ID which is smaller than 2^62.

   * Queue the task on the BPF side, e.g. a map and return ``SCX_DQ_NONE``.

3. When a CPU is ready to schedule, it first looks at its local dq. If
   empty, it invokes ``.consume()`` which should make one or more
   ``scx_bpf_consume()`` calls to consume tasks from dq's. If a
   ``scx_bpf_consume()`` call succeeds, the CPU has the next task to run and
   ``.consume()`` can return.

   If ``.consume()`` is not implemented, the global dq is consumed by
   default.

4. If there's still no task to run, ``.dispatch()`` is invoked which should
   make one or more ``scx_bpf_dispatch()`` calls to dispatch tasks from the
   BPF scheduler to one of the dq's. If more than one tasks have been
   dispatched, go back to the previous consumption step.

5. If there's still no task to run, ``.consume_final()`` is invoked. Except
   that this is invoked right before the CPU goes idle, it's equivalent to
   ``.consume()``. This can be used to implement, e.g., more aggressive task
   stealing from remote dq's.

Note that the BPF scheduler can always choose to dispatch tasks immediately
in ``.enqueue()`` as illustrated in the above dummy example. In such case,
there's no need to implement ``.dispatch()`` as a task is never queued on
the BPF side.

Where to Look
=============

* ``include/linux/sched/ext.h`` defines the core data structures, ops table
  and constants.

* ``kernel/sched/ext.c`` contains sched_ext core implementation and helpers.
  The functions prefixed with ``scx_bpf_`` can be called from the BPF
  scheduler.

* ``tools/sched_ext/`` hosts example BPF scheduler implementations.

  * ``scx_example_dummy[.bpf].c``: Minimal global FIFO scheduler example
    using a custom dq.

  * ``scx_example_qmap[.bpf].c``: A multi-level FIFO scheduler supporting
    five levels of priority implemented with ``BPF_MAP_TYPE_QUEUE``.

ext_lib
=======

``kernel/sched/ext_lib.[hc]`` implement a host of BPF helpers which provide
building blocks for more complex vtime-based schedulers. This isn't intended
for upstream and used to explore what's possible with the BPF scheduler,
evaluate the performance characteristics and chart the direction of BPF
development.

``tools/sched_ext/scxl_example_flat[.bpf].c`` is an example scheduler which
supports vtime based scheduling with multi-domain load balancing. The goal
is implementing all the necessary features generically in BPF so that the
same functionalities can be achieved without using ext_lib.

Caveats
=======

* The current implementation isn't safe in that the BPF scheduler can crash
  the kernel.

  * Unsafe cpumask helpers should be replaced by proper generic BPF helpers.

  * Currently, all kfunc helpers can be called by any operation as BPF
    doesn't yet support filtering kfunc calls per struct_ops operation. Some
    helpers are context sensitive as should be restricted accordingly.

  * Timers used by the BPF scheduler should be shut down when aborting.

* Some BPF verifier checks are circumvented to make ``scxl_example_flat``
  work.

* There are a couple BPF hacks which are still needed even for sched_ext
  proper. They should be removed in the near future.
