/* SPDX-License-Identifier: GPL-2.0 */
enum extl_entity_flags {
	EXTL_ENT_QUEUED		= 1 << 0, /* queued on a sq */
};

struct extl_sq;

struct extl_entity {
	struct task_struct		*task;

	/*
	 * ->sq may change (e.g. due to cgroup or scheduling domain migration)
	 * and needs a bit of dancing around locking.
	 */
	struct extl_sq			*sq;

	u64				key;
	u32				flags;		/* EXTL_ENT_* */

	struct rb_node			rb_node;	/* on sq->rb_root */

	char				data[] __aligned(__alignof__(u64));
};

struct extl_sq {
	u64				id;
	u32				flags;		/* EXTL_SQ_* */
	raw_spinlock_t			lock;

	struct list_head		all_sq_node;	/* all_sqs */
	struct hlist_node		sq_node;	/* sq_hash */

	struct rb_root_cached		rb_root;
	u32				nr_total_tasks;

	char				data[] __aligned(__alignof__(64));
};

DEFINE_STATIC_KEY_FALSE(extl_enabled);

/*
 * There are two lock types, in the locking order - extl_mutex and the sq locks.
 * sq locks may be double locked in address order for migrations. bpf scheduler
 * has access to locking helpers to acquire and release these locks and the
 * locking order and other synchronization requirements are enforced by
 * operation pre/post hooks and the helpers.
 */

/*
 * XXX - The following fields should be in bpf_prog_aux but
 * extl_btf_struct_access() doesn't get env yet, so do a quick and dirty
 * work-around with global variables.
 */
static u32 le_data_observed_end, sq_data_observed_end;

/* extl_mutex protects init/enable/exit */
static DEFINE_MUTEX(extl_mutex);

/*
 * The following fields are protected by extl_mutex and set by extl_bpf_init().
 */
static bool extl_initialized;
static u32 le_data_size, sq_data_size;

static LIST_HEAD(all_sqs);
static int nr_sqs;

/* hashtable of all root sq's. Initialized while enabling. */
static int sq_hash_bits;
static struct hlist_head *sq_hash;

struct extl_pcpu_ctx {
	/*
	 * The sq's this cpu is locking. Each sq lock protects the whole sq
	 * forest and tasks which are associated with it.
	 */
	struct extl_sq			*locked_sqs[2];

	/* dequeue or dispatch? */
	bool				is_deq;

	/*
	 * The following is used to verify that enq/deq bpf operations take and
	 * release ownership of tasks correctly.
	 */
	bool				on_bpf;

	/* a task is in-flight for dispatch and has to be dispatched */
	struct task_struct		*in_flight;
};

static DEFINE_PER_CPU(struct extl_pcpu_ctx, extl_pcpu_ctx);

/**
 * lock_task_sq - Lock the sq a task is associated with
 * @p: task to lock the sq for
 *
 * Find and lock the sq @p is associated with.
 */
static struct extl_sq *lock_task_sq(struct task_struct *p)
{
	lockdep_assert_irqs_disabled();

	while (true) {
		struct extl_sq *sq = p->scx.le->sq;

		if (!sq)
			return NULL;

		/*
		 * @p can be migrated across sq's. As migrations take place with
		 * both source and destination sq's locked, if sq matches while
		 * holding the lock, we know that we're looking at the correct
		 * sq.
		 */
		raw_spin_lock(&sq->lock);
		if (likely(sq == p->scx.le->sq))
			return sq;
		raw_spin_unlock(&sq->lock);
	}
}

static bool le_rb_less(struct rb_node *a, const struct rb_node *b)
{
	struct extl_entity *el_a = rb_entry(a, struct extl_entity, rb_node);
	const struct extl_entity *el_b = rb_entry(b, struct extl_entity, rb_node);

	return el_a->key < el_b->key;
}

static void extl_remove_le(struct extl_entity *le, struct extl_sq *sq)
{
	rb_erase_cached(&le->rb_node, &sq->rb_root);
	le->flags &= ~EXTL_ENT_QUEUED;
}

static void extl_insert_le(struct extl_entity *le, struct extl_sq *sq)
{
	rb_add_cached(&le->rb_node, &sq->rb_root, le_rb_less);
	le->flags |= EXTL_ENT_QUEUED;
}

static struct extl_sq *alloc_sq(u64 id, gfp_t gfp)
{
	struct extl_sq *sq;

	sq = kzalloc(struct_size(sq, data, sq_data_size), gfp);
	if (!sq)
		return ERR_PTR(-ENOMEM);

	sq->id = id;
	raw_spin_lock_init(&sq->lock);
	sq->rb_root = RB_ROOT_CACHED;
	return sq;
}

static __used noinline struct extl_sq *extl_bpf_create_sq(u64 id)
{
	struct extl_sq *sq = NULL;
	int err;

	/* this must be called between extl_bpf_init() and extl_bpf_enable() */
	if (!extl_initialized) {
		err = -ESRCH;
		goto err;
	}
	if (static_branch_unlikely(&extl_enabled)) {
		err = -EBUSY;
		goto err;
	}

	sq = alloc_sq(id, GFP_KERNEL);
	if (IS_ERR(sq)) {
		err = PTR_ERR(sq);
		goto err;
	}

	list_add(&sq->all_sq_node, &all_sqs);
	nr_sqs++;
	return sq;

err:
	if (!IS_ERR_OR_NULL(sq))
		kfree(sq);
	if (err != -ENOMEM)
		scx_ops_error("failed with error %d", err);
	return NULL;
}

static struct extl_sq *find_sq(u64 id)
{
	u32 hash = hash_64(id, sq_hash_bits);
	struct extl_sq *sq;

	hlist_for_each_entry(sq, &sq_hash[hash], sq_node)
		if (likely(sq->id == id))
			return sq;
	return NULL;
}

int __extl_prep_enable_pre(struct task_struct *p, struct task_group *tg)
{
	p->scx.le = kzalloc(struct_size(p->scx.le, data, le_data_size),
			    GFP_KERNEL);
	if (!p->scx.le)
		return -ENOMEM;

	p->scx.le->task = p;
	return 0;
}

static void open_sq_lock_ctx(void)
{
	lockdep_assert_preemption_disabled();
	WARN_ON_ONCE(__this_cpu_read(extl_pcpu_ctx.locked_sqs[0]));
}

/**
 * extl_bpf_sq_lock - Lock a sq
 * @sq: sq to lock
 */
static __used noinline void extl_bpf_sq_lock(struct extl_sq *sq)
{
	struct extl_sq **locked = this_cpu_ptr(extl_pcpu_ctx.locked_sqs);

	if (unlikely(locked[0])) {
		scx_ops_error("sq 0x%llx already locked", locked[0]->id);
		return;
	}

	raw_spin_lock(&sq->lock);
	locked[0] = sq;
}

/**
 * extl_bpf_sq_lock_by_task - Lock the sq associated with a task
 * @p: task to lock the associated sq for
 */
static __used noinline void extl_bpf_sq_lock_by_task(struct task_struct *p)
{
	struct extl_sq **locked = this_cpu_ptr(extl_pcpu_ctx.locked_sqs);
	struct extl_sq *sq;

	if (unlikely(locked[0])) {
		scx_ops_error("sq 0x%llx already locked", locked[0]->id);
		return;
	}

	sq = lock_task_sq(p);
	if (!sq) {
		scx_ops_error("%d [%s] isn't associated with an sq yet",
			       p->pid, p->comm);
		return;
	}

	locked[0] = sq;
}

static bool verify_locked(struct extl_sq *sq)
{
	struct extl_sq **locked = this_cpu_ptr(extl_pcpu_ctx.locked_sqs);

	if (unlikely(locked[0] != sq && locked[1] != sq)) {
		if (locked[1])
			scx_ops_error("sq 0x%llx should be locked but 0x%llx and 0x%llx are locked instead",
				      sq->id, locked[0]->id, locked[1]->id);
		else if (locked[0])
			scx_ops_error("sq 0x%llx should be locked but 0x%llx is locked instead",
				      sq->id, locked[0]->id);
		else
			scx_ops_error("sq 0x%llx should be locked", sq->id);

		return false;
	}

	return true;
}

/**
 * extl_bpf_sq_unlock - Unlock the currently locked sq
 *
 * The counterpart of extl_bpf_sq_lock() and extl_bpf_find_and_lock_sq().
 */
static __used noinline void extl_bpf_sq_unlock(void)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);
	struct extl_sq **locked = pctx->locked_sqs;

	if (unlikely(!locked[0])) {
		scx_ops_error("called when not locked");
		return;
	}

	if (unlikely(locked[1])) {
		scx_ops_error("called while double locked");
		return;
	}

	raw_spin_unlock(&locked[0]->lock);
	locked[0] = NULL;
}

/**
 * extl_bpf_sq_lock_double - Lock two sq's for lb transfers
 * @sq0: sq to lock
 * @sq1: sq to lock
 */
static __used noinline void extl_bpf_sq_lock_double(struct extl_sq *sq0,
						    struct extl_sq *sq1)
{
	struct extl_sq **locked = this_cpu_ptr(extl_pcpu_ctx.locked_sqs);
	struct extl_sq *sqs[2] = { sq0, sq1 };
	int first = sqs[0] > sqs[1];
	int second = first ^ 1;

	if (unlikely(locked[0])) {
		scx_ops_error("sq 0x%llx already locked", locked[0]->id);
		return;
	}
	if (unlikely(!sqs[0] && !sqs[1])) {
		scx_ops_error("no sq to lock");
		return;
	}
	if (!sqs[0])
		sqs[0] = sqs[1];
	else if (!sqs[1])
		sqs[1] = sqs[0];

	raw_spin_lock(&sqs[first]->lock);
	if (sqs[first] != sqs[second])
		raw_spin_lock(&sqs[second]->lock);

	locked[0] = sqs[first];
	locked[1] = sqs[second];
}

/**
 * extl_bpf_sq_unlock_double - Undo double lock
 *
 * The counterpart of extl_bpf_sq_sq_lock_double().
 */
static __used noinline void extl_bpf_sq_unlock_double(void)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);
	struct extl_sq **locked = pctx->locked_sqs;

	if (unlikely(!locked[0] || !locked[1])) {
		scx_ops_error("called when not double locked");
		return;
	}

	raw_spin_unlock(&locked[0]->lock);
	if (locked[0] != locked[1])
		raw_spin_unlock(&locked[1]->lock);
	locked[0] = NULL;
	locked[1] = NULL;
}

/**
 * extl_bpf_sq_lock_double_by_task - Lock two sq's for lb transfers
 * @task: task to lock the associated sq for
 * @sq: sq to lock
 *
 * Lock @task's sq and @sq.
 */
static __used noinline
void extl_bpf_sq_lock_double_by_task(struct task_struct *p, struct extl_sq *sq)
{
	/*
	 * @p may migrate to a different sq until its sq is locked and we don't
	 * know whether we locked the right sq before locking it and verifying
	 * that the @p hasn't migrated away. Do the lock-and-verify dancing.
	 */
	while (true) {
		struct extl_sq *p_sq = p->scx.le->sq;

		extl_bpf_sq_lock_double(p_sq, sq);
		if (p->scx.le->sq == p_sq)
			return;
		extl_bpf_sq_unlock_double();
	}
}

static void close_sq_lock_ctx(void)
{
	struct extl_sq **locked = this_cpu_ptr(extl_pcpu_ctx.locked_sqs);

	if (unlikely(locked[1])) {
		scx_ops_error("returned with sq's 0x%llx and 0x%llx locked",
			      locked[0]->id, locked[1]->id);
		extl_bpf_sq_unlock_double();
	} else if (unlikely(locked[0])) {
		scx_ops_error("returned with sq 0x%llx locked",
			      locked[0]->id);
		extl_bpf_sq_unlock();
	}
}

/**
 * extl_bpf_set_task_sq - Associate a task with an sq
 * @p: task of interest
 * @new_sq: sq to associate
 *
 * Associate @p with @sq which already should have been locked. If @p is already
 * associated with an sq, that sq should have been locked too.
 */
static __used noinline
void extl_bpf_set_task_sq(struct task_struct *p, struct extl_sq *new_sq)
{
	struct extl_sq **locked = this_cpu_ptr(extl_pcpu_ctx.locked_sqs);
	struct extl_entity *ple = p->scx.le;
	struct extl_sq *old_sq = ple->sq;

	if (!verify_locked(new_sq) || (old_sq && !verify_locked(old_sq)))
		return;

	if (ple->flags & EXTL_ENT_QUEUED) {
		scx_ops_error("%d [%s] is busy", p->pid, p->comm);
		return;
	}

	if (new_sq != locked[0] && new_sq != locked[1]) {
		scx_ops_error("new sq 0x%llx is not locked", new_sq->id);
		return;
	}

	rcu_assign_pointer(ple->sq, new_sq);
}

void __extl_enable_pre(struct task_struct *p)
{
	lockdep_assert_irqs_disabled();
	open_sq_lock_ctx();
}

void __extl_enable_post(struct task_struct *p)
{
	lockdep_assert_irqs_disabled();

	if (!rcu_access_pointer(p->scx.le->sq)) {
		struct extl_sq *sq;

		scx_ops_error("->link() should call extl_bpf_set_task_sq()");

		/*
		 * NULL ->sq is gonna cause oops down the line, assign something
		 * so that we can survive until scx_ops_error() can abort the
		 * whole thing.
		 */
		sq = list_first_entry_or_null(&all_sqs, struct extl_sq, all_sq_node);
		p->scx.le->sq = sq;
	}

	close_sq_lock_ctx();
}

void __extl_cancel_enable(struct task_struct *p, struct task_group *tg)
{
	kfree(p->scx.le);
	p->scx.le = NULL;
}

void __extl_disable(struct task_struct *p)
{
	struct extl_entity *le = p->scx.le;

	le->sq = NULL;
	p->scx.le = NULL;
	kfree(le);
}

/**
 * extl_bpf_find_sq - Find a sq
 * @id: sq ID
 *
 * Find the sq matching @id.
 */
static __used noinline struct extl_sq *extl_bpf_find_sq(u64 id)
{
	struct extl_sq *sq;

	sq = find_sq(id);
	if (unlikely(!sq)) {
		scx_ops_error("invalid sq ID 0x%llx", id);
		return NULL;
	}
	return sq;
}

void __extl_enqueue_pre(struct task_struct *p)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);

	pctx->on_bpf = false;
	open_sq_lock_ctx();
}

static bool task_enqueue_check(struct task_struct *p)
{
	struct extl_entity *le = p->scx.le;

	if (unlikely(!p)) {
		scx_ops_error("called with NULL task");
		return false;
	}

	if (!verify_locked(le->sq))
		return false;

	if (unlikely(le->flags & EXTL_ENT_QUEUED)) {
		scx_ops_error("%d [%s] already enqueued, flags=0x%x",
			      p->pid, p->comm, le->flags);
		return false;
	}

	/*
	 * Double enqueue is dangerous as once @p is enqueued and the lock is
	 * released, another CPU can dispatch the task anytime.
	 */
	if (unlikely(__this_cpu_read(extl_pcpu_ctx.on_bpf))) {
		scx_ops_error("double enqueue");
		return false;
	}

	return true;
}

/**
 * extl_bpf_enqueue_task - Enqueue a task on its sq
 * @p: task being enqueued
 * @key: key value to use for insertion
 *
 * Insert @p into its sq at @key. The caller must be have the sq locked. This
 * can be used in either the enqueue path or dispatch path.
 */
static __used noinline void extl_bpf_enqueue_task(struct task_struct *p, u64 key)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);
	struct extl_sq *sq = p->scx.le->sq;

	if (!task_enqueue_check(p))
		return;

	p->scx.le->key = key;
	extl_insert_le(p->scx.le, sq);
	sq->nr_total_tasks++;

	pctx->on_bpf = true;
}

void __extl_enqueue_post(struct task_struct *p, s64 verdict)
{
	bool queued = __this_cpu_read(extl_pcpu_ctx.on_bpf);

	close_sq_lock_ctx();

	if (verdict >= 0 && (verdict == SCX_DQ_NONE) != queued)
		scx_ops_error("inconsistent EXTL_ENT_QUEUED state after enqueue, verdict=0x%llx queued=%d",
			      verdict, queued);
}

void __extl_dequeue_pre(struct task_struct *p)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);

	pctx->is_deq = true;
	pctx->on_bpf = true;
	open_sq_lock_ctx();
}

/**
 * extl_bpf_dequeue_task - Dequeue a task from its sq
 * @p: task to be dequeued
 *
 * Dequeue @p. Must be called with the sq locked.
 */
static __used noinline bool extl_bpf_dequeue_task(struct task_struct *p)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);
	struct extl_entity *le;
	bool dequeued = false;

	if (unlikely(!p)) {
		scx_ops_error("called with NULL task");
		return false;
	}

	if (!verify_locked(p->scx.le->sq))
		return false;

	/*
	 * @p is owned by this CPU, so double dequeue should be harmelss. Let's
	 * still error out for consitency with enqueue.
	 */
	if (pctx->is_deq &&
	    unlikely(!__this_cpu_read(extl_pcpu_ctx.on_bpf))) {
		scx_ops_error("double extl_bpf_dequeue");
		return false;
	}

	le = p->scx.le;

	/* dequeue and dispatch may race, ignore if already dequeued */
	if (le->flags & EXTL_ENT_QUEUED) {
		struct extl_sq *sq = le->sq;

		extl_remove_le(le, sq);
		sq->nr_total_tasks--;
		dequeued = true;
	}

	if (pctx->is_deq)
		pctx->on_bpf = false;

	return dequeued;
}

void __extl_dequeue_post(struct task_struct *p, u64 deq_flags)
{
	close_sq_lock_ctx();

	if (unlikely(__this_cpu_read(extl_pcpu_ctx.on_bpf))) {
		scx_ops_error("EXTL_ENT_QUEUED after dequeue, forcing dequeue");
		extl_bpf_sq_lock_by_task(p);
		extl_bpf_dequeue_task(p);
		extl_bpf_sq_unlock();
	}
}

void __extl_dispatch_pre(void)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);

	pctx->is_deq = false;
	pctx->in_flight = NULL;
	open_sq_lock_ctx();
}

int __extl_task_dispatched(struct task_struct *p)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);
	struct task_struct *in_flight = pctx->in_flight;

	if (unlikely(!in_flight)) {
		scx_ops_error("%d [%s] is being dispatched but it's not in flight",
			      p->pid, p->comm);
		return -EINVAL;
	}

	if (unlikely(p != in_flight)) {
		scx_ops_error("%d [%s] is being dispatched but %d [%s] is in flight",
			      p->pid, p->comm, in_flight->pid, in_flight->comm);
		return -EINVAL;
	}

	pctx->in_flight = NULL;
	return 0;
}

void __extl_dispatch_post(void)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);

	close_sq_lock_ctx();

	if (unlikely(pctx->in_flight)) {
		scx_ops_error("%d [%s] in flight for dispatch didn't get dispatched",
			      pctx->in_flight->pid, pctx->in_flight->comm);
		pctx->in_flight = NULL;
	}
}

/**
 * extl_bpf_dispatch_dequeue - Dequeue a task for dispatching
 * @p: task being dispatched
 *
 * Remove @p from its sq for dispatching. Must be called with the sq locked. The
 * returned task must be dispatched or re-enqueued before relasing the sq lock.
 */
static __used noinline
void extl_bpf_dispatch_dequeue(struct task_struct *p)
{
	struct extl_pcpu_ctx *pctx = this_cpu_ptr(&extl_pcpu_ctx);

	if (unlikely(!extl_bpf_dequeue_task(p))) {
		scx_ops_error("%d [%s] is not queued but being dispatched",
			      p->pid, p->comm);
		return;
	}

	pctx->in_flight = p;
}

/**
 * extl_bpf_sq_first_task - The first task in a sq
 * @sq: sq of interest
 *
 * Return the first extl_entity in @sq. Must be called with @sq locked. The
 * returned task may be dequeued and dispatched.
 */
static __used noinline
struct task_struct *extl_bpf_sq_first_task(struct extl_sq *sq)
{
	struct rb_node *node;

	if (!verify_locked(sq))
		return NULL;

	node = rb_first_cached(&sq->rb_root);
	if (node)
		return rb_entry(node, struct extl_entity, rb_node)->task;
	else
		return NULL;
}

/**
 * extl_bpf_task_sq - Find the sq sq
 * @le: extl_entity to find the sq sq for
 */
static __used noinline struct extl_sq *extl_bpf_task_sq(struct task_struct *p)
{
	return p->scx.le->sq;
}

/**
 * extl_bpf_init - Initialize ext_lib
 * @le_data_size_req: requested extl_entity data size
 * @sq_data_size_req: requested extl_sq data size
 *
 * This is the first step of three-stage ext_lib initialization:
 *
 * 1. extl_bpf_init()
 * 2. sq creation using extl_bpf_create_sq() and other initialization in bpf
 * 3. extl_bpf_enable().
 *
 * @le_data_size_req and @sq_data_size_req determine how many bytes are
 * allocated in extl_entity->data and extl_sq->data, respectively.
 *
 * ext_lib intialization including invoking this function is to be performed
 * from ext_ops->init().
 */
static __used noinline int extl_bpf_init(u32 le_data_size_req, u32 sq_data_size_req)
{
	int err;

	mutex_lock(&extl_mutex);

	if (extl_initialized) {
		scx_ops_error("already initialized");
		err = -EBUSY;
		goto err;
	}

	if (le_data_observed_end >
	    offsetof(struct extl_entity, data) + le_data_size_req) {
		scx_ops_error("le_data access reached %u which is beyond the end at %zu",
			      le_data_observed_end,
			      offsetof(struct extl_entity, data) + le_data_size_req);
		err = -ERANGE;
		goto err;
	}
	if (sq_data_observed_end >
	    offsetof(struct extl_sq, data) + sq_data_size_req) {
		scx_ops_error("sq_data access reached %u which is beyond the end at %zu",
			      sq_data_observed_end,
			      offsetof(struct extl_entity, data) + sq_data_size_req);
		err = -ERANGE;
		goto err;
	}

	le_data_size = le_data_size_req;
	sq_data_size = sq_data_size_req;

	extl_initialized = true;
	mutex_unlock(&extl_mutex);
	return 0;
err:
	le_data_size = 0;
	sq_data_size = 0;
	mutex_unlock(&extl_mutex);
	return err;
}

/**
 * extl_bpf_enable - Commit enabling of ext_lib
 *
 * This is the final step of three-stage ext_lib initialization. See
 * extl_bpf_init() for more info.
 */
static __used noinline int extl_bpf_enable(void)
{
	struct extl_sq *sq;
	int err;

	mutex_lock(&extl_mutex);

	if (!extl_initialized) {
		scx_ops_error("can't be enabled without being initialized first");
		err = -EINVAL;
		goto err_unlock;
	}

	if (!nr_sqs) {
		scx_ops_error("can't be enabled without any sq trees");
		err = -EINVAL;
		goto err_unlock;
	}

	sq_hash_bits = 1;
	sq_hash_bits += ilog2(nr_sqs);

	sq_hash = kvzalloc((1 << sq_hash_bits) * sizeof(sq_hash[0]), GFP_KERNEL);
	if (!sq_hash) {
		scx_ops_error("failed to allocate sq_hash");
		err = -ENOMEM;
		goto err_unlock;
	}

	__hash_init(sq_hash, 1 << sq_hash_bits);

	list_for_each_entry(sq, &all_sqs, all_sq_node)
		hlist_add_head(&sq->sq_node,
			       &sq_hash[hash_64(sq->id, sq_hash_bits)]);

	static_branch_enable_cpuslocked(&extl_enabled);

	mutex_unlock(&extl_mutex);
	return 0;

err_unlock:
	mutex_unlock(&extl_mutex);
	return err;
}

/* ext_ops must have been disabled before calling this function */
void extl_exit(void)
{
	struct extl_sq *sq, *tmp_sq;

	mutex_lock(&extl_mutex);

	static_branch_disable_cpuslocked(&extl_enabled);

	list_for_each_entry_safe(sq, tmp_sq, &all_sqs, all_sq_node)
		kfree(sq);

	INIT_LIST_HEAD(&all_sqs);
	nr_sqs = 0;

	kfree(sq_hash);
	sq_hash = NULL;

	le_data_size = 0;
	sq_data_size = 0;
	le_data_observed_end = 0;
	sq_data_observed_end = 0;

	extl_initialized = false;
	mutex_unlock(&extl_mutex);
}

/*
 * bpf plumbing.
 */
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

extern struct btf *btf_vmlinux;
static const struct btf_type *extl_entity_type;
static const struct btf_type *extl_sq_type;

BTF_SET8_START(extl_kfunc_ids_init)
BTF_ID_FLAGS(func, extl_bpf_init)
BTF_ID_FLAGS(func, extl_bpf_create_sq)
BTF_ID_FLAGS(func, extl_bpf_enable)
BTF_SET8_END(extl_kfunc_ids_init)

static const struct btf_kfunc_id_set extl_kfunc_set_init = {
	.owner			= THIS_MODULE,
	.set			= &extl_kfunc_ids_init,
};

BTF_SET8_START(extl_kfunc_ids_enable_and_set_cpus_allowed)
BTF_ID_FLAGS(func, extl_bpf_set_task_sq)
BTF_SET8_END(extl_kfunc_ids_enable_and_set_cpus_allowed)

static const struct btf_kfunc_id_set extl_kfunc_set_ids_enable_and_set_cpus_allowed = {
	.owner			= THIS_MODULE,
	.set			= &extl_kfunc_ids_enable_and_set_cpus_allowed,
};

BTF_SET8_START(extl_kfunc_ids_sched)
BTF_ID_FLAGS(func, extl_bpf_find_sq)
BTF_ID_FLAGS(func, extl_bpf_sq_lock)
BTF_ID_FLAGS(func, extl_bpf_sq_lock_by_task)
BTF_ID_FLAGS(func, extl_bpf_sq_unlock)
BTF_ID_FLAGS(func, extl_bpf_enqueue_task)
BTF_ID_FLAGS(func, extl_bpf_dequeue_task)
BTF_ID_FLAGS(func, extl_bpf_sq_lock_double)
BTF_ID_FLAGS(func, extl_bpf_sq_lock_double_by_task)
BTF_ID_FLAGS(func, extl_bpf_sq_unlock_double)
BTF_SET8_END(extl_kfunc_ids_sched)

static const struct btf_kfunc_id_set extl_kfunc_set_sched = {
	.owner			= THIS_MODULE,
	.set			= &extl_kfunc_ids_sched,
};

BTF_SET8_START(extl_kfunc_ids_dispatch)
BTF_ID_FLAGS(func, extl_bpf_dispatch_dequeue)
BTF_SET8_END(extl_kfunc_ids_dispatch)

static const struct btf_kfunc_id_set extl_kfunc_set_dispatch = {
	.owner			= THIS_MODULE,
	.set			= &extl_kfunc_ids_dispatch,
};

BTF_SET8_START(extl_kfunc_ids_online)
BTF_ID_FLAGS(func, extl_bpf_sq_first_task)
BTF_ID_FLAGS(func, extl_bpf_task_sq)
BTF_SET8_END(extl_kfunc_ids_online)

static const struct btf_kfunc_id_set extl_kfunc_set_online = {
	.owner			= THIS_MODULE,
	.set			= &extl_kfunc_ids_online,
};

int bpf_sched_extl_btf_struct_access(struct bpf_verifier_log *log,
				     const struct btf *btf,
				     const struct btf_type *t, int off,
				     int size, enum bpf_access_type atype,
				     u32 *next_btf_id)
{
	u32 data_start, data_len, *observed_endp;

	if (t == extl_entity_type) {
		data_start = offsetof(struct extl_entity, data);
		data_len = le_data_size;
		observed_endp = &le_data_observed_end;
	} else if (t == extl_sq_type) {
		data_start = offsetof(struct extl_sq, data);
		data_len = sq_data_size;
		observed_endp = &sq_data_observed_end;
	} else {
		return -EAGAIN;
	}

	if (off + size < data_start) {
		if (atype != BPF_READ) {
			bpf_log(log, "only read is supported outside of data area\n");
			return -EACCES;
		}
		return NOT_INIT;
	}

	*observed_endp = max_t(u32, *observed_endp, off + size);
	return SCALAR_VALUE;
}

int bpf_sched_extl_init(struct btf *btf)
{
	u32 type_id;

	type_id = btf_find_by_name_kind(btf, "extl_entity",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	extl_entity_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "extl_sq",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	extl_sq_type = btf_type_by_id(btf, type_id);

	return 0;
}

/*
 * This can't be done earlier as register_btf_kfunc_id_set() needs most of the
 * system to be up.
 */
static int __init register_extl_kfuncs(void)
{
	int ret;

	/*
	 * FIXME - Many kfunc helpers are context-sensitive and can only be
	 * called from specific ext_ops operations. Unfortunately, we can't
	 * currently tell for which operation we're verifying for. For now,
	 * allow all kfuncs for everybody.
	 */
	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &extl_kfunc_set_init)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &extl_kfunc_set_ids_enable_and_set_cpus_allowed)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &extl_kfunc_set_sched)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &extl_kfunc_set_dispatch)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &extl_kfunc_set_online))) {
		pr_err("sched_ext_lib: failed to register kfunc sets (%d)", ret);
		return ret;
	}

	return 0;
}
__initcall(register_extl_kfuncs);
