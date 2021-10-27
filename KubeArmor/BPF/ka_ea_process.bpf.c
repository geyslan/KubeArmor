// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "common.bpf.h"
#include "maps.bpf.h"
#include "hash.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct filename_key);
	__type(value, struct filename_value);
	__uint(max_entries, 1 << 10);
} ka_ea_filename_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pattern_key);
	__type(value, struct pattern_value);
	__uint(max_entries, 1 << 10);
} ka_ea_pattern_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_spec_key);
	__type(value, struct process_spec_value);
	__uint(max_entries, 1 << 10);
} ka_ea_process_spec_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_filter_key);
	__type(value, struct process_filter_value);
	__uint(max_entries, 1 << 10);
} ka_ea_process_filter_map SEC(".maps");

/* task_auditable checks if task must be audited */
static bool
task_auditable(const struct current_task *ctask)
{
	if (!ctask)
		return false;

	struct filename_key    fnkey;
	struct filename_value *fnvalue;

	fnkey.hash = ctask->filename_hash;
	fnvalue	   = bpf_map_lookup_elem(&ka_ea_filename_map, &fnkey);
	if (!fnvalue)
		return false;

	struct process_spec_key pskey = {
		.pid_ns	       = ctask->pid_ns,
		.mnt_ns	       = ctask->mnt_ns,
		.filename_hash = ctask->filename_hash,
	};

	return !!bpf_map_lookup_elem(&ka_ea_process_spec_map, &pskey);
}

/* task_set_for_audit set task for audit updating process filter map */
static long
task_set_for_audit(const struct current_task *ctask)
{
	if (!ctask)
		return -1;

	struct process_filter_key pfkey = {
		.pid_ns	  = ctask->pid_ns,
		.mnt_ns	  = ctask->mnt_ns,
		.host_pid = ctask->pid,
	};

	struct process_filter_value pfvalue = {
		.inspect = true,
	};

	return bpf_map_update_elem(&ka_ea_process_filter_map, &pfkey, &pfvalue,
				   BPF_ANY);
}

// static bool
// match(const char *pat, const char *str)
// {
// 	if (!pat || !str)
// 		return false;

// 	int str_track = -1;
// 	int pat_track = -1;
// 	int i	      = 0;
// 	int j	      = 0;

// #define do_logic()                                              \
// 	do {                                                    \
// 		if (i >= MAX_FILENAME_LEN || str[i] == '\0')    \
// 			goto loop;                              \
// 		if (j >= MAX_PATTERN_LEN)                       \
// 			return false;                           \
// 		if (pat[j] == '\0' && str[i] == '\0')           \
// 			return true;                            \
// 		if (pat[j] == '*') {                            \
// 			str_track = i;                          \
// 			pat_track = j;                          \
// 			j++;                                    \
// 		} else if (pat[j] != '?' && pat[j] != str[i]) { \
// 			if (pat_track == -1)                    \
// 				return false;                   \
// 			str_track++;                            \
// 			i = str_track;                          \
// 			j = pat_track;                          \
// 		} else {                                        \
// 			i++;                                    \
// 			j++;                                    \
// 		}                                               \
// 	} while (0)

// 	do_logic();
// 	do_logic();
// 	do_logic();
// 	do_logic();
// 	do_logic();

// loop:
// 	while (j < MAX_PATTERN_LEN - 1 && pat[j] == '*')
// 		j++;

// 	return pat[j] == '\0';
// }

// static bool
// match(const char *pat, const char *str)
// {
// 	if (!pat || !str)
// 		return false;

// 	int str_track = -1;
// 	int pat_track = -1;
// 	int i	      = 0;
// 	int j	      = 0;

// 	while (i < MAX_FILENAME_LEN && str[i] != '\0') {
// 		if (j >= MAX_PATTERN_LEN)
// 			return false;
// 		if (pat[j] == '\0' && str[i] == '\0')
// 			return true;
// 		if (pat[j] == '*') {
// 			str_track = i;
// 			pat_track = j;
// 			j++;
// 		} else if (pat[j] != '?' && pat[j] != str[i]) {
// 			if (pat_track == -1)
// 				return false;
// 			str_track++;
// 			i = str_track;
// 			j = pat_track;
// 		} else {
// 			i++;
// 			j++;
// 		}
// 	}

// 	while (j < MAX_PATTERN_LEN - 1 && pat[j] == '*')
// 		j++;

// 	return pat[j] == '\0';
// }

#define CHK_2                                                         \
	do {                                                          \
		if (!wild[w] || !str[i])                              \
			goto CHK_2_OUT;                               \
		two++;                                                \
		if (wild[w] == '*') {                                 \
			if (!wild[++w])                               \
				return true;                          \
			mp = w;                                       \
			cp = i + 1;                                   \
		} else if ((wild[w] == str[i]) || (wild[w] == '?')) { \
			w++;                                          \
			i++;                                          \
		} else {                                              \
			w = mp;                                       \
			i = cp++;                                     \
		}                                                     \
	} while (0)

static bool
match(const char *wild, const char *str)
{
	int w	  = 0;
	int i	  = 0;
	int mp	  = 0;
	int cp	  = 0;

	int one	  = 0;
	int two	  = 0;
	int three = 0;

#define CHK_1                                                \
	do {                                                 \
		if (!str[i] || wild[i] == '*')               \
			goto CHK_1_OUT;                      \
		if ((wild[i] != str[i]) && (wild[i] != '?')) \
			return false;                        \
		one++;                                       \
		i++;                                         \
	} while (0)

	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
	CHK_1;
CHK_1_OUT:
	w = i;

	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
	CHK_2;
CHK_2_OUT:

#define CHK_3                           \
	do {                            \
		if (wild[w] != '*')     \
			goto CHK_3_OUT; \
		three++;                \
		w++;                    \
	} while (0)

	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
	CHK_3;
CHK_3_OUT:

	// if (!wild[w]) {
	// 	printf("one:%d two:%d three:%d\n", one, two, three);
	// }

	return !wild[w];
}

SEC("tp/sched/sched_process_exec")
int
ka_ea_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct current_task ctask = {};

	if (task_get_filename(ctask.filename, sizeof(ctask.filename), ctx) < 0)
		return 0;

	ctask.filename_hash = jenkins_hash(
		ctask.filename, strnlen(ctask.filename, MAX_FILENAME_LEN), 0);
	if (!ctask.filename_hash)
		return 0;

	if (bpf_get_current_comm(&ctask.comm, sizeof(ctask.comm)) < 0)
		return 0;

	task_get_ids(&ctask);

	char pattern[128] = "/bin/*sh";
	bool r;

	r = match(pattern, ctask.filename);
	if (r)
		bpf_printk("pattern: %s - filename: %s - result: %d", pattern,
			   ctask.filename, r);

	if (!task_auditable(&ctask))
		return 0;

	if (task_set_for_audit(&ctask) < 0)
		bpf_printk("[ka-ea-process]: failure setting %s (%u) for audit",
			   ctask.filename, ctask.pid);
	else
		bpf_printk("[ka-ea-process]: %s (%u) set for audit",
			   ctask.filename, ctask.pid);

	return 0;
}

SEC("tp/sched/sched_process_exit")
int
ka_ea_sched_process_exit(void)
{
	struct current_task ctask = {};

	task_get_ids(&ctask);
	if (ctask.pid != ctask.tid) /* disregard threads */
		return 0;

	struct process_filter_key pfkey = {
		.pid_ns	  = ctask.pid_ns,
		.mnt_ns	  = ctask.mnt_ns,
		.host_pid = ctask.pid,
	};

	if (!bpf_map_lookup_elem(&ka_ea_process_filter_map, &pfkey))
		return 0;

	if (bpf_map_delete_elem(&ka_ea_process_filter_map, &pfkey) < 0)
		bpf_printk("[ka-ea-process]: failure unsetting %u for audit",
			   ctask.pid);
	else
		bpf_printk("[ka-ea-process]: %u unset for audit", ctask.pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
